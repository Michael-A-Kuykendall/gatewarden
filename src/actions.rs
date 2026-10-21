//! License actions: machine activation, usage increments and machine removal.
//!
//! These are the license's own actions on its Keygen records, authenticated with
//! `Authorization: License <key>`. Every response that carries data the caller
//! acts on (activation, usage) is signature-verified with the same pipeline as
//! validation, so a local proxy cannot fake "activated" or "under the limit".
//!
//! Keygen does not document stable error codes for a taken fingerprint or a
//! machine limit, so errors are recognised by HTTP 422 plus the JSON:API
//! `errors[].source.pointer` (and `code` when present).

use crate::crypto::pipeline::verify_response_for_method;
use crate::manager::LicenseManager;
use crate::protocol::models::{KeygenValidateResponse, LicenseState};
use crate::GatewardenError;
use reqwest::Method;

/// Result of activating a machine for a license.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activation {
    /// Keygen machine id, when Keygen created the machine in this call.
    pub machine_id: Option<String>,
    /// True when the fingerprint was already activated (nothing was created).
    pub already_active: bool,
}

/// License usage after an increment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    /// Uses recorded on the license.
    pub uses: u64,
    /// The license's use ceiling, if any.
    pub max_uses: Option<u64>,
}

fn json_body(body: &[u8]) -> Result<serde_json::Value, GatewardenError> {
    serde_json::from_slice(body)
        .map_err(|e| GatewardenError::ProtocolError(format!("Parse error: {}", e)))
}

fn error_pointers(value: &serde_json::Value) -> Vec<(String, String)> {
    value
        .get("errors")
        .and_then(|e| e.as_array())
        .map(|errors| {
            errors
                .iter()
                .map(|e| {
                    let pointer = e
                        .pointer("/source/pointer")
                        .and_then(|p| p.as_str())
                        .unwrap_or("")
                        .to_string();
                    let code = e
                        .get("code")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                    (pointer, code)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Interpret a (verified) machine activation response.
pub fn parse_activation(status: u16, body: &[u8]) -> Result<Activation, GatewardenError> {
    match status {
        200 | 201 => {
            let value = json_body(body)?;
            let id = value
                .pointer("/data/id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| GatewardenError::ProtocolError("machine id missing".into()))?;
            Ok(Activation {
                machine_id: Some(id.to_string()),
                already_active: false,
            })
        }
        422 => {
            let value = json_body(body)?;
            let errors = error_pointers(&value);
            if errors
                .iter()
                .any(|(p, c)| p == "/data/attributes/fingerprint" || c.contains("FINGERPRINT"))
            {
                Ok(Activation {
                    machine_id: None,
                    already_active: true,
                })
            } else if errors.iter().any(|(p, c)| {
                p.starts_with("/data/relationships/license")
                    || c.contains("MACHINE_LIMIT")
                    || c.contains("TOO_MANY_MACHINES")
            }) {
                Err(GatewardenError::MachineLimitExceeded)
            } else {
                Err(GatewardenError::ProtocolError(format!(
                    "activation refused: {:?}",
                    errors
                )))
            }
        }
        401 | 403 => Err(GatewardenError::InvalidLicense),
        other => Err(GatewardenError::ProtocolError(format!(
            "activation HTTP {}",
            other
        ))),
    }
}

/// Interpret a (verified) increment-usage response.
pub fn parse_increment(status: u16, body: &[u8]) -> Result<Usage, GatewardenError> {
    match status {
        200 => {
            let value = json_body(body)?;
            let uses = value
                .pointer("/data/attributes/uses")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| GatewardenError::ProtocolError("uses missing".into()))?;
            let max_uses = value
                .pointer("/data/attributes/maxUses")
                .and_then(|v| v.as_u64());
            Ok(Usage { uses, max_uses })
        }
        422 => Err(GatewardenError::UsageLimitExceeded),
        401 | 403 => Err(GatewardenError::InvalidLicense),
        other => Err(GatewardenError::ProtocolError(format!(
            "increment-usage HTTP {}",
            other
        ))),
    }
}

impl LicenseManager {
    /// Validate a key online and return the verified license state as Keygen reports
    /// it, valid or not (e.g. `NO_MACHINE` before activation), without applying
    /// policy or caching. Use it to learn the license id and policy before acting.
    pub fn inspect_key(
        &self,
        license_key: &str,
        fingerprint: Option<&str>,
    ) -> Result<LicenseState, GatewardenError> {
        let response = self
            .client
            .validate_key_with_fingerprint(license_key, &[], fingerprint)?;
        verify_response_for_method(
            &response,
            "post",
            &self.config.public_key_hex,
            self.clock.as_ref(),
        )?;
        let parsed: KeygenValidateResponse = serde_json::from_str(response.body_str()?)
            .map_err(|e| GatewardenError::ProtocolError(format!("Parse error: {}", e)))?;
        LicenseState::from_keygen_response(&parsed)
    }

    /// Activate this machine (by fingerprint) for a license, as the license itself.
    /// A fingerprint that is already activated returns `already_active`.
    pub fn activate_machine(
        &self,
        license_key: &str,
        license_id: &str,
        fingerprint: &str,
        platform: &str,
        name: &str,
    ) -> Result<Activation, GatewardenError> {
        let body = serde_json::json!({ "data": {
            "type": "machines",
            "attributes": { "fingerprint": fingerprint, "platform": platform, "name": name },
            "relationships": { "license": { "data": { "type": "licenses", "id": license_id } } }
        }});
        let response =
            self.client
                .license_request(Method::POST, "/machines", license_key, Some(&body))?;
        verify_response_for_method(
            &response,
            "post",
            &self.config.public_key_hex,
            self.clock.as_ref(),
        )?;
        parse_activation(response.status, &response.body)
    }

    /// Increment a license's usage by `by` (Keygen enforces the policy's `maxUses`).
    pub fn increment_usage(
        &self,
        license_key: &str,
        license_id: &str,
        by: u64,
    ) -> Result<Usage, GatewardenError> {
        let body = serde_json::json!({ "meta": { "increment": by } });
        let path = format!("/licenses/{}/actions/increment-usage", license_id);
        let response =
            self.client
                .license_request(Method::POST, &path, license_key, Some(&body))?;
        verify_response_for_method(
            &response,
            "post",
            &self.config.public_key_hex,
            self.clock.as_ref(),
        )?;
        parse_increment(response.status, &response.body)
    }

    /// Remove one of the license's machines, freeing its slot. The response carries
    /// no data the caller acts on, so only the status is checked.
    pub fn deactivate_machine(
        &self,
        license_key: &str,
        machine_id: &str,
    ) -> Result<(), GatewardenError> {
        let path = format!("/machines/{}", machine_id);
        let response = self
            .client
            .license_request(Method::DELETE, &path, license_key, None)?;
        match response.status {
            200 | 204 | 404 => Ok(()),
            401 | 403 => Err(GatewardenError::InvalidLicense),
            other => Err(GatewardenError::ProtocolError(format!(
                "deactivate HTTP {}",
                other
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_created() {
        let body = br#"{"data":{"id":"m-1","type":"machines","attributes":{"fingerprint":"f"}}}"#;
        assert_eq!(
            parse_activation(201, body).unwrap(),
            Activation {
                machine_id: Some("m-1".into()),
                already_active: false
            }
        );
    }

    #[test]
    fn activation_fingerprint_taken_is_already_active() {
        let body = br#"{"errors":[{"title":"Unprocessable resource","detail":"has already been taken","code":"FINGERPRINT_TAKEN","source":{"pointer":"/data/attributes/fingerprint"}}]}"#;
        assert_eq!(
            parse_activation(422, body).unwrap(),
            Activation {
                machine_id: None,
                already_active: true
            }
        );
    }

    #[test]
    fn activation_machine_limit() {
        let body = br#"{"errors":[{"title":"Unprocessable resource","detail":"machine count has exceeded maximum allowed for license","code":"MACHINE_LIMIT_EXCEEDED","source":{"pointer":"/data/relationships/license"}}]}"#;
        assert!(matches!(
            parse_activation(422, body),
            Err(GatewardenError::MachineLimitExceeded)
        ));
    }

    #[test]
    fn increment_ok_and_exceeded() {
        let body =
            br#"{"data":{"id":"l-1","type":"licenses","attributes":{"uses":7,"maxUses":30}}}"#;
        assert_eq!(
            parse_increment(200, body).unwrap(),
            Usage {
                uses: 7,
                max_uses: Some(30)
            }
        );
        let over = br#"{"errors":[{"title":"Unprocessable resource","detail":"usage exceeds maximum allowed by current policy (30)","source":{"pointer":"/data/attributes/uses"}}]}"#;
        assert!(matches!(
            parse_increment(422, over),
            Err(GatewardenError::UsageLimitExceeded)
        ));
    }

    #[test]
    fn unauthorized_is_invalid_license() {
        assert!(matches!(
            parse_increment(403, b"{}"),
            Err(GatewardenError::InvalidLicense)
        ));
        assert!(matches!(
            parse_activation(401, b"{}"),
            Err(GatewardenError::InvalidLicense)
        ));
    }
}
