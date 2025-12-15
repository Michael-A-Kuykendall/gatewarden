//! Keygen response structs and license state extraction.

use crate::GatewardenError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Raw Keygen validate-key response.
#[derive(Debug, Clone, Deserialize)]
pub struct KeygenValidateResponse {
    pub meta: KeygenValidateMeta,
    pub data: Option<KeygenLicenseData>,
}

/// Metadata from validation response.
#[derive(Debug, Clone, Deserialize)]
pub struct KeygenValidateMeta {
    pub valid: bool,
    pub code: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub scope: Option<KeygenScopeMeta>,
}

/// Scoped entitlements from validation.
#[derive(Debug, Clone, Deserialize)]
pub struct KeygenScopeMeta {
    #[serde(default)]
    pub entitlements: Vec<String>,
}

/// License data from response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeygenLicenseData {
    pub id: String,
    #[serde(rename = "type")]
    pub data_type: String,
    pub attributes: KeygenLicenseAttributes,
}

/// License attributes.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeygenLicenseAttributes {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub expiry: Option<String>,
    #[serde(default)]
    pub max_uses: Option<u64>,
    #[serde(default)]
    pub uses: Option<u64>,
}

/// Normalized license state extracted from Keygen response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseState {
    /// Whether the license is valid.
    pub valid: bool,
    
    /// Entitlement codes present on this license.
    pub entitlements: Vec<String>,
    
    /// License expiry time (if set).
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Maximum uses allowed (if set).
    pub max_uses: Option<u64>,
    
    /// Current use count.
    pub current_uses: Option<u64>,
    
    /// Response code from Keygen.
    pub code: String,
    
    /// Optional detail message.
    pub detail: Option<String>,
}

impl LicenseState {
    /// Extract normalized license state from raw Keygen response.
    pub fn from_keygen_response(response: &KeygenValidateResponse) -> Result<Self, GatewardenError> {
        // Extract entitlements from scope
        let entitlements = response
            .meta
            .scope
            .as_ref()
            .map(|s| s.entitlements.clone())
            .unwrap_or_default();

        // Parse expiry datetime
        let expires_at = response
            .data
            .as_ref()
            .and_then(|d| d.attributes.expiry.as_ref())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        // Extract usage info
        let max_uses = response
            .data
            .as_ref()
            .and_then(|d| d.attributes.max_uses);
        
        let current_uses = response
            .data
            .as_ref()
            .and_then(|d| d.attributes.uses);

        Ok(Self {
            valid: response.meta.valid,
            entitlements,
            expires_at,
            max_uses,
            current_uses,
            code: response.meta.code.clone(),
            detail: response.meta.detail.clone(),
        })
    }
}

/// Parse raw JSON body into Keygen response.
pub fn parse_keygen_response(body: &[u8]) -> Result<KeygenValidateResponse, GatewardenError> {
    serde_json::from_slice(body)
        .map_err(|e| GatewardenError::ProtocolError(format!("Failed to parse Keygen response: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_RESPONSE: &str = r#"{
        "meta": {
            "valid": true,
            "code": "VALID",
            "detail": "License is valid",
            "scope": {
                "entitlements": ["VISION_ANALYSIS", "PREMIUM"]
            }
        },
        "data": {
            "id": "test-license-id",
            "type": "licenses",
            "attributes": {
                "name": "Test License",
                "expiry": "2026-01-01T00:00:00Z",
                "maxUses": 1000,
                "uses": 42
            }
        }
    }"#;

    const INVALID_RESPONSE: &str = r#"{
        "meta": {
            "valid": false,
            "code": "EXPIRED",
            "detail": "License has expired"
        },
        "data": null
    }"#;

    const MINIMAL_RESPONSE: &str = r#"{
        "meta": {
            "valid": true,
            "code": "VALID"
        }
    }"#;

    #[test]
    fn test_parse_valid_response() {
        let response = parse_keygen_response(VALID_RESPONSE.as_bytes()).unwrap();
        assert!(response.meta.valid);
        assert_eq!(response.meta.code, "VALID");
        assert!(response.data.is_some());
    }

    #[test]
    fn test_parse_invalid_response() {
        let response = parse_keygen_response(INVALID_RESPONSE.as_bytes()).unwrap();
        assert!(!response.meta.valid);
        assert_eq!(response.meta.code, "EXPIRED");
        assert!(response.data.is_none());
    }

    #[test]
    fn test_parse_minimal_response() {
        let response = parse_keygen_response(MINIMAL_RESPONSE.as_bytes()).unwrap();
        assert!(response.meta.valid);
        assert!(response.meta.scope.is_none());
        assert!(response.data.is_none());
    }

    #[test]
    fn test_parse_malformed_json() {
        let result = parse_keygen_response(b"not json");
        assert!(matches!(result, Err(GatewardenError::ProtocolError(_))));
    }

    #[test]
    fn test_license_state_extraction() {
        let response = parse_keygen_response(VALID_RESPONSE.as_bytes()).unwrap();
        let state = LicenseState::from_keygen_response(&response).unwrap();

        assert!(state.valid);
        assert_eq!(state.entitlements, vec!["VISION_ANALYSIS", "PREMIUM"]);
        assert!(state.expires_at.is_some());
        assert_eq!(state.max_uses, Some(1000));
        assert_eq!(state.current_uses, Some(42));
        assert_eq!(state.code, "VALID");
    }

    #[test]
    fn test_license_state_minimal() {
        let response = parse_keygen_response(MINIMAL_RESPONSE.as_bytes()).unwrap();
        let state = LicenseState::from_keygen_response(&response).unwrap();

        assert!(state.valid);
        assert!(state.entitlements.is_empty());
        assert!(state.expires_at.is_none());
        assert!(state.max_uses.is_none());
    }

    #[test]
    fn test_license_state_invalid() {
        let response = parse_keygen_response(INVALID_RESPONSE.as_bytes()).unwrap();
        let state = LicenseState::from_keygen_response(&response).unwrap();

        assert!(!state.valid);
        assert_eq!(state.code, "EXPIRED");
        assert_eq!(state.detail, Some("License has expired".to_string()));
    }
}
