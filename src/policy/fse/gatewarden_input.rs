//! Gatewarden-specific FSE input provider.
//!
//! This module defines `GatewardenEvalInput`, which implements the `InputProvider`
//! trait using `LicenseState` extracted from Keygen API responses.

use super::model::{InputProvider, Selector, Value};
use crate::protocol::models::LicenseState;

/// FSE input provider built from validated Gatewarden license responses.
///
/// This struct wraps `LicenseState` and provides selector values for
/// Gatewarden-specific policy evaluation.
#[derive(Debug, Clone)]
pub struct GatewardenEvalInput {
    /// The normalized license state from Keygen.
    state: LicenseState,
    /// Whether the response signature was cryptographically verified.
    signature_verified: bool,
    /// Locally-metered uses for this key (from the `meter` feature), if known.
    /// Subtracted from `max_uses` when reporting `UsageRemaining`.
    local_uses: Option<u64>,
}

impl GatewardenEvalInput {
    /// Construct a new input provider from a validated license response.
    ///
    /// # Arguments
    ///
    /// * `state` - The normalized license state extracted from Keygen response
    /// * `signature_verified` - Whether the Ed25519 signature was valid
    /// * `local_uses` - Locally-metered consumption for this key (see `UsageRemaining`)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let state = LicenseState::from_keygen_response(&response)?;
    /// let input = GatewardenEvalInput::from_validated_response(state, true, None);
    /// ```
    pub fn from_validated_response(
        state: LicenseState,
        signature_verified: bool,
        local_uses: Option<u64>,
    ) -> Self {
        Self {
            state,
            signature_verified,
            local_uses,
        }
    }
}

impl InputProvider for GatewardenEvalInput {
    /// Extract the value for a given selector from this input.
    ///
    /// Maps FSE selectors to fields in `LicenseState`:
    ///
    /// - `SignaturePresent` → `signature_verified` bool
    /// - `StateCode` → `state.code` (e.g., "VALID", "EXPIRED")
    /// - `StateValid` → `state.valid` bool
    /// - `Entitlements` → `state.entitlements` Vec<String>
    /// - `ExpiresAt` → presence check on `state.expires_at`
    /// - `UsageRemaining` → remaining uses (`max_uses - current_uses - local_uses`); `Missing` if no cap
    fn value_for(&self, selector: &Selector) -> Value {
        match selector {
            Selector::SignaturePresent => Value::Bool(self.signature_verified),
            Selector::StateCode => Value::String(self.state.code.clone()),
            Selector::StateValid => Value::Bool(self.state.valid),
            Selector::Entitlements => Value::Strings(self.state.entitlements.clone()),
            Selector::ExpiresAt => {
                if self.state.expires_at.is_some() {
                    Value::Bool(true)
                } else {
                    Value::Missing
                }
            }
            Selector::UsageRemaining => {
                // Remaining uses = max_uses - (Keygen current_uses + local metered uses).
                match self.state.max_uses {
                    None => Value::Missing,
                    Some(limit) => {
                        let current = self.state.current_uses.unwrap_or(0);
                        let local = self.local_uses.unwrap_or(0);
                        Value::U64(limit.saturating_sub(current + local))
                    }
                }
            }
            // Other selectors not applicable to Gatewarden validation context
            _ => Value::Missing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn sample_valid_state() -> LicenseState {
        LicenseState {
            valid: true,
            entitlements: vec!["VISION_ANALYSIS".to_string(), "PREMIUM".to_string()],
            expires_at: Some("2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()),
            max_uses: Some(1000),
            current_uses: Some(42),
            code: "VALID".to_string(),
            detail: Some("License is valid".to_string()),
        }
    }

    fn sample_expired_state() -> LicenseState {
        LicenseState {
            valid: false,
            entitlements: vec![],
            expires_at: Some("2020-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()),
            max_uses: None,
            current_uses: None,
            code: "EXPIRED".to_string(),
            detail: Some("License has expired".to_string()),
        }
    }

    fn sample_no_expiry_state() -> LicenseState {
        LicenseState {
            valid: true,
            entitlements: vec!["BASIC".to_string()],
            expires_at: None,
            max_uses: None,
            current_uses: None,
            code: "VALID".to_string(),
            detail: None,
        }
    }

    #[test]
    fn test_signature_present_selector() {
        let state = sample_valid_state();
        let input = GatewardenEvalInput::from_validated_response(state, true, None);
        assert_eq!(
            input.value_for(&Selector::SignaturePresent),
            Value::Bool(true)
        );

        let state2 = sample_valid_state();
        let input2 = GatewardenEvalInput::from_validated_response(state2, false, None);
        assert_eq!(
            input2.value_for(&Selector::SignaturePresent),
            Value::Bool(false)
        );
    }

    #[test]
    fn test_state_code_selector() {
        let state = sample_valid_state();
        let input = GatewardenEvalInput::from_validated_response(state, true, None);
        assert_eq!(
            input.value_for(&Selector::StateCode),
            Value::String("VALID".to_string())
        );

        let expired_state = sample_expired_state();
        let input2 = GatewardenEvalInput::from_validated_response(expired_state, true, None);
        assert_eq!(
            input2.value_for(&Selector::StateCode),
            Value::String("EXPIRED".to_string())
        );
    }

    #[test]
    fn test_state_valid_selector() {
        let state = sample_valid_state();
        let input = GatewardenEvalInput::from_validated_response(state, true, None);
        assert_eq!(input.value_for(&Selector::StateValid), Value::Bool(true));

        let expired_state = sample_expired_state();
        let input2 = GatewardenEvalInput::from_validated_response(expired_state, true, None);
        assert_eq!(input2.value_for(&Selector::StateValid), Value::Bool(false));
    }

    #[test]
    fn test_entitlements_selector() {
        let state = sample_valid_state();
        let input = GatewardenEvalInput::from_validated_response(state, true, None);
        let expected = vec!["VISION_ANALYSIS".to_string(), "PREMIUM".to_string()];
        assert_eq!(
            input.value_for(&Selector::Entitlements),
            Value::Strings(expected)
        );

        let expired_state = sample_expired_state();
        let input2 = GatewardenEvalInput::from_validated_response(expired_state, true, None);
        assert_eq!(
            input2.value_for(&Selector::Entitlements),
            Value::Strings(vec![])
        );
    }

    #[test]
    fn test_expires_at_selector_present() {
        let state = sample_valid_state();
        let input = GatewardenEvalInput::from_validated_response(state, true, None);
        assert_eq!(input.value_for(&Selector::ExpiresAt), Value::Bool(true));
    }

    #[test]
    fn test_expires_at_selector_missing() {
        let state = sample_no_expiry_state();
        let input = GatewardenEvalInput::from_validated_response(state, true, None);
        assert_eq!(input.value_for(&Selector::ExpiresAt), Value::Missing);
    }

    #[test]
    fn test_usage_remaining_selector() {
        let state = sample_valid_state();
        let input = GatewardenEvalInput::from_validated_response(state, true, None);
        // max_uses (1000) - current_uses (42) = 958 remaining (no local metering).
        assert_eq!(input.value_for(&Selector::UsageRemaining), Value::U64(958));
    }

    #[test]
    fn test_other_selectors_return_missing() {
        let state = sample_valid_state();
        let input = GatewardenEvalInput::from_validated_response(state, true, None);

        // These selectors are not applicable to Gatewarden validation context
        assert_eq!(input.value_for(&Selector::ProfileId), Value::Missing);
        assert_eq!(input.value_for(&Selector::DigestMatches), Value::Missing);
        assert_eq!(
            input.value_for(&Selector::ResponseAgeSeconds),
            Value::Missing
        );
        assert_eq!(input.value_for(&Selector::BridgeTokenValid), Value::Missing);
    }

    #[test]
    fn test_multiple_entitlements() {
        let state = LicenseState {
            valid: true,
            entitlements: vec![
                "ENT_A".to_string(),
                "ENT_B".to_string(),
                "ENT_C".to_string(),
            ],
            expires_at: None,
            max_uses: None,
            current_uses: None,
            code: "VALID".to_string(),
            detail: None,
        };
        let input = GatewardenEvalInput::from_validated_response(state, true, None);
        let expected = vec![
            "ENT_A".to_string(),
            "ENT_B".to_string(),
            "ENT_C".to_string(),
        ];
        assert_eq!(
            input.value_for(&Selector::Entitlements),
            Value::Strings(expected)
        );
    }

    #[test]
    fn test_constructor_captures_state() {
        let state = sample_valid_state();
        let input = GatewardenEvalInput::from_validated_response(state.clone(), true, None);

        // Verify internal state is captured correctly
        assert_eq!(input.state.code, "VALID");
        assert!(input.state.valid);
        assert!(input.signature_verified);
    }
}
