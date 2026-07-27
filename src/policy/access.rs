//! Entitlement and usage cap enforcement.
//!
//! This module enforces access policies based on:
//! - Required entitlements (all must be present)
//! - License validity (state must be valid)
//! - Usage caps (limits from Keygen usage counters; period semantics are consumer-defined)

use crate::protocol::models::LicenseState;
use crate::GatewardenError;

/// Check that a license state meets all access requirements.
///
/// # Arguments
/// * `state` - The license state from Keygen
/// * `required_entitlements` - Entitlement codes that must all be present
///
/// # Returns
/// * `Ok(())` - Access granted
/// * `Err(InvalidLicense)` - License is not valid
/// * `Err(EntitlementMissing)` - Required entitlement not found
pub fn check_access(
    state: &LicenseState,
    required_entitlements: &[&str],
) -> Result<(), GatewardenError> {
    // 1. Check license is valid
    if !state.valid {
        return Err(GatewardenError::InvalidLicense);
    }

    // 2. Check all required entitlements are present
    for required in required_entitlements {
        if !state.entitlements.iter().any(|e| e == *required) {
            return Err(GatewardenError::EntitlementMissing {
                code: (*required).to_string(),
            });
        }
    }

    Ok(())
}

/// Extract usage caps from license state.
///
/// Returns usage cap information derived from Keygen's `uses`/`maxUses` counters.
///
/// Note: Keygen's `uses` counter does not inherently encode a billing period (e.g., monthly)
/// unless your system resets it on that cadence (via a backend job calling Keygen's
/// reset-usage action) or enforces period-based metering outside of Keygen.
#[derive(Debug, Clone)]
pub struct UsageCaps {
    /// Usage limit (None = unlimited). Period semantics are consumer-defined.
    pub max_uses: Option<u64>,

    /// Current usage count reported by Keygen.
    pub current_uses: Option<u64>,

    /// Remaining uses after accounting for Keygen's current count **and** the
    /// locally-metered count (`local_uses`). `None` when there is no cap.
    pub remaining: Option<u64>,

    /// Locally-metered uses for this key, counted by the `meter` feature.
    /// `None` when the `meter` feature is disabled or no local use has occurred.
    pub local_uses: Option<u64>,
}

impl UsageCaps {
    /// Extract caps from license state (no locally-metered uses counted).
    pub fn from_license_state(state: &LicenseState) -> Self {
        Self::with_local(state, 0)
    }

    /// Extract caps, accounting for `local_uses` additional local consumption.
    ///
    /// `remaining` is `max_uses - current_uses - local_uses` (saturating). This
    /// is what makes the offline-enforceable cap visible to callers: the local
    /// meter count is subtracted, not just Keygen's server-side counter.
    pub fn with_local(state: &LicenseState, local_uses: u64) -> Self {
        let max = state.max_uses;
        let current = state.current_uses.unwrap_or(0);
        let remaining = max.map(|m| m.saturating_sub(current + local_uses));
        Self {
            max_uses: max,
            current_uses: state.current_uses,
            remaining,
            local_uses: if local_uses == 0 {
                None
            } else {
                Some(local_uses)
            },
        }
    }

    /// Check if usage is within cap.
    ///
    /// # Arguments
    /// * `additional_uses` - How many new uses to check for
    ///
    /// # Returns
    /// * `true` - Within cap or no cap
    /// * `false` - Would exceed cap
    pub fn allows_usage(&self, additional_uses: u64) -> bool {
        match (self.max_uses, self.current_uses) {
            (Some(limit), Some(current)) => current + additional_uses <= limit,
            (Some(limit), None) => additional_uses <= limit,
            (None, _) => true, // No limit
        }
    }

    /// Check if any cap exists.
    pub fn has_cap(&self) -> bool {
        self.max_uses.is_some()
    }
}

/// Combined access check with usage validation.
pub fn check_access_with_usage(
    state: &LicenseState,
    required_entitlements: &[&str],
    additional_uses: u64,
) -> Result<UsageCaps, GatewardenError> {
    // First check basic access
    check_access(state, required_entitlements)?;

    // Extract and check usage caps (local count is threaded through here)
    let caps = UsageCaps::with_local(state, additional_uses);

    if !caps.allows_usage(additional_uses) {
        return Err(GatewardenError::UsageLimitExceeded);
    }

    Ok(caps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_state(entitlements: Vec<String>) -> LicenseState {
        LicenseState {
            valid: true,
            entitlements,
            expires_at: None,
            max_uses: None,
            current_uses: None,
            code: "VALID".to_string(),
            detail: None,
        }
    }

    fn make_invalid_state() -> LicenseState {
        LicenseState {
            valid: false,
            entitlements: vec![],
            expires_at: None,
            max_uses: None,
            current_uses: None,
            code: "EXPIRED".to_string(),
            detail: None,
        }
    }

    #[test]
    fn test_check_access_valid_with_entitlements() {
        let state = make_valid_state(vec!["vision".to_string(), "pro".to_string()]);
        let result = check_access(&state, &["vision"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_access_valid_multiple_entitlements() {
        let state = make_valid_state(vec!["vision".to_string(), "pro".to_string()]);
        let result = check_access(&state, &["vision", "pro"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_access_invalid_license() {
        let state = make_invalid_state();
        let result = check_access(&state, &["vision"]);
        assert!(matches!(result, Err(GatewardenError::InvalidLicense)));
    }

    #[test]
    fn test_check_access_missing_entitlement() {
        let state = make_valid_state(vec!["basic".to_string()]);
        let result = check_access(&state, &["vision"]);
        assert!(
            matches!(result, Err(GatewardenError::EntitlementMissing { code }) if code == "vision")
        );
    }

    #[test]
    fn test_check_access_missing_one_of_multiple() {
        let state = make_valid_state(vec!["vision".to_string()]);
        let result = check_access(&state, &["vision", "pro"]);
        assert!(
            matches!(result, Err(GatewardenError::EntitlementMissing { code }) if code == "pro")
        );
    }

    #[test]
    fn test_check_access_no_required_entitlements() {
        let state = make_valid_state(vec![]);
        let result = check_access(&state, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_usage_caps_unlimited() {
        let state = make_valid_state(vec![]);
        let caps = UsageCaps::from_license_state(&state);

        assert!(!caps.has_cap());
        assert!(caps.allows_usage(1000000));
    }

    #[test]
    fn test_usage_caps_within_limit() {
        let mut state = make_valid_state(vec![]);
        state.max_uses = Some(100);
        state.current_uses = Some(50);

        let caps = UsageCaps::from_license_state(&state);

        assert!(caps.has_cap());
        assert!(caps.allows_usage(50)); // 50 + 50 = 100, at limit
        assert!(!caps.allows_usage(51)); // 50 + 51 = 101, over limit
    }

    #[test]
    fn test_usage_caps_at_limit() {
        let mut state = make_valid_state(vec![]);
        state.max_uses = Some(100);
        state.current_uses = Some(100);

        let caps = UsageCaps::from_license_state(&state);

        assert!(caps.allows_usage(0)); // Can do nothing
        assert!(!caps.allows_usage(1)); // Over limit
    }

    #[test]
    fn test_usage_caps_no_current_uses() {
        let mut state = make_valid_state(vec![]);
        state.max_uses = Some(100);
        state.current_uses = None;

        let caps = UsageCaps::from_license_state(&state);

        assert!(caps.allows_usage(100));
        assert!(!caps.allows_usage(101));
    }

    #[test]
    fn test_check_access_with_usage_success() {
        let mut state = make_valid_state(vec!["vision".to_string()]);
        state.max_uses = Some(100);
        state.current_uses = Some(50);

        let result = check_access_with_usage(&state, &["vision"], 10);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_access_with_usage_exceeds_cap() {
        let mut state = make_valid_state(vec!["vision".to_string()]);
        state.max_uses = Some(100);
        state.current_uses = Some(95);

        let result = check_access_with_usage(&state, &["vision"], 10);
        assert!(matches!(result, Err(GatewardenError::UsageLimitExceeded)));
    }

    #[test]
    fn test_check_access_with_usage_invalid_license() {
        let mut state = make_invalid_state();
        state.max_uses = Some(1000);
        state.current_uses = Some(0);

        let result = check_access_with_usage(&state, &["vision"], 1);
        assert!(matches!(result, Err(GatewardenError::InvalidLicense)));
    }

    #[test]
    fn test_check_access_with_usage_missing_entitlement() {
        let mut state = make_valid_state(vec!["basic".to_string()]);
        state.max_uses = Some(1000);
        state.current_uses = Some(0);

        let result = check_access_with_usage(&state, &["vision"], 1);
        assert!(matches!(
            result,
            Err(GatewardenError::EntitlementMissing { .. })
        ));
    }
}
