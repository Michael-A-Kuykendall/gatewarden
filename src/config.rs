//! Gatewarden configuration.

use std::time::Duration;

/// Configuration for Gatewarden license validation.
///
/// This struct contains all product-specific settings needed to validate
/// licenses against Keygen.sh.
#[derive(Debug, Clone)]
pub struct GatewardenConfig {
    /// Application name (e.g., "shimmy", "crabcamera")
    pub app_name: &'static str,

    /// Feature name (e.g., "vision", "pro")
    pub feature_name: &'static str,

    /// Keygen account ID (UUID format)
    /// SECURITY: This should be hard-coded in your application, not from environment.
    pub account_id: &'static str,

    /// Keygen Ed25519 public key (hex-encoded, 64 characters)
    /// SECURITY: This should be hard-coded in your application, not from environment.
    pub public_key_hex: &'static str,

    /// Required entitlement codes that the license must have.
    /// All codes must be present for access to be granted.
    pub required_entitlements: &'static [&'static str],

    /// User-Agent product identifier (e.g., "shimmy-vision")
    /// Used by Keygen for crack detection analytics.
    pub user_agent_product: &'static str,

    /// Cache namespace for storing license data.
    /// Each product should use a unique namespace to avoid collisions.
    pub cache_namespace: &'static str,

    /// Grace period for offline operation.
    /// Cached licenses remain valid for this duration after last successful online validation.
    pub offline_grace: Duration,
}

impl GatewardenConfig {
    /// Validate configuration for obvious errors.
    pub fn validate(&self) -> Result<(), crate::GatewardenError> {
        if self.account_id.is_empty() {
            return Err(crate::GatewardenError::ConfigError(
                "account_id cannot be empty".to_string(),
            ));
        }
        if self.public_key_hex.len() != 64 {
            return Err(crate::GatewardenError::ConfigError(format!(
                "public_key_hex must be 64 hex characters, got {}",
                self.public_key_hex.len()
            )));
        }
        if self.cache_namespace.is_empty() {
            return Err(crate::GatewardenError::ConfigError(
                "cache_namespace cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}
