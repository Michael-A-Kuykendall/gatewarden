//! Gatewarden configuration.

use std::time::Duration;

/// Configuration for Gatewarden license validation.
///
/// This struct contains all product-specific settings needed to validate
/// licenses against Keygen.sh.
///
/// # Security note
/// `account_id` and `public_key_hex` should be embedded in your application at
/// compile time where possible, not loaded from untrusted environment variables.
/// The types are `String` so the bridge and serverless deployments can load them
/// from a secrets store at startup.
#[derive(Debug, Clone)]
pub struct GatewardenConfig {
    /// Application name (e.g., "shimmy", "crabcamera")
    pub app_name: String,

    /// Feature name (e.g., "vision", "pro")
    pub feature_name: String,

    /// Keygen account ID (UUID format).
    /// Embed in your binary; do not load from untrusted user input.
    pub account_id: String,

    /// Keygen Ed25519 public key (hex-encoded, 64 characters).
    /// Embed in your binary; do not load from untrusted user input.
    pub public_key_hex: String,

    /// Required entitlement codes that the license must have.
    /// All codes must be present for access to be granted.
    pub required_entitlements: Vec<String>,

    /// User-Agent product identifier (e.g., "shimmy-vision").
    /// Used by Keygen for crack detection analytics.
    pub user_agent_product: String,

    /// Cache namespace for storing license data.
    /// Each product should use a unique namespace to avoid collisions.
    pub cache_namespace: String,

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
