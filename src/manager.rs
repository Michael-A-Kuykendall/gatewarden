//! License Manager - the main public API for Gatewarden.
//!
//! The `LicenseManager` provides a simple interface for license validation:
//! - Online validation with signature verification
//! - Offline fallback with authenticated cache
//! - Usage tracking and cap enforcement

use crate::cache::file::{hash_license_key, FileCache};
use crate::cache::format::CacheRecord;
use crate::client::http::KeygenClient;
use crate::clock::{Clock, SystemClock};
use crate::config::GatewardenConfig;
use crate::crypto::pipeline::verify_response;
use crate::policy::access::{check_access_with_usage, UsageCaps};
use crate::protocol::models::{KeygenValidateResponse, LicenseState};
use crate::GatewardenError;
use std::sync::Arc;

/// License validation result.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the license is valid.
    pub valid: bool,

    /// The license state from Keygen.
    pub state: LicenseState,

    /// Usage cap information.
    pub caps: UsageCaps,

    /// Whether this result came from cache.
    pub from_cache: bool,
}

/// Main license manager for Gatewarden.
///
/// This is the primary public API. Create one instance per application
/// and reuse it for all license checks.
pub struct LicenseManager {
    config: GatewardenConfig,
    clock: Arc<dyn Clock>,
    client: KeygenClient,
    cache: FileCache,
}

impl LicenseManager {
    /// Create a new license manager with the given configuration.
    ///
    /// Uses the system clock for time operations.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Configuration validation fails
    /// - HTTP client creation fails
    /// - Cache directory creation fails
    pub fn new(config: GatewardenConfig) -> Result<Self, GatewardenError> {
        config.validate()?;
        Self::with_clock(config, Arc::new(SystemClock))
    }

    /// Create a license manager with a custom clock (for testing).
    #[cfg(any(test, feature = "test-seams"))]
    pub fn new_with_clock(
        config: GatewardenConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, GatewardenError> {
        config.validate()?;
        Self::with_clock(config, clock)
    }

    fn with_clock(
        config: GatewardenConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, GatewardenError> {
        let client = KeygenClient::new(&config)?;
        let cache = FileCache::new(config.cache_namespace)?;

        Ok(Self {
            config,
            clock,
            client,
            cache,
        })
    }

    /// Validate a license key.
    ///
    /// This performs the full validation pipeline:
    /// 1. Try online validation with Keygen
    /// 2. Verify signature and freshness
    /// 3. Cache successful responses
    /// 4. Fall back to cached response if online fails and cache is valid
    ///
    /// # Errors
    /// - `MissingLicense` - No license key provided
    /// - `SignatureMissing` - Response missing required security headers
    /// - `SignatureInvalid` - Response signature verification failed
    /// - `InvalidLicense` - License is not valid
    /// - `EntitlementMissing` - Required entitlement not found
    /// - `UsageLimitExceeded` - Usage cap exceeded
    /// - `CacheExpired` - Offline and cache has expired
    pub fn validate_key(&self, license_key: &str) -> Result<ValidationResult, GatewardenError> {
        if license_key.is_empty() {
            return Err(GatewardenError::MissingLicense);
        }

        let key_hash = hash_license_key(license_key);

        // Try online validation first
        match self.validate_online(license_key, &key_hash) {
            Ok(result) => Ok(result),
            Err(online_error) => {
                // Try offline fallback
                self.validate_offline(&key_hash, online_error)
            }
        }
    }

    /// Check access for a license without additional validation.
    ///
    /// This uses the cached license state if available.
    /// Use `validate_key` for full validation.
    pub fn check_access(&self, license_key: &str) -> Result<ValidationResult, GatewardenError> {
        if license_key.is_empty() {
            return Err(GatewardenError::MissingLicense);
        }

        let key_hash = hash_license_key(license_key);

        // Load from cache
        let record = self
            .cache
            .load(&key_hash)?
            .ok_or(GatewardenError::InvalidLicense)?;

        // Verify cache is authentic and within grace
        record.verify(
            self.config.public_key_hex,
            self.config.offline_grace,
            self.clock.as_ref(),
        )?;

        // Parse cached response
        let response: KeygenValidateResponse = serde_json::from_str(record.body())
            .map_err(|e| GatewardenError::ProtocolError(format!("Cache parse error: {}", e)))?;

        let state = LicenseState::from_keygen_response(&response)?;
        let caps = check_access_with_usage(
            &state,
            self.config.required_entitlements,
            0, // No new usage
        )?;

        Ok(ValidationResult {
            valid: state.valid,
            state,
            caps,
            from_cache: true,
        })
    }

    /// Online validation with Keygen API.
    fn validate_online(
        &self,
        license_key: &str,
        key_hash: &str,
    ) -> Result<ValidationResult, GatewardenError> {
        // Call Keygen with required entitlements in scope
        // This ensures Keygen echoes back the entitlements in the response
        let response = self
            .client
            .validate_key(license_key, self.config.required_entitlements)?;

        // Verify signature, digest, and freshness
        verify_response(&response, self.config.public_key_hex, self.clock.as_ref())?;

        // Extract fields we need for caching before parsing body
        let date = response.date.clone().unwrap_or_default();
        let signature = response.signature.clone().unwrap_or_default();
        let digest = response.digest.clone();
        let request_path = response.request_path.clone();
        let host = response.host.clone();

        // Parse response
        let body_str = response.body_str()?;
        let keygen_response: KeygenValidateResponse = serde_json::from_str(body_str)
            .map_err(|e| GatewardenError::ProtocolError(format!("Parse error: {}", e)))?;

        let state = LicenseState::from_keygen_response(&keygen_response)?;

        // Check access policy
        let caps = check_access_with_usage(
            &state,
            self.config.required_entitlements,
            0, // No new usage for validation
        )?;

        // Cache successful validation
        let cache_record = CacheRecord::new(
            date,
            signature,
            digest,
            body_str.to_string(),
            request_path,
            host,
            self.clock.as_ref(),
        );
        self.cache.save(key_hash, &cache_record)?;

        Ok(ValidationResult {
            valid: state.valid,
            state,
            caps,
            from_cache: false,
        })
    }

    /// Offline validation from authenticated cache.
    fn validate_offline(
        &self,
        key_hash: &str,
        online_error: GatewardenError,
    ) -> Result<ValidationResult, GatewardenError> {
        // Only fall back for transport errors
        if !matches!(online_error, GatewardenError::KeygenTransport(_)) {
            return Err(online_error);
        }

        // Load cached record
        let record = self.cache.load(key_hash)?.ok_or(online_error)?;

        // Verify cache authenticity and grace period
        record.verify(
            self.config.public_key_hex,
            self.config.offline_grace,
            self.clock.as_ref(),
        )?;

        // Parse cached response
        let response: KeygenValidateResponse = serde_json::from_str(record.body())
            .map_err(|e| GatewardenError::ProtocolError(format!("Cache parse error: {}", e)))?;

        let state = LicenseState::from_keygen_response(&response)?;

        // Check access policy
        let caps = check_access_with_usage(&state, self.config.required_entitlements, 0)?;

        Ok(ValidationResult {
            valid: state.valid,
            state,
            caps,
            from_cache: true,
        })
    }

    /// Get the current configuration.
    pub fn config(&self) -> &GatewardenConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config() -> GatewardenConfig {
        GatewardenConfig {
            app_name: "test-app",
            feature_name: "test",
            account_id: "test-account",
            public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            required_entitlements: &[],
            user_agent_product: "test-product",
            cache_namespace: "gatewarden-test",
            offline_grace: Duration::from_secs(86400),
        }
    }

    #[test]
    fn test_license_manager_creation() {
        let config = test_config();
        let manager = LicenseManager::new(config);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_validate_key_empty() {
        let config = test_config();
        let manager = LicenseManager::new(config).unwrap();
        let result = manager.validate_key("");
        assert!(matches!(result, Err(GatewardenError::MissingLicense)));
    }

    #[test]
    fn test_check_access_empty() {
        let config = test_config();
        let manager = LicenseManager::new(config).unwrap();
        let result = manager.check_access("");
        assert!(matches!(result, Err(GatewardenError::MissingLicense)));
    }

    #[test]
    fn test_config_accessor() {
        let config = test_config();
        let manager = LicenseManager::new(config).unwrap();
        assert_eq!(manager.config().app_name, "test-app");
    }
}
