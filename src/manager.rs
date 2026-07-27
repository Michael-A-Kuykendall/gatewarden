//! License Manager - the main public API for Gatewarden.
//!
//! The `LicenseManager` provides a simple interface for license validation:
//! - Online validation with signature verification
//! - Offline fallback with authenticated cache
//! - Server-side usage cap enforcement (Keygen `maxUses`)
//!
//! Local, offline-enforceable usage metering is available behind the `meter`
//! feature via `LicenseManager::record_use` (see the `0.4.2` release).

use crate::cache::file::{hash_license_key, FileCache};
use crate::cache::format::CacheRecord;
use crate::client::http::KeygenClient;
use crate::clock::{Clock, SystemClock};
use crate::config::GatewardenConfig;
use crate::crypto::pipeline::verify_response;
#[cfg(feature = "meter")]
use crate::meter::UsageMeter;
use crate::policy::access::{check_access_with_usage, UsageCaps};
use crate::policy::fse::compiler::CompiledPlan;
use crate::policy::fse::defaults::compile_default_plan;
use crate::policy::fse::runtime::execute;
use crate::policy::fse::{GatewardenEvalInput, RuleDecision};
use crate::protocol::models::{KeygenValidateResponse, LicenseState};
use crate::GatewardenError;
use std::sync::Arc;
#[cfg(feature = "meter")]
use std::sync::Mutex;

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

    /// Number of unique selectors scanned by FSE (proof metric for O(1) behavior).
    pub selectors_scanned: usize,
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
    fse_plan: CompiledPlan,
    /// Local, offline-enforceable usage meter (only with the `meter` feature).
    #[cfg(feature = "meter")]
    meter: Mutex<Option<UsageMeter>>,
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
        let cache = FileCache::new(&config.cache_namespace)?;

        // Compile default FSE plan
        let fse_plan = compile_default_plan(&config)?;

        // Set up the local usage meter when the feature is enabled.
        #[cfg(feature = "meter")]
        let meter = UsageMeter::with_namespace(&config.cache_namespace).ok();

        Ok(Self {
            config,
            clock,
            client,
            cache,
            fse_plan,
            #[cfg(feature = "meter")]
            meter: Mutex::new(meter),
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
            &self.config.public_key_hex,
            self.config.offline_grace,
            self.clock.as_ref(),
        )?;

        // Parse cached response and enforce policy
        let state = self.parse_cached_state(&record)?;
        let (caps, selectors_scanned) = self.enforce_policy(&state, "check_access", &key_hash)?;

        Ok(ValidationResult {
            valid: state.valid,
            state,
            caps,
            from_cache: true,
            selectors_scanned,
        })
    }

    /// Parse a cached record's body into a normalized license state.
    fn parse_cached_state(&self, record: &CacheRecord) -> Result<LicenseState, GatewardenError> {
        let response: KeygenValidateResponse = serde_json::from_str(record.body())
            .map_err(|e| GatewardenError::ProtocolError(format!("Cache parse error: {}", e)))?;
        LicenseState::from_keygen_response(&response)
    }

    /// Run the FSE policy engine and entitlement/usage checks against a state.
    ///
    /// Returns the usage caps and the number of FSE selectors scanned on success.
    /// `context` is used only for diagnostic logging of failed rules.
    /// `key_hash` identifies the license key so locally-metered consumption can be
    /// folded into the usage cap check (when the `meter` feature is enabled).
    fn enforce_policy(
        &self,
        state: &LicenseState,
        context: &str,
        key_hash: &str,
    ) -> Result<(UsageCaps, usize), GatewardenError> {
        let input = GatewardenEvalInput::from_validated_response(
            state.clone(),
            true,
            Some(self.meter_monthly_count(key_hash)),
        );
        let fse_result = execute(&self.fse_plan, &input);

        if !fse_result.allow {
            for outcome in &fse_result.outcomes {
                if outcome.decision == RuleDecision::False {
                    tracing::warn!("FSE rule failed ({context}): {}", outcome.rule_id);
                }
            }
            return Err(GatewardenError::InvalidLicense);
        }

        let entitlements: Vec<&str> = self
            .config
            .required_entitlements
            .iter()
            .map(|s| s.as_str())
            .collect();
        let additional_uses = self.meter_monthly_count(key_hash);
        let caps = check_access_with_usage(state, &entitlements, additional_uses)?;

        Ok((caps, fse_result.selectors_scanned))
    }

    /// Current locally-metered monthly count for `key_hash`.
    ///
    /// Returns 0 when the `meter` feature is disabled or no meter is available.
    #[cfg(feature = "meter")]
    fn meter_monthly_count(&self, key_hash: &str) -> u64 {
        self.meter
            .lock()
            .ok()
            .and_then(|g| {
                g.as_ref()
                    .map(|m| m.monthly_count(key_hash, self.clock.as_ref()))
            })
            .unwrap_or(0)
    }

    /// Non-meter build: no local meter, so always 0.
    #[cfg(not(feature = "meter"))]
    fn meter_monthly_count(&self, _key_hash: &str) -> u64 {
        0
    }

    /// Online validation with Keygen API.
    fn validate_online(
        &self,
        license_key: &str,
        key_hash: &str,
    ) -> Result<ValidationResult, GatewardenError> {
        // Call Keygen with required entitlements in scope
        // This ensures Keygen echoes back the entitlements in the response
        let entitlements: Vec<&str> = self
            .config
            .required_entitlements
            .iter()
            .map(|s| s.as_str())
            .collect();
        let response = self.client.validate_key(license_key, &entitlements)?;

        // Verify signature, digest, and freshness
        verify_response(&response, &self.config.public_key_hex, self.clock.as_ref())?;

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
        let (caps, selectors_scanned) = self.enforce_policy(&state, "validate_online", key_hash)?;

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
            selectors_scanned,
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
            &self.config.public_key_hex,
            self.config.offline_grace,
            self.clock.as_ref(),
        )?;

        // Parse cached response and enforce policy
        let state = self.parse_cached_state(&record)?;
        let (caps, selectors_scanned) =
            self.enforce_policy(&state, "validate_offline", key_hash)?;

        Ok(ValidationResult {
            valid: state.valid,
            state,
            caps,
            from_cache: true,
            selectors_scanned,
        })
    }

    /// Get the current configuration.
    pub fn config(&self) -> &GatewardenConfig {
        &self.config
    }

    /// Get the compiled FSE plan.
    pub fn fse_plan(&self) -> &CompiledPlan {
        &self.fse_plan
    }

    /// Record one local use of `license_key`, persist it, and re-check the cap.
    ///
    /// This is the entry point for Gatewarden's **offline-enforceable usage
    /// metering** (the `meter` feature). It increments a per-license-key counter
    /// on disk and, if the locally tracked monthly count would exceed the
    /// Keygen `maxUses` cap, returns [`GatewardenError::UsageLimitExceeded`].
    ///
    /// Enforcement works without contacting Keygen, so a client is bounded even
    /// while offline. If no authenticated cache entry (and thus no cap) exists
    /// for the key, the use is still recorded but not capped locally.
    #[cfg(feature = "meter")]
    pub fn record_use(&self, license_key: &str) -> Result<(), GatewardenError> {
        let key_hash = hash_license_key(license_key);

        // Pre-check against the cached Keygen cap before incrementing.
        if let Some(record) = self.cache.load(&key_hash)? {
            if record
                .verify(
                    &self.config.public_key_hex,
                    self.config.offline_grace,
                    self.clock.as_ref(),
                )
                .is_ok()
            {
                if let Ok(state) = self.parse_cached_state(&record) {
                    let caps = UsageCaps::from_license_state(&state);
                    let projected = self.meter_monthly_count(&key_hash) + 1;
                    if !caps.allows_usage(projected) {
                        return Err(GatewardenError::UsageLimitExceeded);
                    }
                }
            }
        }

        let mut guard = self
            .meter
            .lock()
            .map_err(|_| GatewardenError::MeterIO("usage meter lock poisoned".to_string()))?;
        let meter = guard
            .as_mut()
            .ok_or_else(|| GatewardenError::MeterIO("usage meter unavailable".to_string()))?;
        meter.increment(&key_hash, self.clock.as_ref())
    }

    /// Current usage caps for `license_key`, folding in the locally-metered count.
    ///
    /// This is the read-side counterpart to [`LicenseManager::record_use`]: it
    /// returns the same `UsageCaps` that `validate_key`/`check_access` report,
    /// including the true `remaining` after subtracting offline (`meter`) usage.
    /// Used by the bridge to surface `remaining` after a successful `record_use`.
    #[cfg(feature = "meter")]
    pub fn meter_usage(&self, license_key: &str) -> Result<UsageCaps, GatewardenError> {
        let key_hash = hash_license_key(license_key);
        let record = self
            .cache
            .load(&key_hash)?
            .ok_or(GatewardenError::InvalidLicense)?;
        record.verify(
            &self.config.public_key_hex,
            self.config.offline_grace,
            self.clock.as_ref(),
        )?;
        let state = self.parse_cached_state(&record)?;
        let local = self.meter_monthly_count(&key_hash);
        Ok(UsageCaps::with_local(&state, local))
    }

    /// Seed an authenticated cache entry for `license_key` (test/integration only).
    ///
    /// The record is signed with the crate's well-known Ed25519 test seed, so it
    /// verifies against the standard test `public_key_hex`. This lets tests drive
    /// the offline path (`check_access`, `record_use`) without contacting Keygen.
    #[cfg(all(test, feature = "meter"))]
    pub(crate) fn seed_cache_for_test(
        &self,
        license_key: &str,
        body: &str,
        date: &str,
        host: &str,
        path: &str,
    ) -> Result<(), GatewardenError> {
        let key_hash = hash_license_key(license_key);
        let record =
            crate::cache::format::signed_test_record(body, date, host, path, self.clock.as_ref());
        self.cache.save(&key_hash, &record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config() -> GatewardenConfig {
        GatewardenConfig {
            app_name: "test-app".to_string(),
            feature_name: "test".to_string(),
            account_id: "test-account".to_string(),
            public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                .to_string(),
            required_entitlements: vec![],
            user_agent_product: "test-product".to_string(),
            cache_namespace: "gatewarden-test".to_string(),
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

    /// End-to-end exercise of the offline usage meter: seed a signed cache,
    /// drive `record_use`/`check_access`, and confirm that the locally-metered
    /// count is surfaced as `local_uses` and subtracted from `remaining`, and
    /// that the cap is enforced once the local count reaches `maxUses`.
    #[test]
    #[cfg(feature = "meter")]
    fn offline_meter_reports_remaining_and_enforces_cap() {
        use crate::clock::MockClock;
        use chrono::{TimeZone, Utc};
        use std::sync::Arc;
        use std::time::{SystemTime, UNIX_EPOCH};

        // Unique cache namespace per run so the file-backed meter/cache don't
        // leak state across test invocations.
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut config = test_config();
        config.cache_namespace = format!("gatewarden-test-meter-{}", suffix);

        let clock = Arc::new(MockClock::new(
            Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap(),
        ));
        let manager = LicenseManager::new_with_clock(config, clock).unwrap();

        let key = "TEST-LICENSE-KEY-OFFLINE-4242";
        let body = r#"{"meta":{"valid":true,"code":"VALID","scope":{"entitlements":["PREMIUM"]}},"data":{"id":"lic-1","type":"licenses","attributes":{"name":"Test License","maxUses":10,"uses":0}}}"#;
        manager
            .seed_cache_for_test(
                key,
                body,
                "Wed, 15 Jan 2025 12:00:00 GMT",
                "api.keygen.sh",
                "/v1/accounts/test/licenses/lic-1/actions/validate",
            )
            .expect("seed signed cache");

        // Before any local use: Keygen `uses=0`, no local count -> remaining 10.
        let before = manager.check_access(key).expect("check_access");
        assert_eq!(before.caps.remaining, Some(10));
        assert_eq!(before.caps.local_uses, None);

        // Record up to the cap (maxUses = 10) and watch remaining decrement while
        // the locally-metered count climbs.
        for i in 1..=10u64 {
            manager
                .record_use(key)
                .unwrap_or_else(|_| panic!("record_use within cap at iteration {}", i));
            let caps = manager.check_access(key).expect("check_access").caps;
            assert_eq!(caps.local_uses, Some(i), "local_uses after {} records", i);
            assert_eq!(
                caps.remaining,
                Some(10 - i),
                "remaining after {} records",
                i
            );
        }

        // The 11th use must be rejected: the offline cap is hit.
        assert!(
            matches!(
                manager.record_use(key),
                Err(GatewardenError::UsageLimitExceeded)
            ),
            "11th use must be rejected by the offline cap"
        );

        // Read-side surface confirms the post-cap state.
        let info = manager.meter_usage(key).expect("meter_usage");
        assert_eq!(info.local_uses, Some(10));
        assert_eq!(info.remaining, Some(0));
    }
}
