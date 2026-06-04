use crate::auth::RateLimiter;
use crate::config::BridgeConfig;
use gatewarden::LicenseManager;
use std::collections::HashMap;

const DEFAULT_RATE_LIMIT_RPS: u32 = 30;

/// Shared application state injected into every Axum handler.
pub struct AppState {
    /// One LicenseManager per named profile.
    pub managers: HashMap<String, LicenseManager>,
    /// Bridge version string.
    pub version: String,
    /// Optional bearer token required on every /v1/* request.
    pub bearer_token: Option<String>,
    /// Per-IP token-bucket rate limiter.
    pub rate_limiter: RateLimiter,
}

impl AppState {
    /// Build state from loaded config — creates one LicenseManager per profile.
    pub fn new(config: BridgeConfig) -> Result<Self, anyhow::Error> {
        let mut managers = HashMap::new();

        for (profile_id, profile) in &config.profiles {
            let gw_config = profile.to_gatewarden_config(profile_id);
            let manager = LicenseManager::new(gw_config).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to create LicenseManager for profile '{}': {}",
                    profile_id,
                    e
                )
            })?;
            managers.insert(profile_id.clone(), manager);
        }

        let rps = config.rate_limit_rps.unwrap_or(DEFAULT_RATE_LIMIT_RPS);

        Ok(Self {
            managers,
            version: env!("CARGO_PKG_VERSION").to_string(),
            bearer_token: config.bearer_token.clone(),
            rate_limiter: RateLimiter::new(rps),
        })
    }
}
