use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

/// Top-level bridge configuration loaded from TOML.
#[derive(Debug, Deserialize)]
pub struct BridgeConfig {
    /// Port to listen on. Defaults to 4760.
    pub port: Option<u16>,

    /// Bind address. Defaults to "127.0.0.1" (loopback-only for security).
    /// Set to "0.0.0.0" only when deploying in a trusted network container.
    pub bind: Option<String>,

    /// Shared secret for inbound requests. When set, callers MUST supply
    /// `X-Bridge-Token: <token>` on every request to `/v1/*` routes.
    /// Requests without the header (or with a wrong value) receive 401.
    /// Omit this field only for loopback-only dev deployments.
    pub bearer_token: Option<String>,

    /// Maximum requests per second per IP for `/v1/*` routes.
    /// Defaults to 30. Set to 0 to disable (not recommended for public endpoints).
    pub rate_limit_rps: Option<u32>,

    /// Named profiles keyed by profileId.
    /// Clients pass `profileId` so the bridge can look up the corresponding
    /// credentials without the caller ever transmitting the public key.
    pub profiles: HashMap<String, ProfileConfig>,
}

impl BridgeConfig {
    /// Load config from a TOML file.
    pub fn load(path: &str) -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Cannot read config file '{}': {}", path, e))?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Invalid config TOML in '{}': {}", path, e))?;
        if config.profiles.is_empty() {
            anyhow::bail!("Config must define at least one [[profiles]] entry");
        }
        Ok(config)
    }

    pub fn listen_addr(&self) -> String {
        format!(
            "{}:{}",
            self.bind.as_deref().unwrap_or("127.0.0.1"),
            self.port.unwrap_or(4760)
        )
    }
}

/// Per-product profile configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct ProfileConfig {
    /// Keygen account ID (UUID). Embed in config, not from user input.
    pub account_id: String,

    /// Keygen Ed25519 public key — 64 hex chars from Keygen Dashboard > Settings.
    /// This is the verify key, NOT a secret. It's safe to ship in config.
    pub public_key_hex: String,

    /// Entitlement codes the license must carry.
    pub required_entitlements: Option<Vec<String>>,

    /// Offline grace period in seconds. Defaults to 86400 (24 hours).
    pub offline_grace_secs: Option<u64>,

    /// Cache namespace (defaults to profile ID).
    pub cache_namespace: Option<String>,

    /// User-Agent product tag (used by Keygen crack-detection analytics).
    pub user_agent_product: Option<String>,

    /// Feature name for this profile (used in User-Agent).
    pub feature_name: Option<String>,
}

impl ProfileConfig {
    /// Build a GatewardenConfig for this profile.
    pub fn to_gatewarden_config(&self, profile_id: &str) -> gatewarden::GatewardenConfig {
        gatewarden::GatewardenConfig {
            app_name: format!("gatewarden-bridge/{}", env!("CARGO_PKG_VERSION")),
            feature_name: self
                .feature_name
                .clone()
                .unwrap_or_else(|| profile_id.to_string()),
            account_id: self.account_id.clone(),
            public_key_hex: self.public_key_hex.clone(),
            required_entitlements: self.required_entitlements.clone().unwrap_or_default(),
            user_agent_product: self
                .user_agent_product
                .clone()
                .unwrap_or_else(|| format!("bridge-{}", profile_id)),
            cache_namespace: self
                .cache_namespace
                .clone()
                .unwrap_or_else(|| format!("gatewarden-bridge-{}", profile_id)),
            offline_grace: Duration::from_secs(self.offline_grace_secs.unwrap_or(86400)),
        }
    }
}
