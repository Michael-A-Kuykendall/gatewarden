//! # Gatewarden
//!
//! Hardened Keygen.sh license validation infrastructure.
//!
//! Gatewarden provides cryptographically verified license validation with:
//! - Ed25519 response signature verification (MITM prevention)
//! - Response freshness enforcement (replay attack prevention)
//! - Authenticated offline caching (tamper-evident)
//! - Usage metering
//!
//! ## Usage
//!
//! ```ignore
//! use gatewarden::{GatewardenConfig, LicenseManager};
//!
//! let config = GatewardenConfig {
//!     app_name: "myapp",
//!     feature_name: "pro",
//!     account_id: "your-keygen-account-id",
//!     public_key_hex: "your-keygen-public-key",
//!     required_entitlements: &["PRO_FEATURE"],
//!     user_agent_product: "myapp-pro",
//!     cache_namespace: "myapp-pro",
//!     offline_grace: std::time::Duration::from_secs(24 * 60 * 60),
//! };
//!
//! let manager = LicenseManager::new(config)?;
//! let result = manager.validate_key("license-key")?;
//! if result.valid {
//!     println!("License is valid!");
//! }
//! ```

#![deny(warnings)]

// Core modules
pub mod config;
pub mod errors;
pub mod clock;

// Crypto layer
pub mod crypto;

// Protocol layer
pub mod protocol;

// Client layer
pub mod client;

// Cache layer
pub mod cache;

// Metering layer
pub mod meter;

// Policy layer
pub mod policy;

// Manager (main public API)
pub mod manager;

// Optional integrations
pub mod integrations;

// Re-exports for public API
pub use config::GatewardenConfig;
pub use errors::GatewardenError;
pub use clock::{Clock, SystemClock};
pub use manager::{LicenseManager, ValidationResult};
pub use policy::access::UsageCaps;
pub use protocol::models::LicenseState;

#[cfg(any(test, feature = "test-seams"))]
pub use clock::MockClock;
