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
//! let manager = LicenseManager::new(config);
//! ```

#![deny(warnings)]

// Core modules
pub mod config;
pub mod errors;

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

// Optional integrations
pub mod integrations;

// Re-exports for public API
pub use config::GatewardenConfig;
pub use errors::GatewardenError;
