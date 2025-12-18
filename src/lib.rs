//! # Gatewarden
//!
//! **Hardened [Keygen.sh](https://keygen.sh) license validation for Rust.**
//!
//! Gatewarden validates licenses via Keygen's `validate-key` API and
//! **cryptographically verifies** every response using Ed25519 signatures,
//! preventing MITM attacks and spoofed validation responses.
//!
//! ## Features
//!
//! - **Ed25519 signature verification** — responses are signed by Keygen's private key
//! - **Response freshness** — 5-minute replay window prevents old response reuse
//! - **SHA-256 digest verification** — detects body tampering (when header present)
//! - **Authenticated offline cache** — validated responses cached with integrity checks
//! - **Fail-closed security** — missing signatures/headers cause rejection, not bypass
//!
//! ## Quickstart
//!
//! ```no_run
//! use gatewarden::{GatewardenConfig, LicenseManager};
//! use std::time::Duration;
//!
//! fn main() -> Result<(), gatewarden::GatewardenError> {
//!     let config = GatewardenConfig {
//!         app_name: "myapp",
//!         feature_name: "pro",
//!         account_id: "your-keygen-account-id",
//!         public_key_hex: "your-keygen-ed25519-public-key-hex",
//!         required_entitlements: &["PRO_FEATURE"],
//!         user_agent_product: "myapp-pro",
//!         cache_namespace: "myapp-pro",
//!         offline_grace: Duration::from_secs(24 * 60 * 60), // 24 hours
//!     };
//!
//!     let manager = LicenseManager::new(config)?;
//!     let result = manager.validate_key("LICENSE-KEY-HERE")?;
//!
//!     if result.valid {
//!         println!("License valid! (cached: {})", result.from_cache);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Threat Model
//!
//! Gatewarden protects against:
//! - **MITM attacks** — spoofed Keygen responses are rejected (signature mismatch)
//! - **Replay attacks** — old responses rejected after 5-minute freshness window
//! - **Cache tampering** — cached records are signature-verified on load
//!
//! Gatewarden does **not** prevent binary patching or code modification.
//! Client-side licensing can always be bypassed by a determined attacker
//! with access to the binary.
//!
//! ## Configuration
//!
//! - `account_id` — Your Keygen account ID (UUID)
//! - `public_key_hex` — Keygen's Ed25519 verify key (64 hex chars)
//! - `required_entitlements` — Entitlement codes the license must have
//! - `offline_grace` — How long cached validations remain valid offline
//!
//! See [`GatewardenConfig`] for full documentation.

#![deny(warnings)]
#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/gatewarden/0.1.0")]

// Core modules
pub mod clock;
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

// Manager (main public API)
pub mod manager;

// Optional integrations
pub mod integrations;

// Re-exports for public API
pub use clock::{Clock, SystemClock};
pub use config::GatewardenConfig;
pub use errors::GatewardenError;
pub use manager::{LicenseManager, ValidationResult};
pub use policy::access::UsageCaps;
pub use protocol::models::LicenseState;

#[cfg(any(test, feature = "test-seams"))]
pub use clock::MockClock;
