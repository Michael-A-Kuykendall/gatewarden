//! Basic license validation example.
//!
//! This example demonstrates the core workflow for validating a license key
//! and handling common error cases.
//!
//! # Running
//!
//! ```bash
//! export LICENSE_KEY="your-license-key"
//! cargo run --example basic_validation
//! ```
//!
//! # Note
//!
//! In production, `account_id` and `public_key_hex` should be compile-time
//! constants embedded in your binary—not loaded from environment variables.
//! This prevents attackers from simply setting environment variables to
//! point at their own Keygen account.

use gatewarden::{GatewardenConfig, GatewardenError, LicenseManager};
use std::time::Duration;

// These would be your actual Keygen credentials in production.
// Hard-coded here to demonstrate the pattern.
const KEYGEN_ACCOUNT_ID: &str = "00000000-0000-0000-0000-000000000000";
const KEYGEN_PUBLIC_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn main() {
    // License key from user (this CAN come from environment/config)
    let license_key = std::env::var("LICENSE_KEY").expect("Set LICENSE_KEY environment variable");

    // Build configuration with compile-time constants
    let config = GatewardenConfig {
        app_name: "example-app",
        feature_name: "pro",
        account_id: KEYGEN_ACCOUNT_ID,
        public_key_hex: KEYGEN_PUBLIC_KEY,
        required_entitlements: &["PRO_FEATURE"],
        user_agent_product: "example-app",
        cache_namespace: "example-app",
        offline_grace: Duration::from_secs(24 * 60 * 60), // 24 hours
    };

    // Create the license manager
    let manager = match LicenseManager::new(config) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // Validate the license
    //
    // This performs:
    // 1. HTTPS request to Keygen's validate-key API
    // 2. Ed25519 signature verification on the response
    // 3. Freshness check (response must be < 5 minutes old)
    // 4. Entitlement verification
    // 5. Cache the validated response for offline use
    match manager.validate_key(&license_key) {
        Ok(result) => {
            if result.valid {
                println!("✓ License valid!");
                println!("  Entitlements: {:?}", result.state.entitlements);
                println!("  From cache: {}", result.from_cache);

                if let Some(expires) = result.state.expires_at {
                    println!("  Expires: {}", expires);
                }
            } else {
                println!("✗ License invalid");
            }
        }
        Err(e) => {
            // Handle specific error cases appropriately
            match &e {
                GatewardenError::InvalidLicense => {
                    eprintln!("License is invalid or expired");
                }
                GatewardenError::EntitlementMissing { code } => {
                    eprintln!("License missing required entitlement: {}", code);
                }
                GatewardenError::SignatureInvalid => {
                    // Security: someone may be tampering with responses
                    eprintln!("SECURITY: Response signature verification failed!");
                }
                GatewardenError::KeygenTransport(_) => {
                    eprintln!("Network error - trying offline cache...");
                    // You could call check_access() here to use cached validation
                }
                _ => {
                    eprintln!("Validation error: {}", e);
                }
            }
            std::process::exit(1);
        }
    }
}
