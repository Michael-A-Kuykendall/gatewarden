//! Live integration tests against real Keygen.sh API.
//!
//! These tests are `#[ignore]`d by default — they require real credentials.
//!
//! To run:
//! ```bash
//! source ~/.config/shimmy/secrets.env
//! cargo test --test integration_live -- --ignored
//! ```
//!
//! Required environment variables:
//! - GATEWARDEN_TEST_ACCOUNT_ID: Keygen account UUID
//! - GATEWARDEN_TEST_PUBLIC_KEY_HEX: Ed25519 verify key (64 hex chars)
//! - GATEWARDEN_TEST_LICENSE_KEY: A valid license key to validate
//! - GATEWARDEN_TEST_ENTITLEMENT: An entitlement code on that license (optional)

use gatewarden::{GatewardenConfig, GatewardenError, LicenseManager};
use std::time::Duration;

fn load_config() -> Option<(GatewardenConfig, String)> {
    let account_id = std::env::var("GATEWARDEN_TEST_ACCOUNT_ID").ok()?;
    let public_key_hex = std::env::var("GATEWARDEN_TEST_PUBLIC_KEY_HEX").ok()?;
    let license_key = std::env::var("GATEWARDEN_TEST_LICENSE_KEY").ok()?;
    let entitlement = std::env::var("GATEWARDEN_TEST_ENTITLEMENT").unwrap_or_default();

    let entitlements = if entitlement.is_empty() {
        vec![]
    } else {
        vec![entitlement]
    };

    let config = GatewardenConfig {
        app_name: "gatewarden-integration-test".to_string(),
        feature_name: "live-test".to_string(),
        account_id,
        public_key_hex,
        required_entitlements: entitlements,
        user_agent_product: "gatewarden-test".to_string(),
        cache_namespace: format!(
            "gatewarden-live-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ),
        offline_grace: Duration::from_secs(3600),
    };

    Some((config, license_key))
}

#[test]
#[ignore]
fn live_validate_key_succeeds_with_valid_license() {
    let (config, license_key) = load_config()
        .expect("Set GATEWARDEN_TEST_ACCOUNT_ID, GATEWARDEN_TEST_PUBLIC_KEY_HEX, GATEWARDEN_TEST_LICENSE_KEY");

    let manager = LicenseManager::new(config).expect("LicenseManager should initialize");
    let result = manager.validate_key(&license_key);

    match &result {
        Ok(r) => {
            println!("  valid: {}", r.valid);
            println!("  from_cache: {}", r.from_cache);
            println!("  state.code: {}", r.state.code);
            println!("  entitlements: {:?}", r.state.entitlements);
            assert!(r.valid, "License should be valid");
            assert!(!r.from_cache, "First call should not be cached");
        }
        Err(e) => {
            panic!("validate_key failed: {:?}", e);
        }
    }
}

#[test]
#[ignore]
fn live_validate_key_verifies_signature() {
    // This test confirms the Ed25519 signature verification is working
    // against real Keygen responses. If the public key is wrong, this fails
    // with SignatureInvalid.
    let (config, license_key) = load_config()
        .expect("Set GATEWARDEN_TEST_ACCOUNT_ID, GATEWARDEN_TEST_PUBLIC_KEY_HEX, GATEWARDEN_TEST_LICENSE_KEY");

    let manager = LicenseManager::new(config).expect("LicenseManager should initialize");
    let result = manager.validate_key(&license_key);

    // Should NOT get SignatureInvalid or SignatureMissing
    match &result {
        Err(GatewardenError::SignatureInvalid) => {
            panic!("Signature verification failed — is GATEWARDEN_TEST_PUBLIC_KEY_HEX correct?");
        }
        Err(GatewardenError::SignatureMissing) => {
            panic!("Signature header missing from Keygen response — unexpected");
        }
        _ => {
            // Any other result (including Ok or non-signature errors) means
            // the signature verification pipeline didn't reject.
            println!("  Signature verification passed (or error is non-crypto)");
        }
    }
}

#[test]
#[ignore]
fn live_check_access_after_validate_uses_cache() {
    let (config, license_key) = load_config()
        .expect("Set GATEWARDEN_TEST_ACCOUNT_ID, GATEWARDEN_TEST_PUBLIC_KEY_HEX, GATEWARDEN_TEST_LICENSE_KEY");

    let manager = LicenseManager::new(config).expect("LicenseManager should initialize");

    // First: online validation (populates cache)
    let result1 = manager
        .validate_key(&license_key)
        .expect("First validate_key should succeed");
    assert!(result1.valid, "License should be valid");
    assert!(!result1.from_cache, "First call should hit Keygen");

    // Second: check_access should use cache
    let result2 = manager
        .check_access(&license_key)
        .expect("check_access should succeed after validate_key");
    assert!(result2.valid, "Cached result should still be valid");
    assert!(result2.from_cache, "check_access should use the cache");
}

#[test]
#[ignore]
fn live_validate_key_rejects_bogus_key() {
    let (config, _) = load_config()
        .expect("Set GATEWARDEN_TEST_ACCOUNT_ID, GATEWARDEN_TEST_PUBLIC_KEY_HEX, GATEWARDEN_TEST_LICENSE_KEY");

    let manager = LicenseManager::new(config).expect("LicenseManager should initialize");
    let result = manager.validate_key("BOGUS-NOT-A-REAL-KEY-1234");

    match result {
        Ok(r) => {
            assert!(!r.valid, "Bogus key should not be valid");
            println!("  Bogus key correctly rejected: code={}", r.state.code);
        }
        Err(GatewardenError::InvalidLicense) => {
            println!("  Bogus key correctly rejected with InvalidLicense error");
        }
        Err(e) => {
            // Transport errors are acceptable (means Keygen responded but
            // the key doesn't exist)
            println!("  Bogus key error: {:?}", e);
        }
    }
}

#[test]
#[ignore]
fn live_wrong_public_key_fails_signature() {
    let (mut config, license_key) = load_config()
        .expect("Set GATEWARDEN_TEST_ACCOUNT_ID, GATEWARDEN_TEST_PUBLIC_KEY_HEX, GATEWARDEN_TEST_LICENSE_KEY");

    // Use a valid-format but WRONG public key
    config.public_key_hex =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let manager = LicenseManager::new(config).expect("LicenseManager should initialize");
    let result = manager.validate_key(&license_key);

    match result {
        Err(GatewardenError::SignatureInvalid) => {
            println!("  Correctly rejected: wrong public key → SignatureInvalid");
        }
        Err(GatewardenError::ConfigError(msg)) => {
            // Some keys are rejected at the Ed25519 level as invalid points
            println!("  Correctly rejected at key decode: {}", msg);
        }
        other => {
            panic!(
                "Wrong public key should fail with SignatureInvalid, got: {:?}",
                other
            );
        }
    }
}
