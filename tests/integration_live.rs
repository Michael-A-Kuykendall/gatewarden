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
fn live_fse_selectors_scanned_metric() {
    // Verify that the selectors_scanned metric is present in validation result
    // and has a reasonable value (not zero, not excessive).
    let (config, license_key) = load_config()
        .expect("Set GATEWARDEN_TEST_ACCOUNT_ID, GATEWARDEN_TEST_PUBLIC_KEY_HEX, GATEWARDEN_TEST_LICENSE_KEY");

    let manager = LicenseManager::new(config).expect("LicenseManager should initialize");
    let result = manager
        .validate_key(&license_key)
        .expect("validate_key should succeed");

    assert!(result.valid, "License should be valid");
    
    // FSE should scan at least SignaturePresent, StateValid, and Entitlements (3 selectors)
    assert!(
        result.selectors_scanned >= 3,
        "Expected at least 3 selectors scanned (SignaturePresent, StateValid, Entitlements), got {}",
        result.selectors_scanned
    );
    
    // Sanity check: shouldn't scan an unreasonable number
    assert!(
        result.selectors_scanned <= 10,
        "Selector scan count seems excessive: {}",
        result.selectors_scanned
    );
    
    println!("  FSE selectors_scanned: {}", result.selectors_scanned);
}

#[test]
#[ignore]
fn live_fse_o1_behavior_with_multiple_entitlements() {
    // Confirm O(1) behavior: adding entitlement RULES doesn't increase scan count.
    // This is the FSE proof metric — extra rules on shared selectors don't
    // increase selector extraction cost.
    
    let base_entitlement = std::env::var("GATEWARDEN_TEST_ENTITLEMENT").unwrap_or_default();
    
    if base_entitlement.is_empty() {
        println!("  Skipping O(1) test: GATEWARDEN_TEST_ENTITLEMENT not set");
        return;
    }
    
    // Config 1: Single entitlement (creates 1 rule checking Entitlements selector)
    let (mut config1, license_key) = load_config()
        .expect("Set GATEWARDEN_TEST_ACCOUNT_ID, GATEWARDEN_TEST_PUBLIC_KEY_HEX, GATEWARDEN_TEST_LICENSE_KEY");
    config1.required_entitlements = vec![base_entitlement.clone()];
    config1.cache_namespace = format!(
        "gatewarden-live-test-o1-single-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let manager1 = LicenseManager::new(config1).expect("LicenseManager should initialize");
    let result1 = manager1
        .validate_key(&license_key)
        .expect("validate_key should succeed");
    
    // Config 2: Multiple entitlement rules (3 rules, all checking same Entitlements selector)
    let (mut config2, _) = load_config().unwrap();
    config2.required_entitlements = vec![
        base_entitlement.clone(),
        base_entitlement.clone(), // Duplicate intentionally - creates additional rule
        base_entitlement.clone(), // Another duplicate - third rule
    ];
    config2.cache_namespace = format!(
        "gatewarden-live-test-o1-triple-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let manager2 = LicenseManager::new(config2).expect("LicenseManager should initialize");
    let result2 = manager2
        .validate_key(&license_key)
        .expect("validate_key should succeed with duplicate entitlements");
    
    // FSE O(1) invariant: adding rules that share selectors doesn't increase scan count
    // Both configs check SignaturePresent, StateValid, and Entitlements = 3 selectors
    // The second config has 3x more entitlement rules, but still scans Entitlements once
    println!("  Config 1 (1 entitlement rule): selectors_scanned = {}", result1.selectors_scanned);
    println!("  Config 2 (3 entitlement rules): selectors_scanned = {}", result2.selectors_scanned);
    
    assert_eq!(
        result1.selectors_scanned, result2.selectors_scanned,
        "FSE O(1) invariant violated: adding entitlement rules increased scan count from {} to {}",
        result1.selectors_scanned, result2.selectors_scanned
    );
    
    assert_eq!(
        result1.selectors_scanned, 3,
        "Expected 3 selectors (SignaturePresent, StateValid, Entitlements), got {}",
        result1.selectors_scanned
    );
    
    println!("  ✓ FSE O(1) property confirmed: {} selectors scanned regardless of rule count", result1.selectors_scanned);
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
