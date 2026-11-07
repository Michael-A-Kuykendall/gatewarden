//! Live tests of license actions (machine activation, usage increment, machine
//! removal) against real Keygen.sh. Ignored by default.
//!
//! ```bash
//! GATEWARDEN_TEST_ACCOUNT_ID=... GATEWARDEN_TEST_PUBLIC_KEY_HEX=... \
//! GATEWARDEN_TEST_ACTION_LICENSE_KEY=... cargo test --test integration_live_actions -- --ignored
//! ```
//!
//! The license must use a policy with `authenticationStrategy` LICENSE or MIXED,
//! allow at least one free machine slot, and have no `maxUses` ceiling (the test
//! increments its usage by one).

use gatewarden::{GatewardenConfig, LicenseManager};
use std::time::Duration;

fn setup() -> Option<(LicenseManager, String)> {
    let account_id = std::env::var("GATEWARDEN_TEST_ACCOUNT_ID").ok()?;
    let public_key_hex = std::env::var("GATEWARDEN_TEST_PUBLIC_KEY_HEX").ok()?;
    let key = std::env::var("GATEWARDEN_TEST_ACTION_LICENSE_KEY").ok()?;
    let config = GatewardenConfig {
        app_name: "gatewarden-integration-test".to_string(),
        feature_name: "live-actions".to_string(),
        account_id,
        public_key_hex,
        required_entitlements: vec![],
        user_agent_product: "gatewarden-test".to_string(),
        cache_namespace: format!("gatewarden-live-actions-{}", std::process::id()),
        offline_grace: Duration::from_secs(60),
    };
    Some((LicenseManager::new(config).ok()?, key))
}

#[test]
#[ignore]
fn live_activate_increment_deactivate() {
    let Some((manager, key)) = setup() else {
        eprintln!("skipping: GATEWARDEN_TEST_* not set");
        return;
    };
    // validate-key without a fingerprint scope still returns the license record.
    let license_id = match manager.validate_key(&key) {
        Ok(result) => result.state.license_id,
        Err(_) => None,
    }
    .or_else(|| std::env::var("GATEWARDEN_TEST_ACTION_LICENSE_ID").ok())
    .expect("license id (from validation or GATEWARDEN_TEST_ACTION_LICENSE_ID)");

    let fingerprint = format!(
        "{:064x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let before = manager
        .inspect_key(&key, Some(&fingerprint))
        .expect("inspect");
    assert_eq!(before.license_id.as_deref(), Some(license_id.as_str()));
    assert!(
        !before.valid,
        "an unactivated fingerprint is not valid yet: {}",
        before.code
    );
    assert!(before.policy_id.is_some());
    let first = manager
        .activate_machine(
            &key,
            &license_id,
            &fingerprint,
            "linux",
            "gatewarden-live-test",
        )
        .expect("activation");
    let machine_id = first.machine_id.clone().expect("new machine id");
    assert!(!first.already_active);

    let again = manager
        .activate_machine(
            &key,
            &license_id,
            &fingerprint,
            "linux",
            "gatewarden-live-test",
        )
        .expect("second activation");
    assert!(
        again.already_active,
        "a taken fingerprint reports already_active"
    );

    let usage = manager
        .increment_usage(&key, &license_id, 1)
        .expect("increment");
    assert!(usage.uses >= 1);

    manager
        .deactivate_machine(&key, &machine_id)
        .expect("deactivate");
}
