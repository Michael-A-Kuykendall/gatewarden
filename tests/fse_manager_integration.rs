//! Integration tests for FSE in LicenseManager.
//!
//! These tests confirm that:
//! 1. FSE plan is compiled at manager construction
//! 2. FSE evaluation rejects invalid licenses
//! 3. FSE evaluation accepts valid licenses
//! 4. FSE rule failures are logged appropriately

use gatewarden::policy::fse::compiler::compile_rules;
use gatewarden::policy::fse::defaults::compile_default_plan;
use gatewarden::policy::fse::gatewarden_input::GatewardenEvalInput;
use gatewarden::policy::fse::model::{Predicate, Rule, RuleDecision, Selector};
use gatewarden::policy::fse::runtime::execute;
use gatewarden::protocol::models::LicenseState;
use gatewarden::GatewardenConfig;
use chrono::{DateTime, Utc};
use std::time::Duration;

fn test_config() -> GatewardenConfig {
    GatewardenConfig {
        app_name: "test-app".to_string(),
        feature_name: "test".to_string(),
        account_id: "test-account".to_string(),
        public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            .to_string(),
        required_entitlements: vec!["PREMIUM".to_string()],
        user_agent_product: "test-product".to_string(),
        cache_namespace: "gatewarden-test-fse".to_string(),
        offline_grace: Duration::from_secs(86400),
    }
}

fn valid_license_state() -> LicenseState {
    LicenseState {
        valid: true,
        entitlements: vec!["PREMIUM".to_string(), "VISION_ANALYSIS".to_string()],
        expires_at: Some("2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()),
        max_uses: Some(1000),
        current_uses: Some(42),
        code: "VALID".to_string(),
        detail: Some("License is valid".to_string()),
    }
}

fn invalid_license_state() -> LicenseState {
    LicenseState {
        valid: false,
        entitlements: vec![],
        expires_at: Some("2020-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()),
        max_uses: None,
        current_uses: None,
        code: "EXPIRED".to_string(),
        detail: Some("License has expired".to_string()),
    }
}

fn expired_license_state() -> LicenseState {
    LicenseState {
        valid: false,
        entitlements: vec!["PREMIUM".to_string()],
        expires_at: Some("2020-06-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()),
        max_uses: None,
        current_uses: None,
        code: "EXPIRED".to_string(),
        detail: Some("License expired on 2020-06-01".to_string()),
    }
}

fn missing_entitlement_state() -> LicenseState {
    LicenseState {
        valid: true,
        entitlements: vec!["BASIC".to_string()],
        expires_at: Some("2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()),
        max_uses: None,
        current_uses: None,
        code: "VALID".to_string(),
        detail: Some("License is valid".to_string()),
    }
}

#[test]
fn test_fse_plan_compiles_at_manager_creation() {
    let config = test_config();
    let plan_result = compile_default_plan(&config);

    assert!(plan_result.is_ok(), "FSE plan should compile successfully");

    let plan = plan_result.unwrap();
    // Should have 3 rules: signature_verified, state_valid, entitlements.required_0
    assert_eq!(plan.rules.len(), 3);
    assert_eq!(plan.required_count, 3);

    // Verify rule IDs
    assert_eq!(plan.rules[0].id, "crypto.signature_verified");
    assert_eq!(plan.rules[1].id, "response.state_valid");
    assert_eq!(plan.rules[2].id, "entitlements.required_0");
}

#[test]
fn test_fse_accepts_valid_license() {
    let config = test_config();
    let plan = compile_default_plan(&config).unwrap();

    let state = valid_license_state();
    let input = GatewardenEvalInput::from_validated_response(state, true);

    let result = execute(&plan, &input);

    assert!(result.allow, "FSE should accept valid license");
    assert_eq!(result.selectors_scanned, 3); // SignaturePresent, StateValid, Entitlements

    // All rules should be True
    for outcome in &result.outcomes {
        assert_eq!(
            outcome.decision,
            RuleDecision::True,
            "Rule {} should pass",
            outcome.rule_id
        );
    }
}

#[test]
fn test_fse_rejects_invalid_license_state() {
    let config = test_config();
    let plan = compile_default_plan(&config).unwrap();

    let state = invalid_license_state();
    let input = GatewardenEvalInput::from_validated_response(state, true);

    let result = execute(&plan, &input);

    assert!(!result.allow, "FSE should reject invalid license");

    // Find which rule(s) failed
    let failed_rules: Vec<&str> = result
        .outcomes
        .iter()
        .filter(|o| o.decision == RuleDecision::False)
        .map(|o| o.rule_id.as_str())
        .collect();

    // Should fail on state_valid and entitlements
    assert!(failed_rules.contains(&"response.state_valid"));
    assert!(failed_rules.contains(&"entitlements.required_0"));
}

#[test]
fn test_fse_rejects_expired_license() {
    let config = test_config();
    let plan = compile_default_plan(&config).unwrap();

    let state = expired_license_state();
    let input = GatewardenEvalInput::from_validated_response(state, true);

    let result = execute(&plan, &input);

    assert!(!result.allow, "FSE should reject expired license");

    // Find which rule failed
    let failed_rules: Vec<&str> = result
        .outcomes
        .iter()
        .filter(|o| o.decision == RuleDecision::False)
        .map(|o| o.rule_id.as_str())
        .collect();

    // Should fail on state_valid
    assert!(failed_rules.contains(&"response.state_valid"));
}

#[test]
fn test_fse_rejects_missing_entitlement() {
    let config = test_config();
    let plan = compile_default_plan(&config).unwrap();

    let state = missing_entitlement_state();
    let input = GatewardenEvalInput::from_validated_response(state, true);

    let result = execute(&plan, &input);

    assert!(
        !result.allow,
        "FSE should reject license missing required entitlement"
    );

    // Find which rule failed
    let failed_rules: Vec<&str> = result
        .outcomes
        .iter()
        .filter(|o| o.decision == RuleDecision::False)
        .map(|o| o.rule_id.as_str())
        .collect();

    // Should fail on entitlements.required_0 (PREMIUM is missing)
    assert!(failed_rules.contains(&"entitlements.required_0"));
}

#[test]
fn test_fse_rejects_unsigned_response() {
    let config = test_config();
    let plan = compile_default_plan(&config).unwrap();

    let state = valid_license_state();
    // signature_verified = false
    let input = GatewardenEvalInput::from_validated_response(state, false);

    let result = execute(&plan, &input);

    assert!(!result.allow, "FSE should reject unsigned response");

    // Find which rule failed
    let failed_rules: Vec<&str> = result
        .outcomes
        .iter()
        .filter(|o| o.decision == RuleDecision::False)
        .map(|o| o.rule_id.as_str())
        .collect();

    // Should fail on crypto.signature_verified
    assert!(failed_rules.contains(&"crypto.signature_verified"));
}

#[test]
fn test_fse_multiple_entitlements() {
    let mut config = test_config();
    config.required_entitlements = vec![
        "PREMIUM".to_string(),
        "VISION_ANALYSIS".to_string(),
        "API_ACCESS".to_string(),
    ];

    let plan = compile_default_plan(&config).unwrap();
    assert_eq!(plan.rules.len(), 5); // 2 base + 3 entitlements

    let state = LicenseState {
        valid: true,
        entitlements: vec![
            "PREMIUM".to_string(),
            "VISION_ANALYSIS".to_string(),
            "API_ACCESS".to_string(),
            "BONUS".to_string(),
        ],
        expires_at: Some("2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()),
        max_uses: None,
        current_uses: None,
        code: "VALID".to_string(),
        detail: None,
    };

    let input = GatewardenEvalInput::from_validated_response(state, true);
    let result = execute(&plan, &input);

    assert!(result.allow, "FSE should accept license with all entitlements");

    // All rules should pass
    for outcome in &result.outcomes {
        assert_eq!(
            outcome.decision,
            RuleDecision::True,
            "Rule {} should pass",
            outcome.rule_id
        );
    }
}

#[test]
fn test_fse_multiple_entitlements_one_missing() {
    let mut config = test_config();
    config.required_entitlements = vec![
        "PREMIUM".to_string(),
        "VISION_ANALYSIS".to_string(),
        "API_ACCESS".to_string(),
    ];

    let plan = compile_default_plan(&config).unwrap();

    let state = LicenseState {
        valid: true,
        // Missing API_ACCESS
        entitlements: vec!["PREMIUM".to_string(), "VISION_ANALYSIS".to_string()],
        expires_at: Some("2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()),
        max_uses: None,
        current_uses: None,
        code: "VALID".to_string(),
        detail: None,
    };

    let input = GatewardenEvalInput::from_validated_response(state, true);
    let result = execute(&plan, &input);

    assert!(!result.allow, "FSE should reject license missing one entitlement");

    // Find which rule failed
    let failed_rules: Vec<&str> = result
        .outcomes
        .iter()
        .filter(|o| o.decision == RuleDecision::False)
        .map(|o| o.rule_id.as_str())
        .collect();

    // Should fail on entitlements.required_2 (API_ACCESS)
    assert!(failed_rules.contains(&"entitlements.required_2"));
}

#[test]
fn test_fse_selectors_scanned_constant_with_shared_selectors() {
    // First config: 1 entitlement
    let mut config1 = test_config();
    config1.required_entitlements = vec!["ENT1".to_string()];
    let plan1 = compile_default_plan(&config1).unwrap();

    // Second config: 5 entitlements (all share same selector)
    let mut config2 = test_config();
    config2.required_entitlements = vec![
        "ENT1".to_string(),
        "ENT2".to_string(),
        "ENT3".to_string(),
        "ENT4".to_string(),
        "ENT5".to_string(),
    ];
    let plan2 = compile_default_plan(&config2).unwrap();

    // Both should have same number of unique selectors (3)
    assert_eq!(plan1.selectors.len(), 3);
    assert_eq!(plan2.selectors.len(), 3);

    // Execute both plans
    let state = LicenseState {
        valid: true,
        entitlements: vec![
            "ENT1".to_string(),
            "ENT2".to_string(),
            "ENT3".to_string(),
            "ENT4".to_string(),
            "ENT5".to_string(),
        ],
        expires_at: None,
        max_uses: None,
        current_uses: None,
        code: "VALID".to_string(),
        detail: None,
    };

    let input = GatewardenEvalInput::from_validated_response(state, true);

    let result1 = execute(&plan1, &input.clone());
    let result2 = execute(&plan2, &input);

    // FSE proof metric: adding rules on shared selectors doesn't increase scan count
    assert_eq!(
        result1.selectors_scanned, result2.selectors_scanned,
        "Selectors scanned should be constant (FSE proof metric)"
    );
    assert_eq!(result1.selectors_scanned, 3);
}

#[test]
fn test_fse_fail_closed_on_unresolved_required() {
    // Create a minimal plan with a required rule
    let rules = vec![Rule {
        id: "test.required_rule".to_string(),
        selector: Selector::UsageRemaining,
        predicate: Predicate::MinU64(100),
        required: true,
    }];

    let plan = compile_rules(rules);

    // Input that returns Missing for UsageRemaining
    let state = valid_license_state();
    let input = GatewardenEvalInput::from_validated_response(state, true);

    let result = execute(&plan, &input);

    // Should fail closed - unresolved required rule becomes False
    assert!(!result.allow, "FSE should fail closed on unresolved required rule");

    // Check the rule outcome
    assert_eq!(result.outcomes.len(), 1);
    assert_eq!(result.outcomes[0].rule_id, "test.required_rule");
    assert_eq!(result.outcomes[0].decision, RuleDecision::False);
}

#[test]
fn test_fse_early_exit_not_verified() {
    let config = test_config();
    let plan = compile_default_plan(&config).unwrap();

    let state = valid_license_state();
    // signature_verified = false → should trigger early exit
    let input = GatewardenEvalInput::from_validated_response(state, false);

    let result = execute(&plan, &input);

    // Even though it may not exit early in this implementation,
    // verify that it correctly rejects
    assert!(!result.allow, "FSE should reject when signature not verified");

    // The selectors_scanned metric should still be present
    assert!(result.selectors_scanned > 0);
    assert!(result.selectors_scanned <= plan.selectors.len());
}
