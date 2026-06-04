use fse_gatewarden::{evaluate_policy, EvalInput, Rule, Selector, Predicate};
use fse_gatewarden::engine::default_security_rules;

#[test]
fn selector_dedup_single_pass_behavior() {
    let rules = vec![
        Rule {
            id: "sig_required".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "sig_required_2".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "digest_required".to_string(),
            selector: Selector::DigestMatches,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
    ];

    let input = EvalInput {
        profile_id: None,
        signature_present: Some(true),
        digest_matches: Some(true),
        response_age_seconds: None,
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let report = evaluate_policy(rules, input);
    assert!(report.allow);
    assert_eq!(report.selectors_scanned, 2);
}

#[test]
fn fail_closed_on_unresolved_required_selector() {
    let rules = vec![Rule {
        id: "requires_profile".to_string(),
        selector: Selector::ProfileId,
        predicate: Predicate::EqString("chat-chronicle-pro".to_string()),
        required: true,
    }];

    let input = EvalInput {
        profile_id: None,
        signature_present: Some(true),
        digest_matches: Some(true),
        response_age_seconds: Some(42),
        entitlements: vec!["CHAT_CHRONICLE_PRO".to_string()],
        bridge_token_valid: Some(true),
    };

    let report = evaluate_policy(rules, input);
    assert!(!report.allow);
}

#[test]
fn red_team_missing_signature_denies() {
    let rules = default_security_rules("chat-chronicle-pro", "CHAT_CHRONICLE_PRO");
    let input = EvalInput {
        profile_id: Some("chat-chronicle-pro".to_string()),
        signature_present: Some(false),
        digest_matches: Some(true),
        response_age_seconds: Some(10),
        entitlements: vec!["CHAT_CHRONICLE_PRO".to_string()],
        bridge_token_valid: Some(true),
    };

    let report = evaluate_policy(rules, input);
    assert!(!report.allow);
}

#[test]
fn red_team_replay_stale_response_denies() {
    let rules = default_security_rules("chat-chronicle-pro", "CHAT_CHRONICLE_PRO");
    let input = EvalInput {
        profile_id: Some("chat-chronicle-pro".to_string()),
        signature_present: Some(true),
        digest_matches: Some(true),
        response_age_seconds: Some(301),
        entitlements: vec!["CHAT_CHRONICLE_PRO".to_string()],
        bridge_token_valid: Some(true),
    };

    let report = evaluate_policy(rules, input);
    assert!(!report.allow);
}

#[test]
fn red_team_token_spoof_denies() {
    let rules = default_security_rules("chat-chronicle-pro", "CHAT_CHRONICLE_PRO");
    let input = EvalInput {
        profile_id: Some("chat-chronicle-pro".to_string()),
        signature_present: Some(true),
        digest_matches: Some(true),
        response_age_seconds: Some(5),
        entitlements: vec!["CHAT_CHRONICLE_PRO".to_string()],
        bridge_token_valid: Some(false),
    };

    let report = evaluate_policy(rules, input);
    assert!(!report.allow);
}

#[test]
fn all_security_checks_pass_allows_access() {
    let rules = default_security_rules("chat-chronicle-pro", "CHAT_CHRONICLE_PRO");
    let input = EvalInput {
        profile_id: Some("chat-chronicle-pro".to_string()),
        signature_present: Some(true),
        digest_matches: Some(true),
        response_age_seconds: Some(2),
        entitlements: vec!["CHAT_CHRONICLE_PRO".to_string(), "TEAM".to_string()],
        bridge_token_valid: Some(true),
    };

    let report = evaluate_policy(rules, input);
    assert!(report.allow);
}

// ─── Fail-closed: bridge token is a hard gate ─────────────────────────────

/// Even when all signature/digest/entitlement rules pass, a missing bridge token
/// must deny access.  This proves the fail-closed invariant holds when
/// bridge_token_valid is absent (None) — the engine must not grant access.
#[test]
fn fail_closed_missing_bridge_token_denies_even_when_all_else_passes() {
    let rules = default_security_rules("chat-chronicle-pro", "CHAT_CHRONICLE_PRO");
    let input = EvalInput {
        profile_id: Some("chat-chronicle-pro".to_string()),
        signature_present: Some(true),
        digest_matches: Some(true),
        response_age_seconds: Some(5),
        entitlements: vec!["CHAT_CHRONICLE_PRO".to_string()],
        bridge_token_valid: None, // absent = bridge didn't validate
    };

    let report = evaluate_policy(rules, input);
    assert!(!report.allow, "missing bridge token must deny even if crypto checks pass");
}

/// A bridge token explicitly set to false is a hard deny regardless of rule order.
#[test]
fn fail_closed_false_bridge_token_overrides_valid_crypto() {
    let rules = default_security_rules("chat-chronicle-pro", "CHAT_CHRONICLE_PRO");
    let input = EvalInput {
        profile_id: Some("chat-chronicle-pro".to_string()),
        signature_present: Some(true),
        digest_matches: Some(true),
        response_age_seconds: Some(1),
        entitlements: vec!["CHAT_CHRONICLE_PRO".to_string()],
        bridge_token_valid: Some(false),
    };

    let report = evaluate_policy(rules, input);
    assert!(!report.allow, "false bridge token must deny regardless of other rule outcomes");
    // Verify the bridge_token_valid rule is in the outcomes as False.
    let bridge_outcome = report
        .rule_outcomes
        .iter()
        .find(|(id, _)| id == "bridge_token_valid");
    assert!(bridge_outcome.is_some(), "bridge_token_valid rule must appear in outcomes");
    assert!(
        matches!(bridge_outcome.unwrap().1, fse_gatewarden::RuleDecision::False),
        "bridge_token_valid outcome must be False"
    );
}

/// Demonstrates O(unique_selector) evaluation: adding 50 extra bridge-token rules
/// that all share the same selector keeps selectors_scanned constant.
#[test]
fn bridge_token_extra_rules_zero_marginal_selector_cost() {
    use fse_gatewarden::compiler::compile_rules;
    use fse_gatewarden::runtime::execute;

    // Build default 6 rules + 50 extra BridgeTokenValid rules (all shared selector).
    let mut rules = default_security_rules("chat-chronicle-pro", "CHAT_CHRONICLE_PRO");
    for i in 6..56 {
        rules.push(Rule {
            id: format!("extra_bridge_rule_{}", i),
            selector: Selector::BridgeTokenValid,
            predicate: Predicate::BoolIsTrue,
            required: false,
        });
    }

    let plan = compile_rules(rules);
    let input = EvalInput {
        profile_id: Some("chat-chronicle-pro".to_string()),
        signature_present: Some(true),
        digest_matches: Some(true),
        response_age_seconds: Some(5),
        entitlements: vec!["CHAT_CHRONICLE_PRO".to_string()],
        bridge_token_valid: Some(true),
    };

    let result = execute(&plan, &input);
    // 56 rules but only 6 unique selectors — must still scan exactly 6.
    assert_eq!(
        result.selectors_scanned, 6,
        "56 rules sharing 6 selectors must scan exactly 6 selectors (FSE O(unique_selectors) invariant)"
    );
    assert!(result.allow);
}
