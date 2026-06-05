use gatewarden::policy::fse::engine::default_security_rules;
use gatewarden::policy::fse::compiler::compile_rules;
use gatewarden::policy::fse::runtime::execute;
use gatewarden::{evaluate_policy, FseEvalInput as EvalInput, FsePredicate as Predicate,
                 FseRule as Rule, FseRuleDecision as RuleDecision, FseSelector as Selector};

#[test]
fn selector_dedup_single_pass_behavior() {
    let rules = vec![
        Rule {
            id: "crypto.sig_required".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "crypto.sig_required_2".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "crypto.digest_required".to_string(),
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
        id: "response.requires_profile".to_string(),
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

#[test]
fn fail_closed_missing_bridge_token_denies_even_when_all_else_passes() {
    let rules = default_security_rules("chat-chronicle-pro", "CHAT_CHRONICLE_PRO");
    let input = EvalInput {
        profile_id: Some("chat-chronicle-pro".to_string()),
        signature_present: Some(true),
        digest_matches: Some(true),
        response_age_seconds: Some(5),
        entitlements: vec!["CHAT_CHRONICLE_PRO".to_string()],
        bridge_token_valid: None,
    };

    let report = evaluate_policy(rules, input);
    assert!(!report.allow, "missing bridge token must deny even if crypto checks pass");
}

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
    let bridge_outcome = report
        .rule_outcomes
        .iter()
        .find(|(id, _)| id == "bridge.token_valid");
    assert!(bridge_outcome.is_some(), "bridge.token_valid rule must appear in outcomes");
    assert!(
        matches!(bridge_outcome.unwrap().1, RuleDecision::False),
        "bridge.token_valid outcome must be False"
    );
}

#[test]
fn bridge_token_extra_rules_zero_marginal_selector_cost() {
    let mut rules = default_security_rules("chat-chronicle-pro", "CHAT_CHRONICLE_PRO");
    for i in 6..56 {
        rules.push(Rule {
            id: format!("bridge.extra_rule_{}", i),
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
    assert_eq!(
        result.selectors_scanned, 6,
        "56 rules sharing 6 selectors must scan exactly 6 selectors (FSE O(unique_selectors) invariant)"
    );
    assert!(result.allow);
}

// ────────────────────────────────────────────────────────────────────────────
// New Predicate Tests (Task 2: Expand Predicate Vocabulary)
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn predicate_min_u64_allows_equal_value() {
    let rules = vec![Rule {
        id: "response.min_check".to_string(),
        selector: Selector::ResponseAgeSeconds,
        predicate: Predicate::MinU64(100),
        required: true,
    }];

    let input = EvalInput {
        profile_id: None,
        signature_present: None,
        digest_matches: None,
        response_age_seconds: Some(100),
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let report = evaluate_policy(rules, input);
    assert!(report.allow, "MinU64(100) should allow value 100");
}

#[test]
fn predicate_min_u64_allows_greater_value() {
    let rules = vec![Rule {
        id: "response.min_check".to_string(),
        selector: Selector::ResponseAgeSeconds,
        predicate: Predicate::MinU64(50),
        required: true,
    }];

    let input = EvalInput {
        profile_id: None,
        signature_present: None,
        digest_matches: None,
        response_age_seconds: Some(200),
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let report = evaluate_policy(rules, input);
    assert!(report.allow, "MinU64(50) should allow value 200");
}

#[test]
fn predicate_min_u64_denies_lesser_value() {
    let rules = vec![Rule {
        id: "response.min_check".to_string(),
        selector: Selector::ResponseAgeSeconds,
        predicate: Predicate::MinU64(100),
        required: true,
    }];

    let input = EvalInput {
        profile_id: None,
        signature_present: None,
        digest_matches: None,
        response_age_seconds: Some(50),
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let report = evaluate_policy(rules, input);
    assert!(!report.allow, "MinU64(100) should deny value 50");
}

#[test]
fn predicate_exists_allows_present_string() {
    let rules = vec![Rule {
        id: "response.exists_check".to_string(),
        selector: Selector::ProfileId,
        predicate: Predicate::Exists,
        required: true,
    }];

    let input = EvalInput {
        profile_id: Some("chat-chronicle-pro".to_string()),
        signature_present: None,
        digest_matches: None,
        response_age_seconds: None,
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let report = evaluate_policy(rules, input);
    assert!(report.allow, "Exists should allow present string value");
}

#[test]
fn predicate_exists_allows_present_bool() {
    let rules = vec![Rule {
        id: "crypto.exists_check".to_string(),
        selector: Selector::SignaturePresent,
        predicate: Predicate::Exists,
        required: true,
    }];

    let input = EvalInput {
        profile_id: None,
        signature_present: Some(false),
        digest_matches: None,
        response_age_seconds: None,
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let report = evaluate_policy(rules, input);
    assert!(report.allow, "Exists should allow present bool value, even if false");
}

#[test]
fn predicate_exists_denies_missing_value() {
    let rules = vec![Rule {
        id: "response.exists_check".to_string(),
        selector: Selector::ProfileId,
        predicate: Predicate::Exists,
        required: true,
    }];

    let input = EvalInput {
        profile_id: None,
        signature_present: None,
        digest_matches: None,
        response_age_seconds: None,
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let report = evaluate_policy(rules, input);
    assert!(!report.allow, "Exists should deny Missing value");
}

#[test]
fn predicate_in_set_allows_matching_value() {
    let rules = vec![Rule {
        id: "response.in_set_check".to_string(),
        selector: Selector::ProfileId,
        predicate: Predicate::InSet(vec![
            "chat-chronicle-pro".to_string(),
            "chat-chronicle-team".to_string(),
            "chat-chronicle-enterprise".to_string(),
        ]),
        required: true,
    }];

    let input = EvalInput {
        profile_id: Some("chat-chronicle-team".to_string()),
        signature_present: None,
        digest_matches: None,
        response_age_seconds: None,
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let report = evaluate_policy(rules, input);
    assert!(report.allow, "InSet should allow value present in set");
}

#[test]
fn predicate_in_set_denies_non_matching_value() {
    let rules = vec![Rule {
        id: "response.in_set_check".to_string(),
        selector: Selector::ProfileId,
        predicate: Predicate::InSet(vec![
            "chat-chronicle-pro".to_string(),
            "chat-chronicle-team".to_string(),
        ]),
        required: true,
    }];

    let input = EvalInput {
        profile_id: Some("chat-chronicle-free".to_string()),
        signature_present: None,
        digest_matches: None,
        response_age_seconds: None,
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let report = evaluate_policy(rules, input);
    assert!(!report.allow, "InSet should deny value not in set");
}

#[test]
fn predicate_in_set_denies_missing_value() {
    let rules = vec![Rule {
        id: "response.in_set_check".to_string(),
        selector: Selector::ProfileId,
        predicate: Predicate::InSet(vec![
            "chat-chronicle-pro".to_string(),
        ]),
        required: true,
    }];

    let input = EvalInput {
        profile_id: None,
        signature_present: None,
        digest_matches: None,
        response_age_seconds: None,
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let report = evaluate_policy(rules, input);
    assert!(!report.allow, "InSet should deny Missing value");
}
