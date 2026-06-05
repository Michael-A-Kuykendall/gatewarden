use gatewarden::policy::fse::compiler::compile_rules;
use gatewarden::policy::fse::engine::default_security_rules;
use gatewarden::policy::fse::runtime::execute;
use gatewarden::{
    evaluate_policy, FseEvalInput as EvalInput, FsePredicate as Predicate, FseRule as Rule,
    FseRuleDecision as RuleDecision, FseSelector as Selector,
};
use proptest::prelude::*;

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
    assert!(
        !report.allow,
        "missing bridge token must deny even if crypto checks pass"
    );
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
    assert!(
        !report.allow,
        "false bridge token must deny regardless of other rule outcomes"
    );
    let bridge_outcome = report
        .rule_outcomes
        .iter()
        .find(|(id, _)| id == "bridge.token_valid");
    assert!(
        bridge_outcome.is_some(),
        "bridge.token_valid rule must appear in outcomes"
    );
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
    assert!(
        report.allow,
        "Exists should allow present bool value, even if false"
    );
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
        predicate: Predicate::InSet(vec!["chat-chronicle-pro".to_string()]),
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

// ────────────────────────────────────────────────────────────────────────────
// Property-Based Tests (Task 9: Expand Property-Based Tests)
// ────────────────────────────────────────────────────────────────────────────

// Helper strategies for generating test data
fn arb_selector() -> impl Strategy<Value = Selector> {
    prop_oneof![
        Just(Selector::ProfileId),
        Just(Selector::SignaturePresent),
        Just(Selector::DigestMatches),
        Just(Selector::ResponseAgeSeconds),
        Just(Selector::Entitlements),
        Just(Selector::BridgeTokenValid),
        Just(Selector::StateCode),
        Just(Selector::StateValid),
        Just(Selector::ExpiresAt),
        Just(Selector::UsageRemaining),
    ]
}

fn arb_predicate_for_selector(selector: &Selector) -> impl Strategy<Value = Predicate> {
    match selector {
        Selector::ProfileId | Selector::StateCode => prop_oneof![
            "[a-z]{5,15}".prop_map(Predicate::EqString),
            Just(Predicate::Exists),
            proptest::collection::vec("[a-z]{5,15}", 1..5).prop_map(Predicate::InSet),
        ]
        .boxed(),
        Selector::SignaturePresent
        | Selector::DigestMatches
        | Selector::BridgeTokenValid
        | Selector::StateValid => {
            prop_oneof![Just(Predicate::BoolIsTrue), Just(Predicate::Exists),].boxed()
        }
        Selector::ResponseAgeSeconds | Selector::UsageRemaining => prop_oneof![
            any::<u64>().prop_map(Predicate::MaxU64),
            any::<u64>().prop_map(Predicate::MinU64),
            Just(Predicate::Exists),
        ]
        .boxed(),
        Selector::Entitlements => prop_oneof![
            "[A-Z_]{5,20}".prop_map(Predicate::ContainsString),
            Just(Predicate::Exists),
            proptest::collection::vec("[A-Z_]{5,20}", 1..5).prop_map(Predicate::InSet),
        ]
        .boxed(),
        Selector::ExpiresAt => Just(Predicate::Exists).boxed(),
        _ => {
            // Catch-all for future selectors
            Just(Predicate::Exists).boxed()
        }
    }
}

fn arb_rule() -> impl Strategy<Value = Rule> {
    arb_selector().prop_flat_map(|selector| {
        (
            Just(selector.clone()),
            arb_predicate_for_selector(&selector),
            any::<bool>(),
            "[a-z_]{3,10}\\.[a-z_]{3,15}",
        )
            .prop_map(move |(sel, pred, req, id)| Rule {
                id,
                selector: sel,
                predicate: pred,
                required: req,
            })
    })
}

fn arb_eval_input() -> impl Strategy<Value = EvalInput> {
    (
        proptest::option::of("[a-z-]{10,20}"),
        proptest::option::of(any::<bool>()),
        proptest::option::of(any::<bool>()),
        proptest::option::of(any::<u64>()),
        proptest::collection::vec("[A-Z_]{5,20}", 0..10),
        proptest::option::of(any::<bool>()),
    )
        .prop_map(|(profile, sig, digest, age, ents, bridge)| EvalInput {
            profile_id: profile,
            signature_present: sig,
            digest_matches: digest,
            response_age_seconds: age,
            entitlements: ents,
            bridge_token_valid: bridge,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Property: Adding rules with existing selectors doesn't increase scan count
    ///
    /// This is the core FSE invariant: O(unique_selectors), not O(rules).
    /// When we add N rules that all share selectors already in the plan,
    /// selectors_scanned should remain constant.
    #[test]
    fn prop_adding_duplicate_selector_rules_keeps_scan_count_constant(
        base_rules in proptest::collection::vec(arb_rule(), 1..10),
        extra_count in 1..50usize,
        input in arb_eval_input(),
    ) {
        let base_plan = compile_rules(base_rules.clone());
        let base_result = execute(&base_plan, &input);
        let base_scan_count = base_result.selectors_scanned;

        // Add extra_count rules that reuse selectors from base_rules
        let mut extended_rules = base_rules.clone();
        for i in 0..extra_count {
            let base_rule = &base_rules[i % base_rules.len()];
            extended_rules.push(Rule {
                id: format!("extra_rule_{}", i),
                selector: base_rule.selector.clone(),
                predicate: base_rule.predicate.clone(),
                required: false,
            });
        }

        let extended_plan = compile_rules(extended_rules);
        let extended_result = execute(&extended_plan, &input);

        prop_assert_eq!(
            extended_result.selectors_scanned,
            base_scan_count,
            "Adding {} rules with duplicate selectors changed scan count from {} to {}",
            extra_count,
            base_scan_count,
            extended_result.selectors_scanned
        );
    }

    /// Property: selectors_scanned <= plan.selectors.len()
    ///
    /// FSE never scans more selectors than exist in the plan. Early exit
    /// when all required rules are resolved may cause it to scan fewer.
    #[test]
    fn prop_selectors_scanned_bounded_by_plan_size(
        rules in proptest::collection::vec(arb_rule(), 1..50),
        input in arb_eval_input(),
    ) {
        let plan = compile_rules(rules);
        let result = execute(&plan, &input);

        prop_assert!(
            result.selectors_scanned <= plan.selectors.len(),
            "Scanned {} selectors but plan only has {} unique selectors",
            result.selectors_scanned,
            plan.selectors.len()
        );
    }

    /// Property: All required rules True → allow == true
    ///
    /// If we craft an input where every required rule evaluates to True,
    /// the final allow decision must be True (assuming no optional False).
    #[test]
    fn prop_all_required_true_allows_access(
        required_count in 1..20usize,
        optional_count in 0..10usize,
    ) {
        // Build rules with BoolIsTrue predicates and matching input
        let mut rules = Vec::new();
        for i in 0..required_count {
            rules.push(Rule {
                id: format!("required_{}", i),
                selector: Selector::SignaturePresent,
                predicate: Predicate::BoolIsTrue,
                required: true,
            });
        }
        for i in 0..optional_count {
            rules.push(Rule {
                id: format!("optional_{}", i),
                selector: Selector::DigestMatches,
                predicate: Predicate::BoolIsTrue,
                required: false,
            });
        }

        let input = EvalInput {
            profile_id: None,
            signature_present: Some(true),
            digest_matches: Some(true),
            response_age_seconds: None,
            entitlements: vec![],
            bridge_token_valid: None,
        };

        let report = evaluate_policy(rules, input);
        prop_assert!(
            report.allow,
            "All required rules True but allow was false"
        );
    }

    /// Property: Any required rule False → allow == false
    ///
    /// If even one required rule evaluates to False, the overall decision
    /// must be deny (fail-closed).
    #[test]
    fn prop_any_required_false_denies_access(
        passing_required in 0..10usize,
        optional_count in 0..10usize,
    ) {
        let mut rules = Vec::new();

        // Add passing_required rules that will pass
        for i in 0..passing_required {
            rules.push(Rule {
                id: format!("pass_required_{}", i),
                selector: Selector::SignaturePresent,
                predicate: Predicate::BoolIsTrue,
                required: true,
            });
        }

        // Add ONE failing required rule
        rules.push(Rule {
            id: "fail_required".to_string(),
            selector: Selector::DigestMatches,
            predicate: Predicate::BoolIsTrue,
            required: true,
        });

        // Add optional rules
        for i in 0..optional_count {
            rules.push(Rule {
                id: format!("optional_{}", i),
                selector: Selector::BridgeTokenValid,
                predicate: Predicate::BoolIsTrue,
                required: false,
            });
        }

        let input = EvalInput {
            profile_id: None,
            signature_present: Some(true),
            digest_matches: Some(false), // This makes the failing rule fail
            response_age_seconds: None,
            entitlements: vec![],
            bridge_token_valid: Some(true),
        };

        let report = evaluate_policy(rules, input);
        prop_assert!(
            !report.allow,
            "One required rule False but allow was true"
        );
    }

    /// Property: MinU64 predicate matches correctly
    ///
    /// For all threshold values and input values:
    /// - input >= threshold → True
    /// - input < threshold → False
    /// - Missing input → False
    #[test]
    fn prop_min_u64_predicate_correct(
        threshold in any::<u64>(),
        value in any::<u64>(),
    ) {
        let rule = Rule {
            id: "test.min_u64".to_string(),
            selector: Selector::ResponseAgeSeconds,
            predicate: Predicate::MinU64(threshold),
            required: true,
        };

        let input = EvalInput {
            profile_id: None,
            signature_present: None,
            digest_matches: None,
            response_age_seconds: Some(value),
            entitlements: vec![],
            bridge_token_valid: None,
        };

        let report = evaluate_policy(vec![rule], input);
        let expected = value >= threshold;

        prop_assert_eq!(
            report.allow,
            expected,
            "MinU64({}) with value {} should be {} but got {}",
            threshold,
            value,
            expected,
            report.allow
        );
    }

    /// Property: MinU64 with missing input denies
    #[test]
    fn prop_min_u64_missing_denies(threshold in any::<u64>()) {
        let rule = Rule {
            id: "test.min_u64".to_string(),
            selector: Selector::ResponseAgeSeconds,
            predicate: Predicate::MinU64(threshold),
            required: true,
        };

        let input = EvalInput {
            profile_id: None,
            signature_present: None,
            digest_matches: None,
            response_age_seconds: None, // Missing
            entitlements: vec![],
            bridge_token_valid: None,
        };

        let report = evaluate_policy(vec![rule], input);
        prop_assert!(
            !report.allow,
            "MinU64 with Missing input should deny"
        );
    }

    /// Property: Exists predicate matches correctly
    ///
    /// For all selector types:
    /// - Present value (any type) → True
    /// - Missing value → False
    #[test]
    fn prop_exists_predicate_correct_for_string(
        value in proptest::option::of("[a-z]{5,15}"),
    ) {
        let rule = Rule {
            id: "test.exists".to_string(),
            selector: Selector::ProfileId,
            predicate: Predicate::Exists,
            required: true,
        };

        let input = EvalInput {
            profile_id: value.clone(),
            signature_present: None,
            digest_matches: None,
            response_age_seconds: None,
            entitlements: vec![],
            bridge_token_valid: None,
        };

        let report = evaluate_policy(vec![rule], input);
        let expected = value.is_some();

        prop_assert_eq!(
            report.allow,
            expected,
            "Exists with value {:?} should be {} but got {}",
            value,
            expected,
            report.allow
        );
    }

    /// Property: Exists predicate correct for bool (even false)
    #[test]
    fn prop_exists_predicate_correct_for_bool(
        value in proptest::option::of(any::<bool>()),
    ) {
        let rule = Rule {
            id: "test.exists".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::Exists,
            required: true,
        };

        let input = EvalInput {
            profile_id: None,
            signature_present: value,
            digest_matches: None,
            response_age_seconds: None,
            entitlements: vec![],
            bridge_token_valid: None,
        };

        let report = evaluate_policy(vec![rule], input);
        let expected = value.is_some();

        prop_assert_eq!(
            report.allow,
            expected,
            "Exists with bool {:?} should be {} but got {}",
            value,
            expected,
            report.allow
        );
    }

    /// Property: Exists predicate correct for u64
    #[test]
    fn prop_exists_predicate_correct_for_u64(
        value in proptest::option::of(any::<u64>()),
    ) {
        let rule = Rule {
            id: "test.exists".to_string(),
            selector: Selector::ResponseAgeSeconds,
            predicate: Predicate::Exists,
            required: true,
        };

        let input = EvalInput {
            profile_id: None,
            signature_present: None,
            digest_matches: None,
            response_age_seconds: value,
            entitlements: vec![],
            bridge_token_valid: None,
        };

        let report = evaluate_policy(vec![rule], input);
        let expected = value.is_some();

        prop_assert_eq!(
            report.allow,
            expected,
            "Exists with u64 {:?} should be {} but got {}",
            value,
            expected,
            report.allow
        );
    }

    /// Property: InSet predicate matches correctly
    ///
    /// For all set contents and input values:
    /// - value in set → True
    /// - value not in set → False
    /// - Missing value → False
    #[test]
    fn prop_in_set_predicate_correct(
        set in proptest::collection::vec("[a-z]{5,10}", 1..10),
        test_value in "[a-z]{5,10}",
    ) {
        let rule = Rule {
            id: "test.in_set".to_string(),
            selector: Selector::ProfileId,
            predicate: Predicate::InSet(set.clone()),
            required: true,
        };

        let input = EvalInput {
            profile_id: Some(test_value.clone()),
            signature_present: None,
            digest_matches: None,
            response_age_seconds: None,
            entitlements: vec![],
            bridge_token_valid: None,
        };

        let report = evaluate_policy(vec![rule], input);
        let expected = set.contains(&test_value);

        prop_assert_eq!(
            report.allow,
            expected,
            "InSet({:?}) with value {} should be {} but got {}",
            set,
            test_value,
            expected,
            report.allow
        );
    }

    /// Property: InSet with missing input denies
    #[test]
    fn prop_in_set_missing_denies(
        set in proptest::collection::vec("[a-z]{5,10}", 1..10),
    ) {
        let rule = Rule {
            id: "test.in_set".to_string(),
            selector: Selector::ProfileId,
            predicate: Predicate::InSet(set),
            required: true,
        };

        let input = EvalInput {
            profile_id: None, // Missing
            signature_present: None,
            digest_matches: None,
            response_age_seconds: None,
            entitlements: vec![],
            bridge_token_valid: None,
        };

        let report = evaluate_policy(vec![rule], input);
        prop_assert!(
            !report.allow,
            "InSet with Missing input should deny"
        );
    }

    /// Property: MaxU64 predicate still works correctly (regression test)
    #[test]
    fn prop_max_u64_predicate_correct(
        threshold in any::<u64>(),
        value in any::<u64>(),
    ) {
        let rule = Rule {
            id: "test.max_u64".to_string(),
            selector: Selector::ResponseAgeSeconds,
            predicate: Predicate::MaxU64(threshold),
            required: true,
        };

        let input = EvalInput {
            profile_id: None,
            signature_present: None,
            digest_matches: None,
            response_age_seconds: Some(value),
            entitlements: vec![],
            bridge_token_valid: None,
        };

        let report = evaluate_policy(vec![rule], input);
        let expected = value <= threshold;

        prop_assert_eq!(
            report.allow,
            expected,
            "MaxU64({}) with value {} should be {} but got {}",
            threshold,
            value,
            expected,
            report.allow
        );
    }

    /// Property: Selector deduplication is exact
    ///
    /// The number of unique selectors in the plan should exactly match
    /// the number of distinct selectors across all rules.
    #[test]
    fn prop_selector_deduplication_exact(
        rules in proptest::collection::vec(arb_rule(), 1..50),
    ) {
        let plan = compile_rules(rules.clone());

        // Count unique selectors manually
        let mut unique_selectors = std::collections::HashSet::new();
        for rule in &rules {
            unique_selectors.insert(rule.selector.clone());
        }

        prop_assert_eq!(
            plan.selectors.len(),
            unique_selectors.len(),
            "Plan has {} selectors but rules have {} unique selectors",
            plan.selectors.len(),
            unique_selectors.len()
        );
    }

    /// Property: Early exit when all required resolved
    ///
    /// If all required rules can be resolved by scanning the first N selectors,
    /// FSE should stop there and not scan remaining selectors.
    #[test]
    fn prop_early_exit_optimization(
        extra_optional_count in 1..20usize,
    ) {
        // Create one required rule using SignaturePresent
        let mut rules = vec![Rule {
            id: "required".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        }];

        // Add optional rules using different selectors
        for i in 0..extra_optional_count {
            rules.push(Rule {
                id: format!("optional_{}", i),
                selector: Selector::ResponseAgeSeconds,
                predicate: Predicate::MaxU64(100),
                required: false,
            });
        }

        let input = EvalInput {
            profile_id: None,
            signature_present: Some(true),
            digest_matches: None,
            response_age_seconds: Some(50),
            entitlements: vec![],
            bridge_token_valid: None,
        };

        let plan = compile_rules(rules);
        let result = execute(&plan, &input);

        // Should only scan SignaturePresent, not ResponseAgeSeconds
        // (early exit after required rule resolved)
        prop_assert_eq!(
            result.selectors_scanned,
            1,
            "Should early-exit after scanning 1 selector (required rule resolved), but scanned {}",
            result.selectors_scanned
        );
    }
}
