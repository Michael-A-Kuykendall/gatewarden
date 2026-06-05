// Compliance test suite for Fused Semantic Execution (FSE) core properties.
//
// These tests verify that the FSE implementation maintains its architectural
// invariants and fail-closed semantics using controlled mock inputs.

use gatewarden::policy::fse::compiler::compile_rules;
use gatewarden::policy::fse::model::{
    EvalInput, InputProvider, Predicate, Rule, RuleDecision, Selector, Value,
};
use gatewarden::policy::fse::runtime::{execute, RuntimeState};

// ────────────────────────────────────────────────────────────────────────────
// Mock Input Providers
// ────────────────────────────────────────────────────────────────────────────

/// Mock input that returns specific values for testing.
#[derive(Debug)]
struct MockInput {
    profile_id: Option<String>,
    signature_present: Option<bool>,
    state_valid: Option<bool>,
    entitlements: Vec<String>,
}

impl MockInput {
    fn new() -> Self {
        Self {
            profile_id: Some("test-profile".to_string()),
            signature_present: Some(true),
            state_valid: Some(true),
            entitlements: vec!["FEATURE_A".to_string(), "FEATURE_B".to_string()],
        }
    }

    fn missing_all() -> Self {
        Self {
            profile_id: None,
            signature_present: None,
            state_valid: None,
            entitlements: vec![],
        }
    }

    fn with_signature(mut self, present: bool) -> Self {
        self.signature_present = Some(present);
        self
    }

    fn with_state_valid(mut self, valid: bool) -> Self {
        self.state_valid = Some(valid);
        self
    }

    fn with_entitlements(mut self, ents: Vec<String>) -> Self {
        self.entitlements = ents;
        self
    }
}

impl InputProvider for MockInput {
    fn value_for(&self, selector: &Selector) -> Value {
        match selector {
            Selector::ProfileId => self
                .profile_id
                .as_ref()
                .map(|v| Value::String(v.clone()))
                .unwrap_or(Value::Missing),
            Selector::SignaturePresent => self
                .signature_present
                .map(Value::Bool)
                .unwrap_or(Value::Missing),
            Selector::StateValid => self.state_valid.map(Value::Bool).unwrap_or(Value::Missing),
            Selector::Entitlements => Value::Strings(self.entitlements.clone()),
            _ => Value::Missing,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// FSE Compliance Tests
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_single_pass_selector_scanning() {
    // FSE Property: N rules sharing M unique selectors → scan exactly M selectors.
    //
    // This is the core FSE invariant: evaluation time is O(unique_selectors),
    // not O(rules). Adding rules on existing selectors adds zero marginal cost.

    let rules = vec![
        Rule {
            id: "rule1".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "rule2".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::Exists,
            required: false,
        },
        Rule {
            id: "rule3".to_string(),
            selector: Selector::StateValid,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "rule4".to_string(),
            selector: Selector::StateValid,
            predicate: Predicate::Exists,
            required: false,
        },
    ];

    let plan = compile_rules(rules);
    let input = MockInput::new();
    let result = execute(&plan, &input);

    // 4 rules, 2 unique selectors → must scan exactly 2
    assert_eq!(
        result.selectors_scanned, 2,
        "FSE must scan each unique selector exactly once"
    );
    assert!(result.allow, "all required rules should pass");
}

#[test]
fn test_fail_closed_on_unresolved_required_rules() {
    // FSE Property: Unresolved required rules → deny (fail-closed).
    //
    // When a required rule's selector returns Missing, the rule must evaluate
    // to False, and the overall policy must deny access.

    let rules = vec![
        Rule {
            id: "crypto.signature_required".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "response.state_required".to_string(),
            selector: Selector::StateValid,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
    ];

    let plan = compile_rules(rules);

    // Input has signature but missing state_valid → one required rule unresolved
    let input_missing = MockInput {
        profile_id: None,
        signature_present: Some(true),
        state_valid: None, // ← Missing value for required rule
        entitlements: vec![],
    };

    let result = execute(&plan, &input_missing);

    assert!(
        !result.allow,
        "Missing required selector must result in deny"
    );

    // Find the unresolved required rule's outcome
    let state_outcome = result
        .outcomes
        .iter()
        .find(|o| o.rule_id == "response.state_required")
        .expect("state_required rule should be in outcomes");

    assert_eq!(
        state_outcome.decision,
        RuleDecision::False,
        "Unresolved required rule must be forced to False"
    );
}

#[test]
fn test_early_exit_when_all_required_resolved() {
    // FSE Property: Early exit when all required rules are resolved.
    //
    // Once all required rules have been evaluated (True or False), the runtime
    // can stop scanning selectors, even if optional rules remain.

    let rules = vec![
        Rule {
            id: "required1".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "required2".to_string(),
            selector: Selector::StateValid,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "optional1".to_string(),
            selector: Selector::ProfileId,
            predicate: Predicate::Exists,
            required: false,
        },
        Rule {
            id: "optional2".to_string(),
            selector: Selector::Entitlements,
            predicate: Predicate::ContainsString("FEATURE_X".to_string()),
            required: false,
        },
    ];

    let plan = compile_rules(rules);
    let input = MockInput::new();

    // Use incremental RuntimeState to observe early termination
    let mut state = RuntimeState::new(&plan);

    // Apply first selector (SignaturePresent)
    let value1 = input.value_for(&Selector::SignaturePresent);
    state.apply(&plan, &Selector::SignaturePresent, &value1);
    assert!(!state.should_terminate(), "1 of 2 required rules resolved");

    // Apply second selector (StateValid)
    let value2 = input.value_for(&Selector::StateValid);
    state.apply(&plan, &Selector::StateValid, &value2);
    assert!(
        state.should_terminate(),
        "All required rules resolved, should allow early exit"
    );

    let result = state.finalize(&plan);
    assert_eq!(
        result.selectors_scanned, 2,
        "Should stop after resolving all required rules"
    );
    assert!(result.allow, "All required rules passed");
}

#[test]
fn test_value_broadcast_single_extraction_multiple_rules() {
    // FSE Property: Value broadcast — one extraction serves N rules.
    //
    // When multiple rules reference the same selector, the value is extracted
    // once and broadcast to all dependent rules. This is the core efficiency
    // gain of the selector-first architecture.

    let rules = vec![
        Rule {
            id: "entitlement1".to_string(),
            selector: Selector::Entitlements,
            predicate: Predicate::ContainsString("FEATURE_A".to_string()),
            required: true,
        },
        Rule {
            id: "entitlement2".to_string(),
            selector: Selector::Entitlements,
            predicate: Predicate::ContainsString("FEATURE_B".to_string()),
            required: true,
        },
        Rule {
            id: "entitlement3".to_string(),
            selector: Selector::Entitlements,
            predicate: Predicate::ContainsString("FEATURE_C".to_string()),
            required: false,
        },
        Rule {
            id: "entitlement4".to_string(),
            selector: Selector::Entitlements,
            predicate: Predicate::Exists,
            required: false,
        },
    ];

    let plan = compile_rules(rules);
    let input = MockInput::new().with_entitlements(vec![
        "FEATURE_A".to_string(),
        "FEATURE_B".to_string(),
    ]);

    let result = execute(&plan, &input);

    // 4 rules, 1 unique selector → must scan exactly 1
    assert_eq!(
        result.selectors_scanned, 1,
        "Value must be extracted once and broadcast to all 4 rules"
    );

    // Verify all 4 rules were evaluated
    assert_eq!(
        result.outcomes.len(),
        4,
        "All rules should have outcomes despite single extraction"
    );

    // Required rules with FEATURE_A and FEATURE_B should pass
    let ent1 = result
        .outcomes
        .iter()
        .find(|o| o.rule_id == "entitlement1")
        .unwrap();
    let ent2 = result
        .outcomes
        .iter()
        .find(|o| o.rule_id == "entitlement2")
        .unwrap();

    assert_eq!(ent1.decision, RuleDecision::True);
    assert_eq!(ent2.decision, RuleDecision::True);
    assert!(result.allow);
}

#[test]
fn test_selector_deduplication_at_compile_time() {
    // FSE Property: Compile-time selector deduplication.
    //
    // The compiler must deduplicate selectors, ensuring the runtime only
    // iterates over unique selectors regardless of how many rules reference them.

    let rules = vec![
        Rule {
            id: "r1".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "r2".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::Exists,
            required: false,
        },
        Rule {
            id: "r3".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: false,
        },
        Rule {
            id: "r4".to_string(),
            selector: Selector::StateValid,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "r5".to_string(),
            selector: Selector::StateValid,
            predicate: Predicate::Exists,
            required: false,
        },
    ];

    let plan = compile_rules(rules);

    // 5 rules, 2 unique selectors
    assert_eq!(
        plan.selectors.len(),
        2,
        "Compiler must deduplicate selectors"
    );
    assert_eq!(plan.rules.len(), 5, "All rules must be preserved");

    // Verify path index structure
    let sig_rules = plan.path_index.get(&Selector::SignaturePresent).unwrap();
    let state_rules = plan.path_index.get(&Selector::StateValid).unwrap();

    assert_eq!(
        sig_rules.len(),
        3,
        "3 rules should reference SignaturePresent"
    );
    assert_eq!(state_rules.len(), 2, "2 rules should reference StateValid");

    // Execute and verify scan count
    let input = MockInput::new();
    let result = execute(&plan, &input);

    assert_eq!(
        result.selectors_scanned, 2,
        "Runtime must scan exactly 2 unique selectors"
    );
}

#[test]
fn test_fail_closed_all_required_false_denies_access() {
    // FSE Property: Fail-closed — if any required rule is False, deny access.
    //
    // Even if all selectors are scanned and resolved, if any required rule
    // evaluates to False, the overall policy must deny.

    let rules = vec![
        Rule {
            id: "crypto.signature".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "response.state".to_string(),
            selector: Selector::StateValid,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
    ];

    let plan = compile_rules(rules);

    // Input has signature=true but state_valid=false
    let input = MockInput::new()
        .with_signature(true)
        .with_state_valid(false);

    let result = execute(&plan, &input);

    assert!(
        !result.allow,
        "One required rule False must deny access"
    );

    // Verify which rule failed
    let state_outcome = result
        .outcomes
        .iter()
        .find(|o| o.rule_id == "response.state")
        .unwrap();

    assert_eq!(
        state_outcome.decision,
        RuleDecision::False,
        "state rule should be False"
    );
}

#[test]
fn test_optional_rules_do_not_affect_allow_decision() {
    // FSE Property: Optional rules don't affect the allow decision.
    //
    // Only required rules determine the final allow/deny outcome.
    // Optional rules are evaluated for observability but don't block access.
    //
    // Note: With early exit optimization, optional rules may remain Unresolved
    // if all required rules are satisfied first. This is correct behavior.

    let rules = vec![
        Rule {
            id: "required1".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "required2".to_string(),
            selector: Selector::StateValid,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "optional1".to_string(),
            selector: Selector::ProfileId,
            predicate: Predicate::EqString("wrong-profile".to_string()),
            required: false,
        },
    ];

    let plan = compile_rules(rules);
    let input = MockInput::new();
    let result = execute(&plan, &input);

    // Required rules pass → access allowed despite optional rule mismatch
    assert!(
        result.allow,
        "Optional rule failures/unresolved must not deny access"
    );

    // Verify all required rules passed
    let req1 = result
        .outcomes
        .iter()
        .find(|o| o.rule_id == "required1")
        .unwrap();
    let req2 = result
        .outcomes
        .iter()
        .find(|o| o.rule_id == "required2")
        .unwrap();

    assert_eq!(req1.decision, RuleDecision::True);
    assert_eq!(req2.decision, RuleDecision::True);

    // Optional rule may be Unresolved due to early exit (correct behavior)
    let opt1 = result
        .outcomes
        .iter()
        .find(|o| o.rule_id == "optional1")
        .unwrap();
    
    assert!(
        matches!(opt1.decision, RuleDecision::Unresolved | RuleDecision::False),
        "Optional rule can be Unresolved (early exit) or False, but doesn't block access"
    );
}

#[test]
fn test_zero_rules_allows_access() {
    // FSE Property: Empty rule set allows access (no requirements to fail).
    //
    // This is the neutral element of the fail-closed semantics: no rules
    // means no constraints, so access is allowed.

    let rules = vec![];
    let plan = compile_rules(rules);
    let input = MockInput::new();
    let result = execute(&plan, &input);

    assert!(result.allow, "Empty rule set must allow access");
    assert_eq!(result.selectors_scanned, 0);
    assert_eq!(result.outcomes.len(), 0);
}

#[test]
fn test_new_predicates_min_u64_compliance() {
    // Test new predicate: MinU64
    // Value must be >= limit to pass

    let rules = vec![Rule {
        id: "min_check".to_string(),
        selector: Selector::ResponseAgeSeconds,
        predicate: Predicate::MinU64(100),
        required: true,
    }];

    let plan = compile_rules(rules);

    // Create custom input with response_age_seconds
    let input_pass = EvalInput {
        profile_id: None,
        signature_present: None,
        digest_matches: None,
        response_age_seconds: Some(150),
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let input_fail = EvalInput {
        profile_id: None,
        signature_present: None,
        digest_matches: None,
        response_age_seconds: Some(50),
        entitlements: vec![],
        bridge_token_valid: None,
    };

    let result_pass = execute(&plan, &input_pass);
    let result_fail = execute(&plan, &input_fail);

    assert!(result_pass.allow, "MinU64: 150 >= 100 should pass");
    assert!(!result_fail.allow, "MinU64: 50 >= 100 should fail");
}

#[test]
fn test_new_predicates_exists_compliance() {
    // Test new predicate: Exists
    // Any non-Missing value should pass

    let rules = vec![Rule {
        id: "exists_check".to_string(),
        selector: Selector::ProfileId,
        predicate: Predicate::Exists,
        required: true,
    }];

    let plan = compile_rules(rules);

    let input_present = MockInput::new();
    let input_missing = MockInput::missing_all();

    let result_present = execute(&plan, &input_present);
    let result_missing = execute(&plan, &input_missing);

    assert!(
        result_present.allow,
        "Exists: present value should pass"
    );
    assert!(
        !result_missing.allow,
        "Exists: Missing value should fail"
    );
}

#[test]
fn test_new_predicates_in_set_compliance() {
    // Test new predicate: InSet
    // String must be in the provided set

    let rules = vec![Rule {
        id: "in_set_check".to_string(),
        selector: Selector::ProfileId,
        predicate: Predicate::InSet(vec![
            "profile-a".to_string(),
            "profile-b".to_string(),
            "profile-c".to_string(),
        ]),
        required: true,
    }];

    let plan = compile_rules(rules);

    let input_in_set = MockInput {
        profile_id: Some("profile-b".to_string()),
        signature_present: None,
        state_valid: None,
        entitlements: vec![],
    };

    let input_not_in_set = MockInput {
        profile_id: Some("profile-x".to_string()),
        signature_present: None,
        state_valid: None,
        entitlements: vec![],
    };

    let result_in = execute(&plan, &input_in_set);
    let result_not_in = execute(&plan, &input_not_in_set);

    assert!(result_in.allow, "InSet: value in set should pass");
    assert!(
        !result_not_in.allow,
        "InSet: value not in set should fail"
    );
}
