use crate::compiler::{compile_rules, CompiledPlan};
use crate::model::{EvalInput, Predicate, Rule, RuleDecision, Selector};
use crate::runtime::{execute, RuntimeResult};

#[derive(Debug, Clone)]
pub struct EvaluationReport {
    pub allow: bool,
    pub selectors_scanned: usize,
    pub rule_outcomes: Vec<(String, RuleDecision)>,
}

pub fn default_security_rules(profile_id: &str, required_entitlement: &str) -> Vec<Rule> {
    vec![
        Rule {
            id: "profile_matches".to_string(),
            selector: Selector::ProfileId,
            predicate: Predicate::EqString(profile_id.to_string()),
            required: true,
        },
        Rule {
            id: "signature_present".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "digest_matches".to_string(),
            selector: Selector::DigestMatches,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "freshness_under_300s".to_string(),
            selector: Selector::ResponseAgeSeconds,
            predicate: Predicate::MaxU64(300),
            required: true,
        },
        Rule {
            id: "has_required_entitlement".to_string(),
            selector: Selector::Entitlements,
            predicate: Predicate::ContainsString(required_entitlement.to_string()),
            required: true,
        },
        Rule {
            id: "bridge_token_valid".to_string(),
            selector: Selector::BridgeTokenValid,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
    ]
}

pub fn evaluate_policy(rules: Vec<Rule>, input: EvalInput) -> EvaluationReport {
    let plan: CompiledPlan = compile_rules(rules);
    let runtime: RuntimeResult = execute(&plan, &input);

    let rule_outcomes = plan
        .rules
        .iter()
        .enumerate()
        .map(|(idx, rule)| (rule.id.clone(), runtime.decisions[idx].clone()))
        .collect();

    EvaluationReport {
        allow: runtime.allow,
        selectors_scanned: runtime.selectors_scanned,
        rule_outcomes,
    }
}
