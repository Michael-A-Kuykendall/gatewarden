use super::compiler::{compile_rules, CompiledPlan};
use super::model::{EvalInput, Predicate, Rule, RuleDecision, Selector};
use super::runtime::{execute, RuntimeResult};

/// The result of evaluating an FSE policy against an input.
#[derive(Debug, Clone)]
pub struct EvaluationReport {
    /// Whether all required rules passed (access granted).
    pub allow: bool,
    /// Number of unique selectors scanned — the FSE proof metric.
    pub selectors_scanned: usize,
    /// Per-rule outcomes: (rule_id, decision).
    pub rule_outcomes: Vec<(String, RuleDecision)>,
}

/// Build the default security rule set for Gatewarden validation.
///
/// Covers: profile match, signature present, digest match, freshness (300s),
/// entitlement check, and bridge token validation. All rules are required.
pub fn default_security_rules(profile_id: &str, required_entitlement: &str) -> Vec<Rule> {
    vec![
        Rule {
            id: "response.profile_matches".to_string(),
            selector: Selector::ProfileId,
            predicate: Predicate::EqString(profile_id.to_string()),
            required: true,
        },
        Rule {
            id: "response.signature_present".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "response.digest_matches".to_string(),
            selector: Selector::DigestMatches,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "response.freshness_under_300s".to_string(),
            selector: Selector::ResponseAgeSeconds,
            predicate: Predicate::MaxU64(300),
            required: true,
        },
        Rule {
            id: "license.has_required_entitlement".to_string(),
            selector: Selector::Entitlements,
            predicate: Predicate::ContainsString(required_entitlement.to_string()),
            required: true,
        },
        Rule {
            id: "bridge.token_valid".to_string(),
            selector: Selector::BridgeTokenValid,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
    ]
}

/// Evaluate a set of rules against an input using the FSE engine.
///
/// Compiles the rules into a plan, executes in a single pass over unique
/// selectors, and returns the evaluation report.
pub fn evaluate_policy(rules: Vec<Rule>, input: EvalInput) -> EvaluationReport {
    let plan: CompiledPlan = compile_rules(rules);
    let runtime: RuntimeResult = execute(&plan, &input);

    EvaluationReport {
        allow: runtime.allow,
        selectors_scanned: runtime.selectors_scanned,
        rule_outcomes: runtime.outcomes.iter().map(|o| (o.rule_id.clone(), o.decision.clone())).collect(),
    }
}
