use crate::compiler::CompiledPlan;
use crate::model::{EvalInput, Predicate, RuleDecision, Value};

#[derive(Debug, Clone)]
pub struct RuntimeResult {
    pub decisions: Vec<RuleDecision>,
    pub selectors_scanned: usize,
    pub allow: bool,
}

pub fn execute(plan: &CompiledPlan, input: &EvalInput) -> RuntimeResult {
    let mut decisions = vec![RuleDecision::Unresolved; plan.rules.len()];
    let mut pending_required = plan.required_count;
    let mut scanned = 0usize;

    for selector in &plan.selectors {
        if pending_required == 0 {
            break;
        }
        scanned += 1;
        let value = input.value_for(selector);

        if let Some(rule_indexes) = plan.path_index.get(selector) {
            for &rule_idx in rule_indexes {
                if decisions[rule_idx] != RuleDecision::Unresolved {
                    continue;
                }
                let rule = &plan.rules[rule_idx];
                let ok = predicate_matches(&value, &rule.predicate);
                decisions[rule_idx] = if ok {
                    RuleDecision::True
                } else {
                    RuleDecision::False
                };
                if rule.required {
                    pending_required = pending_required.saturating_sub(1);
                }
            }
        }
    }

    // Fail closed: any unresolved required rule is forced false.
    for (idx, rule) in plan.rules.iter().enumerate() {
        if rule.required && decisions[idx] == RuleDecision::Unresolved {
            decisions[idx] = RuleDecision::False;
        }
    }

    let allow = plan
        .rules
        .iter()
        .enumerate()
        .filter(|(_, r)| r.required)
        .all(|(i, _)| decisions[i] == RuleDecision::True);

    RuntimeResult {
        decisions,
        selectors_scanned: scanned,
        allow,
    }
}

fn predicate_matches(value: &Value, predicate: &Predicate) -> bool {
    match (value, predicate) {
        (Value::String(v), Predicate::EqString(expected)) => v == expected,
        (Value::Bool(v), Predicate::BoolIsTrue) => *v,
        (Value::U64(v), Predicate::MaxU64(limit)) => v <= limit,
        (Value::Strings(values), Predicate::ContainsString(required)) => {
            values.iter().any(|v| v == required)
        }
        _ => false,
    }
}
