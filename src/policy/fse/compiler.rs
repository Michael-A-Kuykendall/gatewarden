use super::model::{Rule, Selector};
use std::collections::HashMap;

/// Pre-compiled execution plan with deduplicated selectors and path index.
#[derive(Debug, Clone)]
pub struct CompiledPlan {
    /// All rules in insertion order.
    pub rules: Vec<Rule>,
    /// Unique selectors in insertion order (deduplicated).
    pub selectors: Vec<Selector>,
    /// Maps each selector to the indices of rules that reference it.
    pub path_index: HashMap<Selector, Vec<usize>>,
    /// Count of rules marked `required: true`.
    pub required_count: usize,
}

/// Compile a set of rules into a fused execution plan.
///
/// This deduplicates selectors so that evaluation iterates over unique selectors
/// (not rules), achieving the O(unique_selectors) invariant.
pub fn compile_rules(rules: Vec<Rule>) -> CompiledPlan {
    let mut selectors: Vec<Selector> = Vec::new();
    let mut path_index: HashMap<Selector, Vec<usize>> = HashMap::new();
    let mut required_count = 0usize;

    for (i, rule) in rules.iter().enumerate() {
        if rule.required {
            required_count += 1;
        }
        if !selectors.contains(&rule.selector) {
            selectors.push(rule.selector.clone());
        }
        path_index.entry(rule.selector.clone()).or_default().push(i);
    }

    CompiledPlan {
        rules,
        selectors,
        path_index,
        required_count,
    }
}
