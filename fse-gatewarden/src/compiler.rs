use crate::model::{Rule, Selector};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CompiledPlan {
    pub rules: Vec<Rule>,
    pub selectors: Vec<Selector>,
    pub path_index: HashMap<Selector, Vec<usize>>,
    pub required_count: usize,
}

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
