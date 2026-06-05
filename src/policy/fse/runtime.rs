use super::compiler::CompiledPlan;
use super::model::{InputProvider, Predicate, RuleDecision, Selector, Value};

/// A single rule's evaluation outcome.
#[derive(Debug, Clone)]
pub struct RuleOutcome {
    /// The rule's unique identifier.
    pub rule_id: String,
    /// The evaluation decision for this rule.
    pub decision: RuleDecision,
}

/// Result of executing a compiled plan against an input.
#[derive(Debug, Clone)]
pub struct RuntimeResult {
    /// Per-rule outcomes with rule IDs and decisions.
    pub outcomes: Vec<RuleOutcome>,
    /// Number of unique selectors scanned (the FSE proof metric).
    pub selectors_scanned: usize,
    /// Whether all required rules evaluated to True.
    pub allow: bool,
}

/// Incremental evaluation state for event-driven FSE execution.
///
/// This struct enables selector-by-selector evaluation, supporting streaming
/// input sources (e.g., JSON tokenizer) and early termination as soon as all
/// required rules are resolved.
///
/// # Example
///
/// ```ignore
/// let plan = compile_rules(rules);
/// let mut state = RuntimeState::new(&plan);
///
/// for selector in &plan.selectors {
///     if state.should_terminate() {
///         break;
///     }
///     let value = input.value_for(selector);
///     state.apply(&plan, selector, &value);
/// }
///
/// let result = state.finalize(&plan);
/// ```
#[derive(Debug, Clone)]
pub struct RuntimeState {
    /// Per-rule decision states (parallel to plan.rules).
    decisions: Vec<RuleDecision>,
    /// Count of required rules still unresolved.
    pending_required: usize,
    /// Number of selectors scanned so far (the FSE proof metric).
    selectors_scanned: usize,
}

impl RuntimeState {
    /// Create a new runtime state for the given compiled plan.
    ///
    /// All rules start in the `Unresolved` state, and the pending required
    /// counter is initialized to the plan's required rule count.
    pub fn new(plan: &CompiledPlan) -> Self {
        Self {
            decisions: vec![RuleDecision::Unresolved; plan.rules.len()],
            pending_required: plan.required_count,
            selectors_scanned: 0,
        }
    }

    /// Apply a selector value, resolving all rules dependent on it.
    ///
    /// This method:
    /// 1. Increments the selector scan counter
    /// 2. Looks up all rules that reference this selector
    /// 3. Evaluates each unresolved rule's predicate against the value
    /// 4. Updates rule decisions and decrements the pending required counter
    ///
    /// This is the core FSE operation: one value extraction is broadcast to
    /// all rules sharing that selector.
    pub fn apply(&mut self, plan: &CompiledPlan, selector: &Selector, value: &Value) {
        self.selectors_scanned += 1;

        if let Some(rule_indexes) = plan.path_index.get(selector) {
            for &rule_idx in rule_indexes {
                if self.decisions[rule_idx] != RuleDecision::Unresolved {
                    continue;
                }
                let rule = &plan.rules[rule_idx];
                let ok = predicate_matches(value, &rule.predicate);
                self.decisions[rule_idx] = if ok {
                    RuleDecision::True
                } else {
                    RuleDecision::False
                };
                if rule.required {
                    self.pending_required = self.pending_required.saturating_sub(1);
                }
            }
        }
    }

    /// Check if evaluation can terminate early.
    ///
    /// Returns `true` when all required rules have been resolved (either True
    /// or False), allowing the caller to stop scanning selectors.
    ///
    /// This is a key FSE optimization: once all required rules are decided,
    /// optional rules don't need to be evaluated.
    pub fn should_terminate(&self) -> bool {
        self.pending_required == 0
    }

    /// Finalize evaluation with fail-closed semantics and return the result.
    ///
    /// Any required rule still in the `Unresolved` state is forced to `False`.
    /// The final `allow` decision is `true` only if all required rules are `True`.
    ///
    /// This method consumes the state.
    pub fn finalize(mut self, plan: &CompiledPlan) -> RuntimeResult {
        // Fail closed: any unresolved required rule is forced false.
        for (idx, rule) in plan.rules.iter().enumerate() {
            if rule.required && self.decisions[idx] == RuleDecision::Unresolved {
                self.decisions[idx] = RuleDecision::False;
            }
        }

        let allow = plan
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.required)
            .all(|(i, _)| self.decisions[i] == RuleDecision::True);

        let outcomes = plan
            .rules
            .iter()
            .enumerate()
            .map(|(idx, rule)| RuleOutcome {
                rule_id: rule.id.clone(),
                decision: self.decisions[idx].clone(),
            })
            .collect();

        RuntimeResult {
            outcomes,
            selectors_scanned: self.selectors_scanned,
            allow,
        }
    }
}

/// Execute a compiled FSE plan against an input in a single pass.
///
/// This is a convenience wrapper around `RuntimeState` for batch evaluation.
/// For streaming or incremental evaluation, use `RuntimeState` directly.
///
/// For each unique selector in the plan:
/// 1. Extract the value once from the input
/// 2. Broadcast to all rules sharing that selector
/// 3. Resolve each rule's state
/// 4. Early-exit when all required rules are resolved
///
/// After the loop, any still-unresolved required rules are forced to False
/// (fail-closed semantics).
pub fn execute<I: InputProvider>(plan: &CompiledPlan, input: &I) -> RuntimeResult {
    let mut state = RuntimeState::new(plan);

    for selector in &plan.selectors {
        if state.should_terminate() {
            break;
        }
        let value = input.value_for(selector);
        state.apply(plan, selector, &value);
    }

    state.finalize(plan)
}

fn predicate_matches(value: &Value, predicate: &Predicate) -> bool {
    match (value, predicate) {
        (Value::String(v), Predicate::EqString(expected)) => v == expected,
        (Value::Bool(v), Predicate::BoolIsTrue) => *v,
        (Value::U64(v), Predicate::MaxU64(limit)) => v <= limit,
        (Value::Strings(values), Predicate::ContainsString(required)) => {
            values.iter().any(|v| v == required)
        }
        (Value::U64(v), Predicate::MinU64(limit)) => v >= limit,
        (Value::Missing, Predicate::Exists) => false,
        (_, Predicate::Exists) => true,
        (Value::String(v), Predicate::InSet(set)) => set.contains(v),
        _ => false,
    }
}
