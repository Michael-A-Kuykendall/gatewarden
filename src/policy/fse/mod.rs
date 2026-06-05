//! Fused Semantic Execution (FSE) Policy Engine.
//!
//! This software implements Fused Semantic Execution (FSE), a selector-first,
//! single-pass rule evaluation architecture. FSE is the subject of a pending
//! patent by Michael A. Kuykendall. All rights reserved.
//!
//! # Architecture
//!
//! FSE inverts the conventional rule-first evaluation model. Instead of iterating
//! rules and extracting values for each, FSE:
//!
//! 1. **Compiles** rules into a `CompiledPlan` with deduplicated selectors
//! 2. **Executes** by iterating unique selectors once, broadcasting each value
//!    to all rules that reference it
//! 3. **Finalizes** by forcing unresolved required rules to False (fail-closed)
//!
//! The core invariant: `∂runtime / ∂rules ≈ 0` for shared selectors.

/// Rule compilation and selector deduplication.
pub mod compiler;
/// Default FSE plan compilation for Gatewarden.
pub mod defaults;
/// Policy evaluation engine and default rule sets.
pub mod engine;
/// Gatewarden-specific FSE input provider.
pub mod gatewarden_input;
/// Core data types: selectors, predicates, rules, values, and input.
pub mod model;
/// Single-pass execution runtime with early-exit and fail-closed semantics.
pub mod runtime;

pub use compiler::CompiledPlan;
pub use defaults::compile_default_plan;
pub use engine::{evaluate_policy, EvaluationReport};
pub use gatewarden_input::GatewardenEvalInput;
pub use model::{EvalInput, InputProvider, Predicate, Rule, RuleDecision, Selector, Value};
pub use runtime::RuleOutcome;
pub use runtime::RuntimeState;
