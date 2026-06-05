//! Default FSE plan compilation for Gatewarden validation.
//!
//! This module provides `compile_default_plan()`, which builds a hardcoded
//! FSE plan covering:
//! - Signature verification (crypto.signature_verified)
//! - License state validity (response.state_valid)
//! - Required entitlements (entitlements.required_N)

use super::compiler::{compile_rules, CompiledPlan};
use super::model::{Predicate, Rule, Selector};
use crate::config::GatewardenConfig;
use crate::GatewardenError;

/// Compile the default FSE plan for Gatewarden license validation.
///
/// This creates a set of required rules that all licenses must pass:
/// 1. **crypto.signature_verified** — Ed25519 signature must be present and valid
/// 2. **response.state_valid** — Keygen's `meta.valid` must be true
/// 3. **entitlements.required_N** — Each required entitlement from config must be present
///
/// # Arguments
///
/// * `config` - The Gatewarden configuration containing required entitlements
///
/// # Returns
///
/// A compiled FSE plan ready for execution, or an error if compilation fails.
///
/// # Example
///
/// ```ignore
/// let config = GatewardenConfig { required_entitlements: vec!["PREMIUM".into()], ..Default::default() };
/// let plan = compile_default_plan(&config)?;
/// // plan now has 3 rules: signature_verified, state_valid, entitlements.required_0
/// ```
pub fn compile_default_plan(config: &GatewardenConfig) -> Result<CompiledPlan, GatewardenError> {
    let mut rules = vec![
        Rule {
            id: "crypto.signature_verified".to_string(),
            selector: Selector::SignaturePresent,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
        Rule {
            id: "response.state_valid".to_string(),
            selector: Selector::StateValid,
            predicate: Predicate::BoolIsTrue,
            required: true,
        },
    ];

    // Add entitlement rules from config
    for (i, ent) in config.required_entitlements.iter().enumerate() {
        rules.push(Rule {
            id: format!("entitlements.required_{}", i),
            selector: Selector::Entitlements,
            predicate: Predicate::ContainsString(ent.clone()),
            required: true,
        });
    }

    Ok(compile_rules(rules))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config() -> GatewardenConfig {
        GatewardenConfig {
            app_name: "test-app".to_string(),
            feature_name: "test".to_string(),
            account_id: "test-account".to_string(),
            public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                .to_string(),
            required_entitlements: vec![],
            user_agent_product: "test-product".to_string(),
            cache_namespace: "gatewarden-test".to_string(),
            offline_grace: Duration::from_secs(86400),
        }
    }

    #[test]
    fn test_compile_default_plan_no_entitlements() {
        let config = test_config();
        let plan = compile_default_plan(&config).unwrap();

        // Should have 2 base rules: signature_verified, state_valid
        assert_eq!(plan.rules.len(), 2);
        assert_eq!(plan.required_count, 2);

        // Check rule IDs
        assert_eq!(plan.rules[0].id, "crypto.signature_verified");
        assert_eq!(plan.rules[1].id, "response.state_valid");

        // Check all rules are required
        assert!(plan.rules.iter().all(|r| r.required));
    }

    #[test]
    fn test_compile_default_plan_with_entitlements() {
        let mut config = test_config();
        config.required_entitlements = vec![
            "PREMIUM".to_string(),
            "VISION_ANALYSIS".to_string(),
            "API_ACCESS".to_string(),
        ];

        let plan = compile_default_plan(&config).unwrap();

        // Should have 2 base rules + 3 entitlement rules = 5 total
        assert_eq!(plan.rules.len(), 5);
        assert_eq!(plan.required_count, 5);

        // Check base rules
        assert_eq!(plan.rules[0].id, "crypto.signature_verified");
        assert_eq!(plan.rules[1].id, "response.state_valid");

        // Check entitlement rules
        assert_eq!(plan.rules[2].id, "entitlements.required_0");
        assert_eq!(plan.rules[3].id, "entitlements.required_1");
        assert_eq!(plan.rules[4].id, "entitlements.required_2");

        // Verify predicates match config
        if let Predicate::ContainsString(ent) = &plan.rules[2].predicate {
            assert_eq!(ent, "PREMIUM");
        } else {
            panic!("Expected ContainsString predicate");
        }
    }

    #[test]
    fn test_compile_default_plan_selectors_deduplicated() {
        let mut config = test_config();
        config.required_entitlements = vec!["ENT1".to_string(), "ENT2".to_string()];

        let plan = compile_default_plan(&config).unwrap();

        // Should have 3 unique selectors despite 4 rules:
        // SignaturePresent, StateValid, Entitlements (used by 2 rules)
        assert_eq!(plan.selectors.len(), 3);

        // Verify selectors are correct
        assert!(plan.selectors.contains(&Selector::SignaturePresent));
        assert!(plan.selectors.contains(&Selector::StateValid));
        assert!(plan.selectors.contains(&Selector::Entitlements));
    }

    #[test]
    fn test_compile_default_plan_path_index() {
        let mut config = test_config();
        config.required_entitlements = vec!["ENT1".to_string(), "ENT2".to_string()];

        let plan = compile_default_plan(&config).unwrap();

        // SignaturePresent should map to rule 0
        assert_eq!(plan.path_index[&Selector::SignaturePresent], vec![0]);

        // StateValid should map to rule 1
        assert_eq!(plan.path_index[&Selector::StateValid], vec![1]);

        // Entitlements should map to rules 2 and 3 (both entitlement checks)
        assert_eq!(plan.path_index[&Selector::Entitlements], vec![2, 3]);
    }
}
