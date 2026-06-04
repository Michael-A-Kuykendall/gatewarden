use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Selector {
    ProfileId,
    SignaturePresent,
    DigestMatches,
    ResponseAgeSeconds,
    Entitlements,
    BridgeTokenValid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Predicate {
    EqString(String),
    BoolIsTrue,
    MaxU64(u64),
    ContainsString(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub selector: Selector,
    pub predicate: Predicate,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    String(String),
    Bool(bool),
    U64(u64),
    Strings(Vec<String>),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDecision {
    Unresolved,
    True,
    False,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalInput {
    pub profile_id: Option<String>,
    pub signature_present: Option<bool>,
    pub digest_matches: Option<bool>,
    pub response_age_seconds: Option<u64>,
    pub entitlements: Vec<String>,
    pub bridge_token_valid: Option<bool>,
}

impl EvalInput {
    pub fn value_for(&self, selector: &Selector) -> Value {
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
            Selector::DigestMatches => self
                .digest_matches
                .map(Value::Bool)
                .unwrap_or(Value::Missing),
            Selector::ResponseAgeSeconds => self
                .response_age_seconds
                .map(Value::U64)
                .unwrap_or(Value::Missing),
            Selector::Entitlements => Value::Strings(self.entitlements.clone()),
            Selector::BridgeTokenValid => self
                .bridge_token_valid
                .map(Value::Bool)
                .unwrap_or(Value::Missing),
        }
    }
}
