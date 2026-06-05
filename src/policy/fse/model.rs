use serde::{Deserialize, Serialize};

/// Identifies which field of [`EvalInput`] a rule evaluates.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Selector {
    /// The profile ID string.
    ProfileId,
    /// Whether an Ed25519 signature is present on the response.
    SignaturePresent,
    /// Whether the SHA-256 digest matches the response body.
    DigestMatches,
    /// Age of the response in seconds (freshness check).
    ResponseAgeSeconds,
    /// Entitlement codes present on the license.
    Entitlements,
    /// Whether the bridge bearer token was validated.
    BridgeTokenValid,
}

/// The check applied to a resolved selector value.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Predicate {
    /// String equality check.
    EqString(String),
    /// Boolean must be true.
    BoolIsTrue,
    /// Numeric value must be <= limit.
    MaxU64(u64),
    /// String collection must contain the given value.
    ContainsString(String),
    /// Numeric value must be >= limit.
    MinU64(u64),
    /// Value must exist (not Missing).
    Exists,
    /// String must be in the provided set.
    InSet(Vec<String>),
}

/// A single rule binding a selector to a predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Unique identifier for this rule.
    pub id: String,
    /// Which input field to evaluate.
    pub selector: Selector,
    /// The predicate to apply to the extracted value.
    pub predicate: Predicate,
    /// Whether this rule must pass for the overall evaluation to allow.
    pub required: bool,
}

/// A resolved value extracted from the input for a given selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    /// A string value.
    String(String),
    /// A boolean value.
    Bool(bool),
    /// An unsigned 64-bit integer value.
    U64(u64),
    /// A collection of strings.
    Strings(Vec<String>),
    /// The selector's field is absent from the input.
    Missing,
}

/// The resolution state of a single rule after evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDecision {
    /// Not yet evaluated.
    Unresolved,
    /// Predicate matched.
    True,
    /// Predicate did not match or input was missing.
    False,
}

/// The data element provider — supplies values for each selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalInput {
    /// Profile identifier to match against.
    pub profile_id: Option<String>,
    /// Whether the response carried a valid signature.
    pub signature_present: Option<bool>,
    /// Whether the digest header matched the body.
    pub digest_matches: Option<bool>,
    /// Age of the response in seconds.
    pub response_age_seconds: Option<u64>,
    /// Entitlement codes on the license.
    pub entitlements: Vec<String>,
    /// Whether the bridge bearer token was validated.
    pub bridge_token_valid: Option<bool>,
}

impl EvalInput {
    /// Extract the value for a given selector from this input.
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
