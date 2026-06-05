use gatewarden::policy::access::check_access_with_usage;
use gatewarden::policy::fse::engine::default_security_rules;
use gatewarden::LicenseState;
use gatewarden::{evaluate_policy, FseEvalInput as EvalInput};

#[derive(Clone)]
struct Scenario {
    name: &'static str,
    profile_id: Option<&'static str>,
    signature_present: Option<bool>,
    digest_matches: Option<bool>,
    response_age_seconds: Option<u64>,
    entitlements: Vec<&'static str>,
    bridge_token_valid: Option<bool>,
    valid: bool,
    max_uses: Option<u64>,
    current_uses: Option<u64>,
}

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "happy_path",
            profile_id: Some("chat-chronicle-pro"),
            signature_present: Some(true),
            digest_matches: Some(true),
            response_age_seconds: Some(15),
            entitlements: vec!["CHAT_CHRONICLE_PRO"],
            bridge_token_valid: Some(true),
            valid: true,
            max_uses: Some(100),
            current_uses: Some(2),
        },
        Scenario {
            name: "missing_entitlement",
            profile_id: Some("chat-chronicle-pro"),
            signature_present: Some(true),
            digest_matches: Some(true),
            response_age_seconds: Some(10),
            entitlements: vec![],
            bridge_token_valid: Some(true),
            valid: true,
            max_uses: Some(100),
            current_uses: Some(2),
        },
        Scenario {
            name: "invalid_license",
            profile_id: Some("chat-chronicle-pro"),
            signature_present: Some(true),
            digest_matches: Some(true),
            response_age_seconds: Some(10),
            entitlements: vec!["CHAT_CHRONICLE_PRO"],
            bridge_token_valid: Some(true),
            valid: false,
            max_uses: Some(100),
            current_uses: Some(2),
        },
        Scenario {
            name: "stale_response",
            profile_id: Some("chat-chronicle-pro"),
            signature_present: Some(true),
            digest_matches: Some(true),
            response_age_seconds: Some(999),
            entitlements: vec!["CHAT_CHRONICLE_PRO"],
            bridge_token_valid: Some(true),
            valid: true,
            max_uses: Some(100),
            current_uses: Some(2),
        },
        Scenario {
            name: "bridge_token_spoof",
            profile_id: Some("chat-chronicle-pro"),
            signature_present: Some(true),
            digest_matches: Some(true),
            response_age_seconds: Some(10),
            entitlements: vec!["CHAT_CHRONICLE_PRO"],
            bridge_token_valid: Some(false),
            valid: true,
            max_uses: Some(100),
            current_uses: Some(2),
        },
    ]
}

fn legacy_allow(s: &Scenario) -> bool {
    let state = LicenseState {
        valid: s.valid,
        entitlements: s.entitlements.iter().map(|e| e.to_string()).collect(),
        expires_at: None,
        max_uses: s.max_uses,
        current_uses: s.current_uses,
        code: if s.valid {
            "VALID".into()
        } else {
            "INVALID".into()
        },
        detail: None,
    };

    check_access_with_usage(&state, &["CHAT_CHRONICLE_PRO"], 0).is_ok()
}

fn fse_allow(s: &Scenario) -> bool {
    let rules = default_security_rules("chat-chronicle-pro", "CHAT_CHRONICLE_PRO");
    let input = EvalInput {
        profile_id: s.profile_id.map(|v| v.to_string()),
        signature_present: s.signature_present,
        digest_matches: s.digest_matches,
        response_age_seconds: s.response_age_seconds,
        entitlements: s.entitlements.iter().map(|e| e.to_string()).collect(),
        bridge_token_valid: s.bridge_token_valid,
    };
    evaluate_policy(rules, input).allow && s.valid
}

#[test]
fn head_to_head_semantics() {
    for s in scenarios() {
        let legacy = legacy_allow(&s);
        let fse = fse_allow(&s);

        match s.name {
            "happy_path" => {
                assert!(legacy, "legacy should allow happy path");
                assert!(fse, "fse should allow happy path");
            }
            "missing_entitlement" | "invalid_license" => {
                assert!(!legacy, "legacy should deny {}", s.name);
                assert!(!fse, "fse should deny {}", s.name);
            }
            "stale_response" | "bridge_token_spoof" => {
                assert!(legacy, "legacy baseline allows {}", s.name);
                assert!(!fse, "fse should deny {}", s.name);
            }
            _ => unreachable!(),
        }
    }
}
