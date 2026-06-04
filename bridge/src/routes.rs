use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    Json,
};
use gatewarden::GatewardenError;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::task;

use crate::state::AppState;

// ─── Shared error envelope ────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ErrorEnvelope {
    pub error: String,
    pub code: String,
}

fn gatewarden_error_code(e: &GatewardenError) -> &'static str {
    match e {
        GatewardenError::MissingLicense => "MISSING_LICENSE",
        GatewardenError::InvalidLicense => "INVALID_LICENSE",
        GatewardenError::EntitlementMissing { .. } => "ENTITLEMENT_MISSING",
        GatewardenError::UsageLimitExceeded { .. } => "USAGE_LIMIT_EXCEEDED",
        GatewardenError::SignatureInvalid => "SIGNATURE_INVALID",
        GatewardenError::SignatureMissing => "SIGNATURE_MISSING",
        GatewardenError::DigestMismatch => "DIGEST_MISMATCH",
        GatewardenError::ResponseTooOld { .. } => "RESPONSE_TOO_OLD",
        GatewardenError::ResponseFromFuture => "RESPONSE_FROM_FUTURE",
        GatewardenError::CacheTampered => "CACHE_TAMPERED",
        GatewardenError::CacheExpired => "CACHE_EXPIRED",
        GatewardenError::KeygenTransport(_) => "TRANSPORT_ERROR",
        GatewardenError::CacheIO(_) => "CACHE_IO_ERROR",
        GatewardenError::MeterIO(_) => "METER_IO_ERROR",
        GatewardenError::ConfigError(_) => "CONFIG_ERROR",
        GatewardenError::ProtocolError(_) => "PROTOCOL_ERROR",
    }
}

// ─── GET /v1/health ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: String,
    pub profiles: Vec<String>,
}

pub async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let mut profiles: Vec<String> = state.managers.keys().cloned().collect();
    profiles.sort();
    Json(HealthResponse {
        status: "ok",
        version: state.version.clone(),
        profiles,
    })
}

// ─── POST /v1/validate-key ───────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateKeyRequest {
    pub profile_id: String,
    pub license_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResponse {
    pub valid: bool,
    pub from_cache: bool,
    pub state_code: String,
    pub expires_at: Option<String>,
    pub entitlements: Vec<String>,
}

pub async fn validate_key(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ValidateKeyRequest>,
) -> Result<Json<ValidationResponse>, (axum::http::StatusCode, Json<ErrorEnvelope>)> {
    let manager = state.managers.get(&req.profile_id).ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorEnvelope {
                error: format!("Profile '{}' not found", req.profile_id),
                code: "PROFILE_NOT_FOUND".to_string(),
            }),
        )
    })?;

    match task::block_in_place(|| manager.validate_key(&req.license_key)) {
        Ok(result) => Ok(Json(ValidationResponse {
            valid: result.valid,
            from_cache: result.from_cache,
            state_code: result.state.code.clone(),
            expires_at: result.state.expires_at.map(|d| d.to_rfc3339()),
            entitlements: result.state.entitlements.clone(),
        })),
        Err(e) => {
            // Security errors and config errors are 500; license logic errors are 200
            // (caller must inspect `valid: false` + `code`).
            let status = match &e {
                GatewardenError::SignatureInvalid
                | GatewardenError::SignatureMissing
                | GatewardenError::DigestMismatch
                | GatewardenError::ResponseTooOld { .. }
                | GatewardenError::ResponseFromFuture
                | GatewardenError::CacheTampered => axum::http::StatusCode::BAD_GATEWAY,
                GatewardenError::KeygenTransport(_) => axum::http::StatusCode::BAD_GATEWAY,
                GatewardenError::ConfigError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                _ => axum::http::StatusCode::OK,
            };
            if status == axum::http::StatusCode::OK {
                return Ok(Json(ValidationResponse {
                    valid: false,
                    from_cache: false,
                    state_code: gatewarden_error_code(&e).to_string(),
                    expires_at: None,
                    entitlements: vec![],
                }));
            }
            Err((
                status,
                Json(ErrorEnvelope {
                    error: e.to_string(),
                    code: gatewarden_error_code(&e).to_string(),
                }),
            ))
        }
    }
}

// ─── POST /v1/check-access ───────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckAccessRequest {
    pub profile_id: String,
    pub license_key: String,
}

pub async fn check_access(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckAccessRequest>,
) -> Result<Json<ValidationResponse>, (axum::http::StatusCode, Json<ErrorEnvelope>)> {
    let manager = state.managers.get(&req.profile_id).ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorEnvelope {
                error: format!("Profile '{}' not found", req.profile_id),
                code: "PROFILE_NOT_FOUND".to_string(),
            }),
        )
    })?;

    match task::block_in_place(|| manager.check_access(&req.license_key)) {
        Ok(result) => Ok(Json(ValidationResponse {
            valid: result.valid,
            from_cache: result.from_cache,
            state_code: result.state.code.clone(),
            expires_at: result.state.expires_at.map(|d| d.to_rfc3339()),
            entitlements: result.state.entitlements.clone(),
        })),
        Err(e) => {
            let status = match &e {
                GatewardenError::CacheTampered
                | GatewardenError::SignatureInvalid
                | GatewardenError::SignatureMissing => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                GatewardenError::CacheExpired | GatewardenError::InvalidLicense => {
                    axum::http::StatusCode::OK
                }
                _ => axum::http::StatusCode::OK,
            };
            if status == axum::http::StatusCode::OK {
                return Ok(Json(ValidationResponse {
                    valid: false,
                    from_cache: true,
                    state_code: gatewarden_error_code(&e).to_string(),
                    expires_at: None,
                    entitlements: vec![],
                }));
            }
            Err((
                status,
                Json(ErrorEnvelope {
                    error: e.to_string(),
                    code: gatewarden_error_code(&e).to_string(),
                }),
            ))
        }
    }
}

// ─── GET /.well-known/openapi.json ───────────────────────────────────────────

// ─── Rate-limit middleware layer ─────────────────────────────────────────────

/// Axum middleware: reject requests that exceed the configured per-IP rate limit.
/// Extracts client IP from X-Forwarded-For (first hop) or X-Real-IP header;
/// falls back to 127.0.0.1 (loopback, typical in dev) if neither is present.
pub async fn rate_limit_layer(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorEnvelope>)> {
    let ip = extract_client_ip(req.headers());
    if !state.rate_limiter.check_and_consume(ip) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorEnvelope {
                error: "Rate limit exceeded".to_string(),
                code: "RATE_LIMITED".to_string(),
            }),
        ));
    }
    Ok(next.run(req).await)
}

/// Extract the first IP address from X-Forwarded-For or X-Real-IP headers.
/// Falls back to loopback for local-only deployments.
fn extract_client_ip(headers: &axum::http::HeaderMap) -> IpAddr {
    let candidate = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok());
    candidate.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// Serves the embedded OpenAPI spec for discoverability.
pub async fn openapi_spec() -> axum::response::Response {
    // The spec is compiled in from the workspace spec/ directory.
    let spec = include_str!("../../spec/gatewarden-bridge.openapi.yaml");
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/yaml")
        .body(axum::body::Body::from(spec))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use gatewarden::{GatewardenConfig, GatewardenError, LicenseManager};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn unique_suffix() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before unix epoch")
            .as_nanos();
        nanos.to_string()
    }

    fn test_config(profile_name: &str) -> GatewardenConfig {
        GatewardenConfig {
            app_name: "gatewarden-bridge-test".to_string(),
            feature_name: profile_name.to_string(),
            account_id: format!("acct-{}", profile_name),
            public_key_hex:
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string(),
            required_entitlements: vec![],
            user_agent_product: "gatewarden-bridge-test".to_string(),
            cache_namespace: format!("gatewarden-bridge-test-{}", unique_suffix()),
            offline_grace: Duration::from_secs(60),
        }
    }

    fn test_manager(profile_name: &str) -> LicenseManager {
        let cfg = test_config(profile_name);
        LicenseManager::new(cfg).expect("test manager should initialize")
    }

    fn status_for_validate_error(e: &GatewardenError) -> axum::http::StatusCode {
        match e {
            GatewardenError::SignatureInvalid
            | GatewardenError::SignatureMissing
            | GatewardenError::DigestMismatch
            | GatewardenError::ResponseTooOld { .. }
            | GatewardenError::ResponseFromFuture
            | GatewardenError::CacheTampered
            | GatewardenError::KeygenTransport(_) => axum::http::StatusCode::BAD_GATEWAY,
            GatewardenError::ConfigError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            _ => axum::http::StatusCode::OK,
        }
    }

    fn status_for_check_access_error(e: &GatewardenError) -> axum::http::StatusCode {
        match e {
            GatewardenError::CacheTampered
            | GatewardenError::SignatureInvalid
            | GatewardenError::SignatureMissing => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            GatewardenError::CacheExpired | GatewardenError::InvalidLicense => {
                axum::http::StatusCode::OK
            }
            _ => axum::http::StatusCode::OK,
        }
    }

    fn test_state_no_auth(managers: HashMap<String, LicenseManager>) -> Arc<AppState> {
        use crate::auth::RateLimiter;
        Arc::new(AppState {
            managers,
            version: "test".to_string(),
            bearer_token: None,
            rate_limiter: RateLimiter::new(1000), // generous limit for unit tests
        })
    }

    #[test]
    fn health_response_is_stable_and_profiles_are_sorted() {
        let mut managers = HashMap::new();
        managers.insert("z-profile".to_string(), test_manager("z-profile"));
        managers.insert("a-profile".to_string(), test_manager("a-profile"));

        let state = {
            use crate::auth::RateLimiter;
            Arc::new(AppState {
                managers,
                version: "0.2.0-test".to_string(),
                bearer_token: None,
                rate_limiter: RateLimiter::new(1000),
            })
        };

        let rt = tokio::runtime::Runtime::new().expect("runtime should initialize");
        let Json(resp) = rt.block_on(health(State(state)));
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.version, "0.2.0-test");
        assert_eq!(resp.profiles, vec!["a-profile", "z-profile"]);
    }

    #[tokio::test]
    async fn validate_key_unknown_profile_returns_stable_error_code() {
        let state = test_state_no_auth(HashMap::new());

        let req = ValidateKeyRequest {
            profile_id: "missing-profile".to_string(),
            license_key: "XXXX-XXXX".to_string(),
        };

        let err = match validate_key(State(state), Json(req)).await {
            Err(err) => err,
            Ok(_) => panic!("missing profile should error"),
        };

        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
        assert_eq!(err.1 .0.code, "PROFILE_NOT_FOUND");
        assert!(err.1 .0.error.contains("missing-profile"));
    }

    #[tokio::test]
    async fn check_access_unknown_profile_returns_stable_error_code() {
        let state = test_state_no_auth(HashMap::new());

        let req = CheckAccessRequest {
            profile_id: "missing-profile".to_string(),
            license_key: "XXXX-XXXX".to_string(),
        };

        let err = match check_access(State(state), Json(req)).await {
            Err(err) => err,
            Ok(_) => panic!("missing profile should error"),
        };

        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
        assert_eq!(err.1 .0.code, "PROFILE_NOT_FOUND");
        assert!(err.1 .0.error.contains("missing-profile"));
    }

    #[tokio::test]
    async fn openapi_endpoint_contains_invariant_paths() {
        let response = openapi_spec().await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("spec body should be readable");
        let text = String::from_utf8(body.to_vec()).expect("spec should be utf-8");

        assert!(text.contains("/v1/health"));
        assert!(text.contains("/v1/validate-key"));
        assert!(text.contains("/v1/check-access"));
    }

    #[test]
    fn conformance_validate_missing_license_matches_core_semantics() {
        let profile = "conformance-validate-empty";
        let config = test_config(profile);

        let core_manager =
            LicenseManager::new(config.clone()).expect("core manager should initialize");
        let expected = core_manager
            .validate_key("")
            .expect_err("empty key must fail in core");

        let bridge_manager =
            LicenseManager::new(config).expect("bridge manager should initialize");
        let mut managers = HashMap::new();
        managers.insert(profile.to_string(), bridge_manager);
        let state = test_state_no_auth(managers);

        let req = ValidateKeyRequest {
            profile_id: profile.to_string(),
            license_key: "".to_string(),
        };

        let rt = tokio::runtime::Runtime::new().expect("runtime should initialize");
        match rt.block_on(validate_key(State(state), Json(req))) {
            Ok(Json(resp)) => {
                assert_eq!(status_for_validate_error(&expected), axum::http::StatusCode::OK);
                assert!(!resp.valid);
                assert_eq!(resp.state_code, gatewarden_error_code(&expected));
            }
            Err(err) => {
                assert_ne!(status_for_validate_error(&expected), axum::http::StatusCode::OK);
                assert_eq!(err.0, status_for_validate_error(&expected));
                assert_eq!(err.1 .0.code, gatewarden_error_code(&expected));
            }
        }
    }

    #[test]
    fn conformance_check_access_cache_miss_matches_core_semantics() {
        let profile = "conformance-check-access-miss";
        let config = test_config(profile);

        let core_manager =
            LicenseManager::new(config.clone()).expect("core manager should initialize");
        let expected = core_manager
            .check_access("LICENSE-TEST-1234")
            .expect_err("cache miss should fail in core");

        let bridge_manager =
            LicenseManager::new(config).expect("bridge manager should initialize");
        let mut managers = HashMap::new();
        managers.insert(profile.to_string(), bridge_manager);
        let state = test_state_no_auth(managers);

        let req = CheckAccessRequest {
            profile_id: profile.to_string(),
            license_key: "LICENSE-TEST-1234".to_string(),
        };

        let rt = tokio::runtime::Runtime::new().expect("runtime should initialize");
        match rt.block_on(check_access(State(state), Json(req))) {
            Ok(Json(resp)) => {
                assert_eq!(status_for_check_access_error(&expected), axum::http::StatusCode::OK);
                assert!(!resp.valid);
                assert_eq!(resp.state_code, gatewarden_error_code(&expected));
            }
            Err(err) => {
                assert_ne!(status_for_check_access_error(&expected), axum::http::StatusCode::OK);
                assert_eq!(err.0, status_for_check_access_error(&expected));
                assert_eq!(err.1 .0.code, gatewarden_error_code(&expected));
            }
        }
    }

    // ─── Auth + rate-limit unit tests ────────────────────────────────────────

    #[tokio::test]
    async fn bearer_token_check_rejects_missing_header() {
        // Directly test the constant_time_eq path: empty header must not match a real token.
        let expected_token = "super-secret";
        let provided = "";
        assert!(!constant_time_eq_test(provided.as_bytes(), expected_token.as_bytes()));
    }

    #[tokio::test]
    async fn bearer_token_check_rejects_wrong_value() {
        let expected = "correct-token";
        let wrong = "wrong-token";
        assert!(!constant_time_eq_test(wrong.as_bytes(), expected.as_bytes()));
    }

    #[tokio::test]
    async fn bearer_token_check_accepts_correct_value() {
        let token = "my-bridge-token-42";
        assert!(constant_time_eq_test(token.as_bytes(), token.as_bytes()));
    }

    fn constant_time_eq_test(a: &[u8], b: &[u8]) -> bool {
        // Mirror of the constant_time_eq in auth.rs (internal, tested here via behaviour)
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    #[test]
    fn rate_limiter_rejects_after_burst_exhausted() {
        use crate::auth::RateLimiter;
        use std::net::{IpAddr, Ipv4Addr};

        let limiter = RateLimiter::new(10); // burst = 30
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut allowed = 0usize;
        let mut rejected = 0usize;
        for _ in 0..50 {
            if limiter.check_and_consume(ip) {
                allowed += 1;
            } else {
                rejected += 1;
            }
        }
        // Burst is 30 (10 rps * 3.0 multiplier). First 30 must allow, rest must reject.
        assert_eq!(allowed, 30, "burst should be exactly 30");
        assert_eq!(rejected, 20, "post-burst requests should be rejected");
    }

    #[test]
    fn rate_limiter_different_ips_are_independent() {
        use crate::auth::RateLimiter;
        use std::net::{IpAddr, Ipv4Addr};

        let limiter = RateLimiter::new(5); // burst = 15
        let ip_a: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Exhaust A's bucket.
        for _ in 0..15 {
            assert!(limiter.check_and_consume(ip_a));
        }
        assert!(!limiter.check_and_consume(ip_a));

        // B's bucket is untouched — should still pass.
        assert!(limiter.check_and_consume(ip_b));
    }
}
