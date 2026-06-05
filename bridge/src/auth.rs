//! Bearer-token middleware and per-IP rate limiter for the bridge.
//!
//! When `bearer_token` is set in bridge.toml every request to `/v1/*` must
//! carry `X-Bridge-Token: <token>` with the exact configured value.
//! A constant-time comparison prevents timing side-channels.

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::routes::ErrorEnvelope;

// ─── Bearer token check ───────────────────────────────────────────────────────

/// Axum middleware layer: reject requests missing or with wrong X-Bridge-Token.
/// `expected` is `None` when no token is configured (middleware is a no-op).
pub async fn require_bearer_token(
    headers: HeaderMap,
    expected: Option<String>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorEnvelope>)> {
    let Some(expected_val) = expected else {
        // No token configured — pass through.
        return Ok(next.run(req).await);
    };

    let provided = headers
        .get("x-bridge-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !constant_time_eq(provided.as_bytes(), expected_val.as_bytes()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorEnvelope {
                error: "Missing or invalid X-Bridge-Token header".to_string(),
                code: "UNAUTHORIZED".to_string(),
            }),
        ));
    }

    Ok(next.run(req).await)
}

/// Constant-time byte-slice comparison — prevents timing oracle on the token.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ─── Token-bucket rate limiter ────────────────────────────────────────────────

/// Per-IP token bucket entry.
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Shared in-process rate limiter keyed by client IP.
pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    /// Maximum requests per second per IP.
    rps: f64,
    /// Maximum burst = rps * BURST_MULTIPLIER.
    capacity: f64,
}

const BURST_MULTIPLIER: f64 = 3.0;

impl RateLimiter {
    pub fn new(rps: u32) -> Self {
        let rps_f = rps as f64;
        Self {
            buckets: Mutex::new(HashMap::new()),
            rps: rps_f,
            capacity: rps_f * BURST_MULTIPLIER,
        }
    }

    /// Returns true if the request is within the rate limit, consuming one token.
    pub fn check_and_consume(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate limiter lock poisoned");
        let bucket = buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.capacity,
            last_refill: now,
        });

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Prune entries that haven't been seen in over 60 seconds (background hygiene).
    pub fn prune(&self) {
        let threshold = Duration::from_secs(60);
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate limiter lock poisoned");
        buckets.retain(|_, b| now.duration_since(b.last_refill) < threshold);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn constant_time_eq_correct() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer_string"));
    }

    #[test]
    fn rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(10);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        // First 30 requests (burst capacity = 10 * 3.0) should all pass.
        for _ in 0..30 {
            assert!(limiter.check_and_consume(ip));
        }
    }

    #[test]
    fn rate_limiter_rejects_over_burst() {
        let limiter = RateLimiter::new(10); // burst = 30
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..30 {
            assert!(limiter.check_and_consume(ip));
        }
        // 31st should be rejected.
        assert!(!limiter.check_and_consume(ip));
    }

    #[test]
    fn rate_limiter_prune_clears_stale() {
        let limiter = RateLimiter::new(5);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let _ = limiter.check_and_consume(ip);
        assert_eq!(limiter.buckets.lock().unwrap().len(), 1);
        // Manually age the entry past the 60s prune threshold.
        {
            let mut b = limiter.buckets.lock().unwrap();
            b.get_mut(&ip).unwrap().last_refill = Instant::now() - Duration::from_secs(61);
        }
        limiter.prune();
        assert_eq!(limiter.buckets.lock().unwrap().len(), 0);
    }
}
