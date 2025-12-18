//! Authenticated cache record format.
//!
//! The cache record stores all data needed to re-verify a Keygen response:
//! - Original response body
//! - HTTP headers needed for signature verification (Date, Keygen-Signature, Digest)
//! - Timestamp when the record was cached
//!
//! On load, we:
//! 1. Re-verify the signature (required)
//! 2. Compare digest if present
//! 3. Check `now - cached_at <= offline_grace`

use crate::clock::Clock;
use crate::crypto::{
    digest::verify_digest,
    signing::build_signing_string,
    verify::{decode_public_key, parse_signature_header, verify_ed25519},
};
use crate::GatewardenError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Authenticated cache record containing all data needed to re-verify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRecord {
    /// The original HTTP Date header value.
    pub date: String,

    /// The original Keygen-Signature header value.
    pub signature: String,

    /// The original Digest header value (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// The original response body (JSON).
    pub body: String,

    /// When this record was cached (ISO 8601).
    pub cached_at: DateTime<Utc>,

    /// Request path used for signing string reconstruction.
    /// E.g., "/v1/accounts/{account}/licenses/{id}/actions/validate"
    pub request_path: String,

    /// Host used for signing string reconstruction.
    pub host: String,
}

impl CacheRecord {
    /// Create a new cache record from response data.
    pub fn new(
        date: String,
        signature: String,
        digest: Option<String>,
        body: String,
        request_path: String,
        host: String,
        clock: &dyn Clock,
    ) -> Self {
        Self {
            date,
            signature,
            digest,
            body,
            cached_at: clock.now_utc(),
            request_path,
            host,
        }
    }

    /// Serialize the cache record to JSON.
    pub fn to_json(&self) -> Result<String, GatewardenError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| GatewardenError::CacheIO(format!("Failed to serialize cache: {}", e)))
    }

    /// Deserialize a cache record from JSON.
    pub fn from_json(json: &str) -> Result<Self, GatewardenError> {
        serde_json::from_str(json)
            .map_err(|e| GatewardenError::CacheIO(format!("Failed to deserialize cache: {}", e)))
    }

    /// Verify the cached record is authentic and within offline grace.
    ///
    /// This performs:
    /// 1. Signature verification (required)
    /// 2. Digest comparison (if present)
    /// 3. Offline grace check
    ///
    /// Note: We do NOT apply the 5-minute replay window to cached records.
    /// The `offline_grace` parameter controls how long cached data is valid.
    pub fn verify(
        &self,
        public_key_hex: &str,
        offline_grace: Duration,
        clock: &dyn Clock,
    ) -> Result<(), GatewardenError> {
        // 1. Parse signature header
        let parsed_sig = parse_signature_header(&self.signature)?;

        // 2. Decode public key
        let verifying_key = decode_public_key(public_key_hex)?;

        // 3. Reconstruct signing string
        // For POST validate requests, Keygen signs: (request-target), host, date, digest
        let signing_string = build_signing_string(
            "post",
            &self.request_path,
            &self.host,
            &self.date,
            self.digest.as_deref(),
        );

        // 4. Verify Ed25519 signature
        verify_ed25519(&parsed_sig.signature, &signing_string, &verifying_key)
            .map_err(|_| GatewardenError::CacheTampered)?;

        // 5. Verify digest if present
        if let Some(ref digest_header) = self.digest {
            verify_digest(self.body.as_bytes(), Some(digest_header))
                .map_err(|_| GatewardenError::CacheTampered)?;
        }

        // 6. Check offline grace period
        let now = clock.now_utc();
        let age = now.signed_duration_since(self.cached_at);
        let grace_secs = offline_grace.as_secs() as i64;

        if age.num_seconds() > grace_secs {
            return Err(GatewardenError::CacheExpired);
        }

        // Also reject if cached_at is in the future (clock tampering)
        if age.num_seconds() < 0 {
            return Err(GatewardenError::CacheTampered);
        }

        Ok(())
    }

    /// Extract the cached response body.
    pub fn body(&self) -> &str {
        &self.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use crate::crypto::digest::format_digest_header;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};

    // Test signing seed + verifying key (DO NOT USE IN PRODUCTION)
    // This is a well-known Ed25519 test vector seed.
    const TEST_SIGNING_SEED_BYTES: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const TEST_VERIFY_KEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn get_test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SIGNING_SEED_BYTES)
    }

    fn sign_test_data(signing_string: &str) -> String {
        let signing_key = get_test_signing_key();
        let signature = signing_key.sign(signing_string.as_bytes());
        STANDARD.encode(signature.to_bytes())
    }

    fn create_test_record(
        body: &str,
        date: &str,
        host: &str,
        path: &str,
        clock: &MockClock,
    ) -> CacheRecord {
        let digest = format_digest_header(body.as_bytes());
        let signing_string = build_signing_string("post", path, host, date, Some(&digest));
        let signature_b64 = sign_test_data(&signing_string);
        let signature_header = format!(r#"algorithm="ed25519", signature="{}""#, signature_b64);

        CacheRecord::new(
            date.to_string(),
            signature_header,
            Some(digest),
            body.to_string(),
            path.to_string(),
            host.to_string(),
            clock,
        )
    }

    #[test]
    fn test_cache_record_roundtrip() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let body = r#"{"data":{"type":"licenses","attributes":{"valid":true}}}"#;
        let record = create_test_record(
            body,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/abc/actions/validate",
            &clock,
        );

        let json = record.to_json().unwrap();
        let restored = CacheRecord::from_json(&json).unwrap();

        assert_eq!(restored.body, body);
        assert_eq!(restored.date, record.date);
        assert_eq!(restored.signature, record.signature);
        assert_eq!(restored.digest, record.digest);
    }

    #[test]
    fn test_cache_record_verify_valid() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let body = r#"{"data":{"type":"licenses","attributes":{"valid":true}}}"#;
        let record = create_test_record(
            body,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/abc/actions/validate",
            &clock,
        );

        // Verify immediately - should pass
        let result = record.verify(
            TEST_VERIFY_KEY_HEX,
            Duration::from_secs(86400), // 24 hours grace
            &clock,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_cache_record_verify_within_grace() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let body = r#"{"data":{"type":"licenses","attributes":{"valid":true}}}"#;
        let record = create_test_record(
            body,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/abc/actions/validate",
            &clock,
        );

        // Advance 23 hours (within 24-hour grace)
        let later_clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 16, 11, 0, 0).unwrap());
        let result = record.verify(
            TEST_VERIFY_KEY_HEX,
            Duration::from_secs(86400), // 24 hours grace
            &later_clock,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_cache_record_verify_expired() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let body = r#"{"data":{"type":"licenses","attributes":{"valid":true}}}"#;
        let record = create_test_record(
            body,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/abc/actions/validate",
            &clock,
        );

        // Advance 25 hours (beyond 24-hour grace)
        let later_clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 16, 13, 0, 0).unwrap());
        let result = record.verify(
            TEST_VERIFY_KEY_HEX,
            Duration::from_secs(86400), // 24 hours grace
            &later_clock,
        );
        assert!(matches!(result, Err(GatewardenError::CacheExpired)));
    }

    #[test]
    fn test_cache_record_tampered_body() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let body = r#"{"data":{"type":"licenses","attributes":{"valid":true}}}"#;
        let mut record = create_test_record(
            body,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/abc/actions/validate",
            &clock,
        );

        // Tamper with body
        record.body = r#"{"data":{"type":"licenses","attributes":{"valid":false}}}"#.to_string();

        let result = record.verify(TEST_VERIFY_KEY_HEX, Duration::from_secs(86400), &clock);
        assert!(matches!(result, Err(GatewardenError::CacheTampered)));
    }

    #[test]
    fn test_cache_record_tampered_date() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let body = r#"{"data":{"type":"licenses","attributes":{"valid":true}}}"#;
        let mut record = create_test_record(
            body,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/abc/actions/validate",
            &clock,
        );

        // Tamper with date
        record.date = "Thu, 16 Jan 2025 12:00:00 GMT".to_string();

        let result = record.verify(TEST_VERIFY_KEY_HEX, Duration::from_secs(86400), &clock);
        assert!(matches!(result, Err(GatewardenError::CacheTampered)));
    }

    #[test]
    fn test_cache_record_tampered_signature() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let body = r#"{"data":{"type":"licenses","attributes":{"valid":true}}}"#;
        let mut record = create_test_record(
            body,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/abc/actions/validate",
            &clock,
        );

        // Tamper with signature by using a completely different base64 value
        record.signature = r#"algorithm="ed25519", signature="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==""#.to_string();

        let result = record.verify(TEST_VERIFY_KEY_HEX, Duration::from_secs(86400), &clock);
        assert!(matches!(result, Err(GatewardenError::CacheTampered)));
    }

    #[test]
    fn test_cache_record_future_cached_at() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let body = r#"{"data":{"type":"licenses","attributes":{"valid":true}}}"#;
        let record = create_test_record(
            body,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/abc/actions/validate",
            &clock,
        );

        // Verify with a clock that's BEFORE the cached_at time
        let past_clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 11, 0, 0).unwrap());
        let result = record.verify(TEST_VERIFY_KEY_HEX, Duration::from_secs(86400), &past_clock);
        assert!(matches!(result, Err(GatewardenError::CacheTampered)));
    }

    #[test]
    fn test_cache_record_no_digest() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let body = r#"{"data":{"type":"licenses","attributes":{"valid":true}}}"#;
        let date = "Wed, 15 Jan 2025 12:00:00 GMT";
        let host = "api.keygen.sh";
        let path = "/v1/accounts/test/licenses/abc/actions/validate";

        // Sign without digest
        let signing_string = build_signing_string("post", path, host, date, None);
        let signature_b64 = sign_test_data(&signing_string);
        let signature_header = format!(r#"algorithm="ed25519", signature="{}""#, signature_b64);

        let record = CacheRecord::new(
            date.to_string(),
            signature_header,
            None, // No digest
            body.to_string(),
            path.to_string(),
            host.to_string(),
            &clock,
        );

        let result = record.verify(TEST_VERIFY_KEY_HEX, Duration::from_secs(86400), &clock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cache_record_grace_boundary() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let body = r#"{"data":{"type":"licenses","attributes":{"valid":true}}}"#;
        let record = create_test_record(
            body,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/abc/actions/validate",
            &clock,
        );

        // Exactly at grace boundary (should pass)
        let boundary_clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 16, 12, 0, 0).unwrap());
        let result = record.verify(
            TEST_VERIFY_KEY_HEX,
            Duration::from_secs(86400), // 24 hours
            &boundary_clock,
        );
        assert!(result.is_ok());

        // One second over (should fail)
        let over_clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 16, 12, 0, 1).unwrap());
        let result = record.verify(TEST_VERIFY_KEY_HEX, Duration::from_secs(86400), &over_clock);
        assert!(matches!(result, Err(GatewardenError::CacheExpired)));
    }
}
