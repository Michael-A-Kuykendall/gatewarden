//! Verification pipeline composing all cryptographic checks.
//!
//! This module provides the unified verification flow:
//! 1. Check required headers are present (fail-closed)
//! 2. Verify digest (if present)
//! 3. Verify signature
//! 4. Check freshness (not replayed, not future-dated)

use crate::clock::Clock;
use crate::client::http::KeygenResponse;
use crate::crypto::{
    digest::verify_digest,
    freshness::check_date_freshness,
    signing::build_signing_string,
    verify::{decode_public_key, parse_signature_header, verify_ed25519},
};
use crate::GatewardenError;

/// Verify a Keygen response's authenticity and freshness.
///
/// This performs the complete verification pipeline:
/// 1. Ensure required headers (Keygen-Signature, Date) are present
/// 2. Verify digest header matches body (if present)
/// 3. Verify Ed25519 signature
/// 4. Check response is not stale (>5 min) or future-dated
///
/// # Arguments
/// * `response` - The HTTP response to verify
/// * `public_key_hex` - The Keygen account's Ed25519 public key (hex-encoded)
/// * `clock` - Clock for freshness checks
///
/// # Returns
/// * `Ok(())` - Response is verified
/// * `Err(SignatureMissing)` - Missing required headers (fail-closed)
/// * `Err(DigestMismatch)` - Digest header doesn't match body
/// * `Err(SignatureInvalid)` - Signature verification failed
/// * `Err(ResponseTooOld)` - Response is stale (possible replay)
/// * `Err(ResponseFromFuture)` - Response date is in the future
pub fn verify_response(
    response: &KeygenResponse,
    public_key_hex: &str,
    clock: &dyn Clock,
) -> Result<(), GatewardenError> {
    // 1. Fail-closed on missing required headers
    let signature_header = response
        .signature
        .as_ref()
        .ok_or(GatewardenError::SignatureMissing)?;

    let date_header = response
        .date
        .as_ref()
        .ok_or(GatewardenError::SignatureMissing)?;

    // 2. Verify digest if present
    verify_digest(&response.body, response.digest.as_deref())?;

    // 3. Parse signature header
    let parsed_sig = parse_signature_header(signature_header)?;

    // 4. Decode public key
    let verifying_key = decode_public_key(public_key_hex)?;

    // 5. Build signing string
    let signing_string = build_signing_string(
        "post",
        &response.request_path,
        &response.host,
        date_header,
        response.digest.as_deref(),
    );

    // 6. Verify Ed25519 signature
    verify_ed25519(&parsed_sig.signature, &signing_string, &verifying_key)?;

    // 7. Check freshness
    check_date_freshness(date_header, clock)?;

    Ok(())
}

/// Verify a Keygen response without freshness checks.
///
/// This is used for cached responses where we don't apply the 5-minute window.
/// The offline_grace is checked separately by the cache layer.
pub fn verify_response_signature_only(
    response: &KeygenResponse,
    public_key_hex: &str,
) -> Result<(), GatewardenError> {
    // Fail-closed on missing required headers
    let signature_header = response
        .signature
        .as_ref()
        .ok_or(GatewardenError::SignatureMissing)?;

    let date_header = response
        .date
        .as_ref()
        .ok_or(GatewardenError::SignatureMissing)?;

    // Verify digest if present
    verify_digest(&response.body, response.digest.as_deref())?;

    // Parse signature header
    let parsed_sig = parse_signature_header(signature_header)?;

    // Decode public key
    let verifying_key = decode_public_key(public_key_hex)?;

    // Build signing string
    let signing_string = build_signing_string(
        "post",
        &response.request_path,
        &response.host,
        date_header,
        response.digest.as_deref(),
    );

    // Verify Ed25519 signature
    verify_ed25519(&parsed_sig.signature, &signing_string, &verifying_key)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use crate::crypto::digest::format_digest_header;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::{Signer, SigningKey};

    // Test keypair (DO NOT USE IN PRODUCTION)
    const TEST_PRIVATE_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const TEST_PUBLIC_KEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn get_test_signing_key() -> SigningKey {
        let bytes = hex::decode(TEST_PRIVATE_KEY_HEX).unwrap();
        SigningKey::from_bytes(&bytes.try_into().unwrap())
    }

    fn sign_test_data(signing_string: &str) -> String {
        let signing_key = get_test_signing_key();
        let signature = signing_key.sign(signing_string.as_bytes());
        STANDARD.encode(signature.to_bytes())
    }

    fn create_test_response(
        body: &str,
        date: &str,
        host: &str,
        path: &str,
    ) -> KeygenResponse {
        let body_bytes = body.as_bytes().to_vec();
        let digest = format_digest_header(&body_bytes);
        let signing_string = build_signing_string("post", path, host, date, Some(&digest));
        let signature_b64 = sign_test_data(&signing_string);
        let signature_header = format!(r#"algorithm="ed25519", signature="{}""#, signature_b64);

        KeygenResponse {
            status: 200,
            date: Some(date.to_string()),
            signature: Some(signature_header),
            digest: Some(digest),
            body: body_bytes,
            request_path: path.to_string(),
            host: host.to_string(),
        }
    }

    #[test]
    fn test_verify_response_valid() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let response = create_test_response(
            r#"{"data":{"valid":true}}"#,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/actions/validate-key",
        );

        let result = verify_response(&response, TEST_PUBLIC_KEY_HEX, &clock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_response_missing_signature() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let mut response = create_test_response(
            r#"{"data":{"valid":true}}"#,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/actions/validate-key",
        );
        response.signature = None;

        let result = verify_response(&response, TEST_PUBLIC_KEY_HEX, &clock);
        assert!(matches!(result, Err(GatewardenError::SignatureMissing)));
    }

    #[test]
    fn test_verify_response_missing_date() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let mut response = create_test_response(
            r#"{"data":{"valid":true}}"#,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/actions/validate-key",
        );
        response.date = None;

        let result = verify_response(&response, TEST_PUBLIC_KEY_HEX, &clock);
        assert!(matches!(result, Err(GatewardenError::SignatureMissing)));
    }

    #[test]
    fn test_verify_response_digest_mismatch() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let mut response = create_test_response(
            r#"{"data":{"valid":true}}"#,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/actions/validate-key",
        );
        // Tamper with body
        response.body = b"tampered body".to_vec();

        let result = verify_response(&response, TEST_PUBLIC_KEY_HEX, &clock);
        assert!(matches!(result, Err(GatewardenError::DigestMismatch)));
    }

    #[test]
    fn test_verify_response_invalid_signature() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let mut response = create_test_response(
            r#"{"data":{"valid":true}}"#,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/actions/validate-key",
        );
        // Replace with a valid-format but wrong signature (64 bytes = 86 chars base64)
        let wrong_sig = STANDARD.encode([0u8; 64]);
        response.signature = Some(format!(r#"algorithm="ed25519", signature="{}""#, wrong_sig));

        let result = verify_response(&response, TEST_PUBLIC_KEY_HEX, &clock);
        assert!(matches!(result, Err(GatewardenError::SignatureInvalid)));
    }

    #[test]
    fn test_verify_response_stale() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 10, 0).unwrap()); // 10 minutes later
        let response = create_test_response(
            r#"{"data":{"valid":true}}"#,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/actions/validate-key",
        );

        let result = verify_response(&response, TEST_PUBLIC_KEY_HEX, &clock);
        assert!(matches!(result, Err(GatewardenError::ResponseTooOld { .. })));
    }

    #[test]
    fn test_verify_response_future() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 11, 58, 0).unwrap()); // 2 minutes before
        let response = create_test_response(
            r#"{"data":{"valid":true}}"#,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/actions/validate-key",
        );

        let result = verify_response(&response, TEST_PUBLIC_KEY_HEX, &clock);
        assert!(matches!(result, Err(GatewardenError::ResponseFromFuture)));
    }

    #[test]
    fn test_verify_response_signature_only_valid() {
        let response = create_test_response(
            r#"{"data":{"valid":true}}"#,
            "Wed, 15 Jan 2025 12:00:00 GMT",
            "api.keygen.sh",
            "/v1/accounts/test/licenses/actions/validate-key",
        );

        let result = verify_response_signature_only(&response, TEST_PUBLIC_KEY_HEX);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_response_no_digest() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let body = r#"{"data":{"valid":true}}"#;
        let date = "Wed, 15 Jan 2025 12:00:00 GMT";
        let host = "api.keygen.sh";
        let path = "/v1/accounts/test/licenses/actions/validate-key";

        // Sign without digest
        let signing_string = build_signing_string("post", path, host, date, None);
        let signature_b64 = sign_test_data(&signing_string);
        let signature_header = format!(r#"algorithm="ed25519", signature="{}""#, signature_b64);

        let response = KeygenResponse {
            status: 200,
            date: Some(date.to_string()),
            signature: Some(signature_header),
            digest: None,
            body: body.as_bytes().to_vec(),
            request_path: path.to_string(),
            host: host.to_string(),
        };

        let result = verify_response(&response, TEST_PUBLIC_KEY_HEX, &clock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_fails_closed_missing_both() {
        let clock = MockClock::new(Utc.with_ymd_and_hms(2025, 1, 15, 12, 0, 0).unwrap());
        let response = KeygenResponse {
            status: 200,
            date: None,
            signature: None,
            digest: None,
            body: b"{}".to_vec(),
            request_path: "/test".to_string(),
            host: "api.keygen.sh".to_string(),
        };

        let result = verify_response(&response, TEST_PUBLIC_KEY_HEX, &clock);
        assert!(matches!(result, Err(GatewardenError::SignatureMissing)));
    }
}
