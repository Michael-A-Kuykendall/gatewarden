//! SHA-256 digest computation.

use crate::GatewardenError;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

/// Compute SHA-256 digest of body and return base64-encoded result.
///
/// This matches Keygen's digest format: `sha-256=<base64>`.
pub fn sha256_b64(body: &[u8]) -> String {
    let hash = Sha256::digest(body);
    STANDARD.encode(hash)
}

/// Format digest for HTTP Digest header.
pub fn format_digest_header(body: &[u8]) -> String {
    format!("sha-256={}", sha256_b64(body))
}

/// Parse a Digest header and extract the base64 value.
///
/// Expected format: `sha-256=<base64>`
pub fn parse_digest_header(header: &str) -> Option<String> {
    let header = header.trim();
    header
        .strip_prefix("sha-256=")
        .or_else(|| header.strip_prefix("SHA-256="))
        .map(|s| s.to_string())
}

/// Compare computed digest to Digest header.
///
/// # Arguments
/// * `body` - The response body
/// * `digest_header` - The Digest header value (if present)
///
/// # Returns
/// * `Ok(())` - If digest matches or header is absent
/// * `Err(DigestMismatch)` - If header is present and doesn't match
pub fn verify_digest(body: &[u8], digest_header: Option<&str>) -> Result<(), GatewardenError> {
    let Some(header) = digest_header else {
        // No digest header - proceed (documented behavior)
        return Ok(());
    };

    let Some(expected_b64) = parse_digest_header(header) else {
        // Malformed digest header - treat as mismatch
        return Err(GatewardenError::DigestMismatch);
    };

    let computed_b64 = sha256_b64(body);

    if computed_b64 != expected_b64 {
        return Err(GatewardenError::DigestMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty_body() {
        // SHA-256 of empty string
        let digest = sha256_b64(b"");
        assert_eq!(digest, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    }

    #[test]
    fn test_sha256_hello_world() {
        let digest = sha256_b64(b"Hello, World!");
        assert_eq!(digest, "3/1gIbsr1bCvZ2KQgJ7DpTGR3YHH9wpLKGiKNiGCmG8=");
    }

    #[test]
    fn test_format_digest_header() {
        let header = format_digest_header(b"test body");
        assert!(header.starts_with("sha-256="));
    }

    #[test]
    fn test_parse_digest_header_valid() {
        let result = parse_digest_header("sha-256=abc123=");
        assert_eq!(result, Some("abc123=".to_string()));
    }

    #[test]
    fn test_parse_digest_header_uppercase() {
        let result = parse_digest_header("SHA-256=abc123=");
        assert_eq!(result, Some("abc123=".to_string()));
    }

    #[test]
    fn test_parse_digest_header_invalid() {
        let result = parse_digest_header("md5=abc");
        assert_eq!(result, None);
    }

    #[test]
    fn test_verify_digest_match() {
        let body = b"test body";
        let header = format_digest_header(body);
        let result = verify_digest(body, Some(&header));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_digest_mismatch() {
        let body = b"test body";
        let wrong_header = "sha-256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let result = verify_digest(body, Some(wrong_header));
        assert!(matches!(result, Err(GatewardenError::DigestMismatch)));
    }

    #[test]
    fn test_verify_digest_absent() {
        let body = b"test body";
        let result = verify_digest(body, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_digest_malformed_header() {
        let body = b"test body";
        let result = verify_digest(body, Some("not-a-valid-digest"));
        assert!(matches!(result, Err(GatewardenError::DigestMismatch)));
    }
}
