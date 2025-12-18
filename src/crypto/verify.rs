//! Ed25519 signature verification.

use crate::GatewardenError;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::sync::RwLock;

/// Parsed signature header components.
#[derive(Debug, Clone)]
pub struct ParsedSignatureHeader {
    /// Key ID from the signature header (if present).
    pub key_id: Option<String>,
    /// Signature algorithm (should be "ed25519").
    pub algorithm: String,
    /// Base64-encoded signature.
    pub signature: String,
    /// Headers included in the signing string.
    pub headers: Vec<String>,
}

/// Parse a Keygen-Signature header.
///
/// Format: `keyid="...", algorithm="ed25519", signature="<base64>", headers="..."`
pub fn parse_signature_header(header: &str) -> Result<ParsedSignatureHeader, GatewardenError> {
    let mut parts: HashMap<String, String> = HashMap::new();

    // Parse key="value" pairs
    for part in header.split(',') {
        let part = part.trim();
        if let Some(eq_pos) = part.find('=') {
            let key = part[..eq_pos].trim().to_lowercase();
            let value = part[eq_pos + 1..].trim();
            // Strip quotes if present
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            parts.insert(key, value.to_string());
        }
    }

    let algorithm = parts
        .get("algorithm")
        .ok_or_else(|| {
            GatewardenError::ProtocolError("Missing algorithm in signature header".to_string())
        })?
        .clone();

    if algorithm != "ed25519" {
        return Err(GatewardenError::ProtocolError(format!(
            "Unsupported signature algorithm: {} (expected ed25519)",
            algorithm
        )));
    }

    let signature = parts
        .get("signature")
        .ok_or_else(|| {
            GatewardenError::ProtocolError("Missing signature in signature header".to_string())
        })?
        .clone();

    let headers = parts
        .get("headers")
        .map(|h| h.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    Ok(ParsedSignatureHeader {
        key_id: parts.get("keyid").cloned(),
        algorithm,
        signature,
        headers,
    })
}

/// Cache for decoded verifying keys.
static KEY_CACHE: OnceCell<RwLock<HashMap<String, VerifyingKey>>> = OnceCell::new();

/// Decode a hex-encoded Ed25519 public key.
///
/// The key is cached after first decode for performance.
pub fn decode_public_key(hex_key: &str) -> Result<VerifyingKey, GatewardenError> {
    // Check cache first
    let cache = KEY_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(guard) = cache.read() {
        if let Some(key) = guard.get(hex_key) {
            return Ok(*key);
        }
    }

    // Decode from hex
    let bytes = hex::decode(hex_key)
        .map_err(|e| GatewardenError::ConfigError(format!("Invalid public key hex: {}", e)))?;

    let key_array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GatewardenError::ConfigError("Public key must be 32 bytes".to_string()))?;

    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| GatewardenError::ConfigError(format!("Invalid Ed25519 public key: {}", e)))?;

    // Best-effort insert into cache. If locking fails, still return the decoded key.
    if let Ok(mut guard) = cache.write() {
        guard.insert(hex_key.to_string(), verifying_key);
    }

    Ok(verifying_key)
}

/// Verify an Ed25519 signature against a signing string.
pub fn verify_ed25519(
    signature_b64: &str,
    signing_string: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), GatewardenError> {
    let sig_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|e| GatewardenError::ProtocolError(format!("Invalid signature base64: {}", e)))?;

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| GatewardenError::SignatureInvalid)?;

    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(signing_string.as_bytes(), &signature)
        .map_err(|_| GatewardenError::SignatureInvalid)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_signature_header() {
        let header = r#"keyid="test-id", algorithm="ed25519", signature="dGVzdA==", headers="(request-target) host date digest""#;
        let parsed = parse_signature_header(header).unwrap();

        assert_eq!(parsed.key_id, Some("test-id".to_string()));
        assert_eq!(parsed.algorithm, "ed25519");
        assert_eq!(parsed.signature, "dGVzdA==");
        assert_eq!(
            parsed.headers,
            vec!["(request-target)", "host", "date", "digest"]
        );
    }

    #[test]
    fn test_parse_signature_header_missing_algorithm() {
        let header = r#"keyid="test-id", signature="dGVzdA==""#;
        let result = parse_signature_header(header);
        assert!(matches!(result, Err(GatewardenError::ProtocolError(_))));
    }

    #[test]
    fn test_parse_signature_header_wrong_algorithm() {
        let header = r#"algorithm="rsa-sha256", signature="dGVzdA==""#;
        let result = parse_signature_header(header);
        assert!(matches!(result, Err(GatewardenError::ProtocolError(_))));
    }

    #[test]
    fn test_parse_signature_header_missing_signature() {
        let header = r#"algorithm="ed25519", keyid="test""#;
        let result = parse_signature_header(header);
        assert!(matches!(result, Err(GatewardenError::ProtocolError(_))));
    }

    #[test]
    fn test_decode_public_key_valid() {
        // A known valid Ed25519 public key (from Keygen example)
        // This is a test key, not production
        let hex_key = "799efc7752286e6c3815b13358d98fc0f0b566764458adcb48f1be2c10a55906";
        let result = decode_public_key(hex_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_public_key_invalid_hex() {
        let hex_key = "not-valid-hex";
        let result = decode_public_key(hex_key);
        assert!(matches!(result, Err(GatewardenError::ConfigError(_))));
    }

    #[test]
    fn test_decode_public_key_wrong_length() {
        let hex_key = "0000"; // Too short
        let result = decode_public_key(hex_key);
        assert!(matches!(result, Err(GatewardenError::ConfigError(_))));
    }

    #[test]
    fn test_verify_ed25519_invalid_base64() {
        let hex_key = "799efc7752286e6c3815b13358d98fc0f0b566764458adcb48f1be2c10a55906";
        let key = decode_public_key(hex_key).unwrap();
        let result = verify_ed25519("not-valid-base64!!!", "test", &key);
        assert!(matches!(result, Err(GatewardenError::ProtocolError(_))));
    }

    #[test]
    fn test_verify_ed25519_wrong_signature_length() {
        let hex_key = "799efc7752286e6c3815b13358d98fc0f0b566764458adcb48f1be2c10a55906";
        let key = decode_public_key(hex_key).unwrap();
        // Valid base64 but wrong length
        let result = verify_ed25519("dGVzdA==", "test", &key);
        assert!(matches!(result, Err(GatewardenError::SignatureInvalid)));
    }

    #[test]
    fn test_verify_ed25519_invalid_signature() {
        let hex_key = "799efc7752286e6c3815b13358d98fc0f0b566764458adcb48f1be2c10a55906";
        let key = decode_public_key(hex_key).unwrap();
        // 64 bytes of zeros (valid length but wrong signature)
        let fake_sig = STANDARD.encode([0u8; 64]);
        let result = verify_ed25519(&fake_sig, "test signing string", &key);
        assert!(matches!(result, Err(GatewardenError::SignatureInvalid)));
    }
}
