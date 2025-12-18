//! HTTP signing string construction per draft-cavage-http-signatures.
//!
//! The signing string format for Keygen response verification:
//! ```text
//! (request-target): post /v1/accounts/<id>/licenses/actions/validate-key
//! host: api.keygen.sh
//! date: <Date header>
//! digest: sha-256=<base64>
//! ```

/// Build the signing string for response signature verification.
///
/// # Arguments
/// * `method` - HTTP method (lowercase)
/// * `path` - Request path including query string
/// * `host` - Host header value
/// * `date` - Date header value (RFC 2822 format)
/// * `digest_header` - Optional Digest header value (full header, e.g., "sha-256=abc123")
///
/// # Returns
/// The signing string to verify against the signature.
pub fn build_signing_string(
    method: &str,
    path: &str,
    host: &str,
    date: &str,
    digest_header: Option<&str>,
) -> String {
    // Per draft-cavage-http-signatures:
    // - Components delimited by newline
    // - Component names are lowercase
    // - No trailing newline
    let base = format!(
        "(request-target): {} {}\nhost: {}\ndate: {}",
        method.to_lowercase(),
        path,
        host,
        date
    );

    match digest_header {
        Some(digest) => format!("{}\ndigest: {}", base, digest),
        None => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_string_format() {
        let signing = build_signing_string(
            "post",
            "/v1/accounts/test-account/licenses/actions/validate-key",
            "api.keygen.sh",
            "Wed, 09 Jun 2021 16:08:15 GMT",
            Some("sha-256=827Op2un8OT9KJuN1siRs5h6mxjrUh4LJag66dQjnIM="),
        );

        let expected =
            "(request-target): post /v1/accounts/test-account/licenses/actions/validate-key\n\
                        host: api.keygen.sh\n\
                        date: Wed, 09 Jun 2021 16:08:15 GMT\n\
                        digest: sha-256=827Op2un8OT9KJuN1siRs5h6mxjrUh4LJag66dQjnIM=";

        assert_eq!(signing, expected);
    }

    #[test]
    fn test_signing_string_method_lowercase() {
        let signing = build_signing_string(
            "POST",
            "/v1/test",
            "api.keygen.sh",
            "Wed, 09 Jun 2021 16:08:15 GMT",
            Some("sha-256=abc123="),
        );

        assert!(signing.starts_with("(request-target): post "));
    }

    #[test]
    fn test_signing_string_no_trailing_newline() {
        let signing = build_signing_string(
            "post",
            "/v1/test",
            "api.keygen.sh",
            "Wed, 09 Jun 2021 16:08:15 GMT",
            Some("sha-256=abc123="),
        );

        assert!(!signing.ends_with('\n'));
    }

    #[test]
    fn test_signing_string_keygen_example() {
        // From Keygen docs example
        let signing = build_signing_string(
            "get",
            "/v1/accounts/keygen/licenses?limit=1",
            "api.keygen.sh",
            "Wed, 09 Jun 2021 16:08:15 GMT",
            Some("sha-256=827Op2un8OT9KJuN1siRs5h6mxjrUh4LJag66dQjnIM="),
        );

        let expected = "(request-target): get /v1/accounts/keygen/licenses?limit=1\n\
                        host: api.keygen.sh\n\
                        date: Wed, 09 Jun 2021 16:08:15 GMT\n\
                        digest: sha-256=827Op2un8OT9KJuN1siRs5h6mxjrUh4LJag66dQjnIM=";

        assert_eq!(signing, expected);
    }

    #[test]
    fn test_signing_string_no_digest() {
        let signing = build_signing_string(
            "get",
            "/v1/accounts/test/licenses",
            "api.keygen.sh",
            "Wed, 09 Jun 2021 16:08:15 GMT",
            None,
        );

        let expected = "(request-target): get /v1/accounts/test/licenses\n\
                        host: api.keygen.sh\n\
                        date: Wed, 09 Jun 2021 16:08:15 GMT";

        assert_eq!(signing, expected);
    }
}
