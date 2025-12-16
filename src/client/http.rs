//! Reqwest-based HTTP client for Keygen API.
//!
//! This module handles the raw HTTP communication with Keygen,
//! capturing all headers needed for signature verification.

use crate::config::GatewardenConfig;
use crate::crypto::digest::format_digest_header;
use crate::GatewardenError;
use reqwest::blocking::{Client, Response};
use reqwest::header::{CONTENT_TYPE, DATE, HOST, USER_AGENT};
use std::time::Duration;

/// HTTP response with captured headers and body.
#[derive(Debug)]
pub struct KeygenResponse {
    /// HTTP status code.
    pub status: u16,

    /// Date header value.
    pub date: Option<String>,

    /// Keygen-Signature header value.
    pub signature: Option<String>,

    /// Digest header value.
    pub digest: Option<String>,

    /// Raw response body.
    pub body: Vec<u8>,

    /// Request path used (for signing string reconstruction).
    pub request_path: String,

    /// Host used (for signing string reconstruction).
    pub host: String,
}

impl KeygenResponse {
    /// Extract headers from a reqwest Response.
    fn from_response(
        response: Response,
        request_path: String,
        host: String,
    ) -> Result<Self, GatewardenError> {
        let status = response.status().as_u16();
        let headers = response.headers().clone();

        let date = headers
            .get(DATE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let signature = headers
            .get("Keygen-Signature")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let digest = headers
            .get("Digest")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let body = response
            .bytes()
            .map_err(|e| GatewardenError::KeygenTransport(format!("Failed to read body: {}", e)))?
            .to_vec();

        Ok(Self {
            status,
            date,
            signature,
            digest,
            body,
            request_path,
            host,
        })
    }

    /// Get the body as a UTF-8 string.
    pub fn body_str(&self) -> Result<&str, GatewardenError> {
        std::str::from_utf8(&self.body)
            .map_err(|e| GatewardenError::ProtocolError(format!("Invalid UTF-8 in body: {}", e)))
    }
}

/// Keygen HTTP client.
pub struct KeygenClient {
    client: Client,
    user_agent: String,
    account_id: String,
    host: String,
    timeout: Duration,
}

impl KeygenClient {
    /// Create a new Keygen client from config.
    pub fn new(config: &GatewardenConfig) -> Result<Self, GatewardenError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| GatewardenError::KeygenTransport(format!("Failed to create client: {}", e)))?;

        let user_agent = build_user_agent(config);

        Ok(Self {
            client,
            user_agent,
            account_id: config.account_id.to_string(),
            host: "api.keygen.sh".to_string(),
            timeout: Duration::from_secs(30),
        })
    }

    /// Create a client with custom host (for testing).
    #[cfg(test)]
    pub fn with_host(config: &GatewardenConfig, host: String) -> Result<Self, GatewardenError> {
        let mut client = Self::new(config)?;
        client.host = host;
        Ok(client)
    }

    /// Set request timeout.
    ///
    /// # Panics
    /// This method will panic if the client builder fails (extremely unlikely with just timeout).
    /// If you need fallible construction, use `try_with_timeout` instead.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        // Note: reqwest Client::builder().timeout().build() is infallible in practice,
        // but we document the panic potential for completeness.
        self.client = Client::builder()
            .timeout(timeout)
            .build()
            .expect("reqwest client builder with only timeout should never fail");
        self
    }

    /// Set request timeout with fallible construction.
    pub fn try_with_timeout(mut self, timeout: Duration) -> Result<Self, GatewardenError> {
        self.timeout = timeout;
        self.client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| GatewardenError::ConfigError(format!("Failed to build HTTP client: {}", e)))?;
        Ok(self)
    }

    /// Validate a license key with entitlement scope.
    ///
    /// The `scope_entitlements` parameter specifies which entitlements to assert.
    /// Keygen will echo these back in the response if the license has them,
    /// enabling entitlement-based access control.
    pub fn validate_key(&self, license_key: &str, scope_entitlements: &[&str]) -> Result<KeygenResponse, GatewardenError> {
        let path = format!(
            "/v1/accounts/{}/licenses/actions/validate-key",
            self.account_id
        );

        let url = format!("https://{}{}", self.host, path);

        // Build request body
        // Include scope.entitlements to get entitlements echoed back in response
        let body = if scope_entitlements.is_empty() {
            serde_json::json!({
                "meta": {
                    "key": license_key
                }
            })
        } else {
            serde_json::json!({
                "meta": {
                    "key": license_key,
                    "scope": {
                        "entitlements": scope_entitlements
                    }
                }
            })
        };
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| GatewardenError::ProtocolError(format!("Failed to serialize: {}", e)))?;

        // Compute digest for request
        let digest_header = format_digest_header(&body_bytes);

        let response = self
            .client
            .post(&url)
            .header(USER_AGENT, &self.user_agent)
            .header(HOST, &self.host)
            .header(CONTENT_TYPE, "application/vnd.api+json")
            .header("Digest", &digest_header)
            .header("Accept", "application/vnd.api+json")
            .body(body_bytes)
            .send()
            .map_err(|e| GatewardenError::KeygenTransport(format!("Request failed: {}", e)))?;

        KeygenResponse::from_response(response, path, self.host.clone())
    }

    /// Get the configured host.
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// Build a User-Agent string from config.
///
/// Format: `<product>/gatewarden <app>/<version>`
/// Example: `shimmy-vision/gatewarden shimmy/1.0.0`
pub fn build_user_agent(config: &GatewardenConfig) -> String {
    let product = &config.user_agent_product;
    let app = &config.app_name;

    // Get gatewarden version from Cargo.toml
    let gw_version = env!("CARGO_PKG_VERSION");

    format!("{}/gatewarden-{} {}", product, gw_version, app)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> GatewardenConfig {
        GatewardenConfig {
            app_name: "shimmy/1.0.0",
            feature_name: "vision",
            account_id: "test-account-id",
            public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            required_entitlements: &["vision"],
            user_agent_product: "shimmy-vision",
            cache_namespace: "shimmy",
            offline_grace: Duration::from_secs(86400),
        }
    }

    #[test]
    fn test_build_user_agent() {
        let config = test_config();
        let ua = build_user_agent(&config);

        assert!(ua.starts_with("shimmy-vision/gatewarden-"));
        assert!(ua.contains("shimmy/1.0.0"));
    }

    #[test]
    fn test_build_user_agent_format() {
        let config = GatewardenConfig {
            app_name: "myapp/2.0.0",
            feature_name: "pro",
            account_id: "acc",
            public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            required_entitlements: &[],
            user_agent_product: "myproduct",
            cache_namespace: "myproduct",
            offline_grace: Duration::from_secs(0),
        };

        let ua = build_user_agent(&config);
        let gw_version = env!("CARGO_PKG_VERSION");

        assert_eq!(ua, format!("myproduct/gatewarden-{} myapp/2.0.0", gw_version));
    }

    #[test]
    fn test_keygen_response_body_str_valid_utf8() {
        let response = KeygenResponse {
            status: 200,
            date: None,
            signature: None,
            digest: None,
            body: b"hello world".to_vec(),
            request_path: "/test".to_string(),
            host: "api.keygen.sh".to_string(),
        };

        assert_eq!(response.body_str().unwrap(), "hello world");
    }

    #[test]
    fn test_keygen_response_body_str_invalid_utf8() {
        let response = KeygenResponse {
            status: 200,
            date: None,
            signature: None,
            digest: None,
            body: vec![0xFF, 0xFE],
            request_path: "/test".to_string(),
            host: "api.keygen.sh".to_string(),
        };

        assert!(response.body_str().is_err());
    }

    #[test]
    fn test_client_creation() {
        let config = test_config();
        let client = KeygenClient::new(&config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_host() {
        let config = test_config();
        let client = KeygenClient::new(&config).unwrap();
        assert_eq!(client.host(), "api.keygen.sh");
    }
}
