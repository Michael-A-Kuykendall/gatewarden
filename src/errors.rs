//! Gatewarden error types.

use thiserror::Error;

/// Errors that can occur during license validation.
#[derive(Debug, Error)]
pub enum GatewardenError {
    /// Configuration is invalid.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Response signature or date header is missing (fail-closed).
    #[error("Response signature or date header missing")]
    SignatureMissing,

    /// Response signature verification failed.
    #[error("Response signature verification failed")]
    SignatureInvalid,

    /// Computed digest does not match Digest header.
    #[error("Response digest mismatch")]
    DigestMismatch,

    /// Response is older than allowed freshness window (replay attack).
    #[error("Response too old ({age_seconds}s), possible replay attack")]
    ResponseTooOld {
        /// Age of the response in seconds.
        age_seconds: i64,
    },

    /// Response date is in the future (clock tampering).
    #[error("Response date is in the future, possible clock tampering")]
    ResponseFromFuture,

    /// Failed to parse Keygen protocol response.
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// HTTP transport error communicating with Keygen.
    #[error("Keygen transport error: {0}")]
    KeygenTransport(String),

    /// Cache I/O error.
    #[error("Cache I/O error: {0}")]
    CacheIO(String),

    /// Cache has been tampered with.
    #[error("Cache tampering detected")]
    CacheTampered,

    /// Cache has expired beyond offline grace period.
    #[error("Cache expired (offline grace exceeded)")]
    CacheExpired,

    /// No license key provided.
    #[error("No license key provided")]
    MissingLicense,

    /// License is invalid or expired.
    #[error("Invalid or expired license")]
    InvalidLicense,

    /// Required entitlement is missing.
    #[error("Required entitlement missing: {code}")]
    EntitlementMissing {
        /// The entitlement code that was required but missing.
        code: String,
    },

    /// Usage limit exceeded.
    #[error("Usage limit exceeded")]
    UsageLimitExceeded,

    /// Meter I/O error.
    #[error("Meter I/O error: {0}")]
    MeterIO(String),
}
