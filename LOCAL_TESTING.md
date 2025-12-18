# Gatewarden Local Testing Guide

This document describes how to test Gatewarden against the real Keygen.sh API during development.

## Prerequisites

### Environment Setup

Test credentials should be provided via environment variables (recommended via a local `.env` file that is **not** committed to git).
Load them before testing:

```bash
source .env
```

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `KEYGEN_ACCOUNT_ID` | Keygen account UUID |
| `KEYGEN_PUBLIC_KEY` | Ed25519 public key for signature verification |
| `KEYGEN_PRODUCT_ID` | Product UUID for license validation |
| `KEYGEN_TEST_LICENSE_VALID` | Valid license with VISION_ANALYSIS entitlement |
| `KEYGEN_TEST_LICENSE_EXPIRED` | Expired license |
| `KEYGEN_TEST_LICENSE_SUSPENDED` | Suspended license |
| `KEYGEN_TEST_LICENSE_NO_ENTITLEMENT` | Valid license without required entitlement |

## Test License Matrix

| License Type | Expected Result | HTTP Status | Error |
|--------------|-----------------|-------------|-------|
| VALID | Success | 200 | None |
| EXPIRED | Failure | 403 | `LicenseExpired` |
| SUSPENDED | Failure | 403 | `LicenseSuspended` |
| NO_ENTITLEMENT | Failure | 403 | `MissingEntitlement` |
| INVALID | Failure | 404 | `LicenseNotFound` |

## Integration Testing

### Running Integration Tests

```bash
# From gatewarden directory
source .env
cargo test --test integration -- --nocapture
```

### Manual Validation via a Consumer App

The most reliable way to test Gatewarden is through a consumer application that uses it.

Example request pattern (adjust URL + schema to your app):

```bash
source .env

# Expect success
curl -s -X POST "http://127.0.0.1:8080/api/license/check" \
  -H "Content-Type: application/json" \
  -d "{\"license\": \"$KEYGEN_TEST_LICENSE_VALID\"}"

# Expect forbidden / missing entitlement
curl -s -X POST "http://127.0.0.1:8080/api/license/check" \
  -H "Content-Type: application/json" \
  -d "{\"license\": \"$KEYGEN_TEST_LICENSE_NO_ENTITLEMENT\"}"
```

## Key Implementation Details

### Entitlements Scope

**CRITICAL**: For Keygen to echo entitlements in the response, Gatewarden must include them in the request scope:

```json
{
  "meta": {
    "key": "LICENSE-KEY",
    "scope": {
      "entitlements": ["VISION_ANALYSIS"]
    }
  }
}
```

This is implemented in `src/client/http.rs::validate_key()`. Without this scope, Keygen returns empty entitlements even if the license has them assigned.

### Signature Verification Flow

1. Gatewarden receives response headers including `Keygen-Signature`
2. Constructs signing string from `(request-target)`, `host`, `date`, `digest`
3. Verifies Ed25519 signature against configured public key
4. Caches valid response with signature for offline grace period

### Offline Grace Period

- Default: 24 hours
- During grace period, cached validation is used if API is unreachable
- Cache includes cryptographic proof (signature) to prevent tampering
- After grace period expires, online validation is required

## Debugging

### Enable Tracing

```bash
RUST_LOG=gatewarden=debug cargo test --test integration
```

### Common Issues

1. **Empty entitlements in response**: Verify `scope.entitlements` is included in request
2. **Signature verification failed**: Check public key matches account
3. **License not found (404)**: Verify license key format and account ID
4. **Unexpected cache hit**: Clear cache directory (`~/.cache/gatewarden/`)

## Security Notes

- **NEVER** commit real license keys to git
- **NEVER** log license keys, even at debug level
- Treat any test keys as secrets
- All signature verification uses constant-time comparison
