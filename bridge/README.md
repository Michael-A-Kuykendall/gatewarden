# Gatewarden Bridge

**Language-agnostic HTTP sidecar for hardened Keygen.sh license validation.**

The bridge exposes Gatewarden's Ed25519-verified license validation as a local JSON API.
TypeScript, Python, Go, Ruby — any runtime can validate licenses without reimplementing
cryptographic signature verification.

## Quick Start

```bash
# Build
cargo build --release -p gatewarden-bridge

# Run (loads config from bridge.toml in current directory)
./target/release/gatewarden-bridge

# Or specify a config path
./target/release/gatewarden-bridge /path/to/bridge.toml
```

## Configuration

Create a `bridge.toml` file:

```toml
# Network settings
port = 4760                    # Default port
bind = "127.0.0.1"            # Loopback only — NEVER expose to the internet

# Authentication (STRONGLY recommended for any non-dev deployment)
bearer_token = "your-random-token-at-least-20-chars-long"

# Rate limiting (per IP)
rate_limit_rps = 30            # Requests per second per IP (burst = 3x)

# Product profiles — one per product/plan you validate
[profiles.myapp-pro]
account_id = "your-keygen-account-uuid"
public_key_hex = "64-hex-char-ed25519-verify-key-from-keygen-dashboard"
required_entitlements = ["PRO"]
offline_grace_secs = 86400     # 24 hours offline cache validity
```

### Configuration Reference

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `port` | No | `4760` | TCP port to listen on |
| `bind` | No | `"127.0.0.1"` | Bind address. Use `0.0.0.0` only in containers |
| `bearer_token` | No | None | Shared secret for `X-Bridge-Token` header auth |
| `rate_limit_rps` | No | `30` | Max requests/second per IP (burst = 3×) |

### Profile Configuration

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `account_id` | Yes | — | Your Keygen account UUID |
| `public_key_hex` | Yes | — | Ed25519 verify key from Keygen Dashboard (64 hex chars) |
| `required_entitlements` | No | `[]` | Entitlement codes the license must carry |
| `offline_grace_secs` | No | `86400` | How long cached validations stay valid (seconds) |
| `cache_namespace` | No | profile ID | Directory name for cache files |
| `user_agent_product` | No | `bridge-{profileId}` | User-Agent tag for Keygen analytics |
| `feature_name` | No | profile ID | Feature identifier in User-Agent |

## API Endpoints

### `GET /v1/health`

Readiness probe. Returns available profiles.

```bash
curl http://127.0.0.1:4760/v1/health \
  -H "X-Bridge-Token: your-token"
```

```json
{"status": "ok", "version": "0.2.1", "profiles": ["myapp-pro"]}
```

### `POST /v1/validate-key`

Always validates against Keygen online, verifies the Ed25519 signature, and caches
the result. Falls back to cache only on network failure.

```bash
curl -X POST http://127.0.0.1:4760/v1/validate-key \
  -H "Content-Type: application/json" \
  -H "X-Bridge-Token: your-token" \
  -d '{"profileId": "myapp-pro", "licenseKey": "XXXX-XXXX-XXXX-XXXX"}'
```

**Success response (200):**
```json
{
  "valid": true,
  "fromCache": false,
  "stateCode": "VALID",
  "expiresAt": "2027-01-01T00:00:00+00:00",
  "entitlements": ["PRO"]
}
```

**Invalid license (200 with `valid: false`):**
```json
{
  "valid": false,
  "fromCache": false,
  "stateCode": "MISSING_LICENSE",
  "expiresAt": null,
  "entitlements": []
}
```

### `POST /v1/check-access`

Cache-first access check. Uses the locally cached validation if it's within the
offline grace period. Does NOT call Keygen if a valid cache entry exists.

```bash
curl -X POST http://127.0.0.1:4760/v1/check-access \
  -H "Content-Type: application/json" \
  -H "X-Bridge-Token: your-token" \
  -d '{"profileId": "myapp-pro", "licenseKey": "XXXX-XXXX-XXXX-XXXX"}'
```

Same response shape as `validate-key`.

### `GET /.well-known/openapi.json`

Returns the OpenAPI 3.1 spec (YAML). No authentication required. Use for client
code generation or Swagger UI integration.

## Authentication

When `bearer_token` is set in config, every request to `/v1/*` must include:

```
X-Bridge-Token: your-configured-token
```

Requests without a valid token receive `401 Unauthorized`:
```json
{"error": "Missing or invalid X-Bridge-Token header", "code": "UNAUTHORIZED"}
```

The token comparison uses constant-time equality to prevent timing attacks.

## Rate Limiting

Per-IP token-bucket rate limiting. Default: 30 requests/second with 3× burst (90 tokens).

Requests exceeding the limit receive `429 Too Many Requests`:
```json
{"error": "Rate limit exceeded", "code": "RATE_LIMITED"}
```

## Client Examples

### TypeScript / Node.js

```typescript
const BRIDGE_URL = "http://127.0.0.1:4760";
const BRIDGE_TOKEN = process.env.GATEWARDEN_BRIDGE_TOKEN;

async function validateLicense(licenseKey: string): Promise<boolean> {
  const res = await fetch(`${BRIDGE_URL}/v1/validate-key`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Bridge-Token": BRIDGE_TOKEN,
    },
    body: JSON.stringify({ profileId: "myapp-pro", licenseKey }),
  });

  if (!res.ok) {
    return false; // fail-closed
  }

  const data = await res.json();
  return data.valid === true;
}
```

### Python

```python
import requests

BRIDGE_URL = "http://127.0.0.1:4760"
BRIDGE_TOKEN = "your-token"

def validate_license(license_key: str) -> bool:
    resp = requests.post(
        f"{BRIDGE_URL}/v1/validate-key",
        json={"profileId": "myapp-pro", "licenseKey": license_key},
        headers={"X-Bridge-Token": BRIDGE_TOKEN},
        timeout=7,
    )
    if resp.status_code != 200:
        return False
    return resp.json().get("valid", False)
```

### curl (testing)

```bash
# Health check
curl -s http://127.0.0.1:4760/v1/health -H "X-Bridge-Token: your-token" | jq

# Validate
curl -s -X POST http://127.0.0.1:4760/v1/validate-key \
  -H "Content-Type: application/json" \
  -H "X-Bridge-Token: your-token" \
  -d '{"profileId":"myapp-pro","licenseKey":"YOUR-KEY"}' | jq
```

## Security

- **Loopback only** — bind to `127.0.0.1` by default. Never expose to the internet.
- **Bearer token** — always configure a strong (20+ char) token for production.
- **Fail-closed** — security errors (signature invalid, digest mismatch) return HTTP 502, not 200.
- **License keys are never logged or cached in plaintext** — cache entries are keyed by SHA-256 hash.
- **Config file permissions** — `bridge.toml` contains your bearer token. Set `chmod 600 bridge.toml` on Unix.

## Error Codes

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| `PROFILE_NOT_FOUND` | 404 | profileId doesn't match any configured profile |
| `MISSING_LICENSE` | 200 | No license key provided |
| `INVALID_LICENSE` | 200 | License key invalid or expired |
| `ENTITLEMENT_MISSING` | 200 | License lacks required entitlement |
| `SIGNATURE_INVALID` | 502 | Response signature verification failed |
| `SIGNATURE_MISSING` | 502 | Response missing required signature |
| `DIGEST_MISMATCH` | 502 | Response body was tampered with |
| `RESPONSE_TOO_OLD` | 502 | Possible replay attack (>5 min old) |
| `TRANSPORT_ERROR` | 502 | Network error reaching Keygen |
| `CACHE_EXPIRED` | 200 | Offline grace period exceeded |
| `UNAUTHORIZED` | 401 | Missing or wrong X-Bridge-Token |
| `RATE_LIMITED` | 429 | Per-IP rate limit exceeded |

## Multi-Profile

One bridge instance can serve multiple products. Each profile has its own
Keygen account, public key, and entitlement requirements:

```toml
[profiles.myapp-free]
account_id = "..."
public_key_hex = "..."
required_entitlements = []

[profiles.myapp-pro]
account_id = "..."
public_key_hex = "..."
required_entitlements = ["PRO"]

[profiles.other-product]
account_id = "different-account-uuid"
public_key_hex = "different-key"
required_entitlements = ["ENTERPRISE"]
```

Clients specify which profile to validate against via the `profileId` field in requests.

## Patent Notice

The Gatewarden policy engine implements Fused Semantic Execution (FSE), a
selector-first, single-pass rule evaluation architecture. FSE is the subject of
a pending patent by Michael A. Kuykendall. All rights reserved.
