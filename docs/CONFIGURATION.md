# Configuration Reference

## GatewardenConfig (Rust Library)

Used when integrating Gatewarden directly into a Rust application.

```rust
use gatewarden::GatewardenConfig;
use std::time::Duration;

let config = GatewardenConfig {
    app_name: "myapp".to_string(),
    feature_name: "pro".to_string(),
    account_id: "uuid-from-keygen-dashboard".to_string(),
    public_key_hex: "64-hex-char-ed25519-verify-key".to_string(),
    required_entitlements: vec!["PRO".to_string()],
    user_agent_product: "myapp-pro".to_string(),
    cache_namespace: "myapp-pro".to_string(),
    offline_grace: Duration::from_secs(86400),
};
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `app_name` | String | Yes | Application identifier (appears in User-Agent) |
| `feature_name` | String | Yes | Feature/plan name (e.g., "pro", "enterprise") |
| `account_id` | String | Yes | Keygen account UUID. Get from Dashboard → Settings |
| `public_key_hex` | String | Yes | Ed25519 verify key (64 hex chars). Dashboard → Settings → Public Key |
| `required_entitlements` | Vec\<String\> | Yes | Entitlement codes that must ALL be present. Empty vec = no entitlement check |
| `user_agent_product` | String | Yes | Product tag for Keygen analytics (crack detection) |
| `cache_namespace` | String | Yes | Directory name for cache files. Use unique per-product to avoid collisions |
| `offline_grace` | Duration | Yes | How long cached validations stay valid when Keygen is unreachable |

### Validation Rules

- `account_id` must not be empty
- `public_key_hex` must be exactly 64 characters
- `cache_namespace` must not be empty

### Security Notes

- `account_id` and `public_key_hex` should be compiled into your binary where possible
- These are NOT secrets — the public key is safe to ship in source code
- The secret is the *private* signing key, which stays on Keygen's servers

---

## Bridge Configuration (bridge.toml)

Used when running the `gatewarden-bridge` sidecar for non-Rust consumers.

### Full Example

```toml
# ─── Network ──────────────────────────────────────────
port = 4760
bind = "127.0.0.1"

# ─── Authentication ───────────────────────────────────
bearer_token = "your-strong-random-token-minimum-20-chars"

# ─── Rate Limiting ────────────────────────────────────
rate_limit_rps = 30

# ─── Profiles ─────────────────────────────────────────
[profiles.myapp-pro]
account_id = "00000000-0000-0000-0000-000000000000"
public_key_hex = "64chars..."
required_entitlements = ["PRO"]
offline_grace_secs = 86400
cache_namespace = "myapp-pro-bridge"
user_agent_product = "myapp-pro"
feature_name = "pro"
```

### Top-Level Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | u16 | 4760 | TCP port to listen on |
| `bind` | String | "127.0.0.1" | Bind address. Use "0.0.0.0" only in containers |
| `bearer_token` | String? | None | Shared secret for X-Bridge-Token header. STRONGLY recommended |
| `rate_limit_rps` | u32? | 30 | Max requests/second per IP. Burst = 3× this value |

### Profile Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `account_id` | String | Required | Keygen account UUID |
| `public_key_hex` | String | Required | Ed25519 verify key (64 hex chars) |
| `required_entitlements` | Vec\<String\>? | [] | Entitlement codes to enforce |
| `offline_grace_secs` | u64? | 86400 | Cache validity in seconds |
| `cache_namespace` | String? | profile ID | Cache directory name |
| `user_agent_product` | String? | "bridge-{profileId}" | User-Agent tag |
| `feature_name` | String? | profile ID | Feature identifier |

### Environment Variables

The bridge does not read environment variables directly. All configuration comes
from the TOML file. However, you can template your TOML using deployment tools
(envsubst, Consul, etc.) before passing it to the bridge.

---

## Cache Location

Gatewarden stores cache files under the OS data directory:

| OS | Path |
|----|------|
| Linux | `~/.local/share/{cache_namespace}/` |
| macOS | `~/Library/Application Support/{cache_namespace}/` |
| Windows | `%APPDATA%/{cache_namespace}/` |

Cache files are:
- Named by the first 16 hex chars of the SHA-256 hash of the license key
- JSON-formatted authenticated records containing the original signature
- Re-verified on every load (signature + digest + grace period)
- Permission-restricted to 0600 on Unix

---

## Keygen Dashboard Setup

1. Create an account at [keygen.sh](https://keygen.sh)
2. Go to **Settings** → copy your **Account ID** (UUID)
3. Go to **Settings** → copy your **Public Key** (64 hex chars, Ed25519)
4. Create a **Product** and a **Policy** with your desired entitlements
5. Create a **License** for testing

The account ID and public key go into your `GatewardenConfig` or `bridge.toml`.
The license key is what your end users provide at runtime.
