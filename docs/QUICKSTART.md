# Quickstart — From Zero to Validated License in 5 Minutes

## Prerequisites

- A [Keygen.sh](https://keygen.sh) account with at least one license created
- Your Ed25519 public key (64 hex chars) from Keygen Dashboard → Settings
- Rust 1.70+ (for the library) or a pre-built bridge binary (for non-Rust runtimes)

---

## Path A: Rust Library (Direct Integration)

### 1. Add to Cargo.toml

```toml
[dependencies]
gatewarden = "0.2"
```

### 2. Validate a License

```rust
use gatewarden::{GatewardenConfig, LicenseManager};
use std::time::Duration;

fn main() -> Result<(), gatewarden::GatewardenError> {
    let config = GatewardenConfig {
        app_name: "myapp".to_string(),
        feature_name: "pro".to_string(),
        account_id: "your-keygen-account-uuid".to_string(),
        public_key_hex: "your-64-char-hex-ed25519-verify-key".to_string(),
        required_entitlements: vec!["PRO".to_string()],
        user_agent_product: "myapp-pro".to_string(),
        cache_namespace: "myapp-pro".to_string(),
        offline_grace: Duration::from_secs(24 * 60 * 60),
    };

    let manager = LicenseManager::new(config)?;

    // Online validation — hits Keygen, verifies signature, caches result
    let result = manager.validate_key("USER-LICENSE-KEY")?;

    if result.valid {
        println!("Access granted (cached: {})", result.from_cache);
    } else {
        println!("License invalid");
    }

    Ok(())
}
```

### 3. Offline Access Checks

After a successful `validate_key()`, use `check_access()` for subsequent checks.
It reads from the authenticated cache without hitting Keygen:

```rust
let result = manager.check_access("USER-LICENSE-KEY")?;
// Works offline for up to `offline_grace` duration
```

---

## Path B: Bridge Sidecar (TypeScript, Python, Go, etc.)

### 1. Build the Bridge

```bash
git clone https://github.com/Michael-A-Kuykendall/gatewarden
cd gatewarden
cargo build --release -p gatewarden-bridge
```

### 2. Configure

Create `bridge.toml`:

```toml
port = 4760
bind = "127.0.0.1"
bearer_token = "generate-a-random-token-at-least-20-chars"

[profiles.myapp-pro]
account_id = "your-keygen-account-uuid"
public_key_hex = "your-64-char-hex-ed25519-verify-key"
required_entitlements = ["PRO"]
offline_grace_secs = 86400
```

### 3. Run

```bash
./target/release/gatewarden-bridge bridge.toml
```

### 4. Call from Any Language

```bash
curl -X POST http://127.0.0.1:4760/v1/validate-key \
  -H "Content-Type: application/json" \
  -H "X-Bridge-Token: your-token" \
  -d '{"profileId": "myapp-pro", "licenseKey": "USER-LICENSE-KEY"}'
```

Response:
```json
{"valid": true, "fromCache": false, "stateCode": "VALID", "entitlements": ["PRO"]}
```

---

## What Gets Verified

Every response from Keygen passes through:

1. **Ed25519 signature verification** — proves the response came from Keygen
2. **SHA-256 digest check** — proves the body wasn't modified in transit
3. **Freshness check** — rejects responses older than 5 minutes (anti-replay)
4. **Entitlement enforcement** — verifies required feature codes are present

If any check fails, access is denied. No exceptions.

---

## Next Steps

- [Configuration Reference](CONFIGURATION.md) — all options explained
- [Architecture](ARCHITECTURE.md) — how the security layers compose
- [Bridge README](../bridge/README.md) — full bridge API documentation
