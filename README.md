<p align="center">
    <img src="assets/gatewarden-logo.png" alt="Gatewarden" width="350"/>
</p>

Hardened Keygen.sh license validation for Rust.

Gatewarden validates licenses using Keygen’s `validate-key` API and **cryptographically verifies** Keygen responses (Ed25519 signatures + optional SHA-256 digest) to prevent MITM/spoofed responses. It also supports an authenticated on-disk cache for offline grace.

## What this protects (threat model)

Gatewarden is designed to protect against:
- Spoofed Keygen responses (MITM / proxy tampering)
- Replay of old responses (online freshness window)
- Tampering of cached validation records

Gatewarden does **not** prevent a determined attacker from bypassing licensing by patching your application binary. That is true for any client-side licensing mechanism.

## Quickstart

```rust
use gatewarden::{GatewardenConfig, LicenseManager};

fn main() -> Result<(), gatewarden::GatewardenError> {
    let config = GatewardenConfig {
        app_name: "myapp/1.0.0",
        feature_name: "pro",
        account_id: "<your-keygen-account-id>",
        public_key_hex: "<your-keygen-ed25519-public-key-hex>",
        required_entitlements: &["PRO"],
        user_agent_product: "myapp",
        cache_namespace: "myapp",
        offline_grace: std::time::Duration::from_secs(24 * 60 * 60),
    };

    let manager = LicenseManager::new(config)?;
    let result = manager.validate_key("LICENSE-KEY")?;

    if result.valid {
        println!("License OK (from_cache={})", result.from_cache);
    }

    Ok(())
}
```

## Offline grace

If the online request fails due to transport errors, Gatewarden can fall back to an authenticated cached record for `offline_grace`.

## Configuration notes

- `public_key_hex` is Keygen’s Ed25519 **verify** key (public).
- `required_entitlements` is a static list of entitlement codes that must be present in Keygen’s signed response.
- License keys are **not** persisted; cache entries are keyed by a SHA-256 hash of the license key.

## API overview

- `LicenseManager::validate_key(license_key)` performs an online validate (with signature verification) and writes an authenticated cache record.
- `LicenseManager::check_access(license_key)` prefers the cache (if valid under `offline_grace`) and otherwise falls back to the online path.

## Local testing

See LOCAL_TESTING.md.

## Contributing

See CONTRIBUTING.md.

## Security

See SECURITY.md.

## Publishing

This repository is OSS-ready, but the crate is currently configured with `publish = false` in `Cargo.toml`.
When you're ready to publish to crates.io, flip that to `true` (or remove the key) and run your normal release flow.
