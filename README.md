<p align="center">
    <img src="https://raw.githubusercontent.com/Michael-A-Kuykendall/gatewarden/master/assets/gatewarden-logo.png" alt="Gatewarden" width="350"/>
</p>

<p align="center">
    <a href="https://crates.io/crates/gatewarden"><img src="https://img.shields.io/crates/v/gatewarden.svg" alt="Crates.io"></a>
    <a href="https://docs.rs/gatewarden"><img src="https://docs.rs/gatewarden/badge.svg" alt="Docs.rs"></a>
    <a href="https://github.com/Michael-A-Kuykendall/gatewarden/actions"><img src="https://github.com/Michael-A-Kuykendall/gatewarden/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/Michael-A-Kuykendall/gatewarden/blob/master/LICENSE"><img src="https://img.shields.io/crates/l/gatewarden.svg" alt="License"></a>
</p>

<p align="center"><em>Yes, the logo is a bit much for a license validation library. We're aware.</em></p>

<p align="center"><strong>Languages:</strong> <a href="docs/zh-CN/README.md">简体中文</a> · <a href="docs/zh-TW/README.md">繁體中文</a></p>

<h2 align="center">Hardened <a href="https://keygen.sh">Keygen.sh</a> license validation for Rust.</h2>

**Gatewarden is for developers who use Keygen.sh and want cryptographic assurance—not just HTTP success—that a license validation response is authentic.**

*Hardened* means Gatewarden treats license validation as an adversarial protocol, not a trusted API call. It upgrades Keygen's client-side validation from "API trust" to "cryptographic trust."

### 💝 Support Gatewarden

🚀 **If Gatewarden helps you, consider [sponsoring](https://github.com/sponsors/Michael-A-Kuykendall) — 100% of support goes to keeping it free forever.**

- **$5/month**: Coffee Hero ☕ — Eternal gratitude + name in [SPONSORS.md](SPONSORS.md)
- **$25/month**: Developer Supporter 🐛 — Priority bug response + roadmap influence
- **$100/month**: Corporate Backer 🏢 — Logo in README + release-note recognition
- **$500/month**: Enterprise Partner 🚀 — Prominent logo + monthly office hours + roadmap input

[**🎯 Become a Sponsor**](https://github.com/sponsors/Michael-A-Kuykendall) | See our amazing [sponsors](SPONSORS.md) 🙏

**Thank you to our sponsors:** [ZephyrCloudIO](https://github.com/ZephyrCloudIO) (Corporate Backer) · alistairheath (Coffee Hero)

---

## Why Gatewarden?

Most Keygen integrations just check `meta.valid == true` in the JSON response. That's fine until someone points your app at a proxy that returns `{"meta":{"valid":true}}` for every request.

Gatewarden verifies the **Ed25519 signature** that Keygen attaches to every response, ensuring:

| Threat | Protection |
|--------|------------|
| **MITM / proxy spoofing** | Response must be signed by Keygen's private key |
| **Replay attacks** | Response rejected if older than 5 minutes |
| **Body tampering** | SHA-256 digest verified (when present) |
| **Cache tampering** | Cached records re-verified on load |
| **Missing signatures** | Fail-closed: no signature = rejected |

## Non-Goals

Gatewarden does **not** attempt to:
- Replace Keygen.sh (it's a client for Keygen, not an alternative)
- Prevent binary patching or runtime memory manipulation
- Provide DRM or anti-reverse-engineering

If an attacker has full control of the machine, they can bypass any client-side check. Gatewarden raises the bar from "intercept HTTP" to "reverse engineer binary."

## Quickstart

```rust
use gatewarden::{GatewardenConfig, LicenseManager};
use std::time::Duration;

fn main() -> Result<(), gatewarden::GatewardenError> {
    let config = GatewardenConfig {
        app_name: "myapp".to_string(),
        feature_name: "pro".to_string(),
        account_id: "your-keygen-account-id".to_string(),
        public_key_hex: "your-keygen-ed25519-verify-key".to_string(),
        required_entitlements: vec!["PRO_FEATURE".to_string()],
        user_agent_product: "myapp".to_string(),
        cache_namespace: "myapp".to_string(),
        offline_grace: Duration::from_secs(24 * 60 * 60), // 24 hours
    };

    let manager = LicenseManager::new(config)?;
    
    // validate_key: always hits Keygen, verifies signature, updates cache
    let result = manager.validate_key("LICENSE-KEY")?;

    if result.valid {
        println!("License valid (cached: {})", result.from_cache);
    }
    Ok(())
}
```

## API Overview

| Method | Behavior |
|--------|----------|
| `validate_key(key)` | Online validation → signature verify → cache |
| `check_access(key)` | Prefer cache (if within offline grace) → fallback to online |

Both methods verify signatures and entitlements. Use `validate_key` when you want fresh validation; use `check_access` for typical runtime checks where offline grace is acceptable.

## Error Handling

Gatewarden uses typed errors for precise handling:

```rust
use gatewarden::GatewardenError;

match manager.validate_key(&license_key) {
    Ok(result) if result.valid => { /* proceed */ }
    Ok(_) => { /* license invalid */ }
    
    // License issues (user-actionable)
    Err(GatewardenError::InvalidLicense) => { /* expired or revoked */ }
    Err(GatewardenError::EntitlementMissing { code }) => { /* wrong tier */ }
    
    // Security events (log and investigate)
    Err(GatewardenError::SignatureInvalid) => { /* possible tampering */ }
    Err(GatewardenError::SignatureMissing) => { /* response unsigned */ }
    Err(GatewardenError::DigestMismatch) => { /* body modified */ }
    Err(GatewardenError::ResponseTooOld { .. }) => { /* replay attempt */ }
    
    // Network issues (may use offline cache)
    Err(GatewardenError::KeygenTransport(_)) => { /* try check_access() */ }
    
    Err(e) => { /* other errors */ }
}
```

## Configuration

| Field | Description |
|-------|-------------|
| `account_id` | Your Keygen account UUID |
| `public_key_hex` | Keygen's Ed25519 verify key (64 hex characters) |
| `required_entitlements` | Entitlement codes the license must have |
| `offline_grace` | How long cached validations remain valid when offline |
| `cache_namespace` | Directory name for cache files (under the user data dir, e.g. `dirs::data_dir()/<namespace>/`) |

Get your public key from Keygen Dashboard → Settings → Public Key.

## Offline Grace

When online validation fails due to network issues, Gatewarden falls back to the authenticated cache:

1. Cache records include the original Keygen signature
2. Records are re-verified on every load (tamper-resistant)
3. Records expire after `offline_grace` duration
4. License keys are never stored—cache entries are keyed by SHA-256 hash

## Fail-Closed by Design

Most license libraries fail *open*. Gatewarden fails *closed*:

- Missing signature → **reject**
- Invalid signature → **reject**
- Stale response (>5 min) → **reject**
- Cache tampering detected → **reject**

Security failures are distinguishable from network failures through typed errors, so you can handle them appropriately.

## Security Model

**What Gatewarden protects:**
- Remote attackers cannot spoof valid license responses
- Network-level adversaries cannot replay old responses
- Local attackers cannot modify cached validation records

**Philosophy:** Licensing is not a business rule—it is an adversarial interface. Gatewarden treats it accordingly.

## Offline Usage Metering (feature `meter`)

Gatewarden can enforce usage caps **locally and offline** — something Keygen's
server-side `maxUses` cannot guarantee without connectivity. This is a key
differentiator. Enable the `meter` cargo feature, then:

```rust
// Record a local use; returns UsageLimitExceeded when the cap is breached.
manager.record_use("LICENSE-KEY")?;

// Every validation consults the local meter automatically:
let result = manager.check_access("LICENSE-KEY")?;
// result.caps includes max_uses / current_uses / remaining / local_uses

// Read the current counts (incl. offline usage) at any time:
let caps = manager.meter_usage("LICENSE-KEY")?;
// caps.remaining == max_uses - current_uses - local_uses
```

- The meter is **per-license-keyed** (keyed by the license-key hash).
- `LicenseManager::record_use(key)` increments, persists, and re-checks the cap.
- The local monthly count is threaded into `check_access_with_usage`, so every
  validation respects the local cap even offline.
- `Selector::UsageRemaining` reports the actual remaining uses
  (`max_uses - current_uses - local_uses`).
- Cap enforcement requires a known cap: a license must have been validated/cached
  at least once (online or via the offline cache) so its `maxUses` is known. When
  no cap is known, `record_use` still records locally but does not cap.
- Via the bridge, `POST /v1/record-use` records a use and returns `429`
  (`USAGE_LIMIT_EXCEEDED`) on breach; both `POST /v1/record-use` and the
  validation responses surface usage caps
  (`usage`: `maxUses`, `currentUses`, `remaining`, `localUses`).

When `meter` is **not** enabled, behavior is unchanged — the API is additive and
non-breaking. See [docs/QUICKSTART.md](docs/QUICKSTART.md) and the
`[0.4.2]` entry in [CHANGELOG.md](CHANGELOG.md) for details.

## Examples

See [`examples/basic_validation.rs`](examples/basic_validation.rs) for a complete working example with error handling.

## Local Testing

See [LOCAL_TESTING.md](LOCAL_TESTING.md) for integration testing against real Keygen APIs.

## Bridge API (Connector Surface)

For non-Rust runtimes (TypeScript, JavaScript, Python), Gatewarden can be exposed via a local sidecar bridge.

- Protocol overview: [docs/bridge-protocol.md](docs/bridge-protocol.md)
- OpenAPI contract: [spec/gatewarden-bridge.openapi.yaml](spec/gatewarden-bridge.openapi.yaml)

This keeps Gatewarden as the single cryptographic source of truth while enabling generated clients and standard API discovery.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

**Open Source, Not Open Contribution:** This project does not accept unsolicited pull requests. Please open an issue first to discuss proposed changes.

## Patent Notice & Licensing

**MIT License with FSE Patent Restrictions**

Gatewarden is licensed under the MIT License (see [LICENSE](LICENSE)). However, the Fused Semantic Execution (FSE) implementation in `src/policy/fse/` is subject to additional patent license restrictions.

**FSE Patent Status:** Pending patent application by Michael A. Kuykendall. All rights reserved.

### What This Means

✅ **You MAY:**
- Use Gatewarden for Keygen.sh license validation (its intended purpose)
- Modify, distribute, and create derivative works of Gatewarden
- Study the FSE code for educational purposes

❌ **You MAY NOT:**
- Extract FSE and use it in other projects
- Reimplement the FSE algorithm for other use cases
- Create competing products using FSE

**For FSE licensing inquiries:** See [FSE_PATENT_LICENSE.md](FSE_PATENT_LICENSE.md) or contact michaelallenkuykendall@gmail.com

## License

MIT — see [LICENSE](LICENSE).  
FSE Patent Restrictions — see [FSE_PATENT_LICENSE.md](FSE_PATENT_LICENSE.md).
