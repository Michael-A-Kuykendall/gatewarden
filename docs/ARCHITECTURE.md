# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Your Application                       │
│                                                          │
│  ┌──────────────┐         ┌────────────────────────┐    │
│  │ LicenseManager│◄───────►│  Keygen.sh API         │    │
│  │  (Rust API)   │         │  (api.keygen.sh)       │    │
│  └──────┬────────┘         └────────────────────────┘    │
│         │                                                │
│         ▼                                                │
│  ┌──────────────────────────────────────────┐           │
│  │         Crypto Verification Pipeline      │           │
│  │                                           │           │
│  │  1. Signature present? (fail-closed)      │           │
│  │  2. Ed25519 verify (signing string)       │           │
│  │  3. SHA-256 digest check (body)           │           │
│  │  4. Freshness check (< 5 min)            │           │
│  └──────────────┬───────────────────────────┘           │
│                 │                                        │
│         ┌───────┴───────┐                               │
│         ▼               ▼                               │
│  ┌─────────────┐  ┌──────────────┐                     │
│  │ Policy Layer │  │ File Cache   │                     │
│  │ (access.rs)  │  │ (atomic I/O) │                     │
│  └──────────────┘  └──────────────┘                     │
└─────────────────────────────────────────────────────────┘
```

## Bridge Sidecar (Non-Rust Consumers)

```
┌──────────────────┐        ┌─────────────────────┐
│  TypeScript App   │──HTTP──►│  gatewarden-bridge  │
│  Python App       │        │  (Axum, port 4760)  │
│  Go / Ruby / etc  │        │                     │
└──────────────────┘        │  ┌─────────────────┐│
                             │  │ Bearer Token Auth││
                             │  │ Rate Limiter     ││
                             │  │ Profile Router   ││
                             │  └────────┬────────┘│
                             │           │         │
                             │  ┌────────▼────────┐│
                             │  │ LicenseManager   ││
                             │  │ (one per profile)││
                             │  └─────────────────┘│
                             └─────────────────────┘
```

## Module Map

```
gatewarden (library crate)
├── crypto/
│   ├── verify.rs       — Ed25519 signature verification + key cache
│   ├── signing.rs      — HTTP signing string construction
│   ├── digest.rs       — SHA-256 body digest
│   ├── freshness.rs    — Response age / replay detection
│   └── pipeline.rs     — Composed verification (all 4 checks)
├── client/
│   └── http.rs         — Reqwest client for Keygen API
├── cache/
│   ├── file.rs         — Atomic file-based cache backend
│   └── format.rs       — Authenticated cache record (re-verifies on load)
├── policy/
│   ├── access.rs       — Entitlement + usage cap enforcement
│   └── fse/            — Fused Semantic Execution engine (patent pending)
│       ├── model.rs    — Selectors, predicates, rules, values
│       ├── compiler.rs — Rule → CompiledPlan (selector deduplication)
│       ├── engine.rs   — evaluate_policy() + default_security_rules()
│       └── runtime.rs  — Single-pass execution with early exit
├── protocol/
│   └── models.rs       — Keygen response parsing + LicenseState
├── manager.rs          — Public API: LicenseManager
├── config.rs           — GatewardenConfig
├── clock.rs            — Clock trait (real + mock for testing)
├── errors.rs           — Typed error enum
└── meter/              — Usage tracking (future)

bridge (binary crate)
├── main.rs             — Axum server setup, background prune task
├── config.rs           — TOML config loading + ProfileConfig
├── state.rs            — AppState (managers + rate limiter + auth)
├── auth.rs             — Bearer token middleware + RateLimiter
└── routes.rs           — /v1/health, /v1/validate-key, /v1/check-access
```

## Security Architecture

### Threat Model

| Threat | Mitigation | Module |
|--------|-----------|--------|
| Spoofed validation response | Ed25519 signature verification | crypto/verify.rs |
| Replayed old response | 5-minute freshness window | crypto/freshness.rs |
| Body tampering in transit | SHA-256 digest verification | crypto/digest.rs |
| Cache file modification | Re-verify signature on every cache load | cache/format.rs |
| Missing security headers | Fail-closed: no signature = rejected | crypto/pipeline.rs |
| Exhausted offline cache | Configurable grace period, then deny | cache/format.rs |
| Bridge token guessing | Constant-time comparison | bridge/auth.rs |
| Bridge flood/DoS | Per-IP token-bucket rate limiting | bridge/auth.rs |

### Fail-Closed Principle

Every security check in Gatewarden defaults to **deny** on uncertainty:

- Missing `Keygen-Signature` header → `SignatureMissing` error (not bypass)
- Missing `Date` header → `SignatureMissing` error
- Malformed digest header → `DigestMismatch` error
- Cache record with future `cached_at` → `CacheTampered` error
- FSE rule with `Value::Missing` input → predicate returns `false`
- Unresolved required FSE rule → forced to `False` at finalization

### Data Flow: Online Validation

```
User calls validate_key("LICENSE-KEY")
    │
    ▼
HTTP POST to api.keygen.sh/v1/accounts/{id}/licenses/actions/validate-key
    │
    ▼
Response received with headers: Date, Keygen-Signature, Digest
    │
    ├── Missing Signature or Date? → REJECT (SignatureMissing)
    │
    ▼
Verify digest: SHA-256(body) == Digest header value
    │
    ├── Mismatch? → REJECT (DigestMismatch)
    │
    ▼
Parse Keygen-Signature header → extract base64 signature
Build signing string: (request-target) + host + date + digest
Verify Ed25519(signature, signing_string, public_key)
    │
    ├── Invalid? → REJECT (SignatureInvalid)
    │
    ▼
Parse Date header → check age
    │
    ├── > 300 seconds old? → REJECT (ResponseTooOld)
    ├── > 60 seconds in future? → REJECT (ResponseFromFuture)
    │
    ▼
Parse JSON body → extract LicenseState
Check entitlements + usage caps
    │
    ├── Missing entitlement? → REJECT (EntitlementMissing)
    ├── Usage exceeded? → REJECT (UsageLimitExceeded)
    │
    ▼
Cache the authenticated record (atomic write)
Return ValidationResult { valid: true }
```

## FSE Policy Engine

The Fused Semantic Execution engine provides composable, testable policy
evaluation. See the [FSE steering doc](../.kiro/steering/fused-semantic-execution.md)
for the architectural principles and patent context.

Currently the FSE engine is tested in isolation. In v0.3.0 it will be wired
into the live validation pipeline as the authoritative policy decision point.
