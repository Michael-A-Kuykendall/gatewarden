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
└── meter/              — Offline usage metering (feature `meter`)

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

The Fused Semantic Execution engine is the authoritative policy decision point
for license validation. FSE is a selector-first, single-pass evaluation architecture
that achieves O(M) runtime complexity where M = unique selectors, independent of
rule count.

### Core Architecture

```
Compile Phase (startup)
─────────────────────
  GatewardenConfig
       │
       ▼
  compile_default_plan()
       │
       ├─→ crypto.signature_verified (required)
       ├─→ response.state_valid (required)
       └─→ entitlements.required_N (required, one per config)
       │
       ▼
  CompiledPlan
  ├── rules: Vec<Rule>
  ├── selectors: Vec<Selector>  ← deduplicated
  └── path_index: HashMap<Selector, Vec<usize>>

Execute Phase (per request)
──────────────────────────
  ValidationResponse + signature_verified
       │
       ▼
  GatewardenEvalInput::from_validated_response()
       │
       ▼
  execute(plan, input)
  ├─→ For each unique selector:
  │     ├─→ Extract value ONCE
  │     └─→ Broadcast to all dependent rules
  ├─→ Early exit when all required rules resolved
  └─→ Finalize (fail-closed)
       │
       ▼
  RuntimeResult { allow: bool, outcomes, selectors_scanned }
```

### Selectors

FSE selectors extract values from the validation response:

| Selector | Type | Source |
|----------|------|--------|
| `SignaturePresent` | Bool | Crypto pipeline verification result |
| `StateCode` | String | `response.meta.code` ("VALID", "EXPIRED", etc.) |
| `StateValid` | Bool | `response.meta.valid` |
| `Entitlements` | Vec\<String\> | `response.data.attributes.entitlements` |
| `ExpiresAt` | Bool (presence) | `response.data.attributes.expiresAt` |
| `UsageRemaining` | U64 | Remaining uses (`max_uses - current_uses - local_uses`); `Missing` when uncapped |

### Default Rules

Every `LicenseManager` compiles a default FSE plan at initialization:

```rust
Rule { id: "crypto.signature_verified", selector: SignaturePresent, predicate: BoolIsTrue, required: true }
Rule { id: "response.state_valid", selector: StateValid, predicate: BoolIsTrue, required: true }
Rule { id: "entitlements.required_0", selector: Entitlements, predicate: ContainsString("PRO"), required: true }
// ... one rule per required_entitlements entry
```

### Integration Point

FSE evaluation occurs in `LicenseManager::validate_online()` immediately after
cryptographic verification:

```rust
// 1. Crypto verification
verify_response(&response, &self.config.public_key_hex, self.clock.as_ref())?;

// 2. Parse response
let state = LicenseState::from_keygen_response(&keygen_response)?;

// 3. FSE policy evaluation ← authoritative decision
let input = GatewardenEvalInput::from_validated_response(state.clone(), true);
let fse_result = execute(&self.fse_plan, &input);

if !fse_result.allow {
    return Err(GatewardenError::InvalidLicense);
}

// 4. Cache + return result
```

### Performance Characteristics

FSE achieves constant-time evaluation per rule when selectors are shared:

- **Without FSE:** Adding 10 entitlement rules = 10 additional selector extractions
- **With FSE:** Adding 10 rules on `Entitlements` selector = 0 additional extractions

The `RuntimeResult::selectors_scanned` metric proves this O(1) property in tests.

### Patent Notice

FSE implements a selector-first, single-pass rule evaluation architecture that is
the subject of a pending patent by Michael A. Kuykendall. See source headers for
full patent notice.
