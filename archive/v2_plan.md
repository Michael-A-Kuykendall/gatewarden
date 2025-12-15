# Gatewarden Slice-Gated Implementation Plan v2

This plan **replaces** the earlier slice ladder. It incorporates the review findings: early config + errors + clock, explicit fixture strategy, decomposed HTTP/pipeline slices, and a more precise shimmy migration path.

This is written for strict Slice-Gated execution: each slice is small, independently testable, and **must** pass its gate before proceeding.

---

## 0) Decisions Locked for v0 (to avoid churn)

### D0.1 Entitlements abstraction
**v0 uses config-driven required codes** (`required_entitlements: &'static [&'static str]`).
- Rationale: prevents type-system over-engineering and reduces degrees of freedom early.
- Future: add `trait EntitlementSet` behind a feature flag once v0 is stable.

### D0.2 Fixture strategy
**Synthetic fixtures + deterministic test vectors** are primary truth for v0.
- Optional later: add a small capture tool to record real Keygen responses (redacted) to expand fixtures.

### D0.3 Cache migration
**Fresh start by default** (new cache namespace/version).
- Optional later slice to read legacy shimmy cache if required, but it is not needed to ship Gatewarden v0.

### D0.4 Signature/header behavior
If signature+date headers are present, verification is mandatory (fail-closed on invalid).
If missing, behavior is **explicit and gated** (v0 default: treat as `SignatureMissing` and fail-closed).

---

## 1) Global Non-Negotiables
- `cargo clippy -- -D warnings` and `cargo test` must be green at every slice boundary.
- No logging of license keys.
- Any security decision that changes trust boundaries must be represented by a test.

---

# Slice Tickets

## Slice 00 — Test Infrastructure Baseline

### Objective
Create deterministic test structure so subsequent slices are not blocked by missing scaffolding.

### Scope (Must Do)
- Create `tests/` with:
  - `tests/fixtures/` directory
  - README describing fixture format and provenance
- Add first test vector files:
  - signing-string vectors
  - signature header parsing vectors
  - date parsing vectors

### Non-Goals
- No crypto implementation yet

### Gate
```bash
cargo test
```

---

## Slice 01 — Crate Skeleton + Core Types (Config, Errors, Clock)

### Objective
Lock the foundational types needed by crypto, cache, and client work.

### Scope (Must Do)
- Crate skeleton + modules:
  - `crypto/`, `protocol/`, `client/`, `cache/`, `meter/`, `policy/`, `errors/`, `integrations/`
- Define `GatewardenConfig` (public) with at minimum:
  - `app_name`, `feature_name`, `account_id`, `public_key_hex`
  - `required_entitlements`, `user_agent_product`, `cache_namespace`, `offline_grace`
- Define `GatewardenError` (public) with variants needed through Slice 06:
  - `ConfigError`, `SignatureMissing`, `SignatureInvalid`, `DigestMismatch`
  - `ResponseTooOld`, `ResponseFromFuture`, `ProtocolError`
  - `KeygenTransport`, `CacheIO`, `CacheTampered`
- Define clock seam:
  - `trait Clock { fn now_utc(&self) -> chrono::DateTime<chrono::Utc>; }`
  - `SystemClock`
  - `MockClock` (cfg(test))

### Non-Goals
- No Keygen calls

### Gate
```bash
cargo clippy -- -D warnings
cargo test
```

---

## Slice 02 — Deterministic Digest + Signing String Builder

### Objective
Implement deterministic primitives required by signature verification.

### Scope (Must Do)
- `crypto::sha256_b64(body: &[u8]) -> String`
- `crypto::build_signing_string(method, path, host, date, digest_b64) -> String`
- Unit tests using fixtures created in Slice 00

### Non-Goals
- No signature verification yet

### Gate
```bash
cargo test crypto_signing_string_vectors
```

---

## Slice 03 — Signature Header Parsing + Public Key Decode (once)

### Objective
Parse Keygen-Signature header and decode public key once.

### Scope (Must Do)
- Robust signature header parsing:
  - extract `algorithm`, `signature`, and declared header list
- Enforce `algorithm == ed25519`
- Decode public key hex via `once_cell` or equivalent
- Tests:
  - valid header parses
  - missing fields fail
  - unsupported algorithm fails

### Non-Goals
- No Ed25519 verify yet

### Gate
```bash
cargo test signature_header_parsing_vectors
```

---

## Slice 04 — Ed25519 Verification

### Objective
Verify signature against computed signing string.

### Scope (Must Do)
- `crypto::verify_ed25519(signature_b64, signing_string, verifying_key) -> Result<(), GatewardenError>`
- Positive and negative vectors (mutated body/date/signature)

### Non-Goals
- No freshness checks

### Gate
```bash
cargo test crypto_signature_vectors
```

---

## Slice 05 — Freshness Enforcement (Replay + Future)

### Objective
Reject replayed or future-dated responses with deterministic clock.

### Scope (Must Do)
- Parse RFC 2822 date
- Reject >5 minutes old
- Reject >60s future
- Use `Clock` seam for deterministic tests

### Gate
```bash
cargo test freshness_vectors
```

---

## Slice 06 — Digest Header Comparison (When Present)

### Objective
Compare computed digest to `Digest` header and reject mismatches.

### Scope (Must Do)
- Parse `Digest: sha-256=<base64>`
- If present: compare to computed digest
- If absent: proceed (documented)

### Gate
```bash
cargo test digest_mismatch_vectors
```

---

## Slice 07 — Protocol Models + LicenseState Extraction

### Objective
Deserialize Keygen JSON and normalize into `LicenseState`.

### Scope (Must Do)
- Protocol structs in `protocol/` (Keygen validate response)
- `LicenseState` extraction:
  - `valid`
  - `entitlements` (scoped)
  - `expires_at` (parsed to UTC)
  - `meta` (code/detail)
- Fixture tests for multiple response shapes

### Gate
```bash
cargo test protocol_fixtures
```

---

## Slice 08 — Authenticated Cache Record Format + Verification on Load

### Objective
Cache is a security boundary: it must be tamper-evident and re-verified.

### Scope (Must Do)
- Define cache record:
  - `date`, `signature`, `body`, `cached_at`
- Verify on load:
  - freshness check (or cache-age policy; define explicitly)
  - signature verification
  - digest comparison if stored header included
- Tests: tamper body/date/signature must fail `CacheTampered`

### Gate
```bash
cargo test cache_tamper_vectors
```

---

## Slice 09 — File Cache Backend (Atomic)

### Objective
Persist authenticated cache record on disk.

### Scope (Must Do)
- Store under `dirs::data_dir()/cache_namespace/`
- Atomic write (temp file + rename)
- Read/verify roundtrip tests

### Gate
```bash
cargo test cache_roundtrip_file_backend
```

---

## Slice 10 — Usage Meter Store (Clocked)

### Objective
Implement usage metering and deterministic rollover.

### Scope (Must Do)
- `UsageStats` persisted to disk
- Rollover rules:
  - daily resets daily
  - monthly resets monthly
- Uses `Clock` seam

### Gate
```bash
cargo test meter_rollover_vectors
```

---

## Slice 11a — HTTP Client: Raw Request + Header Capture

### Objective
Call Keygen validate endpoint and capture headers + body without policy.

### Scope (Must Do)
- Build reqwest client
- POST validate-key
- Capture:
  - status
  - `Keygen-Signature` (if any)
  - `Date` / `Keygen-Date`
  - `Digest` (if any)
  - raw body bytes
- Mock server tests

### Gate
```bash
cargo test client_parses_headers
```

---

## Slice 11b — User-Agent Builder (Config-Driven)

### Objective
Create deterministic User-Agent string from config.

### Scope (Must Do)
- `client::build_user_agent(config) -> String`
- Tests verify exact string format (stable)

### Gate
```bash
cargo test user_agent_vectors
```

---

## Slice 12a — Verification Pipeline Composer (Headers+Body → VerifiedBody)

### Objective
Compose digest + signature + freshness checks into one verified step.

### Scope (Must Do)
- Input: captured headers + raw body
- Output: verified raw body (bytes) or error
- Fail-closed on missing signature/date (per v0 decision)

### Gate
```bash
cargo test verification_pipeline_vectors
```

---

## Slice 12b — Online Validate: Verify → Parse → Cache Write

### Objective
End-to-end online validation pipeline.

### Scope (Must Do)
- Call Keygen (11a)
- Verify (12a)
- Parse (07)
- Persist authenticated cache record (09)

### Gate
```bash
cargo test online_pipeline_happy_path
```

---

## Slice 13 — Offline Fallback Policy (Authenticated Cache + Grace)

### Objective
If online fails, allow offline only when cache is authenticated and within grace.

### Scope (Must Do)
- `offline_grace` enforced
- Fail-closed on:
  - tampered cache
  - expired grace

### Gate
```bash
cargo test offline_fallback_policy
```

---

## Slice 14 — Access Policy (Entitlements + Usage Caps)

### Objective
Decide whether feature is allowed based on config + LicenseState + UsageStats.

### Scope (Must Do)
- Require all `required_entitlements` codes
- Enforce monthly cap if present (from Keygen attributes mapping)
- Typed errors:
  - missing license
  - invalid license
  - feature not enabled
  - usage limit exceeded

### Gate
```bash
cargo test policy_vectors
```

---

## Slice 15 — Public API Freeze (LicenseManager)

### Objective
Publish stable, minimal API surface for consumers.

### Scope (Must Do)
- `LicenseManager::new(config, clock)`
- `load()`
- `validate_key()`
- `check_access()`
- `record_usage()`
- Rustdoc examples

### Gate
```bash
cargo clippy -- -D warnings
cargo test
cargo doc
```

---

## Slice 16a — Shimmy: Add Dependency (No Behavior Change)

### Objective
Introduce Gatewarden dependency without switching runtime behavior.

### Scope (Must Do)
- Add gatewarden crate dependency
- Compile-only integration smoke test

### Gate
```bash
shimmy CI green
```

---

## Slice 16b — Shimmy: Feature-Flagged Switch (Dual Path)

### Objective
Add `use_gatewarden` feature to switch implementations.

### Scope (Must Do)
- Feature flag chooses Gatewarden vs legacy
- Equivalence tests run both paths against identical fixtures

### Gate
```bash
shimmy CI green
```

---

## Slice 16c — Shimmy: Remove Legacy Licensing

### Objective
Remove old licensing module once Gatewarden is proven.

### Scope (Must Do)
- Delete `vision_license.rs` usage
- Update docs

### Gate
```bash
shimmy CI green
```

---

# Copilot / Agent Instructions (Repository Hygiene)

## Slice X — Add `.github/copilot-instructions.md`

### Objective
Ensure AI agents operate under Slice-Gated rules and do not introduce scope creep.

### Scope (Must Do)
- Create `.github/copilot-instructions.md` with:
  - “One slice at a time” rule
  - “No behavior changes without a slice” rule
  - “Fail-closed security boundary” rule
  - Required gate commands per PR

### Gate
- File exists
- Contains explicit slice execution rules

---

# Risk / Assumption Audit (Critique-First)

1. **Keygen header availability**: failing closed on missing signature/date can cause unexpected runtime failures if Keygen does not send them consistently. This is intentional for security, but must be validated with real traffic before rollout.
2. **Digest header variance**: the plan compares digest only when present; if Keygen varies digest behavior, this is safe but may reduce defense-in-depth.
3. **Cache privacy**: storing raw response bodies may persist sensitive metadata. Consumers must accept this, or v1 must introduce a redacted cache format.
4. **Usage cap semantics**: mapping `max_uses/uses` into “monthly cap” assumes Keygen policy alignment. This must be verified per-product.
5. **Clock dependency**: freshness enforcement assumes system clocks are reasonable. If end-user clocks drift heavily, fail-closed behavior may be triggered.

# Action Items for Verification
- Capture at least one real Keygen validate response (redacting license key) to confirm header behavior, especially signatures and date.
- Confirm whether Keygen sends `Digest` header in production for your account.
- Confirm that `max_uses` corresponds to the intended cap policy for each product.
- Decide whether cache should store raw body or a minimized authenticated payload.

# Flagged Claims (Statements a hostile reviewer will challenge)
- “Offline is safe.” Only true if cache is authenticated and grace is tight.
- “MITM is prevented.” Only true if signature verification is always required and fail-closed.
- “Replay is prevented.” Only within the tested freshness window and with sane clocks.
- “Equivalence to shimmy.” Only true if dual-path tests demonstrate identical outcomes on fixtures.

