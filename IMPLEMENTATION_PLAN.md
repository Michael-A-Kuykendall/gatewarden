# Gatewarden Slice-Gated Implementation Plan v3

This plan supersedes v2. It resolves the remaining ambiguities flagged in the v2 evaluation and tightens gates, semantics, and slice ownership.

---

## 0) Decisions Locked for v0 (Anti-Churn)

### D0.1 Entitlements abstraction
**v0 uses config-driven required codes**: `required_entitlements: &'static [&'static str]`.
- Future: optional `EntitlementSet` trait once v0 is stable.

### D0.2 Fixture ownership
**Each slice owns its fixtures.**
- Slice 00 creates structure + conventions only.
- Every slice that introduces logic must add/update fixtures that prove it.

### D0.3 Cache validity policy (resolved)
**v0 cache validity is governed by `offline_grace`.**
- Cache authenticity: must re-verify signature and digest (if digest header present/stored).
- Cache “freshness”: evaluate against `cached_at` and `offline_grace`, not the Keygen `Date` 5-minute replay window.
- Rationale: the 5-minute replay window applies to *live* responses. A cache is intentionally retained for offline operation.

### D0.4 Signature/header behavior (fail-closed)
**v0 requires signature + date headers. Missing headers fail-closed.**
- Missing signature/date results in `SignatureMissing`.
- This is explicitly test-gated.

### D0.5 Usage cap semantics (risk locked, verification required)
**v0 preserves current shimmy semantics** (mapping `max_uses/uses` into cap fields) but treats this as a *policy assumption*.
- Action item is mandatory: verify Keygen policy semantics (monthly vs lifetime).
- If verification shows mismatch, a dedicated slice will be added to correct mapping under a gate.

### D0.6 Clock injection and public API
**Public API does not expose Clock.**
- Default is `SystemClock`.
- Clock injection is available via an internal/test-only constructor or feature-gated constructor.

### D0.7 Copilot instructions
`.github/copilot-instructions.md` is considered **Slice 00b** and must be present before implementation begins.

---

## 1) Global Non-Negotiables
- Every slice must pass:
  - `cargo clippy -- -D warnings`
  - `cargo test`
- `#![deny(warnings)]` in `lib.rs`.
- No logging of license keys.
- Any change to trust boundaries must be represented by at least one failing test vector that becomes passing.

---

# Slice Tickets

## Slice 00 — Test Infrastructure Skeleton

### Objective
Create test directories, naming conventions, and fixture documentation.

### Scope (Must Do)
- Create:
  - `tests/`
  - `tests/fixtures/`
  - `tests/fixtures/README.md` describing:
    - how fixtures are named
    - how each slice must add fixtures for its logic
    - prohibition on live Keygen calls in unit tests

### Non-Goals
- Do not attempt to “pre-fill” fixtures for future slices.

### Gate
```bash
cargo test
```

---

## Slice 00b — Repository Agent Instructions

### Objective
Ensure AI agents and contributors follow Slice-Gated rules.

### Scope (Must Do)
- Add `.github/copilot-instructions.md` with:
  - one-slice-at-a-time rule
  - no behavior change without new slice
  - fail-closed security boundary rule
  - required gate commands

### Gate
- File exists and includes explicit Slice-Gated rules.

---

## Slice 01 — Crate Skeleton + Core Types (Config, Errors) + Deny Warnings

### Objective
Lock foundational types used by all subsequent slices.

### Scope (Must Do)
- Crate skeleton + modules:
  - `crypto/`, `protocol/`, `client/`, `cache/`, `meter/`, `policy/`, `errors/`, `integrations/`
- In `lib.rs`:
  - `#![deny(warnings)]`
- Define `GatewardenConfig` (public):
  - `app_name`, `feature_name`, `account_id`, `public_key_hex`
  - `required_entitlements`, `user_agent_product`
  - `cache_namespace`, `offline_grace`
- Define `GatewardenError` (public) minimally covering slices through 07:
  - `ConfigError(String)`
  - `SignatureMissing`
  - `SignatureInvalid`
  - `DigestMismatch`
  - `ResponseTooOld`
  - `ResponseFromFuture`
  - `ProtocolError(String)`
  - `KeygenTransport(String)`
  - `CacheIO(String)`
  - `CacheTampered`

### Non-Goals
- No clock seam in public API

### Gate
```bash
cargo clippy -- -D warnings
cargo test
```

---

## Slice 01.5 — Deterministic Clock Seam (Internal/Test)

### Objective
Provide deterministic time for tests without exposing clock in public API.

### Scope (Must Do)
- Add internal clock seam:
  - `trait Clock { fn now_utc(&self) -> chrono::DateTime<chrono::Utc>; }`
  - `SystemClock`
  - `MockClock` (cfg(test))
- Expose only internally:
  - `LicenseManager::new(config)` uses `SystemClock`
  - `LicenseManager::new_with_clock(config, clock)` available behind `cfg(test)` and/or `feature = "test-seams"`

### Gate
```bash
cargo clippy -- -D warnings
cargo test
```

---

## Slice 02 — Digest + Signing String Builder

### Objective
Implement deterministic primitives required for signature verification.

### Scope (Must Do)
- Implement:
  - `crypto::sha256_b64(body: &[u8]) -> String`
  - `crypto::build_signing_string(method, path, host, date, digest_b64) -> String`
- Add fixtures owned by this slice:
  - `tests/fixtures/crypto_signing_string/*.json`

### Gate
```bash
cargo test crypto_signing_string_vectors
```

---

## Slice 03 — Signature Header Parsing + Public Key Decode (Once)

### Objective
Parse signature header and decode the verifying key once.

### Scope (Must Do)
- Robust parsing:
  - extract `algorithm`, `signature`, and header list
- Enforce `algorithm == ed25519`
- Decode public key hex once (e.g., `once_cell`)
- Add fixtures owned by this slice:
  - `tests/fixtures/signature_header/*.json`

### Gate
```bash
cargo test signature_header_parsing_vectors
```

---

## Slice 04 — Ed25519 Verification

### Objective
Verify signature against computed signing string.

### Scope (Must Do)
- `crypto::verify_response_signature(...) -> Result<(), GatewardenError>`
- Add fixtures owned by this slice:
  - positive vector
  - mutated body
  - mutated date
  - corrupted signature

### Gate
```bash
cargo test crypto_signature_vectors
```

---

## Slice 05 — Freshness Enforcement (Replay + Future)

### Objective
Reject replayed or future-dated *live* responses.

### Scope (Must Do)
- Parse RFC 2822 date
- Reject >5 minutes old
- Reject >60s future
- Tests use `MockClock`
- Add fixtures owned by this slice:
  - `tests/fixtures/freshness/*.json`

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
- Add fixtures owned by this slice:
  - digest present match
  - digest present mismatch
  - digest absent

### Gate
```bash
cargo test digest_mismatch_vectors
```

---

## Slice 07 — Protocol Models + LicenseState Extraction

### Objective
Deserialize Keygen JSON and normalize into `LicenseState`.

### Scope (Must Do)
- Protocol structs under `protocol/`
- Normalize into `LicenseState`:
  - `valid`
  - `entitlements`
  - `expires_at` parsed to UTC
  - `meta` code/detail
- Add fixtures owned by this slice:
  - valid response
  - invalid response
  - missing scope
  - missing data attributes

### Gate
```bash
cargo test protocol_fixtures
```

---

## Slice 08 — Authenticated Cache Record + Verification on Load (Policy Resolved)

### Objective
Make cache tamper-evident and enforce offline validity via `offline_grace`.

### Scope (Must Do)
- Cache record includes:
  - `date`, `signature`, optional `digest`, `body`, `cached_at`
- On load:
  - verify signature (required)
  - compare digest if present
  - validate `now - cached_at <= offline_grace`
- Explicitly do **not** apply 5-minute replay window to cache.
- Add fixtures owned by this slice:
  - tamper body/date/signature => `CacheTampered`
  - expired grace => deterministic rejection

### Gate
```bash
cargo test cache_tamper_vectors
cargo test cache_grace_policy_vectors
```

---

## Slice 09 — File Cache Backend (Atomic)

### Objective
Persist authenticated cache record on disk.

### Scope (Must Do)
- Store under `dirs::data_dir()/cache_namespace/`
- Atomic write (temp + rename)
- Roundtrip tests

### Gate
```bash
cargo test cache_roundtrip_file_backend
```

---

## Slice 10 — Usage Meter Store (Clocked)

### Objective
Usage stats persistence + deterministic rollover.

### Scope (Must Do)
- `UsageStats` with daily/monthly counters
- Rollover rules via `Clock`
- File persistence
- Add fixtures owned by this slice:
  - daily rollover
  - monthly rollover

### Gate
```bash
cargo test meter_rollover_vectors
```

---

## Slice 11a — HTTP Client: Raw Request + Header Capture

### Objective
Call Keygen validate endpoint and capture headers + raw body.

### Scope (Must Do)
- Reqwest POST validate-key
- Capture:
  - status
  - signature header
  - date header
  - digest header
  - raw body bytes
- Mock server tests

### Gate
```bash
cargo test client_parses_headers
```

---

## Slice 11b — User-Agent Builder (Config-Driven)

### Objective
Build stable, deterministic User-Agent string.

### Scope (Must Do)
- `client::build_user_agent(config) -> String`
- Tests assert exact format

### Gate
```bash
cargo test user_agent_vectors
```

---

## Slice 12a — Verification Pipeline (Fail-Closed Explicit)

### Objective
Compose digest + signature + freshness checks into one verified step.

### Scope (Must Do)
- Input: captured headers + raw body
- Output: verified body bytes
- Rules:
  - missing signature/date => `SignatureMissing` (fail-closed)
  - digest mismatch => `DigestMismatch`
  - signature invalid => `SignatureInvalid`
  - stale/future => freshness errors
- Add fixtures owned by this slice:
  - **missing signature/date fails closed**

### Gate
```bash
cargo test verification_pipeline_vectors
cargo test verification_fails_closed_missing_sig
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

## Slice 13 — Offline Fallback (Authenticated Cache + Grace)

### Objective
If online fails, allow offline only when cache is authenticated and within grace.

### Scope (Must Do)
- Enforce `offline_grace`
- Fail-closed on:
  - tampered cache
  - expired cache

### Gate
```bash
cargo test offline_fallback_policy
```

---

## Slice 14 — Access Policy (Entitlements + Usage Caps)

### Objective
Enforce entitlements and cap semantics.

### Scope (Must Do)
- Require all `required_entitlements`
- Preserve shimmy cap mapping for v0:
  - map Keygen fields into cap fields exactly as legacy behavior
- Add explicit test vectors for cap logic (present/absent)

### Gate
```bash
cargo test policy_vectors
```

---

## Slice 14.5 — Keygen Cap Semantics Verification (Required Before Release)

### Objective
Prove whether `max_uses` is monthly or lifetime for your Keygen policy.

### Scope (Must Do)
- Document Keygen policy configuration and expected reset behavior
- Add an internal markdown note (private repo) describing verified semantics
- If mismatch discovered:
  - add a new corrective slice (14.6) to adjust mapping under tests

### Gate
- Document exists and is linked from crate-level docs.

---

## Slice 15 — Public API Freeze (LicenseManager)

### Objective
Freeze minimal API surface.

### Scope (Must Do)
- Public constructor uses `SystemClock` only:
  - `LicenseManager::new(config)`
- Public methods:
  - `load()`
  - `validate_key()`
  - `check_access()`
  - `record_usage()`
- `new_with_clock` is `cfg(test)` or `feature = "test-seams"`
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
Introduce Gatewarden dependency without switching behavior.

### Gate
```bash
shimmy CI green
```

---

## Slice 16b — Shimmy: Feature-Flagged Switch (Dual Path Equivalence)

### Objective
Add `use_gatewarden` feature and run equivalence tests.

### Scope (Must Do)
- Dual-path tests execute legacy and gatewarden against identical fixtures

### Gate
```bash
shimmy CI green
```

---

## Slice 16c — Shimmy: Remove Legacy Licensing

### Objective
Remove legacy implementation once proven.

### Gate
```bash
shimmy CI green
```

---

# Risk / Assumption Audit (Critique-First)

1. **Fail-closed signature requirement** may break if Keygen does not send signature/date consistently for your endpoint/account. This is intentional; verify early with real traffic.
2. **Cache stores raw response**; may persist metadata you later regret. If unacceptable, v1 must introduce a redacted authenticated cache format.
3. **System clock drift** can cause false failures (freshness checks). This is the cost of replay defense.
4. **Usage cap semantics** may be wrong if Keygen `max_uses` is lifetime. Slice 14.5 is required prior to release.

# Action Items for Verification
- Capture at least one real Keygen validate response (redacting license key) to confirm signature/date/digest header behavior.
- Verify Keygen policy reset behavior for `max_uses/uses` and document it (Slice 14.5).
- Decide whether caching raw response body is acceptable from a privacy standpoint; if not, schedule v1 redacted cache slice.

# Flagged Claims (Hostile Review Targets)
- “Offline is safe.” Only true if cache is authenticated and grace enforced.
- “MITM is prevented.” Only true if signature verification is mandatory and fail-closed.
- “Replay is prevented.” Only within the freshness window and with sane clocks.
- “Cap semantics are correct.” Only after Slice 14.5 verification.

