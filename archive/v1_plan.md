# Gatewarden Slice‑Gated Implementation Plan

This document converts the agreed Gatewarden Golden Spec into **copy‑paste‑ready slice tickets**, each independently verifiable, shippable, and auditable. The slices are ordered and gated. **No slice may proceed until its gate is green.**

---

## Slice 01 — Crate Skeleton & Lint Gate

### Objective
Create the `gatewarden` crate skeleton with strict linting, module layout, and CI‑ready defaults.

### Scope (Must Do)
- Create private Rust crate `gatewarden/`
- Add module scaffolding:
  - `crypto/`
  - `protocol/`
  - `client/`
  - `cache/`
  - `meter/`
  - `policy/`
  - `errors/`
  - `integrations/`
- Enable `#![deny(warnings)]`
- Enable clippy pedantic baseline

### Non‑Goals
- No Keygen logic
- No IO
- No async runtime use

### Gate
```bash
cargo clippy -- -D warnings
cargo test
```

---

## Slice 02 — Deterministic Digest & Signing String Builder

### Objective
Implement deterministic SHA‑256 digest and Keygen signing‑string construction.

### Scope (Must Do)
- Implement `crypto::sha256_b64(body: &[u8]) -> String`
- Implement `crypto::build_signing_string(method, path, date, digest)`
- Exact format compliance:
  - lowercase headers
  - exact ordering
  - no trailing newline

### Non‑Goals
- No signature verification
- No HTTP

### Gate
```bash
cargo test crypto_signing_string_vectors
```

---

## Slice 03 — Signature Header Parsing & Ed25519 Verification

### Objective
Parse `Keygen-Signature` header and verify Ed25519 signatures.

### Scope (Must Do)
- Parse signature header fields
- Enforce algorithm == `ed25519`
- Decode public key once via `once_cell`
- Verify against signing string

### Non‑Goals
- No freshness checks
- No HTTP

### Gate
```bash
cargo test crypto_signature_vectors
```

---

## Slice 04 — Response Freshness Enforcement

### Objective
Reject replayed or future‑dated responses.

### Scope (Must Do)
- RFC‑2822 date parsing
- Reject responses older than 5 minutes
- Reject responses >60s in future

### Non‑Goals
- No signature logic

### Gate
```bash
cargo test freshness_vectors
```

---

## Slice 05 — Digest Header Comparison

### Objective
Compare computed digest to response `Digest` header when present.

### Scope (Must Do)
- Parse `Digest: sha-256=<base64>` header
- Reject mismatches
- Ignore absence (documented behavior)

### Non‑Goals
- No requirement that Digest header exist

### Gate
```bash
cargo test digest_mismatch_vectors
```

---

## Slice 06 — Protocol Models & LicenseState Extraction

### Objective
Deserialize Keygen responses and extract normalized `LicenseState`.

### Scope (Must Do)
- Implement protocol structs
- Extract entitlements
- Extract expiry
- Preserve meta codes

### Non‑Goals
- No policy decisions

### Gate
```bash
cargo test protocol_fixtures
```

---

## Slice 07 — Authenticated Cache Format & Verification

### Objective
Define authenticated cache format and verify on load.

### Scope (Must Do)
- Cache record includes:
  - raw body
  - signature
  - date
  - cached_at
- Re‑verify signature + freshness on load
- Reject tampering

### Non‑Goals
- No file IO yet

### Gate
```bash
cargo test cache_tamper_vectors
```

---

## Slice 08 — File‑Based Cache Backend

### Objective
Persist authenticated cache to disk.

### Scope (Must Do)
- Use `dirs::data_dir()`
- Namespace via config
- Atomic write strategy

### Non‑Goals
- No SQLite backend

### Gate
```bash
cargo test cache_roundtrip_file_backend
```

---

## Slice 09 — Usage Meter Store

### Objective
Implement usage counters and reset rules.

### Scope (Must Do)
- Daily + monthly counters
- Deterministic clock injection
- File persistence

### Non‑Goals
- No entitlement logic

### Gate
```bash
cargo test meter_rollover_vectors
```

---

## Slice 10 — Keygen HTTP Client

### Objective
Implement HTTP client and header capture.

### Scope (Must Do)
- reqwest client
- Custom User‑Agent
- Capture headers + body
- No parsing yet

### Non‑Goals
- No policy

### Gate
```bash
cargo test client_parses_headers
```

---

## Slice 11 — Online Validation Pipeline

### Objective
Verify, parse, and cache online validation results.

### Scope (Must Do)
- Verify digest
- Verify signature
- Enforce freshness
- Parse protocol
- Write authenticated cache

### Non‑Goals
- No offline fallback

### Gate
```bash
cargo test online_pipeline_happy_path
```

---

## Slice 12 — Offline Fallback Policy

### Objective
Allow offline validation using authenticated cache within grace window.

### Scope (Must Do)
- Enforce grace duration
- Fail closed on expired or tampered cache

### Non‑Goals
- No entitlement checks

### Gate
```bash
cargo test offline_fallback_policy
```

---

## Slice 13 — Access Policy & Entitlements

### Objective
Enforce required entitlements and usage caps.

### Scope (Must Do)
- Required entitlement codes
- Monthly usage cap logic
- Typed errors

### Non‑Goals
- No HTTP mapping

### Gate
```bash
cargo test policy_vectors
```

---

## Slice 14 — Public API Finalization

### Objective
Freeze public API and documentation.

### Scope (Must Do)
- Expose `LicenseManager`
- Hide internals
- Rustdoc examples

### Gate
```bash
cargo test
cargo doc
```

---

## Slice 15 — Shimmy Vision Migration

### Objective
Replace shimmy‑vision licensing with Gatewarden.

### Scope (Must Do)
- Integrate Gatewarden
- Preserve behavior equivalence
- Migration tests

### Gate
```bash
shimmy CI green
```

---

## Slice Rules (Non‑Negotiable)
- Each slice must compile and test independently
- No speculative refactors
- No behavior changes without a new slice
- All security decisions must be explicit and test‑gated

