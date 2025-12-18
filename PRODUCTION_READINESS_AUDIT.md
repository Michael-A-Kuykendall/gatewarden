# Gatewarden Production Readiness Audit (v0.1.x)

**Scope:** Gatewarden crate only (not Shimmy). This is a “development-manager style” readiness checklist: what’s ready, what’s not, and what blocks production use.

**Audit date:** 2025-12-17

---

## Executive summary

Gatewarden’s core security-critical path (Keygen response verification + authenticated offline cache) is implemented with a fail-closed posture and has strong unit-test coverage around crypto primitives, freshness, cache tamper detection, and policy checks.

**What’s solid today**
- Crypto verification pipeline is *fail-closed* on missing `Date` or `Keygen-Signature` headers.
- Replay protection is enforced online (5-minute window + future tolerance).
- Offline cache is tamper-evident: cached records must re-verify signature/digest and obey `offline_grace`.
- Local persistence uses atomic write patterns.
- The library avoids runtime logging by default (reducing risk of leaking secrets).
- `cargo clippy -- -D warnings` and `cargo test` are clean.

**Primary gaps before “production-ready”**
- No visible CI workflows in the repo; there’s no automated enforcement of clippy/tests/security checks.
- Publishing/release posture: `publish = false` is set; crates.io release is not enabled.
- Usage-cap period semantics must be made explicit: Keygen’s `uses/maxUses` are counters; “monthly” behavior requires either (a) an external scheduled reset via Keygen’s usage actions or (b) local period-based metering.
- Docs claim “Enable Tracing” via `RUST_LOG=gatewarden=debug`, but current code has no `tracing` macro usage; either add structured logs carefully (no license key) or adjust docs.

---

## Readiness checklist (pass/fail)

Legend:
- ✅ **Pass**: meets bar for a production library.
- ⚠️ **Needs work**: acceptable for dev, but not “prod-ready” yet.
- ❌ **Fail / Blocker**: must be resolved before production release.

### 1) Build health & quality gates
- ✅ `cargo clippy -- -D warnings` passes (warnings denied).
- ✅ `cargo test` passes (unit + smoke + doc-tests behavior intentional).
- ✅ Library code avoids `panic!`/`expect()` and uses typed errors.
- ⚠️ Test-only `unwrap()` exists (fine), but keep it confined to `#[cfg(test)]`.

### 2) API stability & ergonomics
- ✅ Public API is small and clear: `GatewardenConfig`, `LicenseManager`, typed `GatewardenError`.
- ✅ Config validation exists (account id, public key format/length, namespace).
- ⚠️ Versioning/release policy isn’t described (SemVer expectations, breaking-change policy).

### 3) Security model (threats & mitigations)
- ✅ Threat model is documented in README.
- ✅ MITM/tampering mitigated by Ed25519 signature verification.
- ✅ Replay mitigated online via freshness checks (`Date` parsing + max age + future tolerance).
- ✅ Cache tampering mitigated by re-verification of signature/digest.
- ✅ License keys are not stored; cache keys are derived via SHA-256 hash.
- ⚠️ Consider explicitly documenting what data *is* persisted (headers/body of Keygen response) and retention behavior.

### 4) Crypto correctness & fail-closed behavior
- ✅ Signature and `Date` are required (missing => fail-closed).
- ✅ Digest verification is supported (mismatch => fail), and digest is optional per protocol.
- ✅ Signing-string canonicalization is tested with vectors.
- ✅ Public key decode is validated (hex length enforced).

### 5) Offline behavior & cache safety
- ✅ Offline grace is explicit (`offline_grace` duration).
- ✅ Offline fallback is constrained to transport errors (doesn’t silently accept “denied” online results).
- ✅ Cache records check for time tampering (future `cached_at` rejected).
- ✅ Filesystem writes are atomic (temp + rename).
- ⚠️ Consider adding a documented cache location override for environments with strict disk policies.

### 6) Policy enforcement (entitlements, usage)
- ✅ Entitlement enforcement is explicit and configurable.
- ⚠️ **Action required:** clarify and enforce usage period semantics.
  - Keygen exposes `uses` + `maxUses` counters and usage actions (increment/decrement/reset). This is not inherently “monthly” unless you reset usage on that cadence.
  - If the commercial policy is “monthly cap”, pick one:
    - (A) **Keygen-driven monthly:** run a backend job that calls Keygen’s reset-usage action monthly, then Gatewarden’s cap check matches Keygen counters.
    - (B) **App-driven monthly:** enforce a monthly meter locally (Gatewarden has a `UsageMeter` module that rolls over by UTC month, but it is not yet integrated into the validation path).

### 7) Observability & supportability
- ✅ Default behavior is silent (minimizes accidental secret logging).
- ⚠️ Docs mention `RUST_LOG=gatewarden=debug`, but no `tracing` macros are present.
  - Decide one:
    - (A) Add minimal structured `tracing` events (never log license keys), or
    - (B) Update docs to remove/replace tracing guidance.

### 8) CI / supply-chain / repo hygiene
- ❌ **Blocker:** no CI workflows found (expected: clippy/tests/fmt/audit).
- ⚠️ Add `cargo deny`/`cargo audit` equivalent to catch advisories (policy choice).
- ✅ SECURITY.md exists with responsible disclosure instructions.

### 9) Release / publishing readiness
- ❌ **Blocker (for crates.io):** `publish = false` currently configured.
- ⚠️ Define a release checklist (tagging, changelog, MSRV if any, CI gates, crate metadata completeness).

---

## Known blockers & explicit contracts

### Blocker A — crates.io publishing is disabled
- Current state: `publish = false` in Gatewarden’s `Cargo.toml`.
- Impact: any release gate expecting crates.io packaging/publishing will fail until this is flipped.
- Remediation: when ready, remove `publish = false` (or set `publish = true`) and run the release process.

### Blocker B — CI workflows are missing
- Current state: no GitHub Actions workflows were visible in `.github/workflows/`.
- Impact: there is no automated enforcement of clippy/tests/security checks.
- Remediation: add CI that runs clippy/tests on supported OS targets and blocks merges on failure.

---

## Evidence captured during audit

### Build + test gates
- `cargo clippy -- -D warnings`: PASS
- `cargo test`: PASS (102 unit tests + smoke test)

### Code hygiene scans (qualitative)
- No `panic!` or `expect()` patterns observed in library source.
- `unwrap()` usage appears confined to test code.
- No runtime logging macros observed in library source.

---

## Integration proof plan (Shimmy ↔ Gatewarden)

Goal: validate that Shimmy’s vision endpoints enforce licensing via Gatewarden correctly.

Expected behaviors (from Shimmy’s published invariants):
- Missing license: **402**
- Invalid license: **403**
- Valid license + required entitlement: **200** (or batch SSE start)

The functional proof is executed in Shimmy (consumer app) by:
1) Starting the vision server (via VS Code Task).
2) Sending requests using `.env` test licenses.

A short “Integration Results” section should be appended after running the live checks.

---

## Integration results (executed)

Environment:
- Shimmy vision server started via VS Code Task `shimmy-serve-vision`
- Bind: `127.0.0.1:11435`
- Requests sent with `curl` from the Shimmy workspace

Results:
- ✅ Missing license returns **402** when request includes required fields (`mode`): `POST /api/vision` with `{ "url": "https://example.com", "mode": "web", "screenshot": false }`.
- ✅ Invalid license returns **403**: `POST /api/vision` with `{ "license": "INVALID-KEY", "url": "https://example.com", "mode": "web", "screenshot": false }`.
- ✅ Valid license returns **200** using `.env` (`KEYGEN_TEST_LICENSE_VALID`) and local base64 fixture (`test_image.b64`): `POST /api/vision` with `{ "license": "$KEYGEN_TEST_LICENSE_VALID", "image_base64": "…", "mode": "ocr" }`.

Note:
- A request omitting `mode` returns **422** (schema/validation), so license gating is reached only after required request fields are present.
