# Changelog

All notable changes to Gatewarden will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.2] - 2026-07-26

### Added

- **Offline usage metering revived (feature `meter`).** The client-side,
  offline-enforceable usage cap is back, reworked per the 0.4.2 plan:
  - **Per-license-keyed meter** (`src/meter/`), keyed by the license-key hash
    (the original 0.4.0 design was per-namespace).
  - `LicenseManager::record_use(key)` increments the local meter, persists it,
    and re-checks the cap — returning `UsageLimitExceeded` when the local count
    would exceed the Keygen `maxUses`. Enforced locally even when offline.
  - Local monthly count is now threaded into `check_access_with_usage` (the old
    `additional_uses: 0` no-op is gone), so every validation respects the local
    cap.
  - `GatewardenError::MeterIO` restored (gated behind `meter`).
  - `Selector::UsageRemaining` now reports the actual remaining uses
    (`max_uses - current_uses - local_metered`) instead of `Missing`.
- **Bridge: `POST /v1/record-use`** records a local use via `record_use` and
  returns `429` (`USAGE_LIMIT_EXCEEDED`) on cap breach. The bridge now builds
  gatewarden with the `meter` feature.
- **Bridge validation responses now surface usage caps** (`usage`: `maxUses`,
  `currentUses`, `remaining`) on both `/v1/validate-key` and `/v1/check-access`.

### Changed

- `UsageCaps.monthly_limit` renamed to `max_uses` to align with Keygen's
  `maxUses` terminology (breaking for direct consumers of the struct).

## [0.4.1] - 2026-07-26

### Security

- **Bridge rate-limiter bypass fixed.** The per-IP token bucket keyed off the
  caller-controlled `X-Forwarded-For` / `X-Real-IP` headers, letting a client
  reset its own bucket by spoofing a fresh IP on every request. The client IP
  is now taken from the real TCP peer address via `ConnectInfo`, which is not
  attacker-controllable.

### Changed

- Bumped direct `sha2` dependency to `0.11` to deduplicate `sha2`/`digest` in
  the tree (ed25519-dalek 3.0 pulls `sha2 0.11`; we were pinning `0.10`).
- Fixed a misleading bridge config error message (`[[profiles]]` →
  `[profiles.<name>]`).

## [0.4.0] - 2026-07-26

### Removed (breaking)

- **Unwired `meter` module** (`UsageMeter`, `UsageStats`) — this subsystem was
  never integrated into the validation pipeline. Removed along with the
  `GatewardenError::MeterIO` variant. The feature (client-side, offline-
  enforceable usage caps) is a candidate for a future release; it has been
  shelved with full recovery instructions in
  [`docs/shelved/usage-meter.md`](docs/shelved/usage-meter.md).
- **Empty `integrations` module** — placeholder with no implementation.
- **`crypto::pipeline::verify_response_signature_only`** — unused; the cache
  layer performs its own signature-only verification via `CacheRecord::verify`.
- **`protocol::models::parse_keygen_response`** — redundant; use
  `serde_json::from_slice`/`from_str` directly.

### Changed

- Refactored `LicenseManager` to share a single `enforce_policy` helper across
  the online, offline, and cached-access paths (removed 3× duplication).
- Fixed README documentation of the cache location (`dirs::data_dir()`).

## [0.3.0] - 2026-06-05

### Added

- **FSE policy engine integrated into validation pipeline** — The Fused Semantic
  Execution engine is now the authoritative policy decision point for all license
  validations. FSE achieves O(M) evaluation time where M = unique selectors,
  independent of rule count.
  - `LicenseManager` compiles an FSE plan at initialization via `compile_default_plan()`
  - Default rules cover signature verification, state validity, and entitlement checks
  - `validate_online()` executes FSE evaluation after crypto verification
  - Failed rule IDs are logged for debugging (e.g., "entitlements.required_0")

- **Event-driven FSE runtime API** (`src/policy/fse/runtime.rs`)
  - `RuntimeState` with incremental evaluation support
  - `apply(selector, value)` — apply a selector value to all dependent rules
  - `should_terminate()` — check for early exit condition
  - `finalize()` — fail-closed finalization of unresolved rules
  - Existing `execute()` function preserved for backward compatibility

- **Expanded FSE predicates** (`src/policy/fse/model.rs`)
  - `MinU64(n)` — value >= n
  - `Exists` — value != Missing
  - `InSet(Vec<String>)` — string membership check

- **Namespaced rule IDs** — All FSE rules now have structured IDs:
  - `crypto.*` — cryptographic checks (signature, digest, freshness)
  - `response.*` — Keygen API response fields
  - `entitlements.*` — entitlement-based rules
  - `usage.*` — usage cap rules (future)

- **Gatewarden-specific selectors** (`src/policy/fse/model.rs`)
  - `StateCode` → String ("VALID", "EXPIRED", "SUSPENDED", etc.)
  - `StateValid` → Bool (meta.valid field)
  - `Entitlements` → Vec\<String\> (user's entitlements)
  - `ExpiresAt` → Bool (presence check for expiration date)
  - `UsageRemaining` → U64 (future usage tracking, returns Missing currently)

- **GatewardenEvalInput** (`src/policy/fse/gatewarden_input.rs`)
  - Implements `EvalInput` trait for FSE engine
  - `from_validated_response()` constructor builds input from license state
  - Maps Keygen response fields to FSE selector values

- **Bridge FSE logging** — Bridge startup logs now show FSE plan stats per profile:
  ```
  INFO Profile 'prod': 5 rules, 4 unique selectors
  ```
  Failed FSE rules are logged with their IDs during validation.

### Changed

- **`RuntimeResult` structure** — Now returns `Vec<RuleOutcome>` instead of
  `Vec<RuleDecision>` to include rule IDs in outcomes.

### Testing

- **FSE compliance test suite** (`tests/fse_compliance.rs`)
  - Single-pass selector scanning verification
  - Fail-closed semantics on unresolved required rules
  - Early exit on all-required-resolved condition
  - Value broadcast property (one extract, multiple rules)
  - Selector deduplication at compile time

- **Expanded property-based tests** (`tests/fse_invariants.rs`)
  - Property: Adding rules with existing selectors doesn't increase scan count
  - Property: `selectors_scanned <= plan.selectors.len()`
  - Property: All required True → allow == true
  - Property: Any required False → allow == false
  - Property: New predicates (MinU64, Exists, InSet) match correctly
  - 1000+ generated test cases per property (proptest)

### Migration Guide (0.2.x → 0.3.0)

No breaking API changes. FSE integration is internal to `LicenseManager`.

If you were directly using FSE engine types from `fse-gatewarden` crate in 0.2.x,
update imports to use the new paths in `src/policy/fse/`.

---

## [0.2.0] - 2026-06-03

### Breaking Changes

- **`GatewardenConfig` fields are now owned `String` / `Vec<String>`** instead of `&'static str`
	/ `&'static [&'static str]`. Update your config construction:
	```rust
	// Before (0.1.x):
	app_name: "my-app",
	required_entitlements: &["PRO"],

	// After (0.2.0):
	app_name: "my-app".to_string(),
	required_entitlements: vec!["PRO".to_string()],
	```
	This change enables runtime config loading (from TOML, secrets stores, or
	Cloudflare Wrangler secrets) without requiring `'static` lifetimes.

### Added

- **Bridge binary (`gatewarden-bridge`)** — a language-agnostic HTTP sidecar that
	exposes Gatewarden validation over a local JSON API (`127.0.0.1:4760`). TypeScript,
	Python, Go, Ruby, and any other runtime can validate licenses without
	reimplementing Ed25519 signature verification.
	- `GET  /v1/health` — readiness probe
	- `POST /v1/validate-key` — always validates against Keygen
	- `POST /v1/check-access` — cache-first, with offline grace period
	- `GET  /.well-known/openapi.json` — self-describing API spec
	- Multi-profile: one bridge instance serves multiple products/plans
	- Config loaded from TOML at startup; no secrets in source code

- **Cloudflare Workers bridge template** (`templates/cloudflare-worker/`) — an
	opt-in, zero-binary deployment path for teams already using Cloudflare. Exposes
	the same HTTP contract as the local sidecar.
	- Ed25519 response signature verification via Web Crypto API
	- Response freshness check (5-minute window) and body digest verification
	- Offline cache via CF KV (optional KV namespace binding)
	- Secrets via `wrangler secret put` — never hardcoded
	- Constant-time access token comparison (`X-Bridge-Token`)
	- License keys are never stored; only SHA-256 hash used as cache key

- **Stripe webhook hardening** (`cloudflare-worker/stripe-keygen-webhook.js`):
	- Constant-time HMAC signature comparison (prevents timing attacks on webhook
		signature verification)
	- Idempotency guard: duplicate Stripe events are detected and ignored using
		a KV-backed store (`STRIPE_IDEMPOTENCY_KV`) with 24-hour TTL
	- Error responses no longer leak internal error messages to callers

- **Bridge security hardening** (`bridge/`):
	- Bearer token authentication via `X-Bridge-Token` header — constant-time
		comparison prevents timing attacks; token set via `bearer_token` in bridge
		TOML config or environment; requests without a valid token receive 401
	- Per-IP token-bucket rate limiting — configurable `rate_limit_rps` (default 30
		RPS, burst = 3×); callers exceeding burst receive 429; buckets pruned after 60s
		of inactivity to prevent memory growth

- **FSE-compliant policy engine** (`fse-gatewarden/`) — a new crate implementing
	the Fused Semantic Execution architecture for license policy evaluation:
	- Selector deduplication at compile time via `compile_rules()` — N rules sharing
		M selectors evaluate in O(M) time, not O(N)
	- Single-pass evaluation: `execute(&plan, &input)` scans each unique selector once
	- Fail-closed semantics: unresolved required rules → False/deny; a missing or false
		`bridge_token_valid` input denies even when all other signals are valid
	- `default_security_rules()` covers the standard Gatewarden invariants
		(signature, digest, freshness, entitlement, bridge-token chain)
	- 9 FSE invariant tests + head-to-head benchmark proving O(unique_selectors) property:
		`selectors_scanned` stays constant at 6 regardless of rule count (6 → 200)


### Fixed

- Example `examples/basic_validation.rs` updated for `String` field types

### Migration Guide (0.1.x → 0.2.0)

1. Add `.to_string()` to all `&'static str` fields in your `GatewardenConfig`.
2. Change `required_entitlements: &["CODE"]` to `required_entitlements: vec!["CODE".to_string()]`.
3. No changes to `LicenseManager::new()`, `validate_key()`, or `check_access()` call sites.

---

## [0.1.2] - 2025-12-18

### Fixed
- Fix CI and License badge URLs (wrong GitHub org)
- Add GitHub repo description and topics

## [0.1.1] - 2025-12-18

### Fixed
- Fix README logo URL (use `master` branch, not `main`)

## [0.1.0] - 2025-12-18

### Added
- Initial release of Gatewarden
- Ed25519 response signature verification (MITM prevention)
- SHA-256 digest verification (body tampering detection)
- Response freshness enforcement (5-minute replay window)
- Authenticated offline caching with configurable grace period
- `LicenseManager` public API for license validation
- `validate_key()` - online validation with signature verification
- `check_access()` - cache-first access check
- Support for Keygen entitlements via `required_entitlements` config
- Usage cap tracking via `UsageCaps` struct
- File-based atomic cache backend
- Clock abstraction for deterministic testing

### Security
- Fail-closed security model: missing signatures/headers result in rejection
- License keys are never logged or persisted (cache keyed by SHA-256 hash)
- Constant-time signature verification via ed25519-dalek
