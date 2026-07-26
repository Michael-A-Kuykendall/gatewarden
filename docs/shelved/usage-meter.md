# Shelved Feature: Client-Side Usage Meter

**Status:** Shelved (removed from the build, preserved here for future revival)
**Removed in:** v0.4.0
**Last commit containing the full source:** `b6c49071c8579ea477b309c016cfb68e33d501bb`

---

## What it was

A local, file-backed usage counter (`UsageMeter` + `UsageStats`) that tracked
**daily / monthly / lifetime** usage counts with automatic, deterministic
rollover driven by the injectable [`Clock`](../../src/clock.rs) trait.

Original locations:

- `src/meter/mod.rs`
- `src/meter/usage.rs`

Key surface:

| Type / fn | Purpose |
|-----------|---------|
| `UsageStats` | Serde-serializable counters: `daily_count`, `monthly_count`, `lifetime_count`, plus `daily_date` / `monthly_period` markers for rollover |
| `UsageStats::increment(&Clock)` | Bumps all counters, resetting daily/monthly on UTC date/month change |
| `UsageMeter::new(PathBuf)` / `with_namespace(&str)` | File-backed store under `dirs::data_dir()/<namespace>/usage.json` |
| `UsageMeter::increment(&Clock)` | Increment + atomic persist (temp file + rename) |
| `UsageMeter::daily_count` / `monthly_count` / `lifetime_count` | Read current counts (rollover-aware) |

The code was clean, fully unit-tested (daily/monthly/year rollover, persistence,
reload), and idiomatic. Quality was **not** the reason for removal.

## Why it was shelved

It was **never wired into the system** — a sealed island:

1. `LicenseManager` exposed **no** `record_use()` / `consume()` entry point, so
   a consumer of the crate had no way to drive metering through the public API.
2. Every `check_access_with_usage(...)` call in `manager.rs` passed
   `additional_uses: 0`, so even the Keygen server-side cap check was a no-op.
3. The bridge's rate limiting is a separate token-bucket (`auth.rs`), unrelated
   to this meter.

Rather than ship dead public API on a published crate, it was removed and
documented here.

## Why we might want it back

**Client-side, offline-enforceable usage caps** are a legitimately valuable
feature for a licensing library — e.g. "500 calls/month, enforced locally even
when the client is offline," instead of trusting only Keygen's server-side
counter (which requires connectivity and a reset cadence you control).

## What it would take to make it real (design checklist)

This is a real feature, not a 5-minute reconnect. Before revival, decide:

- [ ] **Entry point:** add `LicenseManager::record_use(&self, key: &str) -> Result<(), GatewardenError>`
      that increments the meter, persists, and re-checks caps.
- [ ] **Wire the count in:** pass `meter.monthly_count(clock)` (not `0`) into
      `check_access_with_usage`, returning `UsageLimitExceeded` when local usage
      would exceed the Keygen `maxUses`.
- [ ] **Metering scope:** per-license-key vs per-install? (Meter file is
      per-namespace today; keying by license-key hash may be needed.)
- [ ] **Reset semantics:** does local monthly rollover align with Keygen's
      billing period, or is it independent?
- [ ] **Offline behavior:** does local metering keep counting during the offline
      grace window, and reconcile on the next online validation?
- [ ] **Restore the `GatewardenError::MeterIO` variant** (also removed in v0.4.0).
- [ ] Consider gating behind a `meter` cargo feature until stabilized.

## How to recover the exact original source

The complete original implementation (including its full test module) lives at
commit `b6c49071c8579ea477b309c016cfb68e33d501bb`:

```bash
# View the files
git show b6c49071c8579ea477b309c016cfb68e33d501bb:src/meter/usage.rs
git show b6c49071c8579ea477b309c016cfb68e33d501bb:src/meter/mod.rs

# Restore them into the working tree
git checkout b6c49071c8579ea477b309c016cfb68e33d501bb -- src/meter/mod.rs src/meter/usage.rs
```

Then re-add `pub mod meter;` to `src/lib.rs` and re-add the
`GatewardenError::MeterIO(String)` variant to `src/errors.rs`.
