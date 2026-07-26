# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
```

## Active Feature Context: Offline Usage Metering (target: 0.4.2)

This is the **headline feature in progress**. Read this before touching anything
under `src/meter/`, `Cargo.toml`'s `meter` feature, `LicenseManager`, or the
`UsageRemaining` FSE selector. Full plan lives in beads epic **`gatewarden-a1p`**
(tasks M1–M8); never start meter work without first running `bd show gatewarden-a1p`.

**What it is:** client-side, offline-enforceable usage caps ("500 calls/month,
enforced locally even offline") — a real differentiator vs. Keygen's server-side
`maxUses` (which needs connectivity). The public surface is `LicenseManager::record_use(key)`.

**History (why this looks like "dead code" — it is NOT):**
- v0.4.0 **deliberately** shelved `src/meter/` as unwired dead code to ship a clean
  release. That was a conscious decision, documented in `docs/shelved/usage-meter.md`
  and CHANGELOG 0.4.0 "Removed (breaking)". It was NEVER a bug.
- v0.4.1 shipped successfully (see its CHANGELOG).
- 0.4.2 revives the meter **properly**, wired into the public API and the enforcement path.

**Agreed design:**
- Gated behind a new cargo feature `meter` (non-breaking, additive API).
- **Per-license-keyed** meter (new working-tree design, keyed by license-key hash),
  superseding the original per-namespace design at `b6c49071c8579ea477b309c016cfb68e33d501bb`.
- `LicenseManager::record_use(key)` → increments meter, persists, re-checks cap
  (returns `UsageLimitExceeded` when exceeded).
- Thread the local count into `check_access_with_usage` (replaces the
  `additional_uses: 0` no-op at `manager.rs:202`); restore `GatewardenError::MeterIO`
  (gated); wire `UsageRemaining` (M5); bridge `/v1/record-use` + surface caps (M6).

**CRITICAL — current working-tree state (do not delete!):**
The offline usage meter is **revived and wired as of v0.4.2** (per-license-keyed,
feature-gated behind `meter`). It is no longer the old "unwired partial":
- `src/meter/{mod,usage}.rs` exist and are wired via `pub mod meter;` in
  `src/lib.rs` (cfg `meter`), re-exporting `UsageMeter`.
- `LicenseManager::record_use(key)` exists; local monthly count is threaded into
  `check_access_with_usage` (replacing the old `additional_uses: 0` no-op).
- `GatewardenError::MeterIO` is restored (gated behind `meter`).
- `Selector::UsageRemaining` reports the actual remaining uses.
- Bridge exposes `POST /v1/record-use` and surfaces usage caps on validate/check.

**Do NOT delete or re-shelve this subsystem.** It was lost once by being deleted
as "unwired dead code"; it is now wired. See CHANGELOG `[0.4.2]` and
`docs/shelved/usage-meter.md` (status: revived).

**Cross-session references:** `docs/shelved/usage-meter.md` (recovery + revival
notes), `gatewarden-sessions-combined.md` (full transcript of the meter saga +
how context got lost), beads `gatewarden-a1p` M1–M8.

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

