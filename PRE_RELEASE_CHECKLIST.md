# Pre-Release Checklist for v0.3.0

## Security & Secrets Audit

- [x] No secrets in git history (checked with `git log --all --full-history`)
- [x] No API keys or tokens in code (only test fixtures with dummy keys)
- [x] `.gitignore` properly configured for secrets (`.env`, `.env.*`, `.secrets`)
- [x] Account ID in copilot-instructions.md is test-only (6270bf9c... is documented)
- [ ] Run cleanup script to remove internal development artifacts

## FSE Patent Protection

- [x] `FSE_PATENT_LICENSE.md` created with clear use restrictions
- [x] `LICENSE` file updated to reference FSE patent restrictions
- [x] README updated with patent notice and license summary
- [x] Patent notice present in FSE source files (src/policy/fse/*.rs)
- [x] CHANGELOG documents FSE as patent-pending

## Repository Cleanup

- [ ] Remove Kiro IDE artifacts from history:
  - `.kiro/specs/**`
  - `.kiro/steering/**`
  - `resume_session.prompt.md`
  
- [ ] Remove GitHub Copilot artifacts from history:
  - `.github/copilot-instructions.md`
  
- [ ] Remove Chat Chronicle artifacts from history:
  - `.github/skills/chat-chronicle/**`

- [ ] Update `.gitignore` to prevent future commits of these files

## Code Quality

- [x] All tests passing (171/171)
- [x] Clippy clean (`cargo clippy -- -D warnings`)
- [x] Release build succeeds (`cargo build --release`)
- [x] No blocking TODOs or FIXMEs in code
- [x] Documentation complete (ARCHITECTURE, DEVELOPERS, CHANGELOG, ROADMAP)

## Version & Release Metadata

- [x] Version bumped to 0.3.0 in `Cargo.toml`
- [x] Bridge version bumped to 0.3.0 in `bridge/Cargo.toml`
- [x] CHANGELOG date set (2026-06-05)
- [x] ROADMAP marks v0.3.0 as "Current — Released"
- [ ] Git tag created: `v0.3.0`
- [ ] Tag pushed to origin

## Files to Remove (via git-filter-repo)

Run `bash cleanup_repo.sh` to execute:

```bash
# Kiro IDE artifacts
.kiro/specs/gatewarden-v0.2.1/*
.kiro/specs/gatewarden-v0.3.0/*
.kiro/steering/local-secrets-and-testing.md
resume_session.prompt.md

# GitHub Copilot artifacts
.github/copilot-instructions.md

# Chat Chronicle artifacts
.github/skills/chat-chronicle/SKILL.md
```

## Post-Cleanup Verification

After running `cleanup_repo.sh`:

- [ ] Verify file count: `git ls-files | wc -l`
- [ ] Verify removed files are gone: `git log --all --oneline -- .kiro`
- [ ] Check commit count: should be slightly less than 30 (original count)
- [ ] Test build: `cargo build --release`
- [ ] Test suite: `cargo test --all-features`

## Force Push Warning

⚠️ **After running cleanup_repo.sh, you MUST force-push:**

```bash
git push origin --force --all
git push origin --force --tags
```

This rewrites history. Anyone with a clone must re-clone.

## crates.io Publishing

After force-push is complete:

```bash
# Dry run first
cargo publish --dry-run

# If clean, publish
cargo publish
```

## Final Verification

- [ ] Visit crates.io and verify published successfully
- [ ] Clone fresh repo and verify builds
- [ ] Check docs.rs builds documentation correctly
- [ ] Create GitHub release from v0.3.0 tag
- [ ] Announce release (if applicable)

---

## Execution Order

1. ✅ Complete all "Security & Secrets Audit" items
2. ✅ Complete all "FSE Patent Protection" items
3. ✅ Complete all "Code Quality" items
4. ✅ Complete all "Version & Release Metadata" items
5. ⏭️ **NEXT:** Run `bash cleanup_repo.sh` (removes internal artifacts)
6. ⏭️ Verify removal worked, force-push
7. ⏭️ Tag v0.3.0, push tag
8. ⏭️ Publish to crates.io
9. ⏭️ Create GitHub release

---

**Current Status:** Ready for cleanup script execution.
