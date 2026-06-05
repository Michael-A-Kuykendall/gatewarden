# Release Process

## Version Scheme

Gatewarden follows [Semantic Versioning](https://semver.org/):

- **MAJOR** — Breaking API changes (field type changes, removed methods)
- **MINOR** — New features, new public API surface (backward compatible)
- **PATCH** — Bug fixes, documentation, internal refactors (no API changes)

## Cutting a Release

### 1. Pre-flight Checks

```bash
# All tests pass
cargo test --workspace

# No warnings
cargo build --workspace

# Clippy clean
cargo clippy --workspace -- -D warnings

# Docs generate cleanly
cargo doc --no-deps

# Format is consistent
cargo fmt --check
```

### 2. Version Bump

Update version strings in:
- `Cargo.toml` (root crate)
- `bridge/Cargo.toml` (package version AND gatewarden dep version)

### 3. Update CHANGELOG.md

Add a new section at the top following [Keep a Changelog](https://keepachangelog.com/):

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- ...

### Fixed
- ...

### Changed
- ...
```

### 4. Commit and Tag

```bash
git add -A
git commit -m "chore: release vX.Y.Z"
git tag vX.Y.Z
git push origin master --tags
```

### 5. Publish

The `publish.yml` CI workflow triggers on tag push and runs:
- `cargo publish` for the `gatewarden` crate
- Bridge binary builds are uploaded as GitHub Release assets (manual for now)

### 6. Post-Release

- Verify crate appears on [crates.io/crates/gatewarden](https://crates.io/crates/gatewarden)
- Verify docs appear on [docs.rs/gatewarden](https://docs.rs/gatewarden)
- Update ROADMAP.md to move completed items

## Hotfix Process

For critical fixes to an already-released version:

1. Branch from the release tag: `git checkout -b hotfix/vX.Y.Z vX.Y.Z`
2. Apply the fix
3. Bump patch version
4. Follow the normal release flow from step 3 onward

## Bridge Binary Releases

Bridge binaries are cross-compiled for:
- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

These are attached to the GitHub Release as assets.
