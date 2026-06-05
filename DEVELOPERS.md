# Developer Guide

Internal reference for the project maintainer. See [CONTRIBUTING.md](CONTRIBUTING.md)
for the open-source participation model.

## Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Git

## Building

```bash
# Full workspace (library + bridge)
cargo build --workspace

# Library only
cargo build

# Bridge only
cargo build -p gatewarden-bridge

# Release build
cargo build --release --workspace
```

## Testing

```bash
# All tests (library + bridge + integration tests)
cargo test --workspace

# Library unit tests only
cargo test --lib

# FSE invariant tests
cargo test --test fse_invariants

# FSE head-to-head comparison tests
cargo test --test fse_head_to_head

# Bridge tests only
cargo test -p gatewarden-bridge

# Run with output visible
cargo test --workspace -- --nocapture
```

## Running the Bridge Locally

```bash
# Copy the example config
cp bridge/bridge.toml.example bridge.toml

# Edit with your Keygen credentials
$EDITOR bridge.toml

# Run
cargo run -p gatewarden-bridge -- bridge.toml

# Test it
curl -s http://127.0.0.1:4760/v1/health \
  -H "X-Bridge-Token: your-token" | jq
```

## Project Structure

```
gatewarden/
├── src/              ← Main library crate
├── bridge/           ← HTTP sidecar binary crate
├── tests/            ← Integration tests (FSE invariants, smoke tests)
├── examples/         ← Runnable examples
├── spec/             ← OpenAPI spec for the bridge
├── docs/             ← User-facing documentation
├── templates/        ← Deployment templates (Cloudflare Worker)
└── .github/          ← CI workflows, issue templates
```

## Code Conventions

- `#![deny(warnings)]` and `#![deny(missing_docs)]` on the library crate
- All public types must have doc comments
- Tests use real cryptographic test vectors (Ed25519 test keys in test modules)
- Clock abstraction (`Clock` trait) for deterministic time-dependent tests
- `#[cfg(any(test, feature = "test-seams"))]` for test-only public APIs

## Adding a New Selector to the FSE Engine

1. Add the variant to `Selector` in `src/policy/fse/model.rs`
2. Add a corresponding field to `EvalInput`
3. Implement `value_for()` for the new selector
4. Add test cases in `tests/fse_invariants.rs`
5. Run `cargo test --test fse_invariants` to confirm

## Release Checklist

1. Update version in root `Cargo.toml` and `bridge/Cargo.toml`
2. Update `bridge/Cargo.toml` gatewarden dependency version
3. Update `CHANGELOG.md`
4. Run `cargo test --workspace`
5. Run `cargo build --release --workspace`
6. Run `cargo doc --no-deps` — verify no warnings
7. Tag: `git tag vX.Y.Z`
8. Push: `git push origin master --tags`
9. CI publishes to crates.io automatically

## Useful Commands

```bash
# Check for compilation issues without building
cargo check --workspace

# Generate docs locally
cargo doc --no-deps --open

# Run clippy lints
cargo clippy --workspace -- -D warnings

# Format check
cargo fmt --check

# Format fix
cargo fmt
```
