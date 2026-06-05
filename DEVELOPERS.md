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

## FSE Policy Evaluation

The Fused Semantic Execution (FSE) engine is the authoritative policy decision
point for license validation. It evaluates rules in a single pass, scanning each
unique selector only once regardless of how many rules reference it.

### Architecture

FSE operates in two phases:

**1. Compile (at startup)**
- `LicenseManager::with_clock()` calls `compile_default_plan(config)`
- Default rules: signature verified, state valid, required entitlements
- Selectors are deduplicated into a `CompiledPlan`
- Each rule gets a namespaced ID (e.g., "entitlements.required_0")

**2. Execute (per validation request)**
- `validate_online()` builds a `GatewardenEvalInput` from the response
- `execute(plan, input)` loops over unique selectors, not rules
- Each selector value is extracted once and broadcast to all dependent rules
- Early exit when all required rules are resolved
- Fail-closed: unresolved required rules → False

### Selectors

Current selectors in `src/policy/fse/model.rs`:

| Selector | Returns | Used For |
|----------|---------|----------|
| `SignaturePresent` | Bool | Crypto verification result |
| `StateCode` | String | License state code ("VALID", "EXPIRED", etc.) |
| `StateValid` | Bool | `meta.valid` from response |
| `Entitlements` | Vec\<String\> | User's entitlements |
| `ExpiresAt` | Bool | Presence check for expiration date |
| `UsageRemaining` | U64 | Future usage tracking |

### Predicates

Available predicates in `src/policy/fse/model.rs`:

| Predicate | Matches When |
|-----------|--------------|
| `BoolIsTrue` | value == true |
| `EqString(s)` | value == s |
| `ContainsString(s)` | Vec\<String\> contains s |
| `InSet(vec)` | value in vec |
| `MinU64(n)` | value >= n |
| `MaxU64(n)` | value <= n |
| `Exists` | value != Missing |

### Adding a New Selector

1. Add the variant to `Selector` in `src/policy/fse/model.rs`
2. Update `GatewardenEvalInput::value_for()` in `src/policy/fse/gatewarden_input.rs`
3. Add unit tests in `src/policy/fse/mod.rs`
4. Add property tests in `tests/fse_invariants.rs`
5. Run `cargo test --lib policy::fse && cargo test --test fse_invariants`

### Adding a New Rule

To add a custom rule beyond the defaults:

```rust
use gatewarden::policy::fse::{Rule, Selector, Predicate};

let custom_rule = Rule {
    id: "custom.max_usage".to_string(),
    selector: Selector::UsageRemaining,
    predicate: Predicate::MinU64(100),
    required: true,
};

// Then recompile the plan with your custom rules
let mut all_rules = default_rules(&config);
all_rules.push(custom_rule);
let plan = compile_rules(&all_rules)?;
```

### Testing FSE Rules

**Unit tests** in `src/policy/fse/mod.rs` test individual predicates:
```bash
cargo test --lib policy::fse
```

**Invariant tests** in `tests/fse_invariants.rs` verify FSE properties:
```bash
cargo test --test fse_invariants --release
```

**Compliance tests** in `tests/fse_compliance.rs` verify fail-closed semantics:
```bash
cargo test --test fse_compliance
```

### Bridge FSE Logging

The bridge logs FSE plan stats at startup:

```
INFO Profile 'prod': 5 rules, 4 unique selectors
INFO Profile 'dev': 3 rules, 3 unique selectors
```

When a rule fails, the rule ID is logged:
```
WARN FSE rule failed: entitlements.required_0
```

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
