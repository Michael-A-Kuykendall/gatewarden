# Copilot Instructions (Gatewarden)

## Project Overview
Gatewarden is a **private Rust crate** providing hardened Keygen.sh license validation infrastructure. It will be reused across multiple commercial products (shimmy-vision, crabcamera-pro, future products).

## Non-Negotiables

### Build Rules
- Zero tolerance for warnings: `cargo clippy -- -D warnings` must pass
- All tests must pass: `cargo test`
- No `unwrap()` or `expect()` in library code (use `?` or explicit error handling)
- No panics in library code

### Slice-Gated Development
- **NEVER** work on code outside the current slice
- **ALWAYS** check the gate before moving to next slice
- **NO** speculative refactors or "while I'm here" changes
- Each slice must compile and test independently

### Security Rules
- **NEVER** log license keys, even at debug level
- **NEVER** include license keys in error messages
- **ALWAYS** use constant-time comparison for signatures
- **NEVER** skip signature verification (even in tests, use explicit bypass)
- Public key and account ID come from consumer config, not hardcoded

## Terminal Command Rules (Windows/Git Bash)
- Use `py` not `python3` on Windows
- Do not use `!` in bash commands
- Do not use quoted heredocs (`<< 'EOF'`) when command substitution is needed - use `jq` instead
- Add `--max-time` to curl for any HTTP requests

## Module Structure
```
src/
├── lib.rs           # Public API surface
├── config.rs        # GatewardenConfig
├── crypto/
│   ├── mod.rs
│   ├── digest.rs    # SHA-256 digest
│   ├── signing.rs   # Signing string builder
│   └── verify.rs    # Ed25519 verification
├── protocol/
│   ├── mod.rs
│   └── models.rs    # Keygen response structs
├── client/
│   ├── mod.rs
│   └── http.rs      # reqwest client
├── cache/
│   ├── mod.rs
│   ├── format.rs    # Authenticated cache format
│   └── file.rs      # File backend
├── meter/
│   ├── mod.rs
│   └── usage.rs     # Usage counters
├── policy/
│   ├── mod.rs
│   └── access.rs    # Entitlement enforcement
└── errors.rs        # GatewardenError enum
```

## Testing Rules
- Use `#[cfg(test)]` for test-only code
- Use `MockClock` for time-dependent tests (never `chrono::Utc::now()` in tests)
- Test fixtures go in `tests/fixtures/`
- Name tests after the vector they verify: `test_signing_string_keygen_example_1`

## Current Slice
**CHECK THE PLAN** at `IMPLEMENTATION_PLAN.md` before ANY work.

## Dependencies (Approved)
```toml
ed25519-dalek = "2"
sha2 = "0.10"
base64 = "0.22"
hex = "0.4"
chrono = { version = "0.4", features = ["serde"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
reqwest = { version = "0.12", features = ["json"] }
tokio = { version = "1", features = ["sync", "fs"] }
thiserror = "2"
tracing = "0.1"
dirs = "5"
once_cell = "1"
```

## What NOT to Do
- Do NOT publish to crates.io (private crate)
- Do NOT add axum/http dependencies in core (optional integration only)
- Do NOT use `Box<dyn Error>` - use typed `GatewardenError`
- Do NOT use `async-trait` - use `impl Future` where needed
- Do NOT add features without explicit approval

## Reference Documents
- Architecture prompt: `shimmy-workspace/docs/GATEWARDEN_ARCHITECTURE_PROMPT.md`
- Implementation plan: `IMPLEMENTATION_PLAN.md`
- Keygen signature docs: https://keygen.sh/docs/api/signatures/
- Keygen security docs: https://keygen.sh/docs/api/security/
