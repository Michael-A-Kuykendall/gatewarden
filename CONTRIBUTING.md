# Contributing to Gatewarden

## Open Source, Not Open Contribution

Gatewarden is **open source** but **not open contribution**.

- The code is freely available under the MIT license
- You can fork, modify, use, and learn from it without restriction
- **Pull requests are not accepted by default**
- All architectural, roadmap, and merge decisions are made by the project maintainer

This model keeps the project coherent, maintains clear ownership of the security
model, and ensures the FSE patent threading remains consistent. It's the same
approach used by SQLite and many infrastructure projects.

## How to Contribute

If you believe you can contribute meaningfully to Gatewarden:

1. **Email the maintainer first**: [michaelallenkuykendall@gmail.com](mailto:michaelallenkuykendall@gmail.com)
2. Describe your background and proposed contribution
3. If there is alignment, a scoped collaboration may be discussed privately
4. Only after discussion will PRs be considered

**Unsolicited PRs will be closed without merge.** This isn't personal, it's how this project operates.

## What We Welcome (via email first)

- Security review notes and threat-model feedback (Issues or email)
- Bug reports with detailed reproduction steps (Issues are fine)
- Security vulnerability reports (please email directly)
- Documentation improvements (discuss first)

## What We Handle Internally

- New features and architectural changes
- FSE engine design and evolution
- Bridge API design decisions
- Dependency updates
- Performance optimizations
- Crypto pipeline modifications

## Bug Reports

Bug reports via GitHub Issues are welcome. Please include:
- Gatewarden version and Rust version
- Operating system
- Minimal reproduction case
- Expected vs actual behavior
- Whether you're using the library directly or through the bridge

## Code Style (for reference)

If a contribution is discussed and approved:
- Rust 2021 edition with `cargo fmt` and `cargo clippy -- -D warnings`
- `#![deny(warnings)]` and `#![deny(missing_docs)]` on the library crate
- All public APIs must have documentation
- No `unwrap()`/`expect()` in library code paths (tests are fine)
- Tests for security boundaries and failure modes
- Clock abstraction for time-dependent logic

## Why This Model?

Building security infrastructure requires tight architectural control. Gatewarden's
cryptographic verification pipeline, fail-closed semantics, and patent-threaded FSE
engine must remain internally consistent. This ensures:

- No regressions to the security model
- Consistent patent threading through the codebase
- Quality control without committee delays
- Clear direction for the project's future

The code is open. The governance is centralized. This is intentional.

## Recognition

Helpful bug reports and community feedback are acknowledged in release notes.
If email collaboration leads to merged work, attribution will be given appropriately.

---

**Maintainer**: Michael A. Kuykendall
