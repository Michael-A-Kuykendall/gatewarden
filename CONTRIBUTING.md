# Contributing to Gatewarden

Thank you for your interest in Gatewarden.

## Open Source, Not Open Contribution

Gatewarden is open source but not open contribution.

- The code is freely available under the MIT license
- You can fork, modify, use, and learn from it without restriction
- Pull requests are not accepted by default
- Architectural decisions are made by the project maintainer

This keeps the project coherent and the security model consistent.

## How to Contribute

If you believe you can contribute meaningfully:

1. Email the maintainer first: michaelallenkuykendall@gmail.com
2. Describe your background and proposed change
3. If aligned, a scoped collaboration may be discussed privately

Unsolicited PRs may be closed without merge.

## What We Welcome (via email first)

- Security review notes and threat-model feedback
- Bug reports with clear repro steps
- Documentation improvements
- Platform-specific fixes

## Development standards

If a contribution is discussed and approved:

- `cargo fmt`
- `cargo clippy -- -D warnings`
- `cargo test`
- No `unwrap()`/`expect()`/panics in library code paths
- Tests for security boundaries and failure modes
