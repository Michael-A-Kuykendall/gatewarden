# Changelog

All notable changes to Gatewarden will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
