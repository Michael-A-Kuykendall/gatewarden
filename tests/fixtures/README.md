# Test Fixtures

This directory contains test vectors for Gatewarden.

## Fixture Ownership

**Each slice owns its fixtures.** When implementing a slice, add the necessary test vectors here.

## Naming Convention

```
tests/fixtures/<module>/<test_name>.json
```

Examples:
- `crypto_signing_string/keygen_example_1.json`
- `signature_header/valid_ed25519.json`
- `freshness/stale_5min.json`

## Fixture Format

Each fixture should be a JSON file with:

```json
{
  "description": "Human-readable description of what this tests",
  "input": { ... },
  "expected": { ... }
}
```

## Prohibition

**Never make live Keygen API calls in unit tests.**

Real Keygen responses (redacted) may be captured for integration tests in a separate `tests/integration/` directory, but unit tests must use synthetic fixtures only.

## Slice Ownership Map

| Slice | Fixture Directory |
|-------|-------------------|
| 02 | `crypto_signing_string/` |
| 03 | `signature_header/` |
| 04 | `crypto_signature/` |
| 05 | `freshness/` |
| 06 | `digest_header/` |
| 07 | `protocol/` |
| 08 | `cache_tamper/` |
| 10 | `meter_rollover/` |
| 12a | `verification_pipeline/` |
| 14 | `policy/` |
