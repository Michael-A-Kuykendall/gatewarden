# Gatewarden Local Testing Guide

Run the offline workspace checks without Keygen credentials:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --no-default-features
```

## Live Keygen integration tests

Live tests are ignored by the normal suite because they contact Keygen and
require dedicated test credentials. Supply the following environment variables
through your local secret manager or another uncommitted source:

- `GATEWARDEN_TEST_ACCOUNT_ID`: Keygen account UUID.
- `GATEWARDEN_TEST_PUBLIC_KEY_HEX`: account Ed25519 verification key.
- `GATEWARDEN_TEST_LICENSE_KEY`: dedicated, active validation test license.
- `GATEWARDEN_TEST_ENTITLEMENT`: optional entitlement on the fixture.
- `GATEWARDEN_TEST_FINGERPRINT`: optional activated fixture fingerprint.

The validation fixture's policy requires a fingerprint-scoped, activated
machine. Run the preflight first and then explicitly run the live suite:

```bash
./scripts/keygen-fixture-preflight.sh
cargo test --test integration_live -- --ignored
```

The preflight must report `VALID`; the suite should execute seven tests.
The [fixture guide](docs/LIVE_KEYGEN_FIXTURE.md) describes the maintainer's local
secret loader, fixture recovery, and the separate live actions test. Actions
create and remove a machine and increment usage, so use a dedicated suitable test
license or the guide's temporary-license helper; do not use a customer license.

Never commit or print secret values. Test with a dedicated account or fixture,
and investigate failures rather than treating ignored tests as passed.
