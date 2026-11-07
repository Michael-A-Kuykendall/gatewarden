# Live Keygen fixture

`tests/integration_live.rs` validates against the real Keygen API. This page
documents the fixture's lifecycle: which pieces must exist, how to check them,
and how to repair them. It contains no credential values; credentials live in
the secrets file and reach the tests through the service-secrets loader.

## Pieces

| Piece | Source | Notes |
|---|---|---|
| `GATEWARDEN_TEST_ACCOUNT_ID` | secrets file | Keygen account UUID |
| `GATEWARDEN_TEST_PUBLIC_KEY_HEX` | secrets file | Ed25519 verify key, 64 hex chars |
| `GATEWARDEN_TEST_LICENSE_KEY` | secrets file | Dedicated automated-testing license (ACTIVE) |
| `GATEWARDEN_TEST_ENTITLEMENT` | secrets file | Entitlement code on that license (optional) |
| `GATEWARDEN_TEST_FINGERPRINT` | optional env | Fixture machine fingerprint; defaults to `gatewarden-live-fixture-v1` |
| Fixture machine | Keygen | Machine with the fixture fingerprint, activated on the test license |

## Policy requirement

The fixture license's policy sets `requireFingerprintScope`. Consequences:

- Unscoped `validate_key` returns `valid: false` with code
  `FINGERPRINT_SCOPE_REQUIRED`, which Gatewarden reports as `InvalidLicense`.
  That is correct behavior, not a validation bug: the license is ACTIVE but
  the request did not satisfy the policy.
- The valid-flow checks (valid-license, cache, selector, entitlement) must use
  `validate_key_with_fingerprint` / `check_access_with_fingerprint` with the
  fixture fingerprint.
- The policy is strict with one machine slot, so the fixture fingerprint must
  have an activated machine. Scoped validation without one returns `NO_MACHINE`
(or `FINGERPRINT_SCOPE_MISMATCH` when the license has other machines).

## Preflight

Run this before the live suite. It reports fixture state without printing any
credential value (presence and length only):

```bash
source ../chat-chronicle/scripts/load-service-secrets.sh
./scripts/keygen-fixture-preflight.sh
```

| Preflight verdict | Meaning | Repair |
|---|---|---|
| `VALID` (exit 0) | Fixture is current | Run the suite |
| `NO_MACHINE` / `FINGERPRINT_SCOPE_MISMATCH` (exit 1) | Fixture machine missing or fingerprint wrong | Re-activate (below) |
| `FINGERPRINT_SCOPE_REQUIRED` (exit 1) | Scope not sent | Bug in caller; the tests always scope |
| `EXPIRED` / `SUSPENDED` (exit 1) | License no longer usable | Replace the test license, then re-activate |
| `NOT_FOUND` (exit 1) | Key deleted or wrong account | Fix credentials, then re-activate |

## Activation

Activate the fixture machine as the license itself (no admin token needed).
This consumes the test license's single machine slot:

```bash
source ../chat-chronicle/scripts/load-service-secrets.sh
FINGERPRINT="${GATEWARDEN_TEST_FINGERPRINT:-gatewarden-live-fixture-v1}"
LICENSE_ID="$(curl -s -X POST \
  "https://api.keygen.sh/v1/accounts/${KEYGEN_ACCOUNT_ID}/licenses/actions/validate-key" \
  -H "Content-Type: application/vnd.api+json" \
  -H "Accept: application/vnd.api+json" \
  -d "{\"meta\":{\"key\":\"${GATEWARDEN_TEST_LICENSE_KEY}\"}}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])")"
curl -s -X POST "https://api.keygen.sh/v1/accounts/${KEYGEN_ACCOUNT_ID}/machines" \
  -H "Authorization: License ${GATEWARDEN_TEST_LICENSE_KEY}" \
  -H "Content-Type: application/vnd.api+json" \
  -H "Accept: application/vnd.api+json" \
  -d "{\"data\":{\"type\":\"machines\",\"attributes\":{\"fingerprint\":\"${FINGERPRINT}\",\"platform\":\"linux/ubuntu\",\"name\":\"gatewarden-live-fixture\"},\"relationships\":{\"license\":{\"data\":{\"type\":\"licenses\",\"id\":\"${LICENSE_ID}\"}}}}}"
```

If the slot is occupied by a stale machine, delete that machine first
(list with `GET .../licenses/${LICENSE_ID}/machines` using the admin token),
then re-run the preflight to confirm `VALID`.

## Credentials on the maintainer's machine

The local secrets file is `~/.config/shimmy/secrets.env`. Load it with
`source ../chat-chronicle/scripts/load-service-secrets.sh`; never copy secret
values into the repository, terminal output, issue tracker, or logs. The loader
supplies the validation fixture variables and the Keygen admin token. Run the
preflight before the suite and stop if it is not VALID.

## Running the suite

```bash
source ../chat-chronicle/scripts/load-service-secrets.sh
cargo test --test integration_live -- --ignored
```

Expected: seven passing tests, zero failures. The bogus-key rejection and
wrong-public-key checks guard the failure modes: a stub that returns success
without a Keygen round-trip must fail the bogus-key check in the same run.

## Live actions

The actions test needs a separate license with LICENSE or MIXED authentication,
a free machine slot, fingerprint scope required, and no `maxUses` ceiling. It
increments usage and creates then removes a machine. The regular validation
fixture has only one occupied slot, so do not use it for this test.

To create and delete a temporary test license under an explicitly chosen suitable
policy, load the secrets as above and run:

```bash
GATEWARDEN_TEST_ACTION_POLICY_ID=<suitable-policy-id> python3 scripts/test-live-actions.py
```

On the maintainer's account, `policy_enterprise` is suitable; its policy ID is
`21aba131-02e2-4e05-a76d-dd0530c04ee0`. The helper uses the admin token only
in memory, passes the new license key to the test environment, and deletes the
temporary license even if the test fails. If deletion fails, remove the reported
license ID manually. A forcibly terminated process may also require cleanup.
For an existing dedicated actions fixture, set `GATEWARDEN_TEST_ACTION_LICENSE_KEY`
and, if unscoped validation cannot resolve it, `GATEWARDEN_TEST_ACTION_LICENSE_ID`,
then run `cargo test --test integration_live_actions -- --ignored`. Missing
credentials cause a failure, not a passing skip.
