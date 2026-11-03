#!/usr/bin/env bash
# Preflight for the live Keygen fixture (docs/LIVE_KEYGEN_FIXTURE.md).
#
# Reports whether the fixture license + machine are in a state the live suite
# can use. Prints credential presence and length ONLY — never a value.
#
# Usage:
#   source ../chat-chronicle/scripts/load-service-secrets.sh
#   ./scripts/keygen-fixture-preflight.sh
set -euo pipefail

fail() { echo "PREFLIGHT FAIL: $1"; exit 1; }
pass() { echo "PREFLIGHT PASS: $1"; exit 0; }

# 1. Required variables present (names and value lengths only — never values).
for var in GATEWARDEN_TEST_ACCOUNT_ID GATEWARDEN_TEST_PUBLIC_KEY_HEX GATEWARDEN_TEST_LICENSE_KEY; do
  if [[ -z "${!var:-}" ]]; then
    fail "$var is unset (source the service-secrets loader first)"
  fi
  val="${!var}"
  echo "  $var: set (value length ${#val})"
done

FINGERPRINT="${GATEWARDEN_TEST_FINGERPRINT:-gatewarden-live-fixture-v1}"
echo "  fixture fingerprint: $FINGERPRINT (machine identifier, not a credential)"

if [[ -n "${GATEWARDEN_TEST_ENTITLEMENT:-}" ]]; then
  echo "  GATEWARDEN_TEST_ENTITLEMENT: set"
else
  echo "  GATEWARDEN_TEST_ENTITLEMENT: unset (O(1) check will skip)"
fi

# 2. Scoped validation probe (read-only; consumes no quota).
ENT_JSON="[]"
if [[ -n "${GATEWARDEN_TEST_ENTITLEMENT:-}" ]]; then
  ENT_JSON="[\"${GATEWARDEN_TEST_ENTITLEMENT}\"]"
fi
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
curl -s -X POST \
  "https://api.keygen.sh/v1/accounts/${GATEWARDEN_TEST_ACCOUNT_ID}/licenses/actions/validate-key" \
  -H "Content-Type: application/vnd.api+json" \
  -H "Accept: application/vnd.api+json" \
  -d "{\"meta\":{\"key\":\"${GATEWARDEN_TEST_LICENSE_KEY}\",\"scope\":{\"fingerprint\":\"${FINGERPRINT}\",\"entitlements\":${ENT_JSON}}}}" \
  -o "$TMP"

read -r VALID CODE DETAIL < <(python3 -c "
import json,sys
d = json.load(open('$TMP'))
m = d.get('meta', {})
print(str(m.get('valid', '')).lower(), m.get('code', 'UNKNOWN'), (m.get('detail', '') or '').replace(chr(10), ' ')[:120])
")
echo "  keygen verdict: valid=$VALID code=$CODE detail=$DETAIL"

# 3. Verdict.
case "$CODE" in
  VALID)
    pass "fixture current (code VALID)"
    ;;
  NO_MACHINE|FINGERPRINT_SCOPE_MISMATCH)
    fail "code $CODE — fixture machine missing for fingerprint '$FINGERPRINT'. Re-activate per docs/LIVE_KEYGEN_FIXTURE.md, then re-run."
    ;;
  FINGERPRINT_SCOPE_REQUIRED)
    fail "code FINGERPRINT_SCOPE_REQUIRED — scope was not accepted. Check the fingerprint value and the policy's scope requirement."
    ;;
  EXPIRED|SUSPENDED|NOT_FOUND)
    fail "code $CODE — fixture license is not usable. Replace the test license (secrets file), activate a machine, then re-run."
    ;;
  *)
    fail "unexpected code $CODE (valid=$VALID). Inspect fixture state per docs/LIVE_KEYGEN_FIXTURE.md."
    ;;
esac
