#!/usr/bin/env python3
"""Run live actions using a temporary license; requires an explicitly chosen test policy."""
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

required = (
    "KEYGEN_ACCOUNT_ID",
    "KEYGEN_ADMIN_TOKEN",
    "GATEWARDEN_TEST_ACCOUNT_ID",
    "GATEWARDEN_TEST_PUBLIC_KEY_HEX",
    "GATEWARDEN_TEST_ACTION_POLICY_ID",
)
missing = [name for name in required if not os.environ.get(name)]
if missing:
    sys.exit("Missing environment variables: " + ", ".join(missing))
if os.environ["KEYGEN_ACCOUNT_ID"] != os.environ["GATEWARDEN_TEST_ACCOUNT_ID"]:
    sys.exit("Keygen administration and test accounts must match")

base = "https://api.keygen.sh/v1/accounts/" + os.environ["KEYGEN_ACCOUNT_ID"]
headers = {
    "Authorization": "Bearer " + os.environ["KEYGEN_ADMIN_TOKEN"],
    "Accept": "application/vnd.api+json",
    "Content-Type": "application/vnd.api+json",
}
body = {
    "data": {
        "type": "licenses",
        "attributes": {"name": "gatewarden temporary release integration test"},
        "relationships": {
            "policy": {
                "data": {
                    "type": "policies",
                    "id": os.environ["GATEWARDEN_TEST_ACTION_POLICY_ID"],
                }
            }
        },
    }
}
license_id = None
status = 1
try:
    req = urllib.request.Request(
        base + "/licenses", data=json.dumps(body).encode(), headers=headers, method="POST"
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        license_data = json.load(response)["data"]
    license_id = license_data["id"]
    env = os.environ.copy()
    env["GATEWARDEN_TEST_ACTION_LICENSE_KEY"] = license_data["attributes"]["key"]
    env["GATEWARDEN_TEST_ACTION_LICENSE_ID"] = license_id
    print("Temporary test license created", flush=True)
    status = subprocess.run(
        ["cargo", "test", "--test", "integration_live_actions", "--", "--ignored"],
        env=env,
        check=False,
    ).returncode
except urllib.error.HTTPError as error:
    print("Keygen request failed: HTTP", error.code, file=sys.stderr)
except (OSError, ValueError, KeyError) as error:
    print("Keygen test setup failed:", type(error).__name__, file=sys.stderr)
finally:
    if license_id:
        try:
            req = urllib.request.Request(
                base + "/licenses/" + license_id, headers=headers, method="DELETE"
            )
            with urllib.request.urlopen(req, timeout=20):
                pass
            print("Temporary test license deleted", flush=True)
        except (OSError, urllib.error.HTTPError) as error:
            print(
                "Could not delete temporary test license",
                license_id,
                type(error).__name__,
                file=sys.stderr,
            )
            status = 1
sys.exit(status)
