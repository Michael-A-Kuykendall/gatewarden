# Gatewarden Bridge — Cloudflare Worker Deployment

An optional, zero-binary deployment of the Gatewarden Bridge that runs as a
Cloudflare Worker. Use this when you want license validation available over
HTTPS without shipping a binary sidecar — TypeScript, Python, Go, Ruby, and
any other language can call it.

> **This is opt-in.** If you prefer the local sidecar binary, see
> `gatewarden/bridge/` instead. Both expose the same HTTP API.

---

## Prerequisites

- A [Cloudflare account](https://dash.cloudflare.com/) (free Workers tier works)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- A Keygen account with at least one product

---

## Setup

### 1. Copy the example config

```bash
cp wrangler.toml.example wrangler.toml
```

### 2. Add your profile config

Edit `wrangler.toml` and add your Keygen credentials in the `[vars]` section:

```toml
[vars]
GATEWARDEN_PROFILE_MYAPP_PRO = '{"accountId":"your-keygen-account-uuid","publicKeyHex":"64hexchars","requiredEntitlements":["PRO"],"offlineGraceSecs":86400}'
```

**Where to find these values:**
- `accountId` — Keygen Dashboard > Settings > Account ID
- `publicKeyHex` — Keygen Dashboard > Settings > Ed25519 Public Key (64 hex chars)
- `requiredEntitlements` — the entitlement codes your license plan must carry

> `publicKeyHex` is **not a secret** — it is the verify key, used to check that
> Keygen signed the response. It is safe to put in `[vars]`.

### 3. Set the access token (recommended)

Protect your Worker from unauthorized callers with a shared secret header:

```bash
wrangler secret put BRIDGE_ACCESS_TOKEN
# Enter a long random string, e.g.: openssl rand -hex 32
```

Callers must send `X-Bridge-Token: <your-token>` with every request.

### 4. (Optional) Add KV cache for offline grace

```bash
# Create the namespace
wrangler kv namespace create GATEWARDEN_CACHE_KV

# Paste the returned id into wrangler.toml:
# [[kv_namespaces]]
# binding = "GATEWARDEN_CACHE_KV"
# id = "returned-id"
```

Without KV, `/v1/check-access` still works but cannot serve from cache when
Keygen is unreachable.

### 5. Deploy

```bash
wrangler deploy
```

---

## API

All endpoints are identical to the local sidecar binary.

### `GET /v1/health`

```json
{
  "status": "ok",
  "version": "0.2.0",
  "profiles": ["myapp-pro"],
  "deployment": "cloudflare-worker"
}
```

### `POST /v1/validate-key`

Always validates against Keygen (never serves stale cache).

**Request:**
```json
{ "profileId": "myapp-pro", "licenseKey": "XXXX-XXXX-XXXX-XXXX" }
```

**Response:**
```json
{
  "valid": true,
  "fromCache": false,
  "stateCode": "VALID",
  "expiresAt": "2026-01-01T00:00:00.000Z",
  "entitlements": ["PRO"]
}
```

### `POST /v1/check-access`

Cache-first variant. Returns cached result within `offlineGraceSecs`, otherwise
validates live.

---

## Security notes

- `publicKeyHex` is placed in `[vars]` (non-secret config) because it is the
  Ed25519 **verify** key — not the signing key. It cannot be used to forge
  responses.
- Every Keygen response is verified with Ed25519 before it is trusted. A
  network MITM cannot spoof a valid response.
- License keys are **never stored** in KV — only a SHA-256 hash of the key is
  used as the cache key.
- The `BRIDGE_ACCESS_TOKEN` secret is compared in constant time to prevent
  timing attacks.

---

## Stripe WAF allowlist (optional)

If you are also running the Stripe webhook worker (`stripe-keygen-webhook.js`)
and want to restrict incoming traffic to Stripe IPs, add a WAF rule in the
Cloudflare dashboard:

- **Field:** IP Source Address  
- **Operator:** is not in list  
- **Value:** Add Stripe's published IP list from [stripe.com/docs/ips](https://stripe.com/docs/ips)  
- **Action:** Block

This is belt-and-suspenders on top of the HMAC signature check in the webhook
handler.
