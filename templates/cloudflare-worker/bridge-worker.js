/**
 * Gatewarden Bridge — Cloudflare Worker Deployment
 *
 * An OPTIONAL, opt-in alternative to running the local sidecar binary.
 * Deploy this Worker when you want zero-binary, serverless license validation
 * accessible from any language over HTTPS.
 *
 * Security model:
 *   - public_key_hex is NOT secret (it is the Ed25519 VERIFY key — safe to deploy)
 *   - account_id is NOT secret
 *   - license keys are NEVER stored; they are only used for in-flight validation
 *   - All Keygen secrets (KEYGEN_PRODUCT_TOKEN) must be set via `wrangler secret put`
 *   - The bridge binds to your Worker URL only; protect it with a shared secret header
 *     (BRIDGE_ACCESS_TOKEN) if you want to restrict who can call it
 *
 * Setup:
 *   1. cp wrangler.toml.example wrangler.toml
 *   2. Edit profiles in wrangler.toml
 *   3. wrangler secret put BRIDGE_ACCESS_TOKEN    (random shared secret)
 *   4. wrangler deploy
 *
 * API (same contract as local sidecar):
 *   POST /v1/validate-key    { profileId, licenseKey }
 *   POST /v1/check-access    { profileId, licenseKey }  (cache-first)
 *   GET  /v1/health
 *   GET  /.well-known/openapi.json
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ── Access control ────────────────────────────────────────────────────────
    // Optional: require a shared secret header to prevent unauthorized calls.
    // Set BRIDGE_ACCESS_TOKEN via `wrangler secret put BRIDGE_ACCESS_TOKEN`.
    if (env.BRIDGE_ACCESS_TOKEN) {
      const token = request.headers.get('X-Bridge-Token');
      if (!timingSafeEqual(token || '', env.BRIDGE_ACCESS_TOKEN)) {
        return json({ error: 'Unauthorized', code: 'UNAUTHORIZED' }, 401);
      }
    }

    // ── Routing ───────────────────────────────────────────────────────────────
    if (url.pathname === '/v1/health' && request.method === 'GET') {
      return handleHealth(env);
    }

    if (url.pathname === '/v1/validate-key' && request.method === 'POST') {
      return handleValidateKey(request, env, /* cacheFirst= */ false);
    }

    if (url.pathname === '/v1/check-access' && request.method === 'POST') {
      return handleValidateKey(request, env, /* cacheFirst= */ true);
    }

    if (url.pathname === '/.well-known/openapi.json' && request.method === 'GET') {
      return new Response(OPENAPI_SPEC, {
        headers: { 'Content-Type': 'application/yaml' },
      });
    }

    return json({ error: 'Not found' }, 404);
  },
};

// ── Handlers ──────────────────────────────────────────────────────────────────

function handleHealth(env) {
  const profiles = loadProfiles(env);
  return json({
    status: 'ok',
    version: '0.2.0',
    profiles: Object.keys(profiles),
    deployment: 'cloudflare-worker',
  });
}

/**
 * Validate a license key against Keygen using the profile config.
 *
 * cacheFirst=true  → check KV cache before hitting Keygen (check-access)
 * cacheFirst=false → always hit Keygen first (validate-key)
 */
async function handleValidateKey(request, env, cacheFirst) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON body', code: 'BAD_REQUEST' }, 400);
  }

  const { profileId, licenseKey } = body;

  if (!profileId || typeof profileId !== 'string') {
    return json({ error: 'profileId is required', code: 'BAD_REQUEST' }, 400);
  }
  if (!licenseKey || typeof licenseKey !== 'string') {
    return json({ error: 'licenseKey is required', code: 'MISSING_LICENSE' }, 400);
  }

  const profiles = loadProfiles(env);
  const profile = profiles[profileId];
  if (!profile) {
    return json({ error: `Profile '${profileId}' not found`, code: 'PROFILE_NOT_FOUND' }, 404);
  }

  // ── Cache-first path (check-access) ─────────────────────────────────────
  if (cacheFirst && env.GATEWARDEN_CACHE_KV) {
    const cacheKey = `cache:${profileId}:${await sha256Hex(licenseKey)}`;
    const cached = await env.GATEWARDEN_CACHE_KV.get(cacheKey, 'json');
    if (cached) {
      // Verify the cached record is still within the offline grace period
      const graceSecs = profile.offlineGraceSecs ?? 86400;
      const cachedAt = cached.cachedAt ?? 0;
      const ageSeconds = Math.floor(Date.now() / 1000) - cachedAt;
      if (ageSeconds < graceSecs) {
        return json({ ...cached.result, fromCache: true });
      }
    }
  }

  // ── Online validation via Keygen ─────────────────────────────────────────
  const keygenResult = await validateWithKeygen(licenseKey, profile, env);
  if (!keygenResult.ok) {
    return json(keygenResult.error, keygenResult.status);
  }

  const result = keygenResult.result;

  // ── Write to KV cache on success ─────────────────────────────────────────
  if (result.valid && env.GATEWARDEN_CACHE_KV) {
    const cacheKey = `cache:${profileId}:${await sha256Hex(licenseKey)}`;
    const graceSecs = profile.offlineGraceSecs ?? 86400;
    await env.GATEWARDEN_CACHE_KV.put(
      cacheKey,
      JSON.stringify({ result, cachedAt: Math.floor(Date.now() / 1000) }),
      { expirationTtl: graceSecs + 3600 } // small buffer over grace
    );
  }

  return json({ ...result, fromCache: false });
}

// ── Keygen API call with Ed25519 response signature verification ──────────────

async function validateWithKeygen(licenseKey, profile, env) {
  const accountId = profile.accountId;
  const path = `/v1/accounts/${accountId}/licenses/actions/validate-key`;
  const host = 'api.keygen.sh';
  const url = `https://${host}${path}`;

  const entitlements = profile.requiredEntitlements ?? [];
  const bodyObj =
    entitlements.length > 0
      ? { meta: { key: licenseKey, scope: { entitlements } } }
      : { meta: { key: licenseKey } };

  const bodyBytes = new TextEncoder().encode(JSON.stringify(bodyObj));

  // Compute request digest
  const digestBytes = await crypto.subtle.digest('SHA-256', bodyBytes);
  const digestB64 = btoa(String.fromCharCode(...new Uint8Array(digestBytes)));
  const digestHeader = `sha-256=${digestB64}`;

  const reqDate = new Date().toUTCString();

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/vnd.api+json',
      Accept: 'application/vnd.api+json',
      Host: host,
      Date: reqDate,
      Digest: digestHeader,
      'User-Agent': `gatewarden-bridge-worker/0.2.0`,
    },
    body: bodyBytes,
  });

  const respBody = await resp.text();

  // ── Ed25519 response signature verification ───────────────────────────────
  // This is the core security check: reject any response not signed by Keygen's
  // private key. Without this, a MITM can spoof "valid" responses.
  const sigHeader = resp.headers.get('Keygen-Signature');
  const dateHeader = resp.headers.get('Date');
  const digestRespHeader = resp.headers.get('Digest');

  if (!sigHeader || !dateHeader) {
    return {
      ok: false,
      status: 502,
      error: { error: 'Keygen response missing signature headers', code: 'SIGNATURE_MISSING' },
    };
  }

  // Verify response freshness (5-minute window — prevents replay attacks)
  const respDate = new Date(dateHeader);
  const ageSeconds = (Date.now() - respDate.getTime()) / 1000;
  if (Math.abs(ageSeconds) > 300) {
    return {
      ok: false,
      status: 502,
      error: {
        error: `Response too old (${Math.floor(ageSeconds)}s)`,
        code: 'RESPONSE_TOO_OLD',
      },
    };
  }

  // Verify body digest
  const actualDigestBytes = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(respBody)
  );
  const actualDigestB64 = btoa(String.fromCharCode(...new Uint8Array(actualDigestBytes)));
  if (digestRespHeader && digestRespHeader !== `sha-256=${actualDigestB64}`) {
    return {
      ok: false,
      status: 502,
      error: { error: 'Response digest mismatch', code: 'DIGEST_MISMATCH' },
    };
  }

  // Verify Ed25519 signature
  const sigVerified = await verifyKeygenSignature(
    sigHeader,
    dateHeader,
    digestRespHeader ?? `sha-256=${actualDigestB64}`,
    path,
    host,
    profile.publicKeyHex
  );
  if (!sigVerified) {
    return {
      ok: false,
      status: 502,
      error: { error: 'Keygen response signature invalid', code: 'SIGNATURE_INVALID' },
    };
  }

  // Parse the verified response
  let parsed;
  try {
    parsed = JSON.parse(respBody);
  } catch {
    return { ok: false, status: 502, error: { error: 'Keygen returned invalid JSON', code: 'PROTOCOL_ERROR' } };
  }

  const meta = parsed?.meta ?? {};
  const attrs = parsed?.data?.attributes ?? {};
  const result = {
    valid: meta.valid === true,
    stateCode: meta.code ?? 'UNKNOWN',
    expiresAt: attrs.expiry ?? null,
    entitlements: parsed?.data?.relationships?.entitlements?.data?.map((e) => e.id) ?? [],
  };

  return { ok: true, result };
}

// ── Ed25519 signature verification ───────────────────────────────────────────

async function verifyKeygenSignature(sigHeader, dateHeader, digestHeader, requestPath, host, publicKeyHex) {
  // Parse the Keygen-Signature header
  const parts = {};
  for (const part of sigHeader.split(',')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx < 0) continue;
    const k = part.slice(0, eqIdx).trim();
    const v = part.slice(eqIdx + 1).trim().replace(/^"(.*)"$/, '$1');
    parts[k] = v;
  }

  const { signature, headers: signedHeaders } = parts;
  if (!signature || !signedHeaders) return false;

  // Reconstruct signing string
  const headerParts = (signedHeaders || 'date digest').split(' ');
  const headerValues = {
    '(request-target)': `post ${requestPath}`,
    host,
    date: dateHeader,
    digest: digestHeader,
  };

  const signingString = headerParts
    .map((h) => `${h}: ${headerValues[h] ?? ''}`)
    .join('\n');

  // Import the Ed25519 public key
  const keyBytes = hexToBytes(publicKeyHex);
  let cryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'Ed25519' },
      false,
      ['verify']
    );
  } catch {
    return false;
  }

  const sigBytes = base64ToBytes(signature);
  const msgBytes = new TextEncoder().encode(signingString);

  try {
    return await crypto.subtle.verify('Ed25519', cryptoKey, sigBytes, msgBytes);
  } catch {
    return false;
  }
}

// ── Profile loader ────────────────────────────────────────────────────────────

/**
 * Load profiles from Worker environment variables.
 * 
 * Each profile is defined by JSON in an env var named GATEWARDEN_PROFILE_<PROFILE_ID>.
 * Example (in wrangler.toml):
 *   [vars]
 *   GATEWARDEN_PROFILE_MYAPP_PRO = '{"accountId":"...","publicKeyHex":"64hex",...}'
 */
function loadProfiles(env) {
  const profiles = {};
  const prefix = 'GATEWARDEN_PROFILE_';
  for (const key of Object.keys(env)) {
    if (key.startsWith(prefix)) {
      const profileId = key.slice(prefix.length).toLowerCase().replace(/_/g, '-');
      try {
        profiles[profileId] = JSON.parse(env[key]);
      } catch {
        console.error(`Invalid JSON in ${key}`);
      }
    }
  }
  return profiles;
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Constant-time string comparison — prevents timing attacks. */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ── Embedded OpenAPI spec placeholder ─────────────────────────────────────────
// In production, bundle the real spec here via a build step.
const OPENAPI_SPEC = `# See https://github.com/Michael-A-Kuykendall/gatewarden/blob/main/spec/gatewarden-bridge.openapi.yaml`;
