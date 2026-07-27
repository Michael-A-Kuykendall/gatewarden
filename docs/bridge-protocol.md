# Gatewarden Bridge Protocol

## Purpose

Define an idiomatic, discoverable interface for consuming Gatewarden from non-Rust runtimes while preserving Gatewarden as the single security implementation.

## Recommended Industry Surface

- Primary discovery and client generation: OpenAPI 3.1
- Suggested docs tooling: Swagger UI or Redoc
- Transport for broad compatibility: HTTP localhost sidecar

Why this choice:

- OpenAPI is the most widely adopted API contract for tooling, SDK generation, and documentation.
- A localhost sidecar keeps private keys and cryptographic policy in one hardened Rust process.
- Connector libraries in TypeScript, JavaScript, Python, etc. can remain thin wrappers.

## Contract Artifacts

- OpenAPI spec: spec/gatewarden-bridge.openapi.yaml
- Well-known discovery endpoint (recommended): /.well-known/openapi.json
- Docs endpoint (recommended): /docs

## Operations

- GET /v1/health
- POST /v1/validate-key
- POST /v1/check-access
- POST /v1/record-use — records one local, offline-enforceable usage event
  (feature `meter`); returns `429` (`USAGE_LIMIT_EXCEEDED`) on cap breach.

Validation and record-use responses surface an optional `usage` object with the
locally-metered count folded in: `maxUses`, `currentUses`, `remaining`
(`maxUses - currentUses - localUses`), and `localUses` (offline meter count).
The authoritative field list lives in the OpenAPI spec
(`spec/gatewarden-bridge.openapi.yaml`).

## Profile Model

Requests carry profileId. Sidecar resolves profileId to a local GatewardenConfig.

This avoids shipping account and key material in every request and keeps configuration host-local.

## Error Model

The bridge maps Gatewarden typed errors to stable wire error types:

- MissingLicense
- InvalidLicense
- EntitlementMissing
- SignatureMissing
- SignatureInvalid
- DigestMismatch
- ResponseTooOld
- ResponseFromFuture
- CacheExpired
- KeygenTransport
- ConfigError
- ProtocolError
- InternalError

## Security Notes

- Treat sidecar listener as localhost-only by default.
- Do not expose bridge directly to public internet.
- Keep license keys out of logs.
- Preserve fail-closed behavior for signature and digest failures.

## Release Plan Suggestion

1. Add bridge binary crate in Gatewarden workspace.
2. Ship OpenAPI spec with first bridge release.
3. Publish TypeScript connector generated from OpenAPI + hand-tuned wrapper.
4. Integrate Chat Chronicle against bridge API.
5. Add conformance tests that compare bridge output to direct crate output.
