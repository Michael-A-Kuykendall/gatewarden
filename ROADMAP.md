# Roadmap

The latest published library release is **0.5.0**. See the
[Changelog](CHANGELOG.md) for release dates, breaking changes, and the full
history. The bridge has its own package version, currently 0.4.2.

## Released

### 0.5.0

- License-authenticated machine activation, usage increment, and machine removal.
- Verified license-state inspection without access-policy enforcement.
- Fingerprint-scoped validation and cache entries, including bridge requests.

### 0.4.2

- Revived the per-license offline usage meter behind the `meter` feature.
- Exposed remaining usage and the bridge's `/v1/record-use` endpoint.

### 0.4.1

- Fixed bridge rate limiting to use the TCP peer instead of spoofable forwarded headers.
- Updated cryptographic dependencies and clarified bridge configuration errors.

### 0.4.0

- Shelved the previously unwired offline meter; it was revived and integrated in 0.4.2.
- Consolidated policy enforcement across online, offline, and cached access paths.

### 0.3.0

- Integrated the FSE policy engine into license validation and added runtime,
  predicate, compliance, and property tests.

Earlier published versions and the Git-only 0.2.x development revisions are
recorded in the [Changelog](CHANGELOG.md).

## Future work

These are directions, not commitments to a release or schedule.

- [ ] Async validation path for Tokio applications.
- [ ] TypeScript and Python client packages.
- [ ] Bridge graceful shutdown and config reload.
- [ ] Trusted-proxy configuration with an explicit forwarded-header trust policy;
      the current bridge uses the TCP peer address.
- [ ] Bridge Prometheus metrics and a published container image.
- [ ] Custom FSE rule loading from configuration.
- [ ] Event-driven FSE streaming provider.
- [ ] Rule priority and short-circuit optimization.
- [ ] WebAssembly build of the FSE engine.
