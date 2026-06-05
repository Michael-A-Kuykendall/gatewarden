# Roadmap

## v0.2.1 (Released)

Surgical cleanup and hardening. No behavior changes to validation pipeline.

- [x] FSE engine moved into main crate (`src/policy/fse/`)
- [x] `fse-gatewarden` workspace crate removed
- [x] `#[non_exhaustive]` on FSE public enums
- [x] Patent notice in source and docs
- [x] Rate limiter background prune task (bridge)
- [x] Bearer token strength warning at startup (bridge)
- [x] Stale `html_root_url` removed
- [x] Version bump to 0.2.1
- [x] Bridge README with full user guide
- [x] Documentation hub (QUICKSTART, ARCHITECTURE, CONFIGURATION)

---

## v0.3.0 (Current — Released)

Wire FSE into the live validation pipeline. The FSE engine is now the
authoritative policy decision point.

- [x] Event-driven runtime API (`RuntimeState` with `apply`/`finalize`/`shouldTerminate`)
- [x] Expanded predicates: `MinU64`, `Exists`, `InSet(Vec<String>)`
- [x] Namespaced rule IDs (e.g., `crypto.signature_verified`, `entitlements.required_N`)
- [x] Gatewarden-specific selectors: `StateCode`, `StateValid`, `Entitlements`, `ExpiresAt`, `UsageRemaining`
- [x] `GatewardenEvalInput` implementation for license response mapping
- [x] FSE wired into `LicenseManager::validate_online()` — authoritative policy evaluation
- [x] Bridge startup logging shows FSE plan stats per profile
- [x] `compile_default_plan()` generates rules from `GatewardenConfig`
- [x] Compliance test suite (`fse_compliance.rs`) covering FSE core properties
- [x] Property-based tests expanded (proptest) for FSE invariants and new predicates
- [x] Integration tests confirm FSE decisions with live Keygen API
- [x] Documentation updated (ARCHITECTURE, DEVELOPERS, CHANGELOG, ROADMAP)

---

## v0.4.0 (Next)

Focus: Runtime flexibility, client libraries, and operational tooling.

- [ ] `/v1/check-access` uses FSE plan for cache-read decision path (deferred from v0.3.0)
- [ ] Async validation path (non-blocking for Tokio runtimes)
- [ ] TypeScript client package generated from OpenAPI spec
- [ ] Python client package
- [ ] Graceful shutdown with in-flight request drain (bridge)
- [ ] Hot-reload bridge config without restart
- [ ] Trusted proxy configuration (X-Forwarded-For header trust policy)
- [ ] Prometheus metrics endpoint for the bridge
- [ ] Docker image published to GHCR
- [ ] Custom FSE rule loading from config (beyond defaults)

---

## Long-term

- [ ] Event-driven FSE streaming provider (JSON tokenizer path, per patent FIG. 7)
- [ ] Rule priority ordering and short-circuit optimization
- [ ] WebAssembly build of the FSE engine for browser-side policy evaluation
- [ ] Gatewarden Cloud — hosted bridge as a service (no local binary needed)
