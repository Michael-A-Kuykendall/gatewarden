# Roadmap

## v0.2.1 (Current — In Progress)

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

## v0.3.0 (Next)

Wire FSE into the live validation pipeline. The FSE engine becomes the
authoritative policy decision point.

- [ ] Adopt chat-chronicle's `apply`/`finalize`/`shouldTerminate` split in runtime
- [ ] Expanded predicates: `MinU64`, `Exists`, `InSet(Vec<String>)`
- [ ] Namespaced rule IDs (e.g., `response.signature_present`)
- [ ] Wire FSE into `LicenseManager::validate_online()` — build EvalInput from response
- [ ] Bridge `AppState` holds one `CompiledPlan` per profile (compiled at startup)
- [ ] `/v1/check-access` uses FSE plan for cache-read decision path
- [ ] Compliance test suite modeled on chat-chronicle's fseCompliance.test.ts
- [ ] Property-based tests (proptest) for FSE invariants

---

## v0.4.0 (Future)

- [ ] Async validation path (non-blocking for Tokio runtimes)
- [ ] TypeScript client package generated from OpenAPI spec
- [ ] Python client package
- [ ] Graceful shutdown with in-flight request drain (bridge)
- [ ] Hot-reload bridge config without restart
- [ ] Trusted proxy configuration (X-Forwarded-For header trust policy)
- [ ] Prometheus metrics endpoint for the bridge
- [ ] Docker image published to GHCR

---

## Long-term

- [ ] Event-driven FSE streaming provider (JSON tokenizer path, per patent FIG. 7)
- [ ] Rule priority ordering and short-circuit optimization
- [ ] WebAssembly build of the FSE engine for browser-side policy evaluation
- [ ] Gatewarden Cloud — hosted bridge as a service (no local binary needed)
