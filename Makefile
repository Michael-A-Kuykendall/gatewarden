.PHONY: build test check lint fmt doc clean bridge run-bridge setup

# ─── Setup ─────────────────────────────────────────────────────────────────────

setup:
	git config core.hooksPath .githooks

# ─── Build ─────────────────────────────────────────────────────────────────────

build:
	cargo build --workspace

release:
	cargo build --release --workspace

bridge:
	cargo build --release -p gatewarden-bridge

# ─── Test ──────────────────────────────────────────────────────────────────────

test:
	cargo test --workspace

test-lib:
	cargo test --lib

test-fse:
	cargo test --test fse_invariants --test fse_head_to_head

test-bridge:
	cargo test -p gatewarden-bridge

# ─── Quality ───────────────────────────────────────────────────────────────────

check:
	cargo check --workspace

lint:
	cargo clippy --workspace -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

doc:
	cargo doc --no-deps --open

# ─── Run ───────────────────────────────────────────────────────────────────────

run-bridge:
	cargo run -p gatewarden-bridge -- bridge.toml

# ─── Release Gate ──────────────────────────────────────────────────────────────

release-check: fmt-check lint test doc
	@echo "✅ All release gates passed"

# ─── Clean ─────────────────────────────────────────────────────────────────────

clean:
	cargo clean
