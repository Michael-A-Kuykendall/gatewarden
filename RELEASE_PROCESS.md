# Release Process

Gatewarden follows [Semantic Versioning](https://semver.org/). During the 0.x
series, a minor version can include breaking changes; document migration notes
in the changelog. The library and bridge have separate package versions.

## Release checklist

1. Update the library version and its bridge dependency in the manifests. Bump
   the bridge package version when appropriate; do not assume it always matches
   the library. Update the changelog and roadmap using the actual release date.
2. Run the release checks from a clean checkout:

   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-features -- -D warnings
   cargo test --workspace --all-features
   cargo test --workspace --no-default-features
   cargo package --list
   cargo publish --dry-run
   ```

   Inspect the package list for required source files and unintended local or
   development files. Run the live Keygen tests described in
   [LOCAL_TESTING.md](LOCAL_TESTING.md) with dedicated fixtures.
3. Commit the release, create an annotated `vX.Y.Z` tag, and push the branch
   and that tag. A matching tag starts
   [the publish workflow](.github/workflows/publish.yml), which publishes the
   library to crates.io and creates a GitHub Release. Avoid a concurrent manual
   upload while the workflow is running.
4. Verify the workflow, the published version on
   [crates.io](https://crates.io/crates/gatewarden), and documentation on
   [docs.rs](https://docs.rs/gatewarden). Record any follow-up work.

The publish workflow does not build or attach bridge binaries. Build the bridge
from the repository unless separately provided release assets are available.
