//! Basic smoke test to verify crate compiles.

#[test]
fn crate_compiles() {
    // If this test runs, the crate skeleton is valid.
    let _ = std::any::type_name::<gatewarden::GatewardenConfig>();
    let _ = std::any::type_name::<gatewarden::GatewardenError>();
}
