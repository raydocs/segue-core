#[test]
fn workspace_exports_version() {
    assert_eq!(segue_engine::version(), env!("CARGO_PKG_VERSION"));
}
