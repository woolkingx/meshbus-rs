mod support;

#[test]
fn support_module_compiles() {
    // The mock_auth module compiles. Functional tests land in Task 14/15.
    let _ = support::mock_auth::zone_acceptance();
}
