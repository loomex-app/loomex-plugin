use loomex_protocol::{
    negotiate_protocol_version, RunnerIdentity, RunnerPlatform, RunnerSurface, PROTOCOL_VERSION,
};

#[test]
fn legacy_v1_fixture_remains_compatible() {
    let fixture = include_str!("fixtures/runner-identity-v1.json");
    let identity: RunnerIdentity = serde_json::from_str(fixture).unwrap();

    assert_eq!(identity.protocol_version, PROTOCOL_VERSION);
    assert!(identity.supports_protocol());
    assert_eq!(identity.surface, RunnerSurface::Plugin);
    assert_eq!(identity.platform, RunnerPlatform::Macos);
}

#[test]
fn handshake_matrix_rejects_only_incompatible_offers() {
    assert_eq!(
        negotiate_protocol_version(&[PROTOCOL_VERSION]),
        Ok(PROTOCOL_VERSION)
    );
    assert_eq!(
        negotiate_protocol_version(&["runner.v2", PROTOCOL_VERSION]),
        Ok(PROTOCOL_VERSION)
    );
    assert!(negotiate_protocol_version(&["runner.v2", "runner.v3"]).is_err());
}
