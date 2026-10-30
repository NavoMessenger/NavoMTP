use super::*;

fn users(secret: &str) -> HashMap<String, String> {
    HashMap::from([("alice".to_string(), secret.to_string())])
}

#[test]
fn shared_authority_rejects_registration_through_an_old_generation() {
    let authority = UserAdmissionAuthority::new();
    let secret = "00112233445566778899aabbccddeeff";
    authority.apply_config(&users(secret), &HashMap::new());
    let credential = credential_id_from_hex(secret).unwrap();

    assert!(authority.claim_authenticated("alice", credential).is_some());
    authority.stage_user("alice", secret, false).unwrap();

    assert!(authority.claim_authenticated("alice", credential).is_none());
}

#[test]
fn stale_credential_cannot_cross_delete_and_recreate() {
    let authority = UserAdmissionAuthority::new();
    let old_secret = "00112233445566778899aabbccddeeff";
    let new_secret = "ffeeddccbbaa99887766554433221100";
    authority.apply_config(&users(old_secret), &HashMap::new());
    let old_credential = credential_id_from_hex(old_secret).unwrap();
    let old_incarnation = authority
        .authenticated_incarnation("alice", old_credential)
        .unwrap();

    authority.delete_user("alice");
    let recreated = authority.stage_user("alice", new_secret, true).unwrap();

    assert!(recreated.incarnation > old_incarnation);
    assert!(
        authority
            .authenticated_incarnation("alice", old_credential)
            .is_none()
    );
}

#[test]
fn stale_candidate_cannot_overwrite_newer_mutation() {
    let authority = UserAdmissionAuthority::new();
    let secret = "00112233445566778899aabbccddeeff";
    authority
        .activate_config_source(1, None, &users(secret), &HashMap::new())
        .unwrap();
    let candidate_epoch = authority.epoch();
    authority.stage_user("alice", secret, false).unwrap();

    assert!(
        authority
            .activate_config_source(2, Some(candidate_epoch), &users(secret), &HashMap::new(),)
            .is_none()
    );
    assert!(!authority.is_user_enabled("alice"));

    let disabled = HashMap::from([("alice".to_string(), false)]);
    assert!(
        authority
            .apply_config_from_source(1, &users(secret), &disabled)
            .is_none()
    );
    assert!(
        authority
            .apply_config_from_source(2, &users(secret), &disabled)
            .is_some()
    );
    assert!(!authority.is_user_enabled("alice"));
}

#[test]
fn stale_generation_snapshot_cannot_reopen_reconciled_user() {
    let authority = UserAdmissionAuthority::new();
    let secret = "00112233445566778899aabbccddeeff";
    authority
        .activate_config_source(1, None, &users(secret), &HashMap::new())
        .unwrap();
    authority.stage_user("alice", secret, false).unwrap();

    let disabled = HashMap::from([("alice".to_string(), false)]);
    let epoch = authority.epoch();
    authority
        .activate_config_source(2, Some(epoch), &users(secret), &disabled)
        .unwrap();
    assert!(
        authority
            .apply_config_from_source(1, &users(secret), &HashMap::new())
            .is_none()
    );

    assert!(!authority.is_user_enabled("alice"));
    assert_eq!(authority.stale_config_source_rejections(), 1);
}

#[test]
fn registration_dropped_before_publication_cannot_leave_an_owner() {
    let authority = UserAdmissionAuthority::new();
    let secret = "00112233445566778899aabbccddeeff";
    authority.apply_config(&users(secret), &HashMap::new());
    let credential = credential_id_from_hex(secret).unwrap();
    let mut publication = authority.claim_authenticated("alice", credential).unwrap();
    let registration = publication.take_registration().unwrap();

    drop(registration);
    publication.commit();

    assert_eq!(authority.cancel_user_owners("alice"), 0);
}

#[test]
fn quota_identity_follows_credential_rotation_and_recreation() {
    let quota_store = Arc::new(QuotaStore::default());
    let authority = UserAdmissionAuthority::new_with_quota_store(quota_store.clone());
    let old_secret = "00112233445566778899aabbccddeeff";
    let new_secret = "ffeeddccbbaa99887766554433221100";
    authority.apply_config(&users(old_secret), &HashMap::new());
    let old_incarnation = authority
        .authenticated_incarnation("alice", credential_id_from_hex(old_secret).unwrap())
        .unwrap();
    let old_quota = quota_store.handle_exact("alice", old_incarnation).unwrap();
    old_quota.charge(40);

    let rotated = authority.stage_user("alice", new_secret, true).unwrap();
    let rotated_quota = quota_store
        .handle_exact("alice", rotated.incarnation)
        .unwrap();
    old_quota.charge(20);

    assert_eq!(rotated_quota.used(), 40);
    authority.delete_user("alice");
    let recreated = authority.stage_user("alice", old_secret, true).unwrap();
    assert_eq!(
        quota_store
            .handle_exact("alice", recreated.incarnation)
            .unwrap()
            .used(),
        0
    );
}
