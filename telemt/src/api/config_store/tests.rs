use super::*;
use crate::config::RateLimitBps;

#[tokio::test]
async fn save_sections_preserves_other_tables_and_comments() {
    let dir = std::env::temp_dir().join(format!("cfgtest-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        "# top comment\n[censorship]\ntls_domain = \"old.example\"\n\n[server]\nport = 443\n",
    )
    .unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.censorship.tls_domain = "new.example".to_string();
    cfg.server.port = 443;

    let rev = save_sections_to_disk(&path, &cfg, &["censorship"])
        .await
        .unwrap();

    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("tls_domain = \"new.example\""));
    // Untouched comments and tables remain byte content.
    assert!(written.contains("# top comment"));
    assert!(written.contains("[server]\nport = 443"));
    assert_eq!(rev, compute_revision(&written));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn find_bounds_matches_array_of_tables() {
    let src = "[server]\nport = 1\n\n[[upstreams]]\nkind = \"a\"\n\n[[upstreams]]\nkind = \"b\"\n";
    let bounds = find_toml_table_bounds(src, "upstreams");
    assert!(bounds.is_some(), "should locate [[upstreams]] block start");
    let (start, end) = bounds.unwrap();
    let slice = &src[start..end];
    assert!(slice.starts_with("[[upstreams]]"));
    // The bound spans through the last upstream block.
    assert!(slice.contains("kind = \"b\""));
}

#[test]
fn find_bounds_matches_header_with_inline_comment() {
    let src = "[censorship] # notes\ntls_domain = \"a\"\n\n[server]\nport = 1\n";
    let bounds = find_toml_table_bounds(src, "censorship");
    assert!(bounds.is_some(), "commented header must still match");
    let (start, end) = bounds.unwrap();
    let slice = &src[start..end];
    assert!(slice.starts_with("[censorship] # notes"));
    assert!(slice.contains("tls_domain"));
    // The bound terminates at the next header.
    assert!(!slice.contains("[server]"));
}

#[tokio::test]
async fn save_general_section_keeps_subtables_dotted_without_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    tokio::fs::write(
        &path,
        "[general]\nprefer_ipv6 = false\n\n[general.modes]\ntls = true\n\n\
         [general.links]\npublic_host = \"old.example\"\n\n[server]\nport = 443\n",
    )
    .await
    .unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.general.prefer_ipv6 = true;

    save_sections_to_disk(&path, &cfg, &["general"])
        .await
        .unwrap();

    let written = tokio::fs::read_to_string(&path).await.unwrap();

    // No bare top-level [modes] / [links] headers leaked.
    for line in written.lines() {
        let header = line.trim();
        assert_ne!(header, "[modes]", "leaked top-level [modes]:\n{written}");
        assert_ne!(header, "[links]", "leaked top-level [links]:\n{written}");
    }

    // Sub-tables kept their dotted prefix exactly once each.
    assert_eq!(
        written.matches("[general.modes]").count(),
        1,
        "[general.modes] must appear exactly once:\n{written}"
    );
    assert_eq!(
        written.matches("[general.links]").count(),
        1,
        "[general.links] must appear exactly once:\n{written}"
    );

    // Result parses (duplicate tables would error here).
    toml::from_str::<toml::Value>(&written)
        .unwrap_or_else(|e| panic!("written config must parse: {e}\n{written}"));

    // The unrelated table remains untouched.
    assert!(written.contains("[server]\nport = 443"));
}

#[tokio::test]
async fn save_general_section_is_idempotent_across_repeated_saves() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    tokio::fs::write(
        &path,
        "[general]\nprefer_ipv6 = false\n\n[general.modes]\ntls = true\n\n\
         [general.links]\npublic_host = \"old.example\"\n",
    )
    .await
    .unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.general.prefer_ipv6 = true;

    save_sections_to_disk(&path, &cfg, &["general"])
        .await
        .unwrap();
    save_sections_to_disk(&path, &cfg, &["general"])
        .await
        .unwrap();

    let written = tokio::fs::read_to_string(&path).await.unwrap();
    assert_eq!(written.matches("[general.modes]").count(), 1, "{written}");
    assert_eq!(written.matches("[general.links]").count(), 1, "{written}");
    assert_eq!(written.matches("[general]").count(), 1, "{written}");
    toml::from_str::<toml::Value>(&written)
        .unwrap_or_else(|e| panic!("written config must parse: {e}\n{written}"));
}

#[test]
fn find_bounds_spans_dotted_subtables() {
    let src = "[general]\nprefer_ipv6 = false\n\n[general.modes]\ntls = true\n\n\
               [general.links]\npublic_host = \"a\"\n\n[server]\nport = 1\n";
    let bounds = find_toml_table_bounds(src, "general");
    assert!(bounds.is_some(), "should locate [general] block");
    let (start, end) = bounds.unwrap();
    let slice = &src[start..end];
    assert!(slice.starts_with("[general]"));
    // Nested sub-tables belong to the parent table bound.
    assert!(slice.contains("[general.modes]"));
    assert!(slice.contains("[general.links]"));
    // The bound terminates before an unrelated header.
    assert!(!slice.contains("[server]"));
}

#[test]
fn find_bounds_does_not_overrun_sibling_prefix() {
    // access.users must not swallow access.user_enabled (dot guards the prefix).
    let src = "[access.users]\nalice = \"x\"\n\n[access.user_enabled]\nalice = true\n";
    let bounds = find_toml_table_bounds(src, "access.users").unwrap();
    let slice = &src[bounds.0..bounds.1];
    assert!(slice.starts_with("[access.users]"));
    assert!(!slice.contains("[access.user_enabled]"));
}

#[test]
fn nested_include_detection_does_not_reject_similar_access_keys() {
    assert!(has_include_inside_table(
        "[access.users]\ninclude = \"users.toml\"\n"
    ));
    assert!(!has_include_inside_table(
        "[access.users]\ninclude_user = \"00000000000000000000000000000000\"\n"
    ));
}

#[tokio::test]
async fn save_general_handles_non_contiguous_subtables() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    // Hand-edited layout: [general.modes] sits AFTER an unrelated [server].
    tokio::fs::write(
        &path,
        "[general]\nprefer_ipv6 = false\n\n[server]\nport = 443\n\n\
         [general.modes]\ntls = true\n",
    )
    .await
    .unwrap();

    let mut cfg = ProxyConfig::default();
    cfg.general.prefer_ipv6 = true;

    save_sections_to_disk(&path, &cfg, &["general"])
        .await
        .unwrap();

    let written = tokio::fs::read_to_string(&path).await.unwrap();
    assert_eq!(
        written.matches("[general.modes]").count(),
        1,
        "non-contiguous [general.modes] must not duplicate:\n{written}"
    );
    toml::from_str::<toml::Value>(&written)
        .unwrap_or_else(|e| panic!("written config must parse: {e}\n{written}"));
    // The unrelated section remains present.
    assert!(written.contains("[server]"));
}

#[tokio::test]
async fn manifest_revision_changes_when_an_included_source_changes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    let included = dir.path().join("included.toml");
    tokio::fs::write(&root, "include = \"included.toml\"\n")
        .await
        .unwrap();
    tokio::fs::write(&included, "[censorship]\ntls_domain = \"one.example\"\n")
        .await
        .unwrap();
    let first = current_revision(&root).await.unwrap();

    tokio::fs::write(&included, "[censorship]\ntls_domain = \"two.example\"\n")
        .await
        .unwrap();
    let second = current_revision(&root).await.unwrap();

    assert_ne!(first, second);
}

#[tokio::test]
async fn manifest_revision_does_not_require_typed_config_validation() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    tokio::fs::write(&root, "[server]\nport = \"invalid\"\n")
        .await
        .unwrap();

    let revision = current_revision(&root).await.unwrap();

    assert_eq!(revision.len(), 64);
    assert!(load_config_snapshot(&root, false).await.is_err());
}

#[tokio::test]
async fn access_mutation_writes_only_the_single_included_owner() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    let included = dir.path().join("users.toml");
    let root_body = "include = \"users.toml\"\n[censorship]\ntls_domain = \"example.com\"\n";
    let included_body = "[access.users]\nalice = \"00000000000000000000000000000000\"\n";
    tokio::fs::write(&root, root_body).await.unwrap();
    tokio::fs::write(&included, included_body).await.unwrap();
    let mut cfg = load_config_from_disk(&root).await.unwrap();
    cfg.access.users.insert(
        "bob".to_string(),
        "11111111111111111111111111111111".to_string(),
    );

    let revision = save_access_sections_to_disk(&root, &cfg, &[AccessSection::Users])
        .await
        .unwrap();

    assert_eq!(tokio::fs::read_to_string(&root).await.unwrap(), root_body);
    let written = tokio::fs::read_to_string(&included).await.unwrap();
    assert!(written.contains("bob = \"11111111111111111111111111111111\""));
    assert_eq!(revision, current_revision(&root).await.unwrap());
}

#[tokio::test]
async fn access_mutation_rejects_source_graph_change_after_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    let included = dir.path().join("users.toml");
    let root_body = "include = \"users.toml\"\n[censorship]\ntls_domain = \"one.example\"\n";
    let external_root = "include = \"users.toml\"\n[censorship]\ntls_domain = \"two.example\"\n";
    let included_body = "[access.users]\nalice = \"00000000000000000000000000000000\"\n";
    tokio::fs::write(&root, root_body).await.unwrap();
    tokio::fs::write(&included, included_body).await.unwrap();
    let (mut cfg, revision) = load_config_for_mutation(&root, None).await.unwrap();
    cfg.access.users.insert(
        "bob".to_string(),
        "11111111111111111111111111111111".to_string(),
    );
    tokio::fs::write(&root, external_root).await.unwrap();

    let error = save_access_sections_to_disk_if_revision(
        &root,
        &cfg,
        &[AccessSection::Users],
        Some(&revision),
    )
    .await
    .unwrap_err();

    assert_eq!(error.code, "revision_conflict");
    assert_eq!(
        tokio::fs::read_to_string(&root).await.unwrap(),
        external_root
    );
    assert_eq!(
        tokio::fs::read_to_string(&included).await.unwrap(),
        included_body
    );
}

#[cfg(unix)]
#[tokio::test]
async fn atomic_write_preserves_existing_file_mode() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    tokio::fs::write(&path, "old").await.unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let before = std::fs::metadata(&path).unwrap();

    write_atomic(path.clone(), "new".to_string()).await.unwrap();

    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(after.mode() & 0o7777, 0o640);
    assert_eq!(after.uid(), before.uid());
    assert_eq!(after.gid(), before.gid());
}

#[tokio::test]
async fn config_sidecar_lock_serializes_competing_revision_writers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let original = concat!(
        "[censorship]\n",
        "tls_domain = \"original.example\"\n",
        "[access.users]\n",
        "alice = \"00000000000000000000000000000000\"\n"
    );
    tokio::fs::write(&path, original).await.unwrap();
    let graph = ProxyConfig::read_source_graph(&path).unwrap();
    let revision = compute_source_revision(&graph);

    let first = tokio::spawn(write_atomic_if_unchanged(
        path.clone(),
        revision.clone(),
        path.clone(),
        original.to_string(),
        original.replace("original.example", "first.example"),
    ));
    let second = tokio::spawn(write_atomic_if_unchanged(
        path.clone(),
        revision,
        path.clone(),
        original.to_string(),
        original.replace("original.example", "second.example"),
    ));
    let first = first.await.unwrap();
    let second = second.await.unwrap();

    assert_ne!(first.is_ok(), second.is_ok());
    let (winner_revision, conflict) = match (first, second) {
        (Ok(revision), Err(error)) | (Err(error), Ok(revision)) => (revision, error),
        _ => unreachable!("exactly one cooperative writer must commit"),
    };
    assert_eq!(conflict.code, "revision_conflict");
    assert_eq!(winner_revision, current_revision(&path).await.unwrap());
    let persisted = tokio::fs::read_to_string(&path).await.unwrap();
    assert!(persisted.contains("first.example") || persisted.contains("second.example"));
}

#[tokio::test]
async fn access_mutation_rejects_sections_with_different_source_owners() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    let included = dir.path().join("enabled.toml");
    let root_body = concat!(
        "include = \"enabled.toml\"\n",
        "[access.users]\nalice = \"00000000000000000000000000000000\"\n"
    );
    let included_body = "[access.user_enabled]\nalice = false\n";
    tokio::fs::write(&root, root_body).await.unwrap();
    tokio::fs::write(&included, included_body).await.unwrap();
    let cfg = load_config_from_disk(&root).await.unwrap();

    let error = save_access_sections_to_disk(
        &root,
        &cfg,
        &[AccessSection::Users, AccessSection::UserEnabled],
    )
    .await
    .unwrap_err();

    assert_eq!(error.code, "config_patch_not_atomic");
    assert_eq!(tokio::fs::read_to_string(&root).await.unwrap(), root_body);
    assert_eq!(
        tokio::fs::read_to_string(&included).await.unwrap(),
        included_body
    );
}

#[test]
fn render_user_rate_limits_section() {
    let mut cfg = ProxyConfig::default();
    cfg.access.user_rate_limits.insert(
        "alice".to_string(),
        RateLimitBps {
            up_bps: 1024,
            down_bps: 2048,
        },
    );

    let rendered =
        render_access_section(&cfg, AccessSection::UserRateLimits).expect("section must render");

    assert!(rendered.starts_with("[access.user_rate_limits]\n"));
    assert!(rendered.contains("alice = { up_bps = 1024, down_bps = 2048 }"));
}

#[cfg(unix)]
#[test]
fn source_owner_normalization_preserves_symlinks() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.toml");
    let linked = dir.path().join("linked.toml");
    std::fs::write(&real, "").unwrap();
    symlink(&real, &linked).unwrap();

    assert_eq!(normalize_source_path(&linked), linked);
}
