use base64::Engine as _;

use super::*;

#[test]
fn capability_matches_reference_vectors() {
    let secret = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut dd_secret = vec![0xdd];
    dd_secret.extend_from_slice(&secret);
    for (client_secret, base_path, expected) in [
        (
            secret.as_slice(),
            b"".as_slice(),
            "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk",
        ),
        (
            dd_secret.as_slice(),
            b"".as_slice(),
            "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA",
        ),
        (
            secret.as_slice(),
            b"dobry-cola-super-app".as_slice(),
            "hHz99Xs93EN1j91G9gpNepXwGNNt5YdAFkEVk_LlqdQ",
        ),
        (
            dd_secret.as_slice(),
            b"dobry-cola-super-app".as_slice(),
            "TGUkZaevsavLbHvlNWipnRoYxgzZ51ioWvbxgGT3wHo",
        ),
    ] {
        let capability =
            derive_web_capability(client_secret, b"proxy.example.com", base_path).unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability),
            expected
        );
    }
}

#[test]
fn capability_binds_the_exact_host_and_base_path_identity() {
    let secret = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let root = derive_web_capability(&secret, b"proxy.example.com", b"").unwrap();
    let mixed = derive_web_capability(&secret, b"proxy.example.com", b"MixedCase/path").unwrap();
    let lower = derive_web_capability(&secret, b"proxy.example.com", b"mixedcase/path").unwrap();
    let other_path =
        derive_web_capability(&secret, b"proxy.example.com", b"MixedCase/other").unwrap();
    let other_host =
        derive_web_capability(&secret, b"other.example.com", b"MixedCase/path").unwrap();

    let identities = [root, mixed, lower, other_path, other_host]
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(identities.len(), 5);
}

#[cfg(unix)]
#[test]
fn static_snapshot_remains_anchored_after_root_path_replacement() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("site");
    let detached = temp.path().join("detached");
    let replacement = temp.path().join("replacement");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("index.html"), b"original").unwrap();
    fs::create_dir(&replacement).unwrap();
    fs::write(replacement.join("index.html"), b"replacement").unwrap();

    let directory = open_static_root(&root).unwrap();
    fs::rename(&root, &detached).unwrap();
    symlink(&replacement, &root).unwrap();

    let mut assets = BTreeMap::new();
    let mut total_files = 0;
    let mut total_bytes = 0;
    load_static_directory(
        directory,
        Path::new(""),
        &root,
        &mut assets,
        &mut total_files,
        &mut total_bytes,
        &WebLimitsConfig::default(),
        0,
    )
    .unwrap();

    assert_eq!(assets["/index.html"].body.as_ref(), b"original");
}
