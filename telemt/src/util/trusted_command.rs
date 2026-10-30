use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const TRUSTED_HELPER_DIRS: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];
const TRUSTED_HELPERS: [&str; 12] = [
    "nft",
    "iptables",
    "iptables-restore",
    "ip6tables",
    "ip6tables-restore",
    "conntrack",
    "pfctl",
    "systemctl",
    "rc-update",
    "rc-service",
    "sysrc",
    "service",
];

/// Resolves a privileged helper only through the fixed system allowlist.
pub(crate) fn resolve_trusted_helper(binary: &str) -> Option<PathBuf> {
    if !TRUSTED_HELPERS.contains(&binary) {
        return None;
    }

    TRUSTED_HELPER_DIRS
        .iter()
        .map(|directory| Path::new(directory).join(binary))
        .find_map(|candidate| trusted_executable(&candidate))
}

/// Builds a trusted helper command with its allowlisted invocation name.
pub(crate) fn trusted_helper_command(binary: &str) -> Option<Command> {
    let command_path = resolve_trusted_helper(binary)?;
    Some(command_for_resolved_helper(binary, command_path))
}

fn command_for_resolved_helper(binary: &str, command_path: PathBuf) -> Command {
    let mut command = Command::new(command_path);
    // Multi-call helpers dispatch from argv[0], which canonical path resolution discards.
    command.arg0(binary);
    command
}

fn trusted_executable(candidate: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(candidate).ok()?;
    let metadata = std::fs::metadata(&canonical).ok()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o111 == 0
        || !trusted_parent_chain(canonical.parent()?)
    {
        return None;
    }
    Some(canonical)
}

fn trusted_parent_chain(path: &Path) -> bool {
    for ancestor in path.ancestors() {
        let Ok(metadata) = std::fs::symlink_metadata(ancestor) else {
            return false;
        };
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn privileged_helper_allowlist_rejects_arbitrary_binary() {
        assert!(resolve_trusted_helper("sh").is_none());
        assert!(resolve_trusted_helper("../bin/nft").is_none());
    }

    #[test]
    fn privileged_helper_allowlist_accepts_exact_restore_names() {
        assert!(TRUSTED_HELPERS.contains(&"iptables-restore"));
        assert!(TRUSTED_HELPERS.contains(&"ip6tables-restore"));
        assert!(!TRUSTED_HELPERS.contains(&"iptables-restore-wrapper"));
    }

    #[test]
    fn trusted_multicall_command_preserves_logical_argv0() {
        let command_path = std::fs::canonicalize("/bin/sh").unwrap();
        for binary in [
            "iptables",
            "ip6tables",
            "iptables-restore",
            "ip6tables-restore",
        ] {
            let mut command = command_for_resolved_helper(binary, command_path.clone());
            assert_eq!(command.get_program(), command_path.as_os_str());

            let output = command.args(["-c", "printf '%s' \"$0\""]).output().unwrap();
            assert!(output.status.success());
            assert_eq!(String::from_utf8(output.stdout).unwrap(), binary);
        }
    }

    #[test]
    fn writable_executable_is_not_trusted() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("nft");
        std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o777)).unwrap();

        assert!(trusted_executable(&executable).is_none());
    }
}
