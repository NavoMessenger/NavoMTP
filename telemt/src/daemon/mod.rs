//! Unix daemon support for telemt.
//!
//! Provides classic Unix daemonization (double-fork), PID file management,
//! and privilege dropping for running telemt as a background service.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::unistd::{self, ForkResult, Gid, Uid, chdir, fork, getpid, setsid};
use tracing::info;

// PID file ownership and process-control helpers.
mod pid_file;

pub use pid_file::DaemonStatus;
#[allow(unused_imports)]
pub use pid_file::{PidFile, check_status, read_pid_file, signal_pid_file};

/// Default PID file location.
pub const DEFAULT_PID_FILE: &str = "/var/run/telemt.pid";

/// Daemon configuration options parsed from CLI.
#[derive(Debug, Clone, Default)]
pub struct DaemonOptions {
    /// Run as daemon (fork to background).
    pub daemonize: bool,
    /// Path to PID file.
    pub pid_file: Option<PathBuf>,
    /// Require trusted, symlink-free PID and log parents. Disabled by default for compatibility.
    pub strict_runtime_paths: bool,
    /// User to run as after binding sockets.
    pub user: Option<String>,
    /// Group to run as after binding sockets.
    pub group: Option<String>,
    /// Working directory for the daemon.
    pub working_dir: Option<PathBuf>,
    /// Explicit foreground mode (for systemd Type=simple).
    pub foreground: bool,
}

impl DaemonOptions {
    /// Returns the effective PID file path.
    pub fn pid_file_path(&self) -> &Path {
        self.pid_file
            .as_deref()
            .unwrap_or(Path::new(DEFAULT_PID_FILE))
    }

    /// Returns true if we should actually daemonize.
    /// Foreground flag takes precedence.
    pub fn should_daemonize(&self) -> bool {
        self.daemonize && !self.foreground
    }
}

/// Error types for daemon operations.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// A daemonization fork failed.
    #[error("fork failed: {0}")]
    ForkFailed(#[source] nix::Error),

    /// Creation of the detached session failed.
    #[error("setsid failed: {0}")]
    SetsidFailed(#[source] nix::Error),

    /// Switching to the configured working directory failed.
    #[error("chdir failed: {0}")]
    ChdirFailed(#[source] nix::Error),

    /// Opening `/dev/null` for standard-stream redirection failed.
    #[error("failed to open /dev/null: {0}")]
    DevNullFailed(#[source] io::Error),

    /// Redirecting a standard file descriptor failed.
    #[error("failed to redirect stdio: {0}")]
    RedirectFailed(#[source] nix::Error),

    /// A PID lifecycle operation failed.
    #[error("PID file error: {0}")]
    PidFile(String),

    /// Another process owns the daemon PID lifecycle.
    #[error("another instance is already running (pid {0})")]
    AlreadyRunning(i32),

    /// The configured runtime user does not exist.
    #[error("user '{0}' not found")]
    UserNotFound(String),

    /// The configured runtime group does not exist.
    #[error("group '{0}' not found")]
    GroupNotFound(String),

    /// Applying the configured runtime identity failed.
    #[error("failed to set uid/gid: {0}")]
    PrivilegeDrop(#[source] nix::Error),

    /// An underlying filesystem operation failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Result of a successful daemonize() call.
#[derive(Debug)]
pub enum DaemonizeResult {
    /// We are the parent process and should exit.
    Parent,
    /// We are the daemon child process and should continue.
    Child,
}

/// Performs classic Unix double-fork daemonization.
///
/// This detaches the process from the controlling terminal:
/// 1. First fork - parent exits, child continues
/// 2. setsid() - become session leader
/// 3. Second fork - ensure we can never acquire a controlling terminal
/// 4. chdir("/") - don't hold any directory open
/// 5. Redirect stdin/stdout/stderr to /dev/null
///
/// Returns `DaemonizeResult::Parent` in the original parent (which should exit),
/// or `DaemonizeResult::Child` in the final daemon child.
pub fn daemonize(working_dir: Option<&Path>) -> Result<DaemonizeResult, DaemonError> {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            return Ok(DaemonizeResult::Parent);
        }
        Ok(ForkResult::Child) => {}
        Err(e) => return Err(DaemonError::ForkFailed(e)),
    }

    setsid().map_err(DaemonError::SetsidFailed)?;

    // Second fork to ensure we can never acquire a controlling terminal
    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            std::process::exit(0);
        }
        Ok(ForkResult::Child) => {}
        Err(e) => return Err(DaemonError::ForkFailed(e)),
    }

    let target_dir = working_dir.unwrap_or(Path::new("/"));
    chdir(target_dir).map_err(DaemonError::ChdirFailed)?;

    redirect_stdio_to_devnull()?;

    Ok(DaemonizeResult::Child)
}

/// Redirects stdin, stdout, and stderr to /dev/null.
fn redirect_stdio_to_devnull() -> Result<(), DaemonError> {
    let devnull = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(DaemonError::DevNullFailed)?;

    let devnull_fd = std::os::unix::io::AsRawFd::as_raw_fd(&devnull);

    // Use libc::dup2 directly for redirecting standard file descriptors
    // nix 0.31's dup2 requires OwnedFd which doesn't work well with stdio fds
    unsafe {
        if libc::dup2(devnull_fd, 0) < 0 {
            return Err(DaemonError::RedirectFailed(Errno::last()));
        }
        if libc::dup2(devnull_fd, 1) < 0 {
            return Err(DaemonError::RedirectFailed(Errno::last()));
        }
        if libc::dup2(devnull_fd, 2) < 0 {
            return Err(DaemonError::RedirectFailed(Errno::last()));
        }
    }

    // Keep stdio descriptors open; other source descriptors are closed once by File's Drop.
    // Transfer ownership only after all dup2 calls succeed so errors retain RAII cleanup.
    if devnull_fd <= 2 {
        let _ = std::os::unix::io::IntoRawFd::into_raw_fd(devnull);
    }

    Ok(())
}

// macOS gates nix::unistd::setgroups differently in the current dependency set,
// so call libc directly there while preserving the original nix path elsewhere.
fn set_supplementary_groups(gid: Gid) -> Result<(), nix::Error> {
    #[cfg(target_os = "macos")]
    {
        let groups = [gid.as_raw()];
        let rc = unsafe {
            libc::setgroups(
                i32::try_from(groups.len()).expect("single supplementary group must fit in c_int"),
                groups.as_ptr(),
            )
        };
        if rc == 0 { Ok(()) } else { Err(Errno::last()) }
    }

    #[cfg(not(target_os = "macos"))]
    {
        unistd::setgroups(&[gid])
    }
}

/// Drops privileges to the specified user and group.
///
/// This should be called after binding privileged ports but before entering
/// the main event loop.
pub fn drop_privileges(
    user: Option<&str>,
    group: Option<&str>,
    pid_file: Option<&PidFile>,
) -> Result<(), DaemonError> {
    let target_gid = if let Some(group_name) = group {
        Some(lookup_group(group_name)?)
    } else if let Some(user_name) = user {
        Some(lookup_user_primary_gid(user_name)?)
    } else {
        None
    };

    let target_uid = if let Some(user_name) = user {
        Some(lookup_user(user_name)?)
    } else {
        None
    };

    if (target_uid.is_some() || target_gid.is_some())
        && let Some(pid_file) = pid_file
    {
        for file in pid_file.ownership_file_handles().into_iter().flatten() {
            unistd::fchown(file, target_uid, target_gid).map_err(DaemonError::PrivilegeDrop)?;
        }
    }

    if let Some(gid) = target_gid {
        unistd::setgid(gid).map_err(DaemonError::PrivilegeDrop)?;
        set_supplementary_groups(gid).map_err(DaemonError::PrivilegeDrop)?;
        info!(gid = gid.as_raw(), "Dropped group privileges");
    }

    if let Some(uid) = target_uid {
        unistd::setuid(uid).map_err(DaemonError::PrivilegeDrop)?;
        info!(uid = uid.as_raw(), "Dropped user privileges");

        if uid.as_raw() != 0
            && let Some(pid) = pid_file
        {
            let parent = pid.path().parent().unwrap_or(Path::new("."));
            let probe_path = parent.join(format!(
                ".telemt_pid_probe_{}_{}",
                std::process::id(),
                getpid().as_raw()
            ));
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&probe_path)
                .map_err(|e| {
                    DaemonError::PidFile(format!(
                        "cannot create probe in PID directory {} as uid {} (pid cleanup will fail): {}",
                        parent.display(),
                        uid.as_raw(),
                        e
                    ))
                })?;
            fs::remove_file(&probe_path).map_err(|e| {
                DaemonError::PidFile(format!(
                    "cannot remove probe in PID directory {} as uid {} (pid cleanup will fail): {}",
                    parent.display(),
                    uid.as_raw(),
                    e
                ))
            })?;
        }
    }

    Ok(())
}

/// Looks up a user by name and returns their UID.
fn lookup_user(name: &str) -> Result<Uid, DaemonError> {
    let c_name =
        std::ffi::CString::new(name).map_err(|_| DaemonError::UserNotFound(name.to_string()))?;

    unsafe {
        let pwd = libc::getpwnam(c_name.as_ptr());
        if pwd.is_null() {
            Err(DaemonError::UserNotFound(name.to_string()))
        } else {
            Ok(Uid::from_raw((*pwd).pw_uid))
        }
    }
}

/// Looks up a user's primary GID by username.
fn lookup_user_primary_gid(name: &str) -> Result<Gid, DaemonError> {
    let c_name =
        std::ffi::CString::new(name).map_err(|_| DaemonError::UserNotFound(name.to_string()))?;

    unsafe {
        let pwd = libc::getpwnam(c_name.as_ptr());
        if pwd.is_null() {
            Err(DaemonError::UserNotFound(name.to_string()))
        } else {
            Ok(Gid::from_raw((*pwd).pw_gid))
        }
    }
}

/// Looks up a group by name and returns its GID.
fn lookup_group(name: &str) -> Result<Gid, DaemonError> {
    let c_name =
        std::ffi::CString::new(name).map_err(|_| DaemonError::GroupNotFound(name.to_string()))?;

    unsafe {
        let grp = libc::getgrnam(c_name.as_ptr());
        if grp.is_null() {
            Err(DaemonError::GroupNotFound(name.to_string()))
        } else {
            Ok(Gid::from_raw((*grp).gr_gid))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_options_default() {
        let opts = DaemonOptions::default();
        assert!(!opts.daemonize);
        assert!(!opts.strict_runtime_paths);
        assert!(!opts.should_daemonize());
        assert_eq!(opts.pid_file_path(), Path::new(DEFAULT_PID_FILE));
    }

    #[test]
    fn test_daemon_options_foreground_overrides() {
        let opts = DaemonOptions {
            daemonize: true,
            foreground: true,
            ..Default::default()
        };
        assert!(!opts.should_daemonize());
    }
}
