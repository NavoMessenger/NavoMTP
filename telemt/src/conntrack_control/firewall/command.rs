use std::time::Duration;

#[cfg(unix)]
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::process::Command;

#[cfg(unix)]
use crate::util::trusted_command::{resolve_trusted_helper, trusted_helper_command};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// A privileged helper invocation with arguments kept separate from shell syntax.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CommandSpec {
    /// Logical helper name resolved by the trusted executable policy.
    pub(super) binary: &'static str,
    /// Arguments passed directly to the helper process.
    pub(super) args: Vec<String>,
    /// Optional restore script supplied on standard input.
    pub(super) stdin: Option<String>,
}

impl CommandSpec {
    /// Creates a helper invocation without an input script.
    pub(super) fn new(binary: &'static str, args: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            binary,
            args: args.into_iter().map(str::to_string).collect(),
            stdin: None,
        }
    }

    /// Creates a helper invocation that receives a restore script.
    pub(super) fn with_stdin(
        binary: &'static str,
        args: impl IntoIterator<Item = &'static str>,
        stdin: String,
    ) -> Self {
        Self {
            binary,
            args: args.into_iter().map(str::to_string).collect(),
            stdin: Some(stdin),
        }
    }
}

/// Distinguishes idempotent absence from transaction and execution failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommandErrorKind {
    /// The trusted helper executable is unavailable.
    Missing,
    /// The requested firewall object or rule is absent.
    NotFound,
    /// A terminal or process cancellation interrupted the invocation.
    Cancelled,
    /// The helper exceeded its execution deadline.
    Timeout,
    /// A failure that must not be treated as successful cleanup.
    Failed,
}

/// A classified helper failure retaining its diagnostic for reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CommandError {
    /// Recovery semantics associated with the failure.
    pub(super) kind: CommandErrorKind,
    /// Original helper diagnostic or an execution failure description.
    pub(super) message: String,
}

impl CommandError {
    /// Creates the cancellation failure used by interruptible transactions.
    pub(super) fn cancelled() -> Self {
        Self {
            kind: CommandErrorKind::Cancelled,
            message: "firewall transaction cancelled".to_string(),
        }
    }

    /// Creates a failure that prevents idempotent cleanup from claiming success.
    pub(super) fn failed(message: impl Into<String>) -> Self {
        Self {
            kind: CommandErrorKind::Failed,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

/// Executes firewall commands through a production or deterministic test runner.
pub(super) trait FirewallCommandRunner: Send + Sync {
    /// Reports whether a helper can be resolved under the runner's trust policy.
    fn available(&self, binary: &str) -> bool;

    /// Reports whether the process has the capability required to alter firewall rules.
    fn has_cap_net_admin(&self) -> bool;

    /// Executes one invocation while preserving classified failure semantics.
    async fn run(&self, spec: CommandSpec) -> Result<(), CommandError>;
}

/// Runs trusted system helpers with bounded execution and captured diagnostics.
#[derive(Clone, Copy, Default)]
pub(super) struct SystemCommandRunner;

impl FirewallCommandRunner for SystemCommandRunner {
    fn available(&self, binary: &str) -> bool {
        #[cfg(unix)]
        {
            resolve_trusted_helper(binary).is_some()
        }
        #[cfg(not(unix))]
        {
            let _ = binary;
            false
        }
    }

    fn has_cap_net_admin(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
                return false;
            };
            for line in status.lines() {
                if let Some(raw) = line.strip_prefix("CapEff:") {
                    let caps = raw.trim();
                    if let Ok(bits) = u64::from_str_radix(caps, 16) {
                        const CAP_NET_ADMIN_BIT: u64 = 12;
                        return (bits & (1u64 << CAP_NET_ADMIN_BIT)) != 0;
                    }
                }
            }
            false
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    async fn run(&self, spec: CommandSpec) -> Result<(), CommandError> {
        #[cfg(not(unix))]
        {
            Err(CommandError {
                kind: CommandErrorKind::Missing,
                message: format!("{} is not available", spec.binary),
            })
        }
        #[cfg(unix)]
        {
            let Some(command) = trusted_helper_command(spec.binary) else {
                return Err(CommandError {
                    kind: CommandErrorKind::Missing,
                    message: format!("{} is not available", spec.binary),
                });
            };
            let mut command = Command::from(command);
            command.args(&spec.args);
            command.env("LC_ALL", "C");
            if spec.stdin.is_some() {
                command.stdin(std::process::Stdio::piped());
            }
            command.stdout(std::process::Stdio::null());
            command.stderr(std::process::Stdio::piped());
            command.kill_on_drop(true);
            let mut child = command.spawn().map_err(|error| CommandError {
                kind: CommandErrorKind::Failed,
                message: format!("spawn {} failed: {error}", spec.binary),
            })?;
            let binary = spec.binary;
            let output = tokio::time::timeout(COMMAND_TIMEOUT, async move {
                if let Some(blob) = spec.stdin
                    && let Some(mut writer) = child.stdin.take()
                {
                    writer
                        .write_all(blob.as_bytes())
                        .await
                        .map_err(|error| CommandError {
                            kind: CommandErrorKind::Failed,
                            message: format!("stdin write {binary} failed: {error}"),
                        })?;
                }
                child
                    .wait_with_output()
                    .await
                    .map_err(|error| CommandError {
                        kind: CommandErrorKind::Failed,
                        message: format!("wait {binary} failed: {error}"),
                    })
            })
            .await
            .map_err(|_| CommandError {
                kind: CommandErrorKind::Timeout,
                message: format!("{binary} timed out after {}s", COMMAND_TIMEOUT.as_secs()),
            })??;
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let message = if stderr.is_empty() {
                format!("{binary} exited with status {}", output.status)
            } else {
                stderr
            };
            let kind = classify_command_error(binary, &spec.args, &message);
            Err(CommandError { kind, message })
        }
    }
}

/// Recognizes the existing legacy iptables and native nftables absence formats.
pub(super) fn is_not_found_error(message: &str) -> bool {
    message.contains("No chain/target/match by that name")
        || message.contains("Bad rule (does a matching rule exist in that chain?)")
        || message.contains("Could not process rule: No such file or directory")
}

/// Bounds additional iptables-nft absence diagnostics to owned cleanup and checks.
pub(super) fn classify_command_error(
    binary: &str,
    args: &[String],
    message: &str,
) -> CommandErrorKind {
    if is_not_found_error(message) || is_missing_owned_iptables_chain(binary, args, message) {
        CommandErrorKind::NotFound
    } else {
        CommandErrorKind::Failed
    }
}

fn is_missing_owned_iptables_chain(binary: &str, args: &[String], message: &str) -> bool {
    if !matches!(binary, "iptables" | "ip6tables") {
        return false;
    }
    // An absent jump target is harmless for deletion, but not for installation.
    let chain = match args {
        [flag, table, operation, source, jump, target]
            if flag == "-t"
                && table == "raw"
                && matches!(operation.as_str(), "-C" | "-D")
                && source == "PREROUTING"
                && jump == "-j"
                && target == "TELEMT_NOTRACK" =>
        {
            target.as_str()
        }
        [flag, table, operation, target]
            if flag == "-t"
                && table == "raw"
                && matches!(operation.as_str(), "-F" | "-X")
                && matches!(
                    target.as_str(),
                    "TELEMT_NOTRACK" | "TELEMT_NT_A" | "TELEMT_NT_B"
                ) =>
        {
            target.as_str()
        }
        _ => return false,
    };
    let mut lines = message.lines();
    let Some(first) = lines.next() else {
        return false;
    };
    let diagnostic = if first.starts_with("Chain '") {
        first
    } else {
        let Some((version, diagnostic)) = first
            .strip_prefix(binary)
            .and_then(|line| line.strip_prefix(" v"))
            .and_then(|line| line.split_once(" (nf_tables): "))
        else {
            return false;
        };
        if version.is_empty() || version.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return false;
        }
        diagnostic
    };
    if diagnostic
        .strip_prefix("Chain '")
        .and_then(|line| line.strip_suffix("' does not exist"))
        != Some(chain)
    {
        return false;
    }
    // Reject mixed diagnostics instead of hiding another failure after an absence message.
    let Some(help) = lines.next() else {
        return true;
    };
    help.strip_prefix("Try `")
        .and_then(|line| line.strip_prefix(binary))
        .and_then(|line| line.strip_prefix(" -h' or '"))
        .and_then(|line| line.strip_prefix(binary))
        == Some(" --help' for more information.")
        && lines.next().is_none()
}
