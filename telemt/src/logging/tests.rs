use super::*;

#[test]
fn test_parse_log_cli_options_default() {
    let args: Vec<String> = vec![];
    let options = parse_log_cli_options(&args).unwrap();
    assert!(!LoggingOptions::default().strict_runtime_paths);
    assert_eq!(
        resolve_log_destination(&LoggingConfig::default(), &options).unwrap(),
        LogDestination::Stderr
    );
}

#[test]
fn test_parse_log_cli_options_file() {
    let args = vec!["--log-file".to_string(), "/var/log/telemt.log".to_string()];
    let options = parse_log_cli_options(&args).unwrap();
    match resolve_log_destination(&LoggingConfig::default(), &options).unwrap() {
        LogDestination::File { options } => {
            assert_eq!(options.path, "/var/log/telemt.log");
            assert_eq!(options.rotation, LogRotation::Never);
        }
        _ => panic!("Expected File destination"),
    }
}

#[test]
fn test_parse_log_cli_options_file_daily() {
    let args = vec!["--log-file-daily=/var/log/telemt".to_string()];
    let options = parse_log_cli_options(&args).unwrap();
    match resolve_log_destination(&LoggingConfig::default(), &options).unwrap() {
        LogDestination::File { options } => {
            assert_eq!(options.path, "/var/log/telemt");
            assert_eq!(options.rotation, LogRotation::Daily);
        }
        _ => panic!("Expected File destination"),
    }
}

#[test]
fn test_parse_log_cli_options_bounds() {
    let args = vec![
        "--log-file=/var/log/telemt.log".to_string(),
        "--log-rotation=hourly".to_string(),
        "--log-max-size-bytes=1024".to_string(),
        "--log-max-files=3".to_string(),
        "--log-max-age-secs=60".to_string(),
    ];
    let options = parse_log_cli_options(&args).unwrap();
    match resolve_log_destination(&LoggingConfig::default(), &options).unwrap() {
        LogDestination::File { options } => {
            assert_eq!(options.rotation, LogRotation::Hourly);
            assert_eq!(options.max_size_bytes, 1024);
            assert_eq!(options.max_files, 3);
            assert_eq!(options.max_age_secs, 60);
        }
        _ => panic!("Expected File destination"),
    }
}

#[test]
fn test_parse_log_cli_options_rejects_bad_rotation() {
    let args = vec!["--log-rotation=yearly".to_string()];
    assert!(parse_log_cli_options(&args).is_err());
}

#[cfg(unix)]
#[test]
fn test_parse_log_cli_options_syslog() {
    let args = vec!["--syslog".to_string()];
    let options = parse_log_cli_options(&args).unwrap();
    assert_eq!(
        resolve_log_destination(&LoggingConfig::default(), &options).unwrap(),
        LogDestination::Syslog
    );
}

#[cfg(unix)]
#[test]
fn test_syslog_priority_for_level_mapping() {
    assert_eq!(
        syslog_priority_for_level(&tracing::Level::ERROR),
        libc::LOG_ERR
    );
    assert_eq!(
        syslog_priority_for_level(&tracing::Level::WARN),
        libc::LOG_WARNING
    );
    assert_eq!(
        syslog_priority_for_level(&tracing::Level::INFO),
        libc::LOG_INFO
    );
    assert_eq!(
        syslog_priority_for_level(&tracing::Level::DEBUG),
        libc::LOG_DEBUG
    );
    assert_eq!(
        syslog_priority_for_level(&tracing::Level::TRACE),
        libc::LOG_DEBUG
    );
}
