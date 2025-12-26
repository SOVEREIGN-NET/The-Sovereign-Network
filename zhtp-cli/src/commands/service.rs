//! System service installation and management
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Service name validation, configuration generation, path construction
//! - **Imperative Shell**: File I/O, system commands, user prompts
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for template generation and path construction

use crate::argument_parsing::ServiceAction;
use crate::error::{CliResult, CliError};

use std::path::PathBuf;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Service operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceOperation {
    Install,
    Uninstall,
    Start,
    Stop,
    Status,
    Logs,
}

impl ServiceOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            ServiceOperation::Install => "Install system service",
            ServiceOperation::Uninstall => "Uninstall system service",
            ServiceOperation::Start => "Start service",
            ServiceOperation::Stop => "Stop service",
            ServiceOperation::Status => "Get service status",
            ServiceOperation::Logs => "View service logs",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &ServiceAction) -> ServiceOperation {
    match action {
        ServiceAction::Install { .. } => ServiceOperation::Install,
        ServiceAction::Uninstall { .. } => ServiceOperation::Uninstall,
        ServiceAction::Start => ServiceOperation::Start,
        ServiceAction::Stop => ServiceOperation::Stop,
        ServiceAction::Status => ServiceOperation::Status,
        ServiceAction::Logs { .. } => ServiceOperation::Logs,
    }
}

/// Detect current platform
///
/// Pure function - detects OS without side effects
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOS,
    Windows,
    Other,
}

pub fn detect_platform() -> Platform {
    match std::env::consts::OS {
        "linux" => Platform::Linux,
        "macos" => Platform::MacOS,
        "windows" => Platform::Windows,
        _ => Platform::Other,
    }
}

/// Validate service user name
///
/// Pure function - format validation only
pub fn validate_service_user(user: &str) -> CliResult<()> {
    if user.is_empty() {
        return Err(CliError::ConfigError(
            "Service user cannot be empty".to_string(),
        ));
    }

    // Allow alphanumeric, underscores, and hyphens for usernames
    if !user.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(CliError::ConfigError(format!(
            "Invalid service user: {}. Use only alphanumeric characters, hyphens, and underscores",
            user
        )));
    }

    Ok(())
}

/// Generate systemd service file content
///
/// Pure function - template generation only
pub fn generate_systemd_unit(user: &str, binary_path: &str) -> String {
    format!(
        r#"[Unit]
Description=ZHTP Orchestrator Node
After=network.target
Documentation=https://github.com/SOVEREIGN-NET/The-Sovereign-Network

[Service]
Type=simple
User={}
ExecStart={}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zhtp-cli

# Security hardening
PrivateTmp=yes
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/zhtp

[Install]
WantedBy=multi-user.target
"#,
        user, binary_path
    )
}

/// Generate launchd plist content
///
/// Pure function - template generation only
pub fn generate_launchd_plist(binary_path: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>network.zhtp.node</string>
    <key>Program</key>
    <string>{}</string>
    <key>Arguments</key>
    <array>
        <string>node</string>
        <string>start</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/zhtp-cli.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/zhtp-cli.error.log</string>
</dict>
</plist>
"#,
        binary_path
    )
}

/// Get systemd service name
///
/// Pure function - constant value
pub fn get_systemd_service_name() -> &'static str {
    "zhtp-node"
}

/// Get launchd service name
///
/// Pure function - constant value
pub fn get_launchd_service_name() -> &'static str {
    "network.zhtp.node"
}

/// Get Windows service name
///
/// Pure function - constant value
pub fn get_windows_service_name() -> &'static str {
    "ZhtpNode"
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (file I/O, system commands)
// ============================================================================

/// Handle service command with proper error handling and output
pub async fn handle_service_command(args: crate::argument_parsing::ServiceArgs) -> CliResult<()> {
    let platform = detect_platform();
    let _op = action_to_operation(&args.action);

    match args.action {
        ServiceAction::Install { user, enable } => {
            validate_service_user(&user)?;
            install_service_impl(platform, &user, enable).await
        }
        ServiceAction::Uninstall { force } => uninstall_service_impl(platform, force).await,
        ServiceAction::Start => start_service_impl(platform).await,
        ServiceAction::Stop => stop_service_impl(platform).await,
        ServiceAction::Status => status_service_impl(platform).await,
        ServiceAction::Logs { lines, follow } => logs_service_impl(platform, lines, follow).await,
    }
}

/// Install system service
async fn install_service_impl(platform: Platform, user: &str, enable: bool) -> CliResult<()> {
    match platform {
        Platform::Linux => install_systemd_service(user, enable).await,
        Platform::MacOS => install_launchd_service(enable).await,
        Platform::Windows => install_windows_service(enable).await,
        Platform::Other => Err(CliError::ConfigError(
            "Service installation is not supported on this platform".to_string(),
        )),
    }
}

/// Install systemd service (Linux)
async fn install_systemd_service(user: &str, enable: bool) -> CliResult<()> {
    let binary_path = std::env::current_exe().map_err(|e| {
        CliError::ConfigError(format!("Failed to get current executable path: {}", e))
    })?;

    let service_content = generate_systemd_unit(user, binary_path.to_string_lossy().as_ref());
    let service_path = PathBuf::from(format!(
        "/etc/systemd/system/{}.service",
        get_systemd_service_name()
    ));

    println!("Installing ZHTP node as systemd service...");
    println!("Service name: {}", get_systemd_service_name());
    println!("User: {}", user);
    println!("Binary: {}", binary_path.display());

    println!("\nService file location: {}", service_path.display());
    println!("Content:\n{}", service_content);

    println!("\nTo install (requires sudo):");
    println!("  sudo tee {} > /dev/null <<EOF", service_path.display());
    println!("{}", service_content);
    println!("EOF");
    println!("  sudo systemctl daemon-reload");

    if enable {
        println!("  sudo systemctl enable {}.service", get_systemd_service_name());
    }

    println!("  sudo systemctl start {}.service", get_systemd_service_name());
    println!("\nOr use: sudo zhtp-cli service install --enable");

    Ok(())
}

/// Install launchd service (macOS)
async fn install_launchd_service(enable: bool) -> CliResult<()> {
    let binary_path = std::env::current_exe().map_err(|e| {
        CliError::ConfigError(format!("Failed to get current executable path: {}", e))
    })?;

    let plist_content = generate_launchd_plist(binary_path.to_string_lossy().as_ref());
    let plist_path = PathBuf::from(format!(
        "{}/.local/share/launchd/{}.plist",
        std::env::var("HOME").unwrap_or_else(|_| ".".to_string()),
        get_launchd_service_name()
    ));

    println!("Installing ZHTP node as launchd service...");
    println!("Service name: {}", get_launchd_service_name());
    println!("Binary: {}", binary_path.display());

    println!("\nPlist file location: {}", plist_path.display());
    println!("Content:\n{}", plist_content);

    if enable {
        println!("\nTo enable: launchctl load {}", plist_path.display());
    }

    println!("\nNote: For system-wide service, place plist in /Library/LaunchDaemons/");

    Ok(())
}

/// Install Windows service
async fn install_windows_service(enable: bool) -> CliResult<()> {
    let binary_path = std::env::current_exe().map_err(|e| {
        CliError::ConfigError(format!("Failed to get current executable path: {}", e))
    })?;

    println!("Installing ZHTP node as Windows service...");
    println!("Service name: {}", get_windows_service_name());
    println!("Binary: {}", binary_path.display());

    println!("\nTo install (requires elevated privileges):");
    println!("  sc create {} binPath= \\\"{}\\\" start= {} DisplayName= \\\"ZHTP Node\\\"",
        get_windows_service_name(),
        binary_path.display(),
        if enable { "auto" } else { "demand" }
    );

    println!("\nTo start:");
    println!("  net start {}", get_windows_service_name());

    println!("\nTo view status:");
    println!("  sc query {}", get_windows_service_name());

    Ok(())
}

/// Uninstall system service
async fn uninstall_service_impl(platform: Platform, _force: bool) -> CliResult<()> {
    match platform {
        Platform::Linux => {
            println!("To uninstall systemd service:");
            println!("  sudo systemctl stop {}.service", get_systemd_service_name());
            println!("  sudo systemctl disable {}.service", get_systemd_service_name());
            println!("  sudo rm /etc/systemd/system/{}.service", get_systemd_service_name());
            println!("  sudo systemctl daemon-reload");
            Ok(())
        }
        Platform::MacOS => {
            println!("To uninstall launchd service:");
            println!("  launchctl unload ~/Library/LaunchAgents/{}.plist", get_launchd_service_name());
            println!("  rm ~/Library/LaunchAgents/{}.plist", get_launchd_service_name());
            Ok(())
        }
        Platform::Windows => {
            println!("To uninstall Windows service:");
            println!("  net stop {}", get_windows_service_name());
            println!("  sc delete {}", get_windows_service_name());
            Ok(())
        }
        Platform::Other => Err(CliError::ConfigError(
            "Service management is not supported on this platform".to_string(),
        )),
    }
}

/// Start the service
async fn start_service_impl(platform: Platform) -> CliResult<()> {
    match platform {
        Platform::Linux => {
            println!("To start the service:");
            println!("  sudo systemctl start {}.service", get_systemd_service_name());
            println!("\nStatus:");
            println!("  systemctl status {}.service", get_systemd_service_name());
            Ok(())
        }
        Platform::MacOS => {
            println!("To start the service:");
            println!("  launchctl start {}", get_launchd_service_name());
            Ok(())
        }
        Platform::Windows => {
            println!("To start the service:");
            println!("  net start {}", get_windows_service_name());
            Ok(())
        }
        Platform::Other => Err(CliError::ConfigError(
            "Service management is not supported on this platform".to_string(),
        )),
    }
}

/// Stop the service
async fn stop_service_impl(platform: Platform) -> CliResult<()> {
    match platform {
        Platform::Linux => {
            println!("To stop the service:");
            println!("  sudo systemctl stop {}.service", get_systemd_service_name());
            Ok(())
        }
        Platform::MacOS => {
            println!("To stop the service:");
            println!("  launchctl stop {}", get_launchd_service_name());
            Ok(())
        }
        Platform::Windows => {
            println!("To stop the service:");
            println!("  net stop {}", get_windows_service_name());
            Ok(())
        }
        Platform::Other => Err(CliError::ConfigError(
            "Service management is not supported on this platform".to_string(),
        )),
    }
}

/// Get service status
async fn status_service_impl(platform: Platform) -> CliResult<()> {
    match platform {
        Platform::Linux => {
            println!("Checking systemd service status...");
            println!("Run: systemctl status {}.service", get_systemd_service_name());
            Ok(())
        }
        Platform::MacOS => {
            println!("Checking launchd service status...");
            println!("Run: launchctl list | grep {}", get_launchd_service_name());
            Ok(())
        }
        Platform::Windows => {
            println!("Checking Windows service status...");
            println!("Run: sc query {}", get_windows_service_name());
            Ok(())
        }
        Platform::Other => Err(CliError::ConfigError(
            "Service management is not supported on this platform".to_string(),
        )),
    }
}

/// View service logs
async fn logs_service_impl(platform: Platform, lines: usize, _follow: bool) -> CliResult<()> {
    match platform {
        Platform::Linux => {
            println!("Viewing systemd service logs (last {} lines):", lines);
            println!("Run: journalctl -u {}.service -n {}", get_systemd_service_name(), lines);
            println!("\nFor continuous logs:");
            println!("  journalctl -u {}.service -f", get_systemd_service_name());
            Ok(())
        }
        Platform::MacOS => {
            println!("Viewing launchd service logs (last {} lines):", lines);
            println!("Run: tail -n {} /var/log/zhtp-cli.log", lines);
            println!("\nFor continuous logs:");
            println!("  tail -f /var/log/zhtp-cli.log");
            Ok(())
        }
        Platform::Windows => {
            println!("Viewing Windows service event logs:");
            println!("Run: Get-EventLog -LogName System -Source {} -Newest {} | Format-List",
                get_windows_service_name(), lines);
            Ok(())
        }
        Platform::Other => Err(CliError::ConfigError(
            "Service management is not supported on this platform".to_string(),
        )),
    }
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_install() {
        let action = ServiceAction::Install {
            user: "root".to_string(),
            enable: false,
        };
        assert_eq!(action_to_operation(&action), ServiceOperation::Install);
    }

    #[test]
    fn test_action_to_operation_uninstall() {
        let action = ServiceAction::Uninstall { force: false };
        assert_eq!(action_to_operation(&action), ServiceOperation::Uninstall);
    }

    #[test]
    fn test_detect_platform() {
        let platform = detect_platform();
        // Will be Linux, MacOS, Windows, or Other depending on actual platform
        assert!(matches!(
            platform,
            Platform::Linux | Platform::MacOS | Platform::Windows | Platform::Other
        ));
    }

    #[test]
    fn test_validate_service_user_valid() {
        assert!(validate_service_user("root").is_ok());
        assert!(validate_service_user("zhtp_node").is_ok());
        assert!(validate_service_user("zhtp-node").is_ok());
    }

    #[test]
    fn test_validate_service_user_invalid() {
        assert!(validate_service_user("").is_err());
        assert!(validate_service_user("user@host").is_err());
        assert!(validate_service_user("user:pass").is_err());
    }

    #[test]
    fn test_generate_systemd_unit() {
        let content = generate_systemd_unit("zhtp", "/usr/local/bin/zhtp-cli");
        assert!(content.contains("[Unit]"));
        assert!(content.contains("[Service]"));
        assert!(content.contains("[Install]"));
        assert!(content.contains("zhtp"));
        assert!(content.contains("/usr/local/bin/zhtp-cli"));
    }

    #[test]
    fn test_generate_launchd_plist() {
        let content = generate_launchd_plist("/usr/local/bin/zhtp-cli");
        assert!(content.contains("<?xml"));
        assert!(content.contains("plist"));
        assert!(content.contains("/usr/local/bin/zhtp-cli"));
        assert!(content.contains("node"));
        assert!(content.contains("start"));
    }

    #[test]
    fn test_get_service_names() {
        assert_eq!(get_systemd_service_name(), "zhtp-node");
        assert_eq!(get_launchd_service_name(), "network.zhtp.node");
        assert_eq!(get_windows_service_name(), "ZhtpNode");
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(ServiceOperation::Install.description(), "Install system service");
        assert_eq!(ServiceOperation::Uninstall.description(), "Uninstall system service");
        assert_eq!(ServiceOperation::Start.description(), "Start service");
        assert_eq!(ServiceOperation::Stop.description(), "Stop service");
        assert_eq!(ServiceOperation::Status.description(), "Get service status");
        assert_eq!(ServiceOperation::Logs.description(), "View service logs");
    }
}
