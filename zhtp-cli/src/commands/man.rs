//! Manual page (man) generation and display
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Path validation, output format construction, man page search
//! - **Imperative Shell**: File I/O, directory creation, command parsing
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for validation and path construction

use crate::argument_parsing::ManAction;
use crate::error::{CliResult, CliError};

use std::path::{Path, PathBuf};
use std::fs;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Man page operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManOperation {
    Generate,
    Show,
}

impl ManOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            ManOperation::Generate => "Generate manual pages",
            ManOperation::Show => "Show manual page",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &ManAction) -> ManOperation {
    match action {
        ManAction::Generate { .. } => ManOperation::Generate,
        ManAction::Show { .. } => ManOperation::Show,
    }
}

/// Validate that output directory path is valid
///
/// Pure function - path validation only (no actual I/O)
pub fn validate_output_dir(path_str: &str) -> CliResult<PathBuf> {
    if path_str.is_empty() {
        return Err(CliError::ConfigError(
            "Output directory path cannot be empty".to_string(),
        ));
    }

    let path = PathBuf::from(path_str);

    // Basic sanity checks on path
    if path.as_os_str().is_empty() {
        return Err(CliError::ConfigError(
            "Invalid output directory path".to_string(),
        ));
    }

    Ok(path)
}

/// Validate command name
///
/// Pure function - format validation only
pub fn validate_command_name(name: &str) -> CliResult<()> {
    if name.is_empty() {
        return Err(CliError::ConfigError(
            "Command name cannot be empty".to_string(),
        ));
    }

    // Command names should be alphanumeric with hyphens
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(CliError::ConfigError(format!(
            "Invalid command name: {}. Use only alphanumeric characters, hyphens, and underscores",
            name
        )));
    }

    Ok(())
}

/// Default man page directory
///
/// Pure function - path construction only
pub fn default_man_dir() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".zhtp").join("man")
    } else {
        PathBuf::from("./man")
    }
}

/// Get man page file path
///
/// Pure function - path construction only
pub fn man_file_path(output_dir: &Path, command: &str, section: u32) -> PathBuf {
    output_dir.join(format!("{}.{}", command, section))
}

/// Check if man page directory path is valid format
///
/// Pure function - only checks path validity, doesn't perform I/O
#[allow(dead_code)]
pub fn should_man_page_exist(output_dir: &Path, _command: &str) -> CliResult<()> {
    if !output_dir.is_absolute() && !output_dir.starts_with(".") {
        return Err(CliError::ConfigError(
            "Man page directory path should be absolute or relative (starting with .)".to_string(),
        ));
    }
    Ok(())
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (file I/O, man page generation)
// ============================================================================

/// Handle man command with proper error handling and output
pub async fn handle_man_command(args: crate::argument_parsing::ManArgs) -> CliResult<()> {
    match args.action {
        ManAction::Generate { output, command } => {
            let output_path = validate_output_dir(&output)?;
            generate_man_pages_impl(&output_path, command).await
        }
        ManAction::Show { command } => {
            validate_command_name(&command)?;
            show_man_page_impl(&command).await
        }
    }
}

/// Generate man pages for the CLI
async fn generate_man_pages_impl(
    output_dir: &Path,
    command_filter: Option<String>,
) -> CliResult<()> {
    use clap::CommandFactory;
    use clap_mangen::Man;

    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir).map_err(|e| {
        CliError::ConfigError(format!(
            "Failed to create man page directory: {}",
            e
        ))
    })?;

    // Generate main command man page
    let mut cmd = crate::argument_parsing::ZhtpCli::command();
    let man = Man::new(cmd.clone());

    let main_man_path = output_dir.join("zhtp-cli.1");
    let mut file = fs::File::create(&main_man_path).map_err(|e| {
        CliError::ConfigError(format!(
            "Failed to create man page: {}",
            e
        ))
    })?;

    man.render(&mut file).map_err(|e| {
        CliError::ConfigError(format!(
            "Failed to render man page: {}",
            e
        ))
    })?;

    println!("✓ Generated main man page: {}", main_man_path.display());

    // Generate subcommand man pages if no filter or if filter matches
    let mut count = 1;
    for subcommand in cmd.get_subcommands_mut() {
        let subcommand_name = subcommand.get_name();

        // Skip if filter is specified and doesn't match
        if let Some(ref filter) = command_filter {
            if filter != subcommand_name && !subcommand_name.starts_with(filter) {
                continue;
            }
        }

        let man = Man::new(subcommand.clone());
        let filename = format!("zhtp-cli-{}.1", subcommand_name);
        let subcommand_man_path = output_dir.join(&filename);

        let mut file = fs::File::create(&subcommand_man_path).map_err(|e| {
            CliError::ConfigError(format!(
                "Failed to create subcommand man page: {}",
                e
            ))
        })?;

        man.render(&mut file).map_err(|e| {
            CliError::ConfigError(format!(
                "Failed to render subcommand man page: {}",
                e
            ))
        })?;

        println!("✓ Generated man page: {}", subcommand_man_path.display());
        count += 1;
    }

    println!("\n✅ Generated {} man page(s)", count);
    println!("Location: {}", output_dir.display());
    println!("\nTo install (on Linux/macOS):");
    println!("  sudo cp {}/*.1 /usr/share/man/man1/", output_dir.display());
    println!("  sudo mandb");
    println!("\nTo view:");
    println!("  man zhtp-cli");
    println!("  man zhtp-cli-node");

    Ok(())
}

/// Show a man page for a specific command
async fn show_man_page_impl(command: &str) -> CliResult<()> {
    validate_command_name(command)?;

    // Try to show using system man command
    use std::process::Command;

    let man_page = if command == "zhtp" || command == "zhtp-cli" {
        "zhtp-cli".to_string()
    } else {
        format!("zhtp-cli-{}", command)
    };

    let output = Command::new("man")
        .arg(&man_page)
        .output()
        .map_err(|e| {
            CliError::ConfigError(format!(
                "Failed to show man page: {}. Make sure man pages are installed using 'zhtp-cli man generate'",
                e
            ))
        })?;

    if !output.status.success() {
        return Err(CliError::ConfigError(format!(
            "Man page not found: {}",
            man_page
        )));
    }

    // Output the man page
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_generate() {
        let action = ManAction::Generate {
            output: "./man".to_string(),
            command: None,
        };
        assert_eq!(action_to_operation(&action), ManOperation::Generate);
    }

    #[test]
    fn test_action_to_operation_show() {
        let action = ManAction::Show {
            command: "node".to_string(),
        };
        assert_eq!(action_to_operation(&action), ManOperation::Show);
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(
            ManOperation::Generate.description(),
            "Generate manual pages"
        );
        assert_eq!(ManOperation::Show.description(), "Show manual page");
    }

    #[test]
    fn test_validate_output_dir_empty() {
        assert!(validate_output_dir("").is_err());
    }

    #[test]
    fn test_validate_output_dir_valid() {
        assert!(validate_output_dir("/tmp/man").is_ok());
        assert!(validate_output_dir("./man").is_ok());
        assert!(validate_output_dir("~/man").is_ok());
    }

    #[test]
    fn test_validate_command_name_empty() {
        assert!(validate_command_name("").is_err());
    }

    #[test]
    fn test_validate_command_name_valid() {
        assert!(validate_command_name("node").is_ok());
        assert!(validate_command_name("zhtp-cli").is_ok());
        assert!(validate_command_name("node_start").is_ok());
    }

    #[test]
    fn test_validate_command_name_invalid_chars() {
        assert!(validate_command_name("node!").is_err());
        assert!(validate_command_name("node.cmd").is_err());
        assert!(validate_command_name("node command").is_err());
    }

    #[test]
    fn test_default_man_dir() {
        let dir = default_man_dir();
        assert!(dir.to_string_lossy().contains("man"));
    }

    #[test]
    fn test_man_file_path() {
        let output_dir = PathBuf::from("/tmp");
        let path = man_file_path(&output_dir, "zhtp-cli", 1);
        assert_eq!(path, PathBuf::from("/tmp/zhtp-cli.1"));
    }

    #[test]
    fn test_man_file_path_subcommand() {
        let output_dir = PathBuf::from("./man");
        let path = man_file_path(&output_dir, "zhtp-cli-node", 1);
        assert_eq!(path, PathBuf::from("./man/zhtp-cli-node.1"));
    }
}
