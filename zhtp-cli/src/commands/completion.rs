//! Shell completion command
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Shell type validation, completion path determination
//! - **Imperative Shell**: File I/O, shell detection, completion generation and installation
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::CompletionArgs;
use crate::error::{CliResult, CliError};
use crate::output::Output;

use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::str::FromStr;
use std::fs;
use std::path::PathBuf;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Supported shells for completion
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedShell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
    Elvish,
}

impl FromStr for SupportedShell {
    type Err = CliError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bash" => Ok(SupportedShell::Bash),
            "zsh" => Ok(SupportedShell::Zsh),
            "fish" => Ok(SupportedShell::Fish),
            "powershell" | "pwsh" => Ok(SupportedShell::PowerShell),
            "elvish" => Ok(SupportedShell::Elvish),
            _ => Err(CliError::ConfigError(
                format!("Unsupported shell: '{}'. Supported: bash, zsh, fish, powershell, elvish", s),
            )),
        }
    }
}

impl SupportedShell {
    /// Get the clap_complete Shell enum variant
    pub fn to_clap_shell(&self) -> Shell {
        match self {
            SupportedShell::Bash => Shell::Bash,
            SupportedShell::Zsh => Shell::Zsh,
            SupportedShell::Fish => Shell::Fish,
            SupportedShell::PowerShell => Shell::PowerShell,
            SupportedShell::Elvish => Shell::Elvish,
        }
    }

    /// Get human-friendly name
    pub fn as_str(&self) -> &'static str {
        match self {
            SupportedShell::Bash => "bash",
            SupportedShell::Zsh => "zsh",
            SupportedShell::Fish => "fish",
            SupportedShell::PowerShell => "powershell",
            SupportedShell::Elvish => "elvish",
        }
    }

    /// Get typical completion installation path for this shell
    ///
    /// Pure function - path string construction only
    pub fn completion_path(&self) -> Option<PathBuf> {
        match self {
            SupportedShell::Bash => {
                dirs::home_dir().map(|home| {
                    home.join(".bash_completion.d").join("zhtp-cli")
                })
            }
            SupportedShell::Zsh => {
                dirs::home_dir().map(|home| {
                    home.join(".zsh").join("completions").join("_zhtp-cli")
                })
            }
            SupportedShell::Fish => {
                dirs::home_dir().map(|home| {
                    home.join(".config").join("fish").join("completions").join("zhtp-cli.fish")
                })
            }
            SupportedShell::PowerShell => {
                // PowerShell profile location varies by platform
                None
            }
            SupportedShell::Elvish => {
                dirs::home_dir().map(|home| {
                    home.join(".local").join("share").join("elves").join("lib").join("zhtp-cli.elv")
                })
            }
        }
    }

    /// Get shell initialization instruction
    ///
    /// Pure function - string construction only
    pub fn install_instruction(&self) -> &'static str {
        match self {
            SupportedShell::Bash => {
                "Add to ~/.bashrc:\n  \
                source ~/.bash_completion.d/zhtp-cli"
            }
            SupportedShell::Zsh => {
                "Add to ~/.zshrc:\n  \
                fpath=(~/.zsh/completions $fpath)\n  \
                autoload -U compinit && compinit"
            }
            SupportedShell::Fish => {
                "Fish completions are automatically loaded from ~/.config/fish/completions/"
            }
            SupportedShell::PowerShell => {
                "Add to PowerShell Profile:\n  \
                Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete\n  \
                Register-ArgumentCompleter -CommandName zhtp-cli -ScriptBlock { ... }"
            }
            SupportedShell::Elvish => {
                "Add to ~/.elvish/rc.elv:\n  \
                use ./zhtp-cli"
            }
        }
    }
}

/// Validate that output directory exists or can be created
///
/// Pure function - path validation only (no actual I/O)
pub fn validate_output_path(path_str: &str) -> CliResult<PathBuf> {
    if path_str.is_empty() {
        return Err(CliError::ConfigError(
            "Output path cannot be empty".to_string(),
        ));
    }

    let path = PathBuf::from(path_str);

    // Check if it's just a directory (should exist for safety)
    if path.is_dir() {
        return Err(CliError::ConfigError(
            format!("Path is a directory, not a file: {}", path_str),
        ));
    }

    Ok(path)
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (file I/O, output)
// ============================================================================

/// Handle completion command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_completion_command(args: CompletionArgs) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_completion_command_impl(args, &output).await
}

/// Internal implementation with dependency injection
async fn handle_completion_command_impl(
    args: CompletionArgs,
    output: &dyn Output,
) -> CliResult<()> {
    // Pure parsing
    let shell = args.shell.parse::<SupportedShell>()?;

    output.header(&format!("Generating {} shell completions...", shell.as_str()))?;

    // Generate completions
    let mut cmd = crate::argument_parsing::ZhtpCli::command();
    let clap_shell = shell.to_clap_shell();

    if let Some(output_path) = args.output {
        // Imperative: Write to file
        validate_output_path(&output_path)?;

        let path = PathBuf::from(&output_path);
        let parent = path.parent().map(|p| p.to_path_buf());

        // Create parent directory if needed
        if let Some(parent_dir) = parent {
            if !parent_dir.exists() {
                fs::create_dir_all(&parent_dir).map_err(|e| {
                    CliError::ConfigError(format!(
                        "Failed to create directory {}: {}",
                        parent_dir.display(),
                        e
                    ))
                })?;
            }
        }

        let mut file = fs::File::create(&path).map_err(|e| {
            CliError::ConfigError(format!("Failed to create file {}: {}", output_path, e))
        })?;

        generate(clap_shell, &mut cmd, "zhtp-cli", &mut file);
        output.success(&format!("✓ Completions saved to {}", output_path))?;
    } else {
        // Imperative: Write to stdout
        generate(clap_shell, &mut cmd, "zhtp-cli", &mut std::io::stdout());
    }

    if args.install {
        output.info("Installation instructions:")?;
        output.print(shell.install_instruction())?;

        if let Some(path) = shell.completion_path() {
            output.print(&format!("\nOr copy completions to: {}", path.display()))?;
        }
    } else {
        output.print("")?;
        output.print("To install completions:")?;
        output.print(&format!("  zhtp-cli completion {} --install", shell.as_str()))?;
    }

    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_shell_from_str_bash() {
        assert_eq!("bash".parse::<SupportedShell>().unwrap(), SupportedShell::Bash);
        assert_eq!("BASH".parse::<SupportedShell>().unwrap(), SupportedShell::Bash);
    }

    #[test]
    fn test_supported_shell_from_str_zsh() {
        assert_eq!("zsh".parse::<SupportedShell>().unwrap(), SupportedShell::Zsh);
        assert_eq!("ZSH".parse::<SupportedShell>().unwrap(), SupportedShell::Zsh);
    }

    #[test]
    fn test_supported_shell_from_str_fish() {
        assert_eq!("fish".parse::<SupportedShell>().unwrap(), SupportedShell::Fish);
        assert_eq!("Fish".parse::<SupportedShell>().unwrap(), SupportedShell::Fish);
    }

    #[test]
    fn test_supported_shell_from_str_powershell() {
        assert_eq!("powershell".parse::<SupportedShell>().unwrap(), SupportedShell::PowerShell);
        assert_eq!("pwsh".parse::<SupportedShell>().unwrap(), SupportedShell::PowerShell);
        assert_eq!("PowerShell".parse::<SupportedShell>().unwrap(), SupportedShell::PowerShell);
    }

    #[test]
    fn test_supported_shell_from_str_elvish() {
        assert_eq!("elvish".parse::<SupportedShell>().unwrap(), SupportedShell::Elvish);
        assert_eq!("ELVISH".parse::<SupportedShell>().unwrap(), SupportedShell::Elvish);
    }

    #[test]
    fn test_supported_shell_from_str_invalid() {
        assert!("invalid".parse::<SupportedShell>().is_err());
        assert!("sh".parse::<SupportedShell>().is_err());
        assert!("".parse::<SupportedShell>().is_err());
    }

    #[test]
    fn test_supported_shell_as_str() {
        assert_eq!(SupportedShell::Bash.as_str(), "bash");
        assert_eq!(SupportedShell::Zsh.as_str(), "zsh");
        assert_eq!(SupportedShell::Fish.as_str(), "fish");
        assert_eq!(SupportedShell::PowerShell.as_str(), "powershell");
        assert_eq!(SupportedShell::Elvish.as_str(), "elvish");
    }

    #[test]
    fn test_supported_shell_to_clap_shell() {
        assert_eq!(SupportedShell::Bash.to_clap_shell(), Shell::Bash);
        assert_eq!(SupportedShell::Zsh.to_clap_shell(), Shell::Zsh);
        assert_eq!(SupportedShell::Fish.to_clap_shell(), Shell::Fish);
        assert_eq!(SupportedShell::PowerShell.to_clap_shell(), Shell::PowerShell);
        assert_eq!(SupportedShell::Elvish.to_clap_shell(), Shell::Elvish);
    }

    #[test]
    fn test_supported_shell_completion_path_bash() {
        let path = SupportedShell::Bash.completion_path();
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.to_string_lossy().contains(".bash_completion.d"));
        assert!(p.to_string_lossy().contains("zhtp-cli"));
    }

    #[test]
    fn test_supported_shell_completion_path_zsh() {
        let path = SupportedShell::Zsh.completion_path();
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.to_string_lossy().contains(".zsh"));
        assert!(p.to_string_lossy().contains("completions"));
    }

    #[test]
    fn test_supported_shell_completion_path_fish() {
        let path = SupportedShell::Fish.completion_path();
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.to_string_lossy().contains(".config"));
        assert!(p.to_string_lossy().contains("fish"));
        assert!(p.to_string_lossy().contains("zhtp-cli.fish"));
    }

    #[test]
    fn test_supported_shell_completion_path_powershell() {
        let path = SupportedShell::PowerShell.completion_path();
        assert_eq!(path, None);
    }

    #[test]
    fn test_supported_shell_completion_path_elvish() {
        let path = SupportedShell::Elvish.completion_path();
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.to_string_lossy().contains(".local"));
        assert!(p.to_string_lossy().contains("elves"));
    }

    #[test]
    fn test_validate_output_path_empty() {
        assert!(validate_output_path("").is_err());
    }

    #[test]
    fn test_validate_output_path_valid() {
        assert!(validate_output_path("/tmp/completion.sh").is_ok());
        assert!(validate_output_path("./completions/bash").is_ok());
    }

    #[test]
    fn test_supported_shell_install_instruction_bash() {
        let instruction = SupportedShell::Bash.install_instruction();
        assert!(instruction.contains("bashrc"));
        assert!(instruction.contains("source"));
    }

    #[test]
    fn test_supported_shell_install_instruction_zsh() {
        let instruction = SupportedShell::Zsh.install_instruction();
        assert!(instruction.contains("zshrc"));
        assert!(instruction.contains("fpath"));
    }

    #[test]
    fn test_supported_shell_install_instruction_fish() {
        let instruction = SupportedShell::Fish.install_instruction();
        assert!(instruction.contains("automatically loaded"));
    }
}
