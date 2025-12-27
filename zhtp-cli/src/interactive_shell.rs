//! Interactive Shell Interface
//! 
//! Provides an interactive command shell for ZHTP node management

use anyhow::Result;
use std::io::{self, Write};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{info, warn, error};
use super::command_execution::{CommandContext, execute_command, parse_command};
use zhtp::config::NodeConfig;

/// Interactive shell for ZHTP node management
pub struct InteractiveShell {
    context: CommandContext,
    history: Vec<String>,
    prompt: String,
}

impl InteractiveShell {
    /// Create a new interactive shell
    pub fn new(config: NodeConfig) -> Self {
        Self {
            context: CommandContext {
                config,
                runtime: None,
                interactive_mode: true,
            },
            history: Vec::new(),
            prompt: "zhtp> ".to_string(),
        }
    }

    /// Start the interactive shell
    pub async fn start(&mut self) -> Result<()> {
        self.display_welcome_message();
        
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut input = String::new();

        loop {
            // Display prompt
            print!("{}", self.prompt);
            io::stdout().flush()?;

            // Read input
            input.clear();
            match reader.read_line(&mut input).await {
                Ok(0) => {
                    // EOF reached (Ctrl+D)
                    println!("\n Goodbye!");
                    break;
                }
                Ok(_) => {
                    let command_str = input.trim();
                    
                    // Skip empty commands
                    if command_str.is_empty() {
                        continue;
                    }

                    // Add to history
                    self.history.push(command_str.to_string());

                    // Handle special shell commands
                    if self.handle_shell_commands(command_str).await? {
                        continue;
                    }

                    // Parse and execute command
                    match parse_command(command_str) {
                        Ok(command) => {
                            match execute_command(command, &mut self.context).await {
                                Ok(output) => {
                                    if !output.is_empty() {
                                        println!("{}", output);
                                    }
                                }
                                Err(e) => {
                                    error!("Command failed: {}", e);
                                    println!("Error: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Invalid command: {}", e);
                            println!("{}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read input: {}", e);
                    break;
                }
            }
        }

        // Cleanup on exit
        if self.context.runtime.is_some() {
            println!("Shutting down node...");
            if let Err(e) = execute_command(
                super::command_execution::NodeCommand::Stop,
                &mut self.context
            ).await {
                error!("Failed to shutdown cleanly: {}", e);
            }
        }

        Ok(())
    }

    /// Handle special shell commands that don't go through normal command processing
    async fn handle_shell_commands(&mut self, command: &str) -> Result<bool> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        
        match parts.get(0) {
            Some(&"clear") => {
                // Clear screen
                print!("\x1B[2J\x1B[1;1H");
                io::stdout().flush()?;
                return Ok(true);
            }
            Some(&"history") => {
                // Show command history
                println!("📜 Command History:");
                for (i, cmd) in self.history.iter().enumerate() {
                    println!("  {}: {}", i + 1, cmd);
                }
                return Ok(true);
            }
            Some(&"prompt") => {
                // Change prompt
                if parts.len() > 1 {
                    self.prompt = format!("{} ", parts[1..].join(" "));
                    println!("Prompt changed to: {}", self.prompt.trim());
                } else {
                    println!("Current prompt: {}", self.prompt.trim());
                }
                return Ok(true);
            }
            Some(&"alias") => {
                // Show available aliases
                self.show_aliases();
                return Ok(true);
            }
            _ => {}
        }

        Ok(false)
    }

    /// Display welcome message
    fn display_welcome_message(&self) {
        println!(r#"
Welcome to ZHTP Network Node Interactive Shell

  ████████╗██╗  ██╗████████╗██████╗ 
  ╚══██╔══╝██║  ██║╚══██╔══╝██╔══██╗
     ██║   ███████║   ██║   ██████╔╝
     ██║   ██╔══██║   ██║   ██╔═══╝ 
     ██║   ██║  ██║   ██║   ██║     
     ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝     

Internet Replacement System
• Complete  through mesh networking
• Zero-knowledge privacy for all communications  
• Universal Basic Income through network participation
• Post-quantum cryptographic security

Type 'help' for available commands or 'start' to begin.
Type 'exit' to quit.
"#);
    }

    /// Show available command aliases
    fn show_aliases(&self) {
        println!(r#"
Available Command Aliases:

Network:
  peers              → List connected peers
  connect <addr>     → Connect to peer
  disconnect <addr>  → Disconnect from peer

Node Control:
  start              → Start the node
  stop               → Stop the node
  restart            → Restart the node
  status             → Show node status

Information:
  version            → Show version info
  config             → Show configuration
  help               → Show help

Shell Commands:
  clear              → Clear the screen
  history            → Show command history
  prompt <text>      → Change prompt
  alias              → Show this list
  exit, quit, q      → Exit shell

For full command reference, type 'help'
"#);
    }
}

/// Auto-completion support for interactive shell
pub struct AutoComplete {
    commands: Vec<String>,
}

impl AutoComplete {
    /// Create new auto-completion engine
    pub fn new() -> Self {
        let commands = vec![
            // Node control
            "start".to_string(),
            "stop".to_string(),
            "restart".to_string(),
            "status".to_string(),
            
            // Network
            "peers".to_string(),
            "connect".to_string(),
            "disconnect".to_string(),
            "network".to_string(),
            "mesh".to_string(),
            
            // Identity
            "identities".to_string(),
            "create-id".to_string(),
            "use-id".to_string(),
            "export-id".to_string(),
            "import-id".to_string(),
            
            // Blockchain
            "blockchain".to_string(),
            "balance".to_string(),
            "send".to_string(),
            "transactions".to_string(),
            "mine".to_string(),
            
            // Storage
            "storage".to_string(),
            "store".to_string(),
            "retrieve".to_string(),
            "files".to_string(),
            
            // Economics
            "ubi".to_string(),
            "claim-ubi".to_string(),
            "dao".to_string(),
            "vote".to_string(),
            "propose".to_string(),
            
            // System
            "help".to_string(),
            "version".to_string(),
            "config".to_string(),
            "logs".to_string(),
            "metrics".to_string(),
            "exit".to_string(),
            "quit".to_string(),
            
            // Shell commands
            "clear".to_string(),
            "history".to_string(),
            "prompt".to_string(),
            "alias".to_string(),
        ];

        Self { commands }
    }

    /// Get completions for a partial command
    pub fn get_completions(&self, partial: &str) -> Vec<String> {
        self.commands
            .iter()
            .filter(|cmd| cmd.starts_with(partial))
            .cloned()
            .collect()
    }
}

/// Command suggestion engine
pub struct CommandSuggestions;

impl CommandSuggestions {
    /// Get suggestions for a mistyped command
    pub fn suggest_command(input: &str) -> Vec<String> {
        let commands = vec![
            "start", "stop", "restart", "status",
            "peers", "connect", "disconnect", "network", "mesh",
            "identities", "create-id", "use-id",
            "blockchain", "balance", "send", "transactions",
            "storage", "store", "retrieve", "files",
            "ubi", "claim-ubi", "dao", "vote", "propose",
            "help", "version", "config", "exit"
        ];

        let mut suggestions = Vec::new();
        
        for command in commands {
            if Self::levenshtein_distance(input, command) <= 2 {
                suggestions.push(command.to_string());
            }
        }

        // Sort by similarity
        suggestions.sort_by_key(|cmd| Self::levenshtein_distance(input, cmd));
        suggestions.truncate(3); // Limit to top 3 suggestions
        
        suggestions
    }

    /// Calculate Levenshtein distance between two strings
    fn levenshtein_distance(s1: &str, s2: &str) -> usize {
        let len1 = s1.chars().count();
        let len2 = s2.chars().count();
        
        if len1 == 0 { return len2; }
        if len2 == 0 { return len1; }

        let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

        // Initialize first row and column
        for i in 0..=len1 { matrix[i][0] = i; }
        for j in 0..=len2 { matrix[0][j] = j; }

        let s1_chars: Vec<char> = s1.chars().collect();
        let s2_chars: Vec<char> = s2.chars().collect();

        for i in 1..=len1 {
            for j in 1..=len2 {
                let cost = if s1_chars[i-1] == s2_chars[j-1] { 0 } else { 1 };
                matrix[i][j] = std::cmp::min(
                    std::cmp::min(
                        matrix[i-1][j] + 1,      // deletion
                        matrix[i][j-1] + 1       // insertion
                    ),
                    matrix[i-1][j-1] + cost      // substitution
                );
            }
        }

        matrix[len1][len2]
    }
}

/// Enhanced prompt with status indicators
pub struct StatusPrompt {
    node_running: bool,
    mesh_mode: bool,
    peer_count: usize,
}

impl StatusPrompt {
    /// Create a new status prompt
    pub fn new() -> Self {
        Self {
            node_running: false,
            mesh_mode: false,
            peer_count: 0,
        }
    }

    /// Update status information
    pub fn update_status(&mut self, running: bool, mesh: bool, peers: usize) {
        self.node_running = running;
        self.mesh_mode = mesh;
        self.peer_count = peers;
    }

    /// Generate status-aware prompt
    pub fn generate_prompt(&self) -> String {
        let status_icon = if self.node_running { "[ON]" } else { "[OFF]" };
        let mesh_icon = if self.mesh_mode { "[MESH]" } else { "[NET]" };
        let peer_info = if self.peer_count > 0 {
            format!(" ({} peers)", self.peer_count)
        } else {
            String::new()
        };

        format!("{} {} zhtp{} > ", status_icon, mesh_icon, peer_info)
    }
}
