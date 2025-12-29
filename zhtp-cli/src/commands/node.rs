//! Node management commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Environment type parsing, node type detection logic
//! - **Imperative Shell**: Configuration loading, orchestrator startup, network operations
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::{NodeArgs, NodeAction, ZhtpCli};
use crate::error::{CliResult, CliError};
use crate::output::Output;

use zhtp::config::environment::Environment;
use zhtp::runtime::RuntimeOrchestrator;
use zhtp::runtime::did_startup::WalletStartupManager;
use std::path::PathBuf;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Valid node operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeOperation {
    Start,
    Stop,
    Status,
    Restart,
}

impl NodeOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            NodeOperation::Start => "Start orchestrator node",
            NodeOperation::Stop => "Stop orchestrator node",
            NodeOperation::Status => "Show node status",
            NodeOperation::Restart => "Restart orchestrator node",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &NodeAction) -> NodeOperation {
    match action {
        NodeAction::Start { .. } => NodeOperation::Start,
        NodeAction::Stop => NodeOperation::Stop,
        NodeAction::Status => NodeOperation::Status,
        NodeAction::Restart => NodeOperation::Restart,
    }
}

/// Parse environment/network type from string
///
/// Pure function - deterministic conversion
pub fn parse_network_environment(env_str: &str) -> CliResult<Environment> {
    match env_str.to_lowercase().as_str() {
        "mainnet" | "main" => Ok(Environment::Mainnet),
        "testnet" | "test" => Ok(Environment::Testnet),
        "dev" | "development" => Ok(Environment::Development),
        other => Err(CliError::ConfigError(format!(
            "Unknown network environment: '{}'. Supported: mainnet, testnet, dev",
            other
        ))),
    }
}

/// Normalize keystore path (expand ~ and handle relative paths)
///
/// Pure function - path manipulation only
pub fn normalize_keystore_path(ks_str: &str) -> Option<PathBuf> {
    if ks_str.starts_with("~/") {
        dirs::home_dir().map(|home| home.join(&ks_str[2..]))
    } else if ks_str.is_empty() {
        None
    } else {
        Some(PathBuf::from(ks_str))
    }
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (config, network, orchestration)
// ============================================================================

/// Handle node command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_node_command(args: NodeArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_node_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_node_command_impl(
    args: NodeArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let op = action_to_operation(&args.action);
    output.info(&format!("{}...", op.description()))?;

    match args.action {
        NodeAction::Start {
            config,
            port,
            dev,
            pure_mesh,
            network,
            edge_mode,
            edge_max_headers,
            keystore,
        } => {
            // Pure parsing
            let network_env = network
                .as_ref()
                .map(|n| parse_network_environment(n))
                .transpose()?
                .unwrap_or(Environment::Development);

            let keystore_path = keystore.and_then(|ks| normalize_keystore_path(&ks));

            output.header("Starting ZHTP Orchestrator Node")?;
            if let Some(p) = port {
                output.print(&format!("Port override: {}", p))?;
            }
            if edge_mode {
                output.print(&format!("Edge mode: ENABLED (max {} headers)", edge_max_headers))?;
            }
            output.print(&format!("Network environment: {:?}", network_env))?;

            // Imperative: Configuration loading and orchestrator startup
            start_node_impl(
                config,
                port,
                dev,
                pure_mesh,
                network_env,
                edge_mode,
                edge_max_headers as u32,
                keystore_path,
                output,
            )
            .await
        }
        NodeAction::Stop => {
            output.warning("Stopping node...")?;
            output.print("Use Ctrl+C on the running node process.")?;
            Ok(())
        }
        NodeAction::Status => {
            output.header("Node Status")?;
            output.print(&format!("Server: {}", cli.server))?;
            output.success("Status: Information available at /api/v1/health")?;
            Ok(())
        }
        NodeAction::Restart => {
            output.warning("Restarting node...")?;
            output.print("Stop the current node and start it again.")?;
            Ok(())
        }
    }
}

/// Start the node with configuration
async fn start_node_impl(
    config_path: Option<String>,
    port_override: Option<u16>,
    dev_mode: bool,
    pure_mesh: bool,
    network_env: Environment,
    edge_mode: bool,
    edge_max_headers: u32,
    keystore_path: Option<PathBuf>,
    output: &dyn Output,
) -> CliResult<()> {
    use zhtp::config::{load_configuration, CliArgs};

    output.info("Loading configuration...")?;

    // Build CLI arguments for configuration loader
    let cli_args = CliArgs {
        mesh_port: port_override,
        pure_mesh,
        config: PathBuf::from(config_path.unwrap_or_else(|| "./config".to_string())),
        environment: network_env,
        log_level: if dev_mode {
            "debug".to_string()
        } else {
            "info".to_string()
        },
        data_dir: PathBuf::from("./data"),
    };

    // Load configuration
    let mut node_config = load_configuration(&cli_args)
        .await
        .map_err(|e| {
            CliError::ConfigError(format!("Failed to load configuration: {}", e))
        })?;

    // Detect node type
    let hosted_storage = if node_config.storage_config.hosted_storage_gb > 0 {
        node_config.storage_config.hosted_storage_gb
    } else {
        node_config.storage_config.storage_capacity_gb
    };

    let is_edge_node = edge_mode
        || (!node_config.consensus_config.validator_enabled
            && !node_config.blockchain_config.smart_contracts
            && hosted_storage < 100);

    let is_validator = node_config.consensus_config.validator_enabled;

    // Display node type
    if is_edge_node {
        output.print("Node Type: EDGE NODE")?;
    } else if is_validator {
        output.print("Node Type: VALIDATOR")?;
    } else {
        output.print("Node Type: FULL NODE")?;
    }

    // Apply network override
    node_config.environment = network_env;

    // Apply network isolation if pure mesh mode
    if pure_mesh {
        output.info("Applying network isolation for pure mesh mode...")?;
        use zhtp::config::network_isolation::NetworkIsolationConfig;
        let isolation_config = NetworkIsolationConfig::default();
        if let Err(e) = isolation_config.apply_isolation().await {
            output.warning(&format!("Failed to apply network isolation: {}", e))?;
        }
    }

    // Start orchestrator
    output.info("Starting runtime orchestrator...")?;
    let mut orchestrator = RuntimeOrchestrator::new(node_config.clone()).await.map_err(|e| {
        CliError::ConfigError(format!("Failed to create orchestrator: {}", e))
    })?;

    // Configure edge node if needed
    if is_edge_node {
        orchestrator.set_edge_node(true).await;
        orchestrator.set_edge_max_headers(edge_max_headers as usize).await;
    }

    // PHASE 1: Start network components for peer discovery
    output.info("Starting network components for peer discovery...")?;
    orchestrator
        .start_network_components_for_discovery()
        .await
        .map_err(|e| CliError::ConfigError(format!("Failed to start network: {}", e)))?;

    output.print("Waiting for network stack to initialize...")?;
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // PHASE 2: Discover existing network
    output.info("Discovering existing network...")?;
    let network_info_opt = orchestrator
        .discover_network_with_retry(is_edge_node)
        .await
        .map_err(|e| {
            CliError::ConfigError(format!("Failed to discover network: {}", e))
        })?;

    // PHASE 3: Setup identity and blockchain
    if let Some(network_info) = network_info_opt {
        output.success("Connected to existing ZHTP network!")?;
        output.print(&format!("Network peers: {}", network_info.peer_count))?;
        output.print(&format!("Blockchain height: {}", network_info.blockchain_height))?;

        output.info("Initializing blockchain for sync...")?;
        orchestrator
            .start_blockchain_sync(&network_info)
            .await
            .map_err(|e| {
                CliError::ConfigError(format!("Failed to start blockchain sync: {}", e))
            })?;

        output.print("Waiting for initial sync to start...")?;
        if let Err(_e) = orchestrator
            .wait_for_initial_sync(tokio::time::Duration::from_secs(30))
            .await
        {
            output.warning("Initial sync timeout - will continue syncing in background")?;
        }

        orchestrator.set_joined_existing_network(true).await.map_err(|e| {
            CliError::ConfigError(format!("Failed to set network status: {}", e))
        })?;

        output.info("Starting in guest mode - blockchain will sync")?;
        WalletStartupManager::handle_startup_wallet_flow_with_keystore(keystore_path)
            .await
            .map_err(|e| {
                CliError::IdentityError(format!("Failed to setup wallet: {}", e))
            })?
    } else {
        output.warning("No existing ZHTP network found")?;

        if is_edge_node {
            return Err(CliError::ConfigError(
                "Edge nodes must find an existing network".to_string(),
            ));
        }

        output.print("Starting new genesis network...")?;
        orchestrator.set_joined_existing_network(false).await.map_err(|e| {
            CliError::ConfigError(format!("Failed to set network status: {}", e))
        })?;

        WalletStartupManager::handle_startup_wallet_flow_with_keystore(keystore_path)
            .await
            .map_err(|e| {
                CliError::IdentityError(format!("Failed to setup wallet: {}", e))
            })?
    };

    // PHASE 4: Register and start remaining components
    output.info("Registering remaining system components...")?;
    orchestrator.register_all_components().await.map_err(|e| {
        CliError::ConfigError(format!("Failed to register components: {}", e))
    })?;

    output.info("Starting remaining system components...")?;
    orchestrator.start_all_components().await.map_err(|e| {
        CliError::ConfigError(format!("Failed to start components: {}", e))
    })?;

    output.success("ZHTP orchestrator fully operational!")?;
    output.print("Press Ctrl+C to stop the node")?;

    // Run main loop
    orchestrator.run_main_loop().await.map_err(|e| {
        CliError::ConfigError(format!("Node runtime error: {}", e))
    })?;

    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_start() {
        let action = NodeAction::Start {
            config: None,
            port: None,
            dev: false,
            pure_mesh: false,
            network: None,
            edge_mode: false,
            edge_max_headers: 1000,
            keystore: None,
        };
        assert_eq!(action_to_operation(&action), NodeOperation::Start);
    }

    #[test]
    fn test_action_to_operation_stop() {
        assert_eq!(action_to_operation(&NodeAction::Stop), NodeOperation::Stop);
    }

    #[test]
    fn test_action_to_operation_status() {
        assert_eq!(
            action_to_operation(&NodeAction::Status),
            NodeOperation::Status
        );
    }

    #[test]
    fn test_action_to_operation_restart() {
        assert_eq!(
            action_to_operation(&NodeAction::Restart),
            NodeOperation::Restart
        );
    }

    #[test]
    fn test_parse_network_environment_mainnet() {
        assert!(matches!(
            parse_network_environment("mainnet"),
            Ok(Environment::Mainnet)
        ));
        assert!(matches!(
            parse_network_environment("main"),
            Ok(Environment::Mainnet)
        ));
    }

    #[test]
    fn test_parse_network_environment_testnet() {
        assert!(matches!(
            parse_network_environment("testnet"),
            Ok(Environment::Testnet)
        ));
        assert!(matches!(
            parse_network_environment("test"),
            Ok(Environment::Testnet)
        ));
    }

    #[test]
    fn test_parse_network_environment_dev() {
        assert!(matches!(
            parse_network_environment("dev"),
            Ok(Environment::Development)
        ));
        assert!(matches!(
            parse_network_environment("development"),
            Ok(Environment::Development)
        ));
    }

    #[test]
    fn test_parse_network_environment_case_insensitive() {
        assert!(matches!(
            parse_network_environment("MAINNET"),
            Ok(Environment::Mainnet)
        ));
        assert!(matches!(
            parse_network_environment("TestNet"),
            Ok(Environment::Testnet)
        ));
    }

    #[test]
    fn test_parse_network_environment_invalid() {
        assert!(parse_network_environment("invalid").is_err());
        assert!(parse_network_environment("").is_err());
    }

    #[test]
    fn test_normalize_keystore_path_home() {
        let result = normalize_keystore_path("~/.zhtp/keystore");
        assert!(result.is_some());
        let path = result.unwrap();
        assert!(path.to_string_lossy().contains(".zhtp"));
    }

    #[test]
    fn test_normalize_keystore_path_relative() {
        let result = normalize_keystore_path("./keystore");
        assert_eq!(result, Some(PathBuf::from("./keystore")));
    }

    #[test]
    fn test_normalize_keystore_path_empty() {
        let result = normalize_keystore_path("");
        assert_eq!(result, None);
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(NodeOperation::Start.description(), "Start orchestrator node");
        assert_eq!(NodeOperation::Stop.description(), "Stop orchestrator node");
        assert_eq!(NodeOperation::Status.description(), "Show node status");
        assert_eq!(NodeOperation::Restart.description(), "Restart orchestrator node");
    }
}
