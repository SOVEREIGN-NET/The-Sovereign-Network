//! ZHTP Orchestrator CLI
//! 
//! Command-line interface for the ZHTP orchestrator that provides
//! high-level user commands and coordinates Level 2 components

pub mod commands;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serde_json::Value;

/// ZHTP Orchestrator CLI
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
#[command(name = "zhtp")]
pub struct ZhtpCli {
    /// API server address
    #[arg(short, long, default_value = "127.0.0.1:9333")]
    pub server: String,
    
    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,
    
    /// Output format (json, yaml, table)
    #[arg(short, long, default_value = "table")]
    pub format: String,
    
    /// Configuration file path
    #[arg(short, long)]
    pub config: Option<String>,
    
    /// API key for authentication
    #[arg(long)]
    pub api_key: Option<String>,
    
    /// User ID for authenticated requests
    #[arg(long)]
    pub user_id: Option<String>,
    
    #[command(subcommand)]
    pub command: ZhtpCommand,
}

/// ZHTP Orchestrator commands
#[derive(Subcommand, Debug, Clone)]
pub enum ZhtpCommand {
    /// Start the ZHTP orchestrator node
    Node(NodeArgs),

    /// Wallet operations (orchestrated)
    Wallet(WalletArgs),

    /// DAO operations (orchestrated)
    Dao(DaoArgs),

    /// Identity operations (orchestrated)
    Identity(IdentityArgs),

    /// Network operations (orchestrated)
    Network(NetworkArgs),

    /// Blockchain operations (orchestrated)
    Blockchain(BlockchainArgs),

    /// System monitoring and status
    Monitor(MonitorArgs),

    /// Component management
    Component(ComponentArgs),

    /// Interactive shell
    Interactive(InteractiveArgs),

    /// Server management
    Server(ServerArgs),

    /// Network isolation management
    Isolation(IsolationArgs),

    /// Deploy Web4 sites (React, Next.js, etc.)
    Deploy(DeployArgs),

    /// Manage trust anchors and audit logs
    Trust(TrustArgs),
}

/// Node management commands
#[derive(Args, Debug, Clone)]
pub struct NodeArgs {
    #[command(subcommand)]
    pub action: NodeAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum NodeAction {
    /// Start the ZHTP orchestrator node
    Start {
        /// Configuration file
        #[arg(short, long)]
        config: Option<String>,
        /// Port to bind to (overrides config file mesh_port if specified)
        #[arg(short, long)]
        port: Option<u16>,
        /// Enable development mode
        #[arg(long)]
        dev: bool,
        /// Enable pure mesh mode (ISP-free networking)
        #[arg(long)]
        pure_mesh: bool,
        /// Network environment (overrides config file)
        #[arg(short, long, value_parser = ["mainnet", "testnet", "dev"])]
        network: Option<String>,
        /// Enable edge node mode (lightweight sync for mobile/constrained devices)
        #[arg(long)]
        edge_mode: bool,
        /// Maximum headers to store in edge mode (default: 500 = ~100KB)
        #[arg(long, default_value = "500")]
        edge_max_headers: usize,
        /// Path to identity keystore directory (default: ~/.zhtp/keystore)
        /// Stores node identity and wallet for persistence across restarts.
        #[arg(long)]
        keystore: Option<String>,
    },
    /// Stop the orchestrator node
    Stop,
    /// Get node status
    Status,
    /// Restart the node
    Restart,
}

/// Wallet operation commands
#[derive(Args, Debug, Clone)]
pub struct WalletArgs {
    #[command(subcommand)]
    pub action: WalletAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum WalletAction {
    /// Create new wallet (orchestrated)
    Create {
        /// Wallet name
        #[arg(short, long)]
        name: String,
        /// Wallet type
        #[arg(short, long, default_value = "citizen")]
        wallet_type: String,
    },
    /// Get wallet balance (orchestrated)
    Balance {
        /// Wallet address
        address: String,
    },
    /// Transfer funds (orchestrated)
    Transfer {
        /// From wallet
        #[arg(short, long)]
        from: String,
        /// To wallet
        #[arg(short, long)]
        to: String,
        /// Amount to transfer
        #[arg(short, long)]
        amount: u64,
    },
    /// Get transaction history (orchestrated)
    History {
        /// Wallet address
        address: String,
    },
    /// List all wallets
    List,
}

/// DAO operation commands
#[derive(Args, Debug, Clone)]
pub struct DaoArgs {
    #[command(subcommand)]
    pub action: DaoAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DaoAction {
    /// Get DAO information (orchestrated)
    Info,
    /// Create new proposal (orchestrated)
    Propose {
        /// Proposal title
        #[arg(short, long)]
        title: String,
        /// Proposal description
        #[arg(short, long)]
        description: String,
    },
    /// Vote on proposal (orchestrated)
    Vote {
        /// Proposal ID
        #[arg(short, long)]
        proposal_id: String,
        /// Vote choice (yes/no/abstain)
        #[arg(short, long)]
        choice: String,
    },
    /// Claim UBI (orchestrated)
    ClaimUbi,
}

/// Identity operation commands
#[derive(Args, Debug, Clone)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub action: IdentityAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IdentityAction {
    /// Create new identity (orchestrated)
    Create {
        /// Identity name
        name: String,
    },
    /// Create zero-knowledge DID identity
    CreateDid {
        /// Identity name
        name: String,
        /// Identity type (human, organization, device, service)
        #[arg(short, long, default_value = "human")]
        identity_type: String,
        /// Recovery options
        #[arg(short, long)]
        recovery_options: Vec<String>,
    },
    /// Verify identity (orchestrated)
    Verify {
        /// Identity ID
        identity_id: String,
    },
    /// List identities
    List,
}

/// Network operation commands
#[derive(Args, Debug, Clone)]
pub struct NetworkArgs {
    #[command(subcommand)]
    pub action: NetworkAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum NetworkAction {
    /// Get network status (orchestrated)
    Status,
    /// Get connected peers (orchestrated)
    Peers,
    /// Test network connectivity
    Test,
    /// Ping a specific peer node
    Ping {
        /// Target address (e.g., 192.168.1.164:9002 or node ID)
        target: String,
        /// Number of pings to send
        #[arg(short, long, default_value = "3")]
        count: u32,
    },
}

/// Blockchain operation commands
#[derive(Args, Debug, Clone)]
pub struct BlockchainArgs {
    #[command(subcommand)]
    pub action: BlockchainAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BlockchainAction {
    /// Get blockchain status (orchestrated)
    Status,
    /// Get transaction info (orchestrated)
    Transaction {
        /// Transaction hash
        tx_hash: String,
    },
    /// Get blockchain stats
    Stats,
}

/// Monitoring commands
#[derive(Args, Debug, Clone)]
pub struct MonitorArgs {
    #[command(subcommand)]
    pub action: MonitorAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum MonitorAction {
    /// Show system monitoring
    System,
    /// Show component health
    Health,
    /// Show performance metrics
    Performance,
    /// Show system logs
    Logs,
}

/// Component management commands
#[derive(Args, Debug, Clone)]
pub struct ComponentArgs {
    #[command(subcommand)]
    pub action: ComponentAction,
}

/// Interactive shell commands
#[derive(Args, Debug, Clone)]
pub struct InteractiveArgs {
    /// Initial command to run
    #[arg(short, long)]
    pub command: Option<String>,
}

/// Server management commands
#[derive(Args, Debug, Clone)]
pub struct ServerArgs {
    #[command(subcommand)]
    pub action: ServerAction,
}

/// Network isolation commands
#[derive(Args, Debug, Clone)]
pub struct IsolationArgs {
    #[command(subcommand)]
    pub action: IsolationAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ComponentAction {
    /// List all Level 2 components
    List,
    /// Start a component
    Start {
        /// Component name
        name: String,
    },
    /// Stop a component
    Stop {
        /// Component name
        name: String,
    },
    /// Restart a component
    Restart {
        /// Component name
        name: String,
    },
    /// Get component status
    Status {
        /// Component name
        name: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServerAction {
    /// Start the orchestrator server
    Start,
    /// Stop the orchestrator server
    Stop,
    /// Restart the orchestrator server
    Restart,
    /// Get server status
    Status,
    /// Get server configuration
    Config,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IsolationAction {
    /// Apply network isolation for pure mesh mode
    Apply,
    /// Check current isolation status
    Check,
    /// Remove network isolation
    Remove,
    /// Test network connectivity
    Test,
}

/// Deploy commands for Web4 sites
#[derive(Args, Debug, Clone)]
pub struct DeployArgs {
    #[command(subcommand)]
    pub action: DeployAction,
}

/// Common trust configuration flags
#[derive(Args, Debug, Clone)]
pub struct TrustFlags {
    /// Pin to specific SPKI hash (hex encoded). Most secure option.
    #[arg(long)]
    pub pin_spki: Option<String>,

    /// Expected node DID. Verified after UHP handshake.
    #[arg(long)]
    pub node_did: Option<String>,

    /// Trust on first use. Stores fingerprint for future verification.
    #[arg(long)]
    pub tofu: bool,

    /// Bootstrap mode - accept any certificate (INSECURE, dev only)
    #[arg(long)]
    pub trust_node: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DeployAction {
    /// Deploy a static site to Web4
    Site {
        /// Build directory containing static files
        #[arg(value_name = "BUILD_DIR")]
        build_dir: String,

        /// Target domain (e.g., myapp.zhtp)
        #[arg(short, long)]
        domain: String,

        /// Deployment mode: 'spa' (single page app) or 'static'
        #[arg(short, long, default_value = "spa")]
        mode: Option<String>,

        /// Path to identity keystore directory (REQUIRED for production deploys)
        #[arg(short, long)]
        keystore: String,

        /// Fee to pay for deployment (in ZHTP tokens)
        #[arg(short, long)]
        fee: Option<u64>,

        /// Pin to specific SPKI hash (hex encoded)
        #[arg(long)]
        pin_spki: Option<String>,

        /// Expected node DID
        #[arg(long)]
        node_did: Option<String>,

        /// Trust on first use
        #[arg(long)]
        tofu: bool,

        /// Bootstrap mode (INSECURE, dev only)
        #[arg(long)]
        trust_node: bool,

        /// Dry run - show what would be deployed without deploying
        #[arg(long)]
        dry_run: bool,
    },

    /// Check deployment status for a domain
    Status {
        /// Domain to check
        domain: String,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        /// Pin to specific SPKI hash (hex encoded)
        #[arg(long)]
        pin_spki: Option<String>,

        /// Expected node DID
        #[arg(long)]
        node_did: Option<String>,

        /// Trust on first use
        #[arg(long)]
        tofu: bool,

        /// Bootstrap mode (INSECURE, dev only)
        #[arg(long)]
        trust_node: bool,
    },

    /// List all deployed domains
    List {
        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        /// Pin to specific SPKI hash (hex encoded)
        #[arg(long)]
        pin_spki: Option<String>,

        /// Expected node DID
        #[arg(long)]
        node_did: Option<String>,

        /// Trust on first use
        #[arg(long)]
        tofu: bool,

        /// Bootstrap mode (INSECURE, dev only)
        #[arg(long)]
        trust_node: bool,
    },

    /// View deployment history for a domain
    History {
        /// Domain to check
        domain: String,

        /// Maximum number of versions to show
        #[arg(short, long, default_value = "10")]
        limit: usize,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        /// Pin to specific SPKI hash (hex encoded)
        #[arg(long)]
        pin_spki: Option<String>,

        /// Expected node DID
        #[arg(long)]
        node_did: Option<String>,

        /// Trust on first use
        #[arg(long)]
        tofu: bool,

        /// Bootstrap mode (INSECURE, dev only)
        #[arg(long)]
        trust_node: bool,
    },

    /// Rollback domain to a previous version
    Rollback {
        /// Domain to rollback
        domain: String,

        /// Target version number to rollback to
        #[arg(short, long)]
        to_version: u64,

        /// Path to identity keystore directory (REQUIRED)
        #[arg(short, long)]
        keystore: String,

        /// Pin to specific SPKI hash (hex encoded)
        #[arg(long)]
        pin_spki: Option<String>,

        /// Expected node DID
        #[arg(long)]
        node_did: Option<String>,

        /// Trust on first use
        #[arg(long)]
        tofu: bool,

        /// Bootstrap mode (INSECURE, dev only)
        #[arg(long)]
        trust_node: bool,

        /// Force rollback without confirmation
        #[arg(short, long)]
        force: bool,
    },
}

/// Trust management commands
#[derive(Args, Debug, Clone)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub action: TrustAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TrustAction {
    /// List trusted nodes (trustdb)
    List,

    /// Show audit log entries (TOFU acceptance)
    Audit,

    /// Reset trust for a node
    Reset {
        /// Node address (host:port)
        node: String,
    },
}

/// Main CLI runner
pub async fn run_cli() -> Result<()> {
    let cli = ZhtpCli::parse();
    
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }
    
    match &cli.command {
        ZhtpCommand::Node(args) => commands::node::handle_node_command(args.clone(), &cli).await,
        ZhtpCommand::Wallet(args) => commands::wallet::handle_wallet_command(args.clone(), &cli).await,
        ZhtpCommand::Dao(args) => commands::dao::handle_dao_command(args.clone(), &cli).await,
        ZhtpCommand::Identity(args) => commands::identity::handle_identity_command(args.clone(), &cli).await,
        ZhtpCommand::Network(args) => commands::network::handle_network_command(args.clone(), &cli).await,
        ZhtpCommand::Blockchain(args) => commands::blockchain::handle_blockchain_command(args.clone(), &cli).await,
        ZhtpCommand::Monitor(args) => commands::monitor::handle_monitor_command(args.clone(), &cli).await,
        ZhtpCommand::Component(args) => commands::component::handle_component_command(args.clone(), &cli).await,
        ZhtpCommand::Interactive(args) => commands::interactive::handle_interactive_command(args.clone(), &cli).await,
        ZhtpCommand::Server(args) => commands::server::handle_server_command(args.clone(), &cli).await,
        ZhtpCommand::Isolation(args) => commands::isolation::handle_isolation_command(args.clone(), &cli).await,
        ZhtpCommand::Deploy(args) => commands::deploy::handle_deploy_command(args.clone(), &cli).await,
        ZhtpCommand::Trust(args) => commands::trust::handle_trust_command(args.clone()).await,
    }
}

/// Format output based on CLI format preference
pub fn format_output(data: &Value, format: &str) -> Result<String> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(data)?),
        "yaml" => {
            #[cfg(feature = "yaml")]
            {
                Ok(serde_yaml::to_string(data)?)
            }
            #[cfg(not(feature = "yaml"))]
            {
                Ok(serde_json::to_string_pretty(data)?)
            }
        }
        "table" => {
            if let Some(obj) = data.as_object() {
                let mut result = String::new();
                for (key, value) in obj {
                    result.push_str(&format!("{:<20} {}\n", key, value));
                }
                Ok(result)
            } else if let Some(array) = data.as_array() {
                let mut result = String::new();
                for (i, item) in array.iter().enumerate() {
                    result.push_str(&format!("[{}] {}\n", i, item));
                }
                Ok(result)
            } else {
                Ok(data.to_string())
            }
        }
        _ => Err(anyhow::anyhow!("Unsupported output format: {}", format)),
    }
}

/// Parse command line arguments
pub fn parse_arguments() -> ZhtpCli {
    ZhtpCli::parse()
}

/// Display startup banner
pub fn display_startup_banner() {
    println!("
    ███████╗██╗  ██╗████████╗██████╗ 
    ╚══███╔╝██║  ██║╚══██╔══╝██╔══██╗
      ███╔╝ ███████║   ██║   ██████╔╝
     ███╔╝  ██╔══██║   ██║   ██╔═══╝ 
    ███████╗██║  ██║   ██║   ██║     
    ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     
    
    Zero-Knowledge Hypertext Transfer Protocol
    Orchestrator - Level 2 Components Manager
    ");
}

/// Interactive shell structure
pub struct InteractiveShell {
    // Shell state
}

impl InteractiveShell {
    pub async fn new() -> Result<Self> {
        Ok(Self {})
    }
}

/// Start interactive shell
pub async fn start_interactive_shell() -> Result<InteractiveShell> {
    InteractiveShell::new().await
}
