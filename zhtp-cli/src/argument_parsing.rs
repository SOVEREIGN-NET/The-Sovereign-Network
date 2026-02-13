//! ZHTP Orchestrator CLI
//!
//! Command-line interface for the ZHTP orchestrator that provides
//! high-level user commands and coordinates Level 2 components

// Commands module is declared in lib.rs and accessed via crate::commands
use crate::commands;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, CommandFactory, FromArgMatches};
use clap::parser::ValueSource;
use serde_json::Value;

/// ZHTP Orchestrator CLI
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
#[command(name = "zhtp-cli")]
pub struct ZhtpCli {
    /// QUIC server address (connects to running node via QUIC on port 9334)
    #[arg(short, long, default_value = "127.0.0.1:9334", env = "ZHTP_SERVER")]
    pub server: String,

    /// Named server profile from CLI config (overrides --server)
    #[arg(long, env = "ZHTP_PROFILE")]
    pub profile: Option<String>,

    /// Enable verbose output
    #[arg(short, long, env = "ZHTP_VERBOSE")]
    pub verbose: bool,

    /// Output format (json, yaml, table)
    #[arg(short, long, default_value = "table", env = "ZHTP_FORMAT")]
    pub format: String,

    /// Configuration file path
    #[arg(short, long, env = "ZHTP_CONFIG")]
    pub config: Option<String>,

    /// API key for authentication
    #[arg(long, env = "ZHTP_API_KEY")]
    pub api_key: Option<String>,

    /// User ID for authenticated requests
    #[arg(long, env = "ZHTP_USER_ID")]
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

    /// Citizen management (orchestrated)
    Citizen(CitizenArgs),

    /// UBI status and operations (orchestrated)
    Ubi(UbiArgs),

    /// Identity operations (orchestrated)
    Identity(IdentityArgs),

    /// Network operations (orchestrated)
    Network(NetworkArgs),

    /// Blockchain operations (orchestrated)
    Blockchain(BlockchainArgs),

    /// System monitoring and status
    Monitor(MonitorArgs),

    /// Show version and build information
    Version(VersionArgs),

    /// Generate shell completion scripts
    Completion(CompletionArgs),

    /// Configuration management
    Config(ConfigArgs),

    /// Authentication and onboarding
    Auth(AuthArgs),

    /// Profile management
    Profile(ProfileArgs),

    /// System diagnostics
    Diagnostics(DiagnosticsArgs),

    /// Backup and restore
    Backup(BackupArgs),

    /// Component management
    Component(ComponentArgs),

    /// Interactive shell
    Interactive(InteractiveArgs),

    /// Server management
    Server(ServerArgs),

    /// Reward system management
    Reward(RewardArgs),

    /// Network isolation management
    Isolation(IsolationArgs),

    /// Deploy Web4 sites (React, Next.js, etc.)
    Deploy(DeployArgs),

    /// Manage Web4 domains
    Domain(DomainArgs),

    /// Manage trust anchors and audit logs
    Trust(TrustArgs),

    /// Generate manual pages (man pages)
    Man(ManArgs),

    /// Check for and install updates
    Update(UpdateArgs),

    /// Manage system service installation
    Service(ServiceArgs),

    /// Token operations (create, mint, transfer)
    Token(TokenArgs),
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
        #[arg(short, long, env = "ZHTP_NODE_CONFIG")]
        config: Option<String>,
        /// Port to bind to (overrides config file mesh_port if specified)
        #[arg(short, long, env = "ZHTP_NODE_PORT")]
        port: Option<u16>,
        /// Enable development mode
        #[arg(long, env = "ZHTP_NODE_DEV")]
        dev: bool,
        /// Enable pure mesh mode (ISP-free networking)
        #[arg(long, env = "ZHTP_NODE_PURE_MESH")]
        pure_mesh: bool,
        /// Network environment (overrides config file)
        #[arg(short, long, value_parser = ["mainnet", "testnet", "dev"], env = "ZHTP_NODE_NETWORK")]
        network: Option<String>,
        /// Enable edge node mode (lightweight sync for mobile/constrained devices)
        #[arg(long, env = "ZHTP_NODE_EDGE_MODE")]
        edge_mode: bool,
        /// Maximum headers to store in edge mode (default: 500 = ~100KB)
        #[arg(long, default_value = "500", env = "ZHTP_NODE_EDGE_MAX_HEADERS")]
        edge_max_headers: usize,
        /// Path to identity keystore directory (default: ~/.zhtp/keystore)
        /// Stores node identity and wallet for persistence across restarts.
        #[arg(long, env = "ZHTP_NODE_KEYSTORE")]
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
    /// Get wallet balance for an identity
    Balance {
        /// Identity ID (DID or public key)
        identity_id: String,
        /// Wallet type (primary, staking, governance, etc.)
        #[arg(short, long, default_value = "primary")]
        wallet_type: String,
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
    /// Get transaction history for an identity
    History {
        /// Identity ID (DID or public key)
        identity_id: String,
    },
    /// List all wallets for an identity
    List {
        /// Identity ID (DID or public key)
        identity_id: String,
    },
    /// Get wallet statistics for an identity
    Statistics {
        /// Identity ID (DID or public key)
        identity_id: String,
    },
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
    /// Get DAO treasury balance
    Balance,
    /// Get treasury balance (alias for Balance)
    TreasuryBalance,
}

/// Citizen management commands
#[derive(Args, Debug, Clone)]
pub struct CitizenArgs {
    #[command(subcommand)]
    pub action: CitizenAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CitizenAction {
    /// Register a new citizen for UBI
    Add {
        /// Identity ID (DID format)
        identity_id: String,
    },
    /// List all registered citizens
    List,
}

/// UBI status and operations commands
#[derive(Args, Debug, Clone)]
pub struct UbiArgs {
    #[command(subcommand)]
    pub action: UbiAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum UbiAction {
    /// Show UBI status (eligibility, next payout, pool balance)
    Status {
        /// Optional identity ID (shows personal status if provided, pool status if omitted)
        #[arg(short, long)]
        identity_id: Option<String>,
    },
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

    /// Register a new client-generated identity on the node (creates wallets)
    ///
    /// Calls `POST /api/v1/identity/register` over QUIC.
    ///
    /// This is useful for staging/testing the migration flow end-to-end, because
    /// registration assigns a `display_name` and creates wallets/balances that the
    /// migration can transfer exactly once.
    Register {
        /// Display name (username) to register on the node
        #[arg(long)]
        display_name: String,

        /// Device identifier for the identity being registered
        #[arg(long)]
        device_id: String,

        /// Identity type (human, device, organization)
        #[arg(long, default_value = "human")]
        identity_type: String,

        /// Path to keystore directory used for the QUIC client identity
        #[arg(short, long)]
        keystore: Option<String>,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Migrate an identity to a new DID (seed-only, controlled re-registration)
    ///
    /// This calls `POST /api/v1/identity/migrate` over QUIC.
    ///
    /// The request is signed using the **new** seed-derived root signing key (Dilithium5),
    /// proving control of the recovery phrase for the migrated identity.
    Migrate {
        /// Existing identity display name to migrate (must exist on the node)
        #[arg(long)]
        display_name: String,

        /// Device identifier to bind to the new identity (copied into the new identity record)
        #[arg(long)]
        device_id: String,

        /// 24-word recovery phrase for the NEW identity (quote it)
        ///
        /// If omitted, a new phrase is generated and printed.
        #[arg(long)]
        phrase: Option<String>,

        /// Read the 24-word recovery phrase from a file
        #[arg(long)]
        phrase_file: Option<String>,

        /// Path to keystore directory used for the QUIC client identity
        #[arg(short, long)]
        keystore: Option<String>,

        #[command(flatten)]
        trust: TrustFlags,
    },
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

/// Version command
#[derive(Args, Debug, Clone)]
pub struct VersionArgs {
    /// Show full build information
    #[arg(short, long)]
    pub full: bool,
}

/// Shell completion command
#[derive(Args, Debug, Clone)]
pub struct CompletionArgs {
    /// Shell to generate completions for
    #[arg(value_parser = ["bash", "zsh", "fish", "powershell", "elvish"])]
    pub shell: String,

    /// Output file path (if not provided, prints to stdout)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Install completion for current shell (requires admin/sudo on some platforms)
    #[arg(long)]
    pub install: bool,
}

/// Configuration management command
#[derive(Args, Debug, Clone)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

/// Diagnostics command
#[derive(Args, Debug, Clone)]
pub struct DiagnosticsArgs {
    #[command(subcommand)]
    pub action: DiagnosticsAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DiagnosticsAction {
    /// Full system and node diagnostics
    Full,
    /// Quick health check
    Quick,
    /// System resource diagnostics
    System,
    /// Node status and health
    Node,
    /// Network connectivity diagnostics
    Network,
}

/// Backup and restore command
#[derive(Args, Debug, Clone)]
pub struct BackupArgs {
    #[command(subcommand)]
    pub action: BackupAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BackupAction {
    /// Create encrypted backup
    Create {
        /// Output file path for backup
        #[arg(short, long)]
        output: Option<String>,

        /// Include configuration files in backup
        #[arg(long)]
        include_config: bool,
    },
    /// Restore from encrypted backup
    Restore {
        /// Path to backup file to restore
        #[arg(short, long)]
        input: String,
    },
    /// List available backups
    List,
    /// Delete a backup
    Delete {
        /// Path to backup file to delete
        path: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigAction {
    /// Display current configuration
    Show {
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<String>,

        /// Output format (toml, json, yaml)
        #[arg(short, long)]
        format: Option<String>,
    },
    /// Validate configuration file
    Validate {
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Edit configuration file with $EDITOR
    Edit {
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Initialize default configuration
    Init {
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<String>,

        /// Overwrite existing configuration
        #[arg(long)]
        force: bool,
    },
}

/// Authentication commands
#[derive(Args, Debug, Clone)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub action: AuthAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AuthAction {
    /// Login and create a profile (interactive by default)
    Login {
        /// Profile name
        #[arg(long)]
        profile: Option<String>,

        /// Server address (host:port)
        #[arg(long)]
        server: Option<String>,

        /// Path to identity keystore directory
        #[arg(long)]
        keystore: Option<String>,

        /// Identity DID to use
        #[arg(long)]
        identity: Option<String>,

        /// API key for authentication
        #[arg(long)]
        api_key: Option<String>,

        /// User ID for authentication
        #[arg(long)]
        user_id: Option<String>,

        /// Pin to specific SPKI hash (hex encoded)
        #[arg(long)]
        pin_spki: Option<String>,

        /// Expected node DID
        #[arg(long)]
        node_did: Option<String>,

        /// Trust on first use
        #[arg(long)]
        tofu: bool,

        /// Bootstrap mode - accept any certificate (INSECURE)
        #[arg(long)]
        trust_node: bool,

        /// Set this profile as default
        #[arg(long)]
        set_default: bool,

        /// Do not prompt, require all inputs
        #[arg(long)]
        non_interactive: bool,
    },
}

/// Profile management commands
#[derive(Args, Debug, Clone)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub action: ProfileAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ProfileAction {
    /// List profiles
    List,

    /// Show a profile
    Show {
        /// Profile name
        name: String,
    },

    /// Set default profile
    Use {
        /// Profile name
        name: String,
    },

    /// Create or update a profile
    Set {
        /// Profile name
        name: String,

        /// Server address (host:port)
        #[arg(long)]
        server: Option<String>,

        /// Path to identity keystore directory
        #[arg(long)]
        keystore: Option<String>,

        /// Identity DID to use
        #[arg(long)]
        identity: Option<String>,

        /// API key for authentication
        #[arg(long)]
        api_key: Option<String>,

        /// User ID for authentication
        #[arg(long)]
        user_id: Option<String>,

        /// Pin to specific SPKI hash (hex encoded)
        #[arg(long)]
        pin_spki: Option<String>,

        /// Expected node DID
        #[arg(long)]
        node_did: Option<String>,

        /// Trust on first use
        #[arg(long)]
        tofu: bool,

        /// Bootstrap mode - accept any certificate (INSECURE)
        #[arg(long)]
        trust_node: bool,
    },
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

/// Reward system commands
#[derive(Args, Debug, Clone)]
pub struct RewardArgs {
    #[command(subcommand)]
    pub action: RewardAction,
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
pub enum RewardAction {
    /// Show reward orchestrator status
    Status,
    /// Show combined reward metrics
    Metrics,
    /// Show routing reward details
    Routing,
    /// Show storage reward details
    Storage,
    /// Show reward configuration
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

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        /// Fee to pay for deployment (in SOV tokens)
        #[arg(short, long)]
        fee: Option<u64>,

        /// Dry run - show what would be deployed without deploying
        #[arg(long)]
        dry_run: bool,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Check deployment status for a domain
    Status {
        /// Domain to check
        domain: String,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// List all deployed domains
    List {
        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        #[command(flatten)]
        trust: TrustFlags,
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

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Rollback domain to a previous version
    Rollback {
        /// Domain to rollback
        domain: String,

        /// Target version number to rollback to
        #[arg(short, long)]
        to_version: u64,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        /// Force rollback without confirmation
        #[arg(short, long)]
        force: bool,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Update an existing website deployment
    Update {
        /// Build directory containing updated static files
        #[arg(value_name = "BUILD_DIR")]
        build_dir: String,

        /// Target domain (e.g., myapp.zhtp)
        #[arg(short, long)]
        domain: String,

        /// Deployment mode: 'spa' (single page app) or 'static'
        #[arg(short, long, default_value = "spa")]
        mode: Option<String>,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        /// Fee for update (in SOV tokens)
        #[arg(short, long)]
        fee: Option<u64>,

        /// Dry run - show what would be updated without updating
        #[arg(long)]
        dry_run: bool,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Delete a deployed domain and its manifest
    Delete {
        /// Domain to delete (e.g., myapp.zhtp)
        #[arg(short, long)]
        domain: String,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        /// Force delete without confirmation
        #[arg(short, long)]
        force: bool,

        #[command(flatten)]
        trust: TrustFlags,
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

/// Domain management commands
#[derive(Args, Debug, Clone)]
pub struct DomainArgs {
    #[command(subcommand)]
    pub action: DomainAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DomainAction {
    /// Register a new domain
    Register {
        /// Domain name (e.g., mysite.zhtp)
        #[arg(short, long)]
        domain: String,

        /// Registration duration in days
        #[arg(short, long, default_value = "365")]
        duration: u64,

        /// Domain metadata (JSON string)
        #[arg(short, long)]
        metadata: Option<String>,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Check domain availability
    Check {
        /// Domain name to check
        #[arg(short, long)]
        domain: String,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Get domain information
    Info {
        /// Domain name
        #[arg(short, long)]
        domain: String,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Shortcut: domain status (alias for info)
    Status {
        /// Domain name
        domain: String,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Transfer domain to new owner
    Transfer {
        /// Domain name to transfer
        #[arg(short, long)]
        domain: String,

        /// New owner DID
        #[arg(short, long)]
        new_owner: String,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Release domain from use
    Release {
        /// Domain name to release
        #[arg(short, long)]
        domain: String,

        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        /// Force release without confirmation
        #[arg(short, long)]
        force: bool,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Admin: migrate legacy domain records to the latest format
    Migrate {
        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,

        #[command(flatten)]
        trust: TrustFlags,
    },
}

/// Man page generation
#[derive(Args, Debug, Clone)]
pub struct ManArgs {
    #[command(subcommand)]
    pub action: ManAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ManAction {
    /// Generate man pages
    Generate {
        /// Output directory for man pages
        #[arg(short, long, default_value = "./man")]
        output: String,

        /// Only generate man page for a specific command
        #[arg(short, long)]
        command: Option<String>,
    },

    /// Show man page for a command
    Show {
        /// Command name
        command: String,
    },
}

/// Self-update mechanism
#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    #[command(subcommand)]
    pub action: UpdateAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum UpdateAction {
    /// Check for available updates
    Check,

    /// Install the latest available version
    Install {
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,

        /// Backup existing binary
        #[arg(long, default_value = "true")]
        backup: bool,
    },

    /// Rollback to previous version
    Rollback,

    /// Show current version
    Version,
}

/// Service installation and management
#[derive(Args, Debug, Clone)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub action: ServiceAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServiceAction {
    /// Install as system service
    Install {
        /// User to run service as (Linux)
        #[arg(short, long, default_value = "root")]
        user: String,

        /// Enable service to start on boot
        #[arg(short, long)]
        enable: bool,
    },

    /// Uninstall system service
    Uninstall {
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },

    /// Start the service
    Start,

    /// Stop the service
    Stop,

    /// Get service status
    Status,

    /// Show service logs
    Logs {
        /// Number of lines to show
        #[arg(short, long, default_value = "50")]
        lines: usize,

        /// Follow log output
        #[arg(short, long)]
        follow: bool,
    },
}

/// Token operation commands
#[derive(Args, Debug, Clone)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub action: TokenAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TokenAction {
    /// Create a new custom token
    Create {
        /// Token name (e.g., "MyToken")
        #[arg(short, long)]
        name: String,
        /// Token symbol (e.g., "MTK")
        #[arg(short, long)]
        symbol: String,
        /// Initial supply
        #[arg(long)]
        supply: u64,
        /// Decimal places (default: 8)
        #[arg(short, long, default_value = "8")]
        decimals: u8,
        // NOTE: creator removed - now derived from authenticated session
    },
    /// Mint additional tokens (creator only)
    Mint {
        /// Token ID
        #[arg(short, long)]
        token_id: String,
        /// Amount to mint
        #[arg(short, long)]
        amount: u64,
        /// Recipient address
        #[arg(short, long)]
        to: String,
        // NOTE: creator removed - authorization via authenticated session
    },
    /// Transfer tokens
    Transfer {
        /// Token ID
        #[arg(short, long)]
        token_id: String,
        // NOTE: from removed - sender is the authenticated caller
        /// Recipient address
        #[arg(long)]
        to: String,
        /// Amount to transfer
        #[arg(short, long)]
        amount: u64,
    },
    /// Burn tokens (caller burns own balance)
    Burn {
        /// Token ID
        #[arg(short, long)]
        token_id: String,
        /// Amount to burn
        #[arg(short, long)]
        amount: u64,
    },
    /// Get token information
    Info {
        /// Token ID
        #[arg(short, long)]
        token_id: String,
    },
    /// Get token balance for an address
    Balance {
        /// Token ID
        #[arg(short, long)]
        token_id: String,
        /// Address to check
        #[arg(short, long)]
        address: String,
    },
    /// List all tokens
    List,
}

/// Main CLI runner
pub async fn run_cli() -> Result<()> {
    // Initialize network genesis for replay protection
    // Uses testnet genesis hash from shared constant - CLI commands need this for network communication
    let _ = lib_identity::types::node_id::try_set_network_genesis(
        lib_identity::constants::TESTNET_GENESIS_HASH
    );

    let mut cmd = ZhtpCli::command();
    let matches = cmd.get_matches();
    let mut cli = ZhtpCli::from_arg_matches(&matches)?;

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let config = crate::cli_config::load_config(cli.config.as_deref())?;
    let server_source = matches.value_source("server").unwrap_or(ValueSource::DefaultValue);
    let profile_name = cli.profile.clone().or(config.default_profile.clone());

    let mut runtime_defaults = crate::cli_config::RuntimeDefaults::default();
    if let Some(defaults) = &config.defaults {
        runtime_defaults = crate::cli_config::merge_defaults(runtime_defaults, defaults);
    }

    if let Some(profile_name) = profile_name {
        if server_source == ValueSource::CommandLine {
            return Err(anyhow::anyhow!(
                "Cannot use --profile with --server. Use only one."
            ));
        }
        let profile = crate::cli_config::resolve_profile(&config, &profile_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown profile '{}'", profile_name))?;
        if let Some(server) = &profile.server {
            cli.server = server.clone();
        }
        runtime_defaults = crate::cli_config::merge_profile_config(runtime_defaults, profile);
    } else if let Some(spec) = crate::cli_config::resolve_server_alias(&config, &cli.server) {
        cli.server = spec.address().to_string();
        if let Some(profile_defaults) = spec.profile() {
            runtime_defaults = crate::cli_config::merge_profile_defaults(runtime_defaults, profile_defaults);
        }
    } else if server_source == ValueSource::DefaultValue {
        if let Some(defaults) = &config.defaults {
            if let Some(server) = &defaults.server {
                cli.server = server.clone();
            }
        }
    }

    if cli.api_key.is_none() {
        cli.api_key = runtime_defaults.api_key.clone();
    }
    if cli.user_id.is_none() {
        cli.user_id = runtime_defaults.user_id.clone();
    }

    crate::cli_config::set_runtime_defaults(runtime_defaults);

    match &cli.command {
        ZhtpCommand::Node(args) => commands::node::handle_node_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Wallet(args) => commands::wallet::handle_wallet_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Dao(args) => commands::dao::handle_dao_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Citizen(args) => commands::citizen::handle_citizen_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Ubi(args) => commands::ubi::handle_ubi_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Identity(args) => commands::identity::handle_identity_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Network(args) => commands::network::handle_network_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Blockchain(args) => commands::blockchain::handle_blockchain_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Monitor(args) => commands::monitor::handle_monitor_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Version(args) => commands::version::handle_version_command(args.clone()).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Completion(args) => commands::completion::handle_completion_command(args.clone()).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Config(args) => commands::config::handle_config_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Auth(args) => commands::auth::handle_auth_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Profile(args) => commands::profile::handle_profile_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Diagnostics(args) => commands::diagnostics::handle_diagnostics_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Backup(args) => commands::backup::handle_backup_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Component(args) => commands::component::handle_component_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Interactive(args) => commands::interactive::handle_interactive_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Server(args) => commands::server::handle_server_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Reward(args) => commands::rewards::handle_reward_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Isolation(args) => commands::isolation::handle_isolation_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Deploy(args) => commands::deploy::handle_deploy_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Domain(args) => commands::domain::handle_domain_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Trust(args) => commands::trust::handle_trust_command(args.clone()).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Man(args) => commands::man::handle_man_command(args.clone()).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Update(args) => commands::update::handle_update_command(args.clone()).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Service(args) => commands::service::handle_service_command(args.clone()).await.map_err(anyhow::Error::msg),
        ZhtpCommand::Token(args) => commands::token::handle_token_command(args.clone(), &cli).await.map_err(anyhow::Error::msg),
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
