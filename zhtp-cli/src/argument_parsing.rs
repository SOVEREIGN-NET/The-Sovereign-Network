//! ZHTP Orchestrator CLI
//!
//! Command-line interface for the ZHTP orchestrator that provides
//! high-level user commands and coordinates Level 2 components

// Commands module is declared in lib.rs and accessed via crate::commands
use crate::commands;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serde_json::Value;

/// ZHTP Orchestrator CLI
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
#[command(name = "zhtp-cli")]
pub struct ZhtpCli {
    /// QUIC server address (connects to running node via QUIC on port 9334)
    #[arg(short, long, default_value = "127.0.0.1:9334", env = "ZHTP_SERVER")]
    pub server: String,

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

    /// Oracle governance proposal operations
    Oracle(OracleArgs),

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

    /// Bonding curve operations (deploy, buy, sell, price)
    Curve(CurveArgs),

    /// Genesis configuration and state migration (GENESIS-1, #1909)
    Genesis(GenesisArgs),

    /// CBE token operations (init pools, employment, payroll)
    Cbe(CbeArgs),
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
    /// Mint SOV to an existing wallet (admin, genesis balance recovery)
    MintSov {
        /// 32-byte hex wallet ID
        #[arg(long)]
        wallet_id: String,
        /// Amount in SOV (display units, e.g. 5000)
        #[arg(long)]
        amount: u64,
    },
    /// Provision a wallet for an existing identity (restore or create)
    Provision {
        /// 32-byte hex wallet ID (use existing ID to restore, or generate new)
        #[arg(long)]
        wallet_id: String,
        /// Owner identity DID or hex ID
        #[arg(long)]
        owner: String,
        /// Wallet type: Primary, UBI, Savings
        #[arg(long, default_value = "Primary")]
        wallet_type: String,
        /// Mint SOV welcome bonus (5000 SOV)
        #[arg(long)]
        welcome_bonus: bool,
        /// Dilithium public key hex (2592 bytes). Required if identity not yet registered.
        #[arg(long)]
        public_key: Option<String>,
    },
}

/// DAO operation commands
#[derive(Args, Debug, Clone)]
pub struct DaoArgs {
    #[command(subcommand)]
    pub action: DaoAction,
}

/// Oracle governance commands
#[derive(Args, Debug, Clone)]
pub struct OracleArgs {
    #[command(subcommand)]
    pub action: OracleAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum OracleAction {
    /// Bootstrap oracle committee (direct, no governance required when committee is empty)
    CommitteeUpdate {
        /// New committee members as 32-byte hex key_ids (comma-separated)
        #[arg(long, value_delimiter = ',')]
        members: Vec<String>,
        /// Dilithium signing public keys (hex, comma-separated, same order as --members)
        #[arg(long, value_delimiter = ',')]
        pubkeys: Vec<String>,
        /// Activation epoch (must be in the future)
        #[arg(long)]
        activate_epoch: u64,
        /// Human-readable proposal reason
        #[arg(long, default_value = "Oracle committee update")]
        reason: String,
        /// Optional proposal title
        #[arg(long)]
        title: Option<String>,
        /// Optional proposal description
        #[arg(long)]
        description: Option<String>,
        /// Voting period in days
        #[arg(long)]
        voting_period_days: Option<u32>,
    },
    /// Submit oracle config update governance proposal
    ConfigUpdate {
        /// Oracle epoch duration in seconds
        #[arg(long)]
        epoch_duration: u64,
        /// Maximum source age in seconds
        #[arg(long)]
        max_source_age: u64,
        /// Maximum deviation in basis points (<= 10000)
        #[arg(long)]
        max_deviation_bps: u32,
        /// Maximum consumer staleness in epochs
        #[arg(long, default_value_t = 10)]
        max_price_staleness_epochs: u64,
        /// Activation epoch (must be in the future)
        #[arg(long)]
        activate_epoch: u64,
        /// Human-readable proposal reason
        #[arg(long, default_value = "Oracle config update")]
        reason: String,
        /// Optional proposal title
        #[arg(long)]
        title: Option<String>,
        /// Optional proposal description
        #[arg(long)]
        description: Option<String>,
        /// Voting period in days
        #[arg(long)]
        voting_period_days: Option<u32>,
    },
    /// Get oracle committee status and epoch info
    Status,
    /// Get latest finalized SOV/USD price
    Price,
    /// Get oracle operating config
    Config,
    /// Get pending oracle committee/config updates
    PendingUpdates,
    /// Get oracle slashing events
    SlashingEvents,
    /// Get banned oracle validators
    BannedValidators,
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
    /// Register DAO metadata in canonical DAO registry via signed DaoExecution tx broadcast
    RegistryRegister {
        /// Token ID (32-byte hex)
        #[arg(long)]
        token_id: String,
        /// DAO class (np/fp)
        #[arg(long)]
        class: String,
        /// Metadata hash (32-byte hex)
        #[arg(long)]
        metadata_hash: String,
    },
    /// List registered DAOs
    RegistryList,
    /// Get DAO registry entry by DAO ID
    RegistryGet {
        /// DAO ID (32-byte hex)
        #[arg(long)]
        dao_id: String,
    },
    /// Create DAO via canonical factory DaoExecution tx broadcast
    FactoryCreate {
        /// Token ID (32-byte hex)
        #[arg(long)]
        token_id: String,
        /// DAO class (np/fp)
        #[arg(long)]
        class: String,
        /// Metadata hash (32-byte hex)
        #[arg(long)]
        metadata_hash: String,
    },
    /// Initialize entity registry (one-time, Bootstrap Council only).
    /// Builds and signs the InitEntityRegistry transaction locally from the
    /// provided treasury keys and council identity keystore.
    EntityRegistryInit {
        /// CBE (for-profit) treasury public key, hex-encoded
        #[arg(long)]
        cbe_treasury: String,
        /// Nonprofit treasury public key, hex-encoded
        #[arg(long)]
        nonprofit_treasury: String,
        /// Optional keystore path for the council identity signing this tx
        #[arg(long)]
        keystore: Option<String>,
    },
    /// Show entity registry status
    EntityRegistryStatus,
    /// Record an oracle-committee-attested fiat→CBE on-ramp trade.
    RecordOnRampTrade {
        /// Oracle epoch ID
        #[arg(long)]
        epoch_id: u64,
        /// CBE amount received (atomic units, 18 decimals)
        #[arg(long)]
        cbe_amount: u128,
        /// USDC amount paid (atomic units, 6 decimals)
        #[arg(long)]
        usdc_amount: u128,
        /// Unix timestamp of the off-chain trade
        #[arg(long)]
        traded_at: u64,
        /// Oracle Committee approval pairs as `<dilithium_pk_hex>:<signature_hex>`.
        /// Repeat this flag once per signer.
        #[arg(long = "approval", value_name = "PK_HEX:SIG_HEX")]
        approvals: Vec<String>,
    },
    /// Submit a Bootstrap-Council-approved SOV treasury allocation.
    TreasuryAllocation {
        /// CBE treasury key_id (32-byte hex)
        #[arg(long)]
        source_key_id: String,
        /// Destination DAO treasury wallet key_id (32-byte hex)
        #[arg(long)]
        destination_key_id: String,
        /// Amount of SOV to transfer (atomic units)
        #[arg(long)]
        amount: u64,
        /// Governance spending category (e.g. "Operations")
        #[arg(long)]
        spending_category: String,
        /// On-chain proposal ID that authorised this allocation (32-byte hex)
        #[arg(long)]
        proposal_id: String,
        /// Bootstrap Council approval pairs as `<dilithium_pk_hex>:<signature_hex>`.
        /// Repeat this flag once per signer.
        #[arg(long = "approval", value_name = "PK_HEX:SIG_HEX")]
        approvals: Vec<String>,
    },
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
    /// Register identity on-chain (creates identity + wallets + SOV welcome bonus)
    ///
    /// If no local keystore exists, generates keys first. Then calls the node's
    /// /api/v1/identity/register endpoint to register on-chain with 3 wallets
    /// (Primary, UBI, Savings) and receive the SOV welcome bonus.
    Register {
        /// Display name
        #[arg(short, long)]
        display_name: String,
        /// Device identifier
        #[arg(long, default_value = "cli-device")]
        device_id: String,
        /// Path to identity keystore directory
        #[arg(short, long)]
        keystore: Option<String>,
    },
    /// Verify identity (orchestrated)
    Verify {
        /// Identity ID
        identity_id: String,
    },
    /// List identities
    List,
    /// Simulate identity message flow (local, no network)
    SimulateMessage {
        /// Number of devices to register
        #[arg(short, long, default_value = "2")]
        devices: u32,
        /// Retain until TTL after delivery
        #[arg(long)]
        retain_until_ttl: bool,
    },
    /// Fetch pending identity envelopes from node
    Pending {
        /// Recipient DID
        recipient_did: String,
        /// Device ID
        device_id: String,
    },
    /// Acknowledge delivery of an identity envelope
    Ack {
        /// Recipient DID
        recipient_did: String,
        /// Device ID
        device_id: String,
        /// Message ID
        message_id: u64,
        /// Retain until TTL after delivery
        #[arg(long)]
        retain_until_ttl: bool,
    },
    /// Import identity from .zkdid backup file
    Import {
        /// Path to .zkdid backup file
        #[arg(short, long)]
        file: String,
        /// Path to keystore directory
        #[arg(short, long)]
        keystore: Option<String>,
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
    /// Deploy a contract via canonical ContractDeployment transaction broadcast
    ContractDeploy {
        /// Contract family/type (for example: wasm, token, web4)
        #[arg(long)]
        contract_type: String,
        /// Compiled contract code as hex string
        #[arg(long)]
        code_hex: String,
        /// ABI JSON string
        #[arg(long)]
        abi_json: String,
        /// Optional init args as hex string
        #[arg(long)]
        init_args_hex: Option<String>,
        /// Deployment gas limit
        #[arg(long, default_value = "100000")]
        gas_limit: u64,
        /// Deployment memory limit in bytes
        #[arg(long, default_value = "65536")]
        memory_limit_bytes: u32,
    },
    /// Call a contract method via canonical ContractExecution transaction broadcast
    ContractCall {
        /// Deployed contract ID (32-byte hex)
        #[arg(long)]
        contract_id: String,
        /// Contract type (token, messaging, contact, group, file, governance, web4, ubi, devgrants)
        #[arg(long)]
        contract_type: String,
        /// Contract method name
        #[arg(long)]
        method: String,
        /// Encoded call params as hex string.
        /// Omitted or empty values are both treated as "no params" (empty bytes).
        #[arg(long, default_value = "")]
        params_hex: String,
    },
    /// List deployed contracts from canonical contract registry
    ContractList {
        /// Contract type filter: all, token, or web4
        #[arg(long, default_value = "all")]
        contract_type: String,
        /// Max number of items to return
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Pagination offset
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Get deployed contract metadata by contract ID
    ContractInfo {
        /// Contract ID (32-byte hex)
        #[arg(long)]
        contract_id: String,
    },
    /// Get deployed contract state by contract ID
    ContractState {
        /// Contract ID (32-byte hex)
        #[arg(long)]
        contract_id: String,
    },
    /// Broadcast a pre-signed transaction as hex-encoded bytes
    BroadcastRaw {
        /// Hex-encoded signed transaction bytes (bincode/json serialized)
        #[arg(long)]
        tx_hex: String,
    },
    /// Audit non-canonical wallet state from blockchain.dat and prepare operator-driven migration payloads
    MigrationAudit {
        /// Path to blockchain.dat (defaults to ~/.zhtp/data/testnet/blockchain.dat)
        #[arg(long)]
        dat_file: Option<std::path::PathBuf>,

        /// Include hex-encoded wallet registration transactions for migratable ghost wallets
        #[arg(long)]
        include_tx_hex: bool,
    },
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

        /// Path to identity keystore directory (REQUIRED for production deploys)
        #[arg(short, long)]
        keystore: String,

        /// Fee to pay for deployment (in ZHTP tokens)
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

        /// Path to identity keystore directory (REQUIRED)
        #[arg(short, long)]
        keystore: String,

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

        /// Path to identity keystore directory (REQUIRED)
        #[arg(short, long)]
        keystore: String,

        /// Fee for update (in ZHTP tokens)
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

        /// Path to identity keystore directory (REQUIRED)
        #[arg(short, long)]
        keystore: String,

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

    /// Transfer domain to new owner
    Transfer {
        /// Domain name to transfer
        #[arg(short, long)]
        domain: String,

        /// New owner DID
        #[arg(short, long)]
        new_owner: String,

        /// Path to identity keystore directory (REQUIRED)
        #[arg(short, long)]
        keystore: String,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Release domain from use
    Release {
        /// Domain name to release
        #[arg(short, long)]
        domain: String,

        /// Path to identity keystore directory (REQUIRED)
        #[arg(short, long)]
        keystore: String,

        /// Force release without confirmation
        #[arg(short, long)]
        force: bool,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// Admin: migrate legacy domain records to the latest format
    Migrate {
        /// Path to identity keystore directory (REQUIRED)
        #[arg(short, long)]
        keystore: String,

        #[command(flatten)]
        trust: TrustFlags,
    },

    /// List all domains from the catalog
    Catalog {
        /// Output file (JSON). Stdout if not specified.
        #[arg(short, long)]
        output: Option<String>,

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

/// CBE token operation commands
#[derive(Args, Debug, Clone)]
pub struct CbeArgs {
    #[command(subcommand)]
    pub action: CbeAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CbeAction {
    /// Initialize CBE token: assign 4 pool wallets and distribute the full supply.
    /// One-time Bootstrap Council operation.
    InitPools {
        /// 32-byte hex key_id for the compensation (40%) pool wallet
        #[arg(long)]
        compensation: String,
        /// 32-byte hex key_id for the operational (30%) pool wallet
        #[arg(long)]
        operational: String,
        /// 32-byte hex key_id for the performance (20%) pool wallet
        #[arg(long)]
        performance: String,
        /// 32-byte hex key_id for the strategic (10%) pool wallet
        #[arg(long)]
        strategic: String,
        /// Current block height (used in the tx payload)
        #[arg(long, default_value = "0")]
        height: u64,
    },
    /// Create an on-chain employment contract
    CreateContract {
        /// 32-byte hex DAO ID
        #[arg(long)]
        dao_id: String,
        /// 32-byte hex key_id of the employee's wallet
        #[arg(long)]
        employee: String,
        /// Contract type: 0 = PublicAccess, 1 = Employment
        #[arg(long, default_value = "1")]
        contract_type: u8,
        /// Per-period compensation in CBE atomic units (18 decimals)
        #[arg(long)]
        compensation: u128,
        /// Payment period: 0 = Monthly, 1 = Quarterly, 2 = Annually
        #[arg(long, default_value = "0")]
        period: u8,
        /// Tax rate in basis points (0–5000)
        #[arg(long, default_value = "0")]
        tax_bp: u16,
        /// Tax jurisdiction (ISO country code, e.g. "US")
        #[arg(long, default_value = "")]
        jurisdiction: String,
        /// Profit share in basis points (0–2000)
        #[arg(long, default_value = "0")]
        profit_share_bp: u16,
    },
    /// Process a payroll period for an employment contract (synthetic curve event)
    Payroll {
        /// 32-byte hex employment contract ID
        #[arg(long)]
        contract_id: String,
        /// CBE amount the collaborator earns (X, in 18-decimal atoms)
        #[arg(long)]
        amount_cbe: u128,
        /// Collaborator wallet address (32-byte hex key_id)
        #[arg(long)]
        collaborator: String,
        /// Blake3 hash of the governance-approved deliverable (32-byte hex)
        #[arg(long)]
        deliverable_hash: String,
        /// Path to keystore directory (default: ~/.zhtp/keystore)
        #[arg(long)]
        keystore: Option<String>,
    },
    /// Transfer CBE tokens from your wallet to another
    ///
    /// Requires the sender to have sufficient vested CBE balance.
    /// Compensation pool (40%) has no vesting - immediately transferable.
    /// Other pools (operational, performance, strategic) have vesting schedules.
    Transfer {
        /// Recipient address (32-byte hex key_id or did:zhtp:...)
        #[arg(short, long)]
        to: String,
        /// Amount to transfer (in CBE atoms, 1 CBE = 100,000,000 atoms)
        #[arg(short, long)]
        amount: u64,
    },
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
        /// Treasury recipient DID or key (receives canonical 20% allocation)
        #[arg(long)]
        treasury_recipient: String,
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

/// Bonding curve operation commands
#[derive(Args, Debug, Clone)]
pub struct CurveArgs {
    #[command(subcommand)]
    pub action: CurveAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CurveAction {
    /// Deploy a new bonding curve token
    Deploy {
        /// Token name (e.g., "MyCurveToken")
        #[arg(short, long)]
        name: String,
        /// Token symbol (e.g., "MCT")
        #[arg(short, long)]
        symbol: String,
        /// Curve type: linear, exponential, sigmoid
        #[arg(short, long, default_value = "linear")]
        curve_type: String,
        /// Threshold: standard ($69K), low ($34.5K), high ($138K), or custom amount
        #[arg(short, long, default_value = "standard")]
        threshold: String,
        /// Enable selling (default: true)
        #[arg(long, default_value = "true")]
        sell_enabled: bool,
    },
    /// Buy tokens via bonding curve
    Buy {
        /// Token ID to buy
        #[arg(short, long)]
        token_id: String,
        /// Amount of stablecoins to spend
        #[arg(short, long)]
        stable_amount: u64,
        /// Minimum tokens to receive (slippage protection, optional)
        #[arg(long)]
        min_tokens_out: Option<u64>,
    },
    /// Sell tokens via bonding curve
    Sell {
        /// Token ID to sell
        #[arg(short, long)]
        token_id: String,
        /// Amount of tokens to sell
        #[arg(short, long)]
        token_amount: u64,
        /// Minimum stablecoins to receive (slippage protection, optional)
        #[arg(long)]
        min_stable_out: Option<u64>,
    },
    /// Get bonding curve information for a token
    Info {
        /// Token ID
        #[arg(short, long)]
        token_id: String,
    },
    /// Get current price for a token
    Price {
        /// Token ID
        #[arg(short, long)]
        token_id: String,
    },
    /// Check if token can graduate to AMM
    CanGraduate {
        /// Token ID
        #[arg(short, long)]
        token_id: String,
    },
    /// Graduate token to AMM (requires threshold to be met)
    Graduate {
        /// Token ID to graduate
        #[arg(short, long)]
        token_id: String,
        /// AMM Pool ID to create for the graduated token
        #[arg(short, long)]
        pool_id: String,
        /// SOV amount to seed into AMM pool
        #[arg(long, default_value = "1000000")]
        sov_seed: u64,
        /// Token amount to seed into AMM pool
        #[arg(long, default_value = "1000000")]
        token_seed: u64,
    },
    /// Get full valuation for a token
    Valuation {
        /// Token ID
        #[arg(short, long)]
        token_id: String,
    },
    /// List all bonding curve tokens
    List,
}

/// Genesis configuration and state migration commands (GENESIS-1, #1909)
#[derive(Args, Debug, Clone)]
pub struct GenesisArgs {
    #[command(subcommand)]
    pub command: GenesisCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GenesisCommand {
    /// Build block 0 from genesis.toml and output its hash
    Build {
        /// Path to genesis.toml (uses embedded config if omitted)
        #[arg(short, long)]
        config: Option<std::path::PathBuf>,
        /// Write the hash to this file (in addition to stdout)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// Export the full blockchain state from a .dat file to a JSON snapshot
    ExportState {
        /// Path to blockchain.dat (defaults to ~/.zhtp/data/testnet/blockchain.dat)
        #[arg(short, long)]
        dat_file: Option<std::path::PathBuf>,
        /// Output JSON snapshot file
        #[arg(short, long, default_value = "state-snapshot.json")]
        output: std::path::PathBuf,
    },
    /// Merge a state snapshot into genesis.toml for testnet migration
    MigrateState {
        /// Path to the state snapshot JSON produced by export-state
        #[arg(short, long)]
        snapshot: std::path::PathBuf,
        /// Base genesis.toml to merge into (uses embedded config if omitted)
        #[arg(short, long)]
        config: Option<std::path::PathBuf>,
        /// Output genesis.toml with allocations embedded
        #[arg(short, long, default_value = "genesis-with-state.toml")]
        output: std::path::PathBuf,
    },
}

/// Main CLI runner
pub async fn run_cli() -> Result<()> {
    // Initialize network genesis for replay protection
    // Uses testnet genesis hash from shared constant - CLI commands need this for network communication
    let _ = lib_identity::types::node_id::try_set_network_genesis(
        lib_identity::constants::TESTNET_GENESIS_HASH,
    );

    let cli = ZhtpCli::parse();

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    match &cli.command {
        ZhtpCommand::Node(args) => commands::node::handle_node_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Wallet(args) => commands::wallet::handle_wallet_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Dao(args) => commands::dao::handle_dao_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Oracle(args) => commands::oracle::handle_oracle_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Citizen(args) => commands::citizen::handle_citizen_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Ubi(args) => commands::ubi::handle_ubi_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Identity(args) => {
            commands::identity::handle_identity_command(args.clone(), &cli)
                .await
                .map_err(anyhow::Error::msg)
        }
        ZhtpCommand::Network(args) => commands::network::handle_network_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Blockchain(args) => {
            commands::blockchain::handle_blockchain_command(args.clone(), &cli)
                .await
                .map_err(anyhow::Error::msg)
        }
        ZhtpCommand::Monitor(args) => commands::monitor::handle_monitor_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Version(args) => commands::version::handle_version_command(args.clone())
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Completion(args) => {
            commands::completion::handle_completion_command(args.clone())
                .await
                .map_err(anyhow::Error::msg)
        }
        ZhtpCommand::Config(args) => commands::config::handle_config_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Diagnostics(args) => {
            commands::diagnostics::handle_diagnostics_command(args.clone(), &cli)
                .await
                .map_err(anyhow::Error::msg)
        }
        ZhtpCommand::Backup(args) => commands::backup::handle_backup_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Component(args) => {
            commands::component::handle_component_command(args.clone(), &cli)
                .await
                .map_err(anyhow::Error::msg)
        }
        ZhtpCommand::Interactive(args) => {
            commands::interactive::handle_interactive_command(args.clone(), &cli)
                .await
                .map_err(anyhow::Error::msg)
        }
        ZhtpCommand::Server(args) => commands::server::handle_server_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Reward(args) => commands::rewards::handle_reward_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Isolation(args) => {
            commands::isolation::handle_isolation_command(args.clone(), &cli)
                .await
                .map_err(anyhow::Error::msg)
        }
        ZhtpCommand::Deploy(args) => commands::deploy::handle_deploy_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Domain(args) => commands::domain::handle_domain_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Trust(args) => commands::trust::handle_trust_command(args.clone())
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Man(args) => commands::man::handle_man_command(args.clone())
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Update(args) => commands::update::handle_update_command(args.clone())
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Service(args) => commands::service::handle_service_command(args.clone())
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Token(args) => commands::token::handle_token_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Curve(args) => commands::curve::handle_curve_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Genesis(args) => commands::genesis::handle_genesis_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
        ZhtpCommand::Cbe(args) => commands::cbe::handle_cbe_command(args.clone(), &cli)
            .await
            .map_err(anyhow::Error::msg),
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
    println!(
        "
    ███████╗██╗  ██╗████████╗██████╗ 
    ╚══███╔╝██║  ██║╚══██╔══╝██╔══██╗
      ███╔╝ ███████║   ██║   ██████╔╝
     ███╔╝  ██╔══██║   ██║   ██╔═══╝ 
    ███████╗██║  ██║   ██║   ██║     
    ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     
    
    Zero-Knowledge Hypertext Transfer Protocol
    Orchestrator - Level 2 Components Manager
    "
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_oracle_committee_update_command() {
        let parsed = ZhtpCli::try_parse_from([
            "zhtp-cli",
            "oracle",
            "committee-update",
            "--members",
            "11aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,22bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--activate-epoch",
            "9",
            "--reason",
            "Rotate",
            "--voting-period-days",
            "7",
        ])
        .expect("oracle committee command should parse");

        match parsed.command {
            ZhtpCommand::Oracle(OracleArgs {
                action:
                    OracleAction::CommitteeUpdate {
                        members,
                        activate_epoch,
                        reason,
                        voting_period_days,
                        ..
                    },
            }) => {
                assert_eq!(members.len(), 2);
                assert_eq!(activate_epoch, 9);
                assert_eq!(reason, "Rotate");
                assert_eq!(voting_period_days, Some(7));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parse_oracle_config_update_command() {
        let parsed = ZhtpCli::try_parse_from([
            "zhtp-cli",
            "oracle",
            "config-update",
            "--epoch-duration",
            "600",
            "--max-source-age",
            "120",
            "--max-deviation-bps",
            "900",
            "--max-price-staleness-epochs",
            "10",
            "--activate-epoch",
            "9",
            "--reason",
            "Tune",
        ])
        .expect("oracle config command should parse");

        match parsed.command {
            ZhtpCommand::Oracle(OracleArgs {
                action:
                    OracleAction::ConfigUpdate {
                        epoch_duration,
                        max_source_age,
                        max_deviation_bps,
                        max_price_staleness_epochs,
                        activate_epoch,
                        reason,
                        ..
                    },
            }) => {
                assert_eq!(epoch_duration, 600);
                assert_eq!(max_source_age, 120);
                assert_eq!(max_deviation_bps, 900);
                assert_eq!(max_price_staleness_epochs, 10);
                assert_eq!(activate_epoch, 9);
                assert_eq!(reason, "Tune");
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parse_genesis_build_command() {
        let parsed = ZhtpCli::try_parse_from(["zhtp-cli", "genesis", "build"])
            .expect("genesis build should parse");
        match parsed.command {
            ZhtpCommand::Genesis(GenesisArgs {
                command: GenesisCommand::Build { config, output },
            }) => {
                assert!(config.is_none());
                assert!(output.is_none());
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parse_genesis_export_state_command() {
        let parsed = ZhtpCli::try_parse_from([
            "zhtp-cli",
            "genesis",
            "export-state",
            "--output",
            "snapshot.json",
        ])
        .expect("genesis export-state should parse");
        match parsed.command {
            ZhtpCommand::Genesis(GenesisArgs {
                command: GenesisCommand::ExportState { output, .. },
            }) => {
                assert_eq!(output.to_str().unwrap(), "snapshot.json");
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parse_genesis_migrate_state_command() {
        let parsed = ZhtpCli::try_parse_from([
            "zhtp-cli",
            "genesis",
            "migrate-state",
            "--snapshot",
            "state.json",
            "--output",
            "genesis-out.toml",
        ])
        .expect("genesis migrate-state should parse");
        match parsed.command {
            ZhtpCommand::Genesis(GenesisArgs {
                command:
                    GenesisCommand::MigrateState {
                        snapshot, output, ..
                    },
            }) => {
                assert_eq!(snapshot.to_str().unwrap(), "state.json");
                assert_eq!(output.to_str().unwrap(), "genesis-out.toml");
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parse_blockchain_migration_audit_command() {
        let parsed = ZhtpCli::try_parse_from([
            "zhtp-cli",
            "blockchain",
            "migration-audit",
            "--dat-file",
            "chain.dat",
        ])
        .expect("blockchain migration-audit should parse");
        match parsed.command {
            ZhtpCommand::Blockchain(BlockchainArgs {
                action:
                    BlockchainAction::MigrationAudit {
                        dat_file,
                        include_tx_hex,
                    },
            }) => {
                assert_eq!(dat_file.unwrap().to_str().unwrap(), "chain.dat");
                assert!(!include_tx_hex);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }
}
