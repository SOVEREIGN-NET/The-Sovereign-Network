//! Command Execution and Handling
//! 
//! Handles execution of ZHTP node commands and interactive operations

use anyhow::{Result, Context};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use zhtp::config::{CliArgs, NodeConfig};
use zhtp::runtime::RuntimeOrchestrator;
use tokio::sync::mpsc;
use tracing::{info, warn, error, debug};

/// Command execution context
#[derive(Debug, Clone)]
pub struct CommandContext {
    pub config: NodeConfig,
    pub runtime: Option<RuntimeOrchestrator>,
    pub interactive_mode: bool,
}

/// Available node commands
#[derive(Debug, Clone, PartialEq)]
pub enum NodeCommand {
    // Node lifecycle commands
    Start,
    Stop,
    Restart,
    Status,
    
    // Network commands
    ListPeers,
    ConnectPeer(String),
    DisconnectPeer(String),
    NetworkInfo,
    MeshStatus,
    
    // Identity commands
    ListIdentities,
    CreateIdentity(String),
    ExportIdentity(String),
    ImportIdentity(String, String),
    
    // Blockchain commands
    BlockchainInfo,
    GetBalance(Option<String>),
    SendTransaction(String, String, u64),
    ListTransactions,
    MineBlock,
    
    // Storage commands
    StorageInfo,
    StoreFile(String),
    RetrieveFile(String),
    ListFiles,
    
    // Economics commands
    UbiInfo,
    ClaimUbi,
    DaoInfo,
    VoteProposal(u64, bool),
    CreateProposal(String, String),
    
    // System commands
    Help(Option<String>),
    Version,
    Config,
    Logs(Option<String>),
    Metrics,
    Exit,
}

/// Execute a single command
pub async fn execute_command(
    command: NodeCommand,
    context: &mut CommandContext,
) -> Result<String> {
    match command {
        NodeCommand::Start => execute_start(context).await,
        NodeCommand::Stop => execute_stop(context).await,
        NodeCommand::Restart => execute_restart(context).await,
        NodeCommand::Status => execute_status(context).await,
        
        NodeCommand::ListPeers => execute_list_peers(context).await,
        NodeCommand::ConnectPeer(addr) => execute_connect_peer(context, &addr).await,
        NodeCommand::DisconnectPeer(addr) => execute_disconnect_peer(context, &addr).await,
        NodeCommand::NetworkInfo => execute_network_info(context).await,
        NodeCommand::MeshStatus => execute_mesh_status(context).await,
        
        NodeCommand::ListIdentities => execute_list_identities(context).await,
        NodeCommand::CreateIdentity(name) => execute_create_identity(context, &name).await,
        NodeCommand::ExportIdentity(id) => execute_export_identity(context, &id).await,
        NodeCommand::ImportIdentity(file, password) => execute_import_identity(context, &file, &password).await,
        
        NodeCommand::BlockchainInfo => execute_blockchain_info(context).await,
        NodeCommand::GetBalance(addr) => execute_get_balance(context, addr.as_deref()).await,
        NodeCommand::SendTransaction(to, amount, fee) => execute_send_transaction(context, &to, &amount, fee).await,
        NodeCommand::ListTransactions => execute_list_transactions(context).await,
        NodeCommand::MineBlock => execute_mine_block(context).await,
        
        NodeCommand::StorageInfo => execute_storage_info(context).await,
        NodeCommand::StoreFile(path) => execute_store_file(context, &path).await,
        NodeCommand::RetrieveFile(hash) => execute_retrieve_file(context, &hash).await,
        NodeCommand::ListFiles => execute_list_files(context).await,
        
        NodeCommand::UbiInfo => execute_ubi_info(context).await,
        NodeCommand::ClaimUbi => execute_claim_ubi(context).await,
        NodeCommand::DaoInfo => execute_dao_info(context).await,
        NodeCommand::VoteProposal(id, vote) => execute_vote_proposal(context, id, vote).await,
        NodeCommand::CreateProposal(title, desc) => execute_create_proposal(context, &title, &desc).await,
        
        NodeCommand::Help(topic) => execute_help(topic.as_deref()).await,
        NodeCommand::Version => execute_version().await,
        NodeCommand::Config => execute_config(context).await,
        NodeCommand::Logs(level) => execute_logs(context, level.as_deref()).await,
        NodeCommand::Metrics => execute_metrics(context).await,
        NodeCommand::Exit => execute_exit().await,
    }
}

// Node lifecycle commands
async fn execute_start(context: &mut CommandContext) -> Result<String> {
    if context.runtime.is_some() {
        return Ok("Node is already running".to_string());
    }

    info!(" Starting ZHTP node...");
    
    // Create runtime orchestrator
    let runtime = RuntimeOrchestrator::new(context.config.clone()).await
        .context("Failed to create runtime orchestrator")?;
    
    // Start all components
    runtime.start_all_components().await
        .context("Failed to start node components")?;
    
    context.runtime = Some(runtime);
    
    Ok("ZHTP node started successfully".to_string())
}

async fn execute_stop(context: &mut CommandContext) -> Result<String> {
    if let Some(runtime) = context.runtime.take() {
        info!("Stopping ZHTP node...");
        runtime.shutdown_all_components().await
            .context("Failed to shutdown node components")?;
        Ok("ZHTP node stopped successfully".to_string())
    } else {
        Ok("Node is not running".to_string())
    }
}

async fn execute_restart(context: &mut CommandContext) -> Result<String> {
    if context.runtime.is_some() {
        execute_stop(context).await?;
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }
    execute_start(context).await
}

async fn execute_status(context: &CommandContext) -> Result<String> {
    if let Some(runtime) = &context.runtime {
        let status = runtime.get_component_status().await?;
        let mut result = String::from("ZHTP Node Status:\n");
        
        for (component, is_running) in status {
            let status_icon = if is_running { "" } else { "" };
            result.push_str(&format!("  {} {}\n", status_icon, component));
        }
        
        Ok(result)
    } else {
        Ok("Node is not running".to_string())
    }
}

// Network commands
async fn execute_list_peers(context: &CommandContext) -> Result<String> {
    if let Some(runtime) = &context.runtime {
        let peers = runtime.get_connected_peers().await?;
        if peers.is_empty() {
            Ok("No peers connected".to_string())
        } else {
            let mut result = format!("Connected peers ({}):\n", peers.len());
            for peer in peers {
                result.push_str(&format!("  • {}\n", peer));
            }
            Ok(result)
        }
    } else {
        Ok("Node is not running".to_string())
    }
}

async fn execute_connect_peer(context: &CommandContext, addr: &str) -> Result<String> {
    if let Some(runtime) = &context.runtime {
        runtime.connect_to_peer(addr).await
            .context("Failed to connect to peer")?;
        Ok(format!("Connected to peer: {}", addr))
    } else {
        Ok("Node is not running".to_string())
    }
}

async fn execute_disconnect_peer(context: &CommandContext, addr: &str) -> Result<String> {
    if let Some(runtime) = &context.runtime {
        runtime.disconnect_from_peer(addr).await
            .context("Failed to disconnect from peer")?;
        Ok(format!("Disconnected from peer: {}", addr))
    } else {
        Ok("Node is not running".to_string())
    }
}

async fn execute_network_info(context: &CommandContext) -> Result<String> {
    use lib_network::{get_network_statistics, get_mesh_status};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    let mut info = String::from("Network Information:\n");
    
    match get_network_statistics().await {
        Ok(stats) => {
            info.push_str(&format!("Statistics:\n"));
            info.push_str(&format!("  • Active Peers: {}\n", stats.active_peers));
            info.push_str(&format!("  • Messages Sent: {}\n", stats.messages_sent));
            info.push_str(&format!("  • Messages Received: {}\n", stats.messages_received));
            info.push_str(&format!("  • Bandwidth Usage: {:.2} MB/s\n", stats.bandwidth_usage as f64 / 1_000_000.0));
            info.push_str(&format!("  • Connection Quality: {:.1}%\n", stats.connection_quality * 100.0));
        },
        Err(e) => info.push_str(&format!("Failed to get network statistics: {}\n", e)),
    }
    
    match get_mesh_status().await {
        Ok(mesh_status) => {
            info.push_str(&format!("\nMesh Status:\n"));
            info.push_str(&format!("  • Status: {}\n", if mesh_status.is_connected { "Connected " } else { "Disconnected " }));
            info.push_str(&format!("  • Mesh Nodes: {}\n", mesh_status.mesh_size));
            info.push_str(&format!("  • Routing Efficiency: {:.1}%\n", mesh_status.routing_efficiency * 100.0));
            info.push_str(&format!("  • : {}\n", if mesh_status.isp_bypass_active { "Active " } else { "Inactive " }));
        },
        Err(e) => info.push_str(&format!("Failed to get mesh status: {}\n", e)),
    }
    
    Ok(info)
}

async fn execute_mesh_status(context: &CommandContext) -> Result<String> {
    use lib_network::{get_mesh_status, get_active_peer_count};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    match get_mesh_status().await {
        Ok(status) => {
            let peer_count = get_active_peer_count().await.unwrap_or(0);
            
            let mut result = String::from("Mesh Network Status:\n");
            result.push_str(&format!("Connection: {}\n", if status.is_connected { "Connected " } else { "Disconnected " }));
            result.push_str(&format!("Peer Count: {}\n", peer_count));
            result.push_str(&format!("Mesh Size: {}\n", status.mesh_size));
            result.push_str(&format!(" Routing Efficiency: {:.1}%\n", status.routing_efficiency * 100.0));
            result.push_str(&format!(" : {}\n", if status.isp_bypass_active { "Active " } else { "Inactive " }));
            result.push_str(&format!("Signal Strength: {:.1}%\n", status.signal_strength * 100.0));
            result.push_str(&format!(" Data Throughput: {:.2} MB/s\n", status.throughput as f64 / 1_000_000.0));
            
            Ok(result)
        },
        Err(e) => Ok(format!("Failed to get mesh status: {}", e))
    }
}

// Identity commands
async fn execute_list_identities(context: &CommandContext) -> Result<String> {
    use lib_identity::{initialize_identity_system};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    match initialize_identity_system().await {
        Ok(manager) => {
            match manager.list_all_identities().await {
                Ok(identities) => {
                    if identities.is_empty() {
                        Ok("No identities found".to_string())
                    } else {
                        let mut result = format!("Found {} identities:\n", identities.len());
                        for identity in identities {
                            result.push_str(&format!("  • {} ({}) - {}\n", 
                                identity.name, 
                                identity.email,
                                if identity.is_active { "Active" } else { "Inactive" }
                            ));
                        }
                        Ok(result)
                    }
                },
                Err(e) => Ok(format!("Failed to list identities: {}", e))
            }
        },
        Err(e) => Ok(format!("Failed to initialize identity system: {}", e))
    }
}

async fn execute_create_identity(context: &CommandContext, name: &str) -> Result<String> {
    use lib_identity::{initialize_identity_system, create_citizen_identity};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    let email = format!("{}@zhtp.local", name.to_lowercase().replace(" ", "."));
    
    match initialize_identity_system().await {
        Ok(_manager) => {
            match create_citizen_identity(name.to_string(), email.clone()).await {
                Ok(identity) => {
                    Ok(format!("Identity created successfully!\nID: {}\nName: {}\n📧 Email: {}\nStatus: Active", 
                        identity.identity_id, identity.name, identity.email))
                },
                Err(e) => Ok(format!("Failed to create identity: {}", e))
            }
        },
        Err(e) => Ok(format!("Failed to initialize identity system: {}", e))
    }
}

async fn execute_export_identity(context: &CommandContext, id: &str) -> Result<String> {
    use lib_identity::{initialize_identity_system};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    match initialize_identity_system().await {
        Ok(manager) => {
            match manager.export_identity(id).await {
                Ok(exported_data) => {
                    let filename = format!("identity_{}.json", id);
                    // Save exported identity data to filesystem
                    match std::fs::write(&filename, exported_data) {
                        Ok(()) => Ok(format!("Identity '{}' exported to {}", id, filename)),
                        Err(e) => Ok(format!("Failed to save identity file: {}", e)),
                    }
                },
                Err(e) => Ok(format!("Failed to export identity: {}", e))
            }
        },
        Err(e) => Ok(format!("Failed to initialize identity system: {}", e))
    }
}

async fn execute_import_identity(context: &CommandContext, file: &str, _password: &str) -> Result<String> {
    use lib_identity::{initialize_identity_system};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    match initialize_identity_system().await {
        Ok(mut manager) => {
            // Read identity file and import
            match std::fs::read_to_string(file) {
                Ok(identity_data) => {
                    match manager.import_identity(&identity_data).await {
                        Ok(identity_id) => {
                            Ok(format!("Successfully imported identity from '{}' with ID: {}", file, identity_id))
                        },
                        Err(e) => Ok(format!("Failed to import identity: {}", e)),
                    }
                },
                Err(e) => Ok(format!("Failed to read identity file '{}': {}", file, e)),
            }
        },
        Err(e) => Ok(format!("Failed to initialize identity system: {}", e))
    }
}

// Blockchain commands
async fn execute_blockchain_info(context: &CommandContext) -> Result<String> {
    use lib_blockchain::{get_blockchain_health, get_current_block_height};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    match get_blockchain_health().await {
        Ok(health) => {
            match get_current_block_height().await {
                Ok(height) => {
                    let mut info = format!("Blockchain Information:\n");
                    info.push_str(&format!("Health Status: {}\n", if health.is_healthy { "Healthy " } else { "Unhealthy " }));
                    info.push_str(&format!("Current Block Height: {}\n", height));
                    info.push_str(&format!(" Active Validators: {}\n", health.active_validators));
                    info.push_str(&format!(" Network Hashrate: {:.2} TH/s\n", health.network_hashrate / 1_000_000_000_000.0));
                    info.push_str(&format!("Average Block Time: {:.1}s\n", health.average_block_time));
                    Ok(info)
                },
                Err(e) => Ok(format!("Failed to get block height: {}", e))
            }
        },
        Err(e) => Ok(format!("Failed to get blockchain health: {}", e))
    }
}

#[derive(Debug, Deserialize)]
struct PersistedWalletData {
    wallet_address: String,
}

fn resolve_keystore_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("ZHTP_KEYSTORE") {
        if !path.trim().is_empty() {
            return Ok(PathBuf::from(path));
        }
    }

    let home = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    Ok(home.join(".zhtp").join("keystore"))
}

fn load_wallet_address_from_keystore() -> Result<String> {
    let keystore_path = resolve_keystore_path()?;
    let wallet_path = keystore_path.join(zhtp::keystore_names::WALLET_DATA_FILENAME);
    let data = std::fs::read_to_string(&wallet_path)
        .with_context(|| format!("Failed to read wallet data from {:?}", wallet_path))?;
    let wallet_data: PersistedWalletData = serde_json::from_str(&data)
        .with_context(|| format!("Failed to parse wallet data from {:?}", wallet_path))?;
    if wallet_data.wallet_address.is_empty() {
        return Err(anyhow::anyhow!("Wallet address missing from wallet data"));
    }
    Ok(wallet_data.wallet_address)
}

async fn execute_get_balance(context: &CommandContext, addr: Option<&str>) -> Result<String> {
    use lib_blockchain::{get_account_balance};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    // Use provided address or get current identity address
    let address = match addr {
        Some(addr) => addr.to_string(),
        None => {
            load_wallet_address_from_keystore()?
        }
    };
    
    match get_account_balance(&address).await {
        Ok(balance) => {
            Ok(format!("Balance for {}: {:.6} SOV", address, balance))
        },
        Err(e) => Ok(format!("Failed to get balance: {}", e))
    }
}

async fn execute_send_transaction(context: &CommandContext, to: &str, amount: &str, fee: u64) -> Result<String> {
    use lib_blockchain::{send_transaction};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    let amount_value: f64 = amount.parse()
        .map_err(|_| anyhow::anyhow!("Invalid amount format"))?;
    
    match send_transaction(to, amount_value, fee).await {
        Ok(tx_hash) => {
            Ok(format!("Transaction sent successfully!\n Amount: {} SOV\n To: {}\nFee: {} SOV\nTX Hash: {}", 
                amount_value, to, fee, tx_hash))
        },
        Err(e) => Ok(format!("Failed to send transaction: {}", e))
    }
}

async fn execute_list_transactions(context: &CommandContext) -> Result<String> {
    use lib_blockchain::{get_transaction_history};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    let address = load_wallet_address_from_keystore()?;
    
    match get_transaction_history(address).await {
        Ok(transactions) => {
            if transactions.is_empty() {
                Ok("No transactions found".to_string())
            } else {
                let mut result = format!("Transaction History ({} transactions):\n", transactions.len());
                for (i, tx) in transactions.iter().enumerate().take(10) {
                    result.push_str(&format!("{}. {} {} SOV to {} ({})\n", 
                        i + 1, 
                        if tx.from == address { "Sent" } else { "Received" },
                        tx.amount,
                        if tx.from == address { &tx.to } else { &tx.from },
                        tx.timestamp
                    ));
                }
                Ok(result)
            }
        },
        Err(e) => Ok(format!("Failed to get transaction history: {}", e))
    }
}

async fn execute_mine_block(context: &CommandContext) -> Result<String> {
    use lib_blockchain::{mine_block};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    match mine_block().await {
        Ok(block_hash) => {
            Ok(format!("⛏️ Block mined successfully!\nBlock Hash: {}", block_hash))
        },
        Err(e) => Ok(format!("Failed to mine block: {}", e))
    }
}

// Storage commands
async fn execute_storage_info(context: &CommandContext) -> Result<String> {
    use lib_storage::{UnifiedStorageSystem};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    let storage = UnifiedStorageSystem::new().await
        .context("Failed to initialize storage")?;
    
    match storage.get_storage_stats().await {
        Ok(stats) => {
            let mut info = format!(" Storage System Information:\n");
            info.push_str(&format!("Total Storage: {:.2} GB\n", stats.total_storage as f64 / 1_000_000_000.0));
            info.push_str(&format!(" Used Storage: {:.2} GB\n", stats.used_storage as f64 / 1_000_000_000.0));
            info.push_str(&format!("📁 Total Files: {}\n", stats.file_count));
            info.push_str(&format!("DHT Nodes: {}\n", stats.dht_nodes));
            info.push_str(&format!("Total Earnings: {:.6} SOV\n", stats.total_earnings));
            Ok(info)
        },
        Err(e) => Ok(format!("Failed to get storage stats: {}", e))
    }
}

async fn execute_store_file(context: &CommandContext, path: &str) -> Result<String> {
    use lib_storage::{UnifiedStorageSystem};
    use std::fs;
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    // Read file content
    let content = fs::read(path)
        .context("Failed to read file")?;
    
    let storage = UnifiedStorageSystem::new().await
        .context("Failed to initialize storage")?;
    
    match storage.upload_content(content, None).await {
        Ok(content_hash) => {
            Ok(format!("File stored successfully!\n📁 Path: {}\nContent Hash: {}\n Size: {} bytes", 
                path, content_hash, fs::metadata(path).map(|m| m.len()).unwrap_or(0)))
        },
        Err(e) => Ok(format!("Failed to store file: {}", e))
    }
}

async fn execute_retrieve_file(context: &CommandContext, hash: &str) -> Result<String> {
    use lib_storage::{UnifiedStorageSystem};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    let storage = UnifiedStorageSystem::new().await
        .context("Failed to initialize storage")?;
    
    match storage.download_content(hash).await {
        Ok(content) => {
            let filename = format!("retrieved_{}.dat", &hash[..8]);
            match std::fs::write(&filename, content) {
                Ok(_) => Ok(format!("File retrieved successfully!\nHash: {}\n📁 Saved as: {}", hash, filename)),
                Err(e) => Ok(format!("File retrieved but failed to save: {}", e))
            }
        },
        Err(e) => Ok(format!("Failed to retrieve file: {}", e))
    }
}

async fn execute_list_files(context: &CommandContext) -> Result<String> {
    use lib_storage::{UnifiedStorageSystem};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    let storage = UnifiedStorageSystem::new().await
        .context("Failed to initialize storage")?;
    
    match storage.list_user_content().await {
        Ok(files) => {
            if files.is_empty() {
                Ok("📁 No files stored".to_string())
            } else {
                let mut result = format!("📁 Stored Files ({}):\n", files.len());
                for file in files.iter().take(20) {
                    result.push_str(&format!("  • {} ({:.2} KB) - {}\n", 
                        &file.hash[..16], 
                        file.size as f64 / 1024.0,
                        file.timestamp
                    ));
                }
                Ok(result)
            }
        },
        Err(e) => Ok(format!("Failed to list files: {}", e))
    }
}

// Economics commands
async fn execute_ubi_info(context: &CommandContext) -> Result<String> {
    use lib_economy::{EconomicsEngine, get_ubi_status};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    let economics = EconomicsEngine::new().await
        .context("Failed to initialize economics")?;
    
    match get_ubi_status("current_user").await {
        Ok(ubi_status) => {
            let mut info = format!("Universal Basic Income Information:\n");
            info.push_str(&format!("UBI Status: {}\n", if ubi_status.is_eligible { "Eligible " } else { "Not Eligible " }));
            info.push_str(&format!("💵 Available UBI: {:.6} SOV\n", ubi_status.available_amount));
            info.push_str(&format!("⏰ Next Payment: {}\n", ubi_status.next_payment_time));
            info.push_str(&format!(" Monthly Rate: {:.6} SOV\n", ubi_status.monthly_rate));
            info.push_str(&format!("Participation Score: {:.1}%\n", ubi_status.participation_score * 100.0));
            Ok(info)
        },
        Err(e) => Ok(format!("Failed to get UBI status: {}", e))
    }
}

async fn execute_claim_ubi(context: &CommandContext) -> Result<String> {
    use lib_economy::{claim_ubi_payment};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    match claim_ubi_payment("current_user").await {
        Ok(claim_result) => {
            if claim_result.success {
                Ok(format!("UBI claimed successfully!\nAmount: {:.6} SOV\nTransaction: {}", 
                    claim_result.amount, claim_result.transaction_hash))
            } else {
                Ok(format!("UBI claim failed: {}", claim_result.reason))
            }
        },
        Err(e) => Ok(format!("Failed to claim UBI: {}", e))
    }
}

async fn execute_dao_info(context: &CommandContext) -> Result<String> {
    use lib_economy::{get_dao_status};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    match get_dao_status().await {
        Ok(dao_status) => {
            let mut info = format!(" DAO Governance Information:\n");
            info.push_str(&format!("Treasury Balance: {:.2} SOV\n", dao_status.treasury_balance));
            info.push_str(&format!(" Active Proposals: {}\n", dao_status.active_proposals));
            info.push_str(&format!("Total Voters: {}\n", dao_status.total_voters));
            info.push_str(&format!("Participation Rate: {:.1}%\n", dao_status.participation_rate * 100.0));
            info.push_str(&format!(" Daily UBI Distribution: {:.2} SOV\n", dao_status.daily_ubi_distribution));
            Ok(info)
        },
        Err(e) => Ok(format!("Failed to get DAO status: {}", e))
    }
}

async fn execute_vote_proposal(context: &CommandContext, id: u64, vote: bool) -> Result<String> {
    use lib_economy::{vote_on_proposal};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    match vote_on_proposal("current_user", id, vote).await {
        Ok(vote_result) => {
            if vote_result.success {
                let vote_str = if vote { "YES" } else { "NO" };
                Ok(format!("Vote cast successfully!\n Proposal ID: {}\n👍 Vote: {}\nTransaction: {}", 
                    id, vote_str, vote_result.transaction_hash))
            } else {
                Ok(format!("Vote failed: {}", vote_result.reason))
            }
        },
        Err(e) => Ok(format!("Failed to vote on proposal: {}", e))
    }
}

async fn execute_create_proposal(context: &CommandContext, title: &str, desc: &str) -> Result<String> {
    use lib_economy::{create_dao_proposal};
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    match create_dao_proposal("current_user", title, desc).await {
        Ok(proposal_result) => {
            if proposal_result.success {
                Ok(format!("Proposal created successfully!\n Proposal ID: {}\nTitle: {}\nTransaction: {}", 
                    proposal_result.proposal_id, title, proposal_result.transaction_hash))
            } else {
                Ok(format!("Proposal creation failed: {}", proposal_result.reason))
            }
        },
        Err(e) => Ok(format!("Failed to create proposal: {}", e))
    }
}

// System commands
async fn execute_help(topic: Option<&str>) -> Result<String> {
    match topic {
        Some("commands") => Ok(include_str!("../../../docs/commands.md").to_string()),
        Some("mesh") => Ok("Mesh networking help - see documentation".to_string()),
        Some("ubi") => Ok("UBI system help - see documentation".to_string()),
        Some(topic) => Ok(format!("❓ Help topic '{}' not found", topic)),
        None => Ok(r#"
 ZHTP Network Node - Command Help

Node Control:
  start              Start the ZHTP node
  stop               Stop the ZHTP node  
  restart            Restart the ZHTP node
  status             Show node component status

Network:
  peers              List connected peers
  connect <addr>     Connect to a peer
  disconnect <addr>  Disconnect from a peer
  network            Show network information
  mesh               Show mesh network status

Identity:
  identities         List all identities
  create-id <name>   Create new identity
  export-id <id>     Export identity
  import-id <file>   Import identity

Blockchain:
  blockchain         Show blockchain info
  balance [addr]     Show balance (defaults to keystore identity)
  send <to> <amt>    Send transaction
  transactions       List transactions (keystore identity)
  mine               Mine a block

Storage:
  storage            Show storage info
  store <file>       Store a file
  retrieve <hash>    Retrieve a file
  files              List stored files

Economics:
  ubi                Show UBI information
  claim-ubi          Claim UBI payment
  dao                Show DAO information
  vote <id> <y/n>    Vote on proposal
  propose <title>    Create proposal

System:
  help [topic]       Show this help
  version            Show version
  config             Show configuration
  logs [level]       Show logs
  metrics            Show metrics
  exit               Exit interactive mode

For detailed help: help <topic>
"#.to_string()),
    }
}

async fn execute_version() -> Result<String> {
    Ok(format!(r#"
 ZHTP Network Node v{}

Internet Replacement System
• Complete  through mesh networking
• Zero-knowledge privacy for all communications
• Universal Basic Income through network participation
• Post-quantum cryptographic security
• Decentralized governance through DAO integration

Built with Rust 🦀 | Powered by Zero-Knowledge 
"#, env!("CARGO_PKG_VERSION")))
}

async fn execute_config(context: &CommandContext) -> Result<String> {
    Ok(format!(" Current Configuration:\n{:#?}", context.config))
}

async fn execute_logs(_context: &CommandContext, level: Option<&str>) -> Result<String> {
    match level {
        Some(level) => Ok(format!("Setting log level to '{}' - coming soon...", level)),
        None => Ok("Log viewing coming soon...".to_string()),
    }
}

async fn execute_metrics(context: &CommandContext) -> Result<String> {
    use lib_network::get_network_statistics;
    use lib_blockchain::get_blockchain_health;
    use lib_storage::UnifiedStorageSystem;
    use lib_economy::get_dao_status;
    
    if context.runtime.is_none() {
        return Ok("Node is not running".to_string());
    }
    
    let mut metrics = String::from("ZHTP Node Metrics:\n\n");
    
    // Network metrics
    match get_network_statistics().await {
        Ok(net_stats) => {
            metrics.push_str("Network:\n");
            metrics.push_str(&format!("  • Active Peers: {}\n", net_stats.active_peers));
            metrics.push_str(&format!("  • Messages Sent: {}\n", net_stats.messages_sent));
            metrics.push_str(&format!("  • Messages Received: {}\n", net_stats.messages_received));
            metrics.push_str(&format!("  • Bandwidth: {:.2} MB/s\n", net_stats.bandwidth_usage as f64 / 1_000_000.0));
        },
        Err(_) => metrics.push_str("Network: Unavailable\n"),
    }
    
    // Blockchain metrics  
    match get_blockchain_health().await {
        Ok(bc_health) => {
            metrics.push_str("\nBlockchain:\n");
            metrics.push_str(&format!("  • Health: {}\n", if bc_health.is_healthy { "Healthy" } else { "Unhealthy" }));
            metrics.push_str(&format!("  • Validators: {}\n", bc_health.active_validators));
            metrics.push_str(&format!("  • Hashrate: {:.2} TH/s\n", bc_health.network_hashrate as f64 / 1e12));
            metrics.push_str(&format!("  • Avg Block Time: {:.1}s\n", bc_health.average_block_time));
        },
        Err(_) => metrics.push_str("\nBlockchain: Unavailable\n"),
    }
    
    // Storage metrics
    match UnifiedStorageSystem::new().await {
        Ok(storage) => {
            match storage.get_storage_stats().await {
                Ok(storage_stats) => {
                    metrics.push_str("\n Storage:\n");
                    metrics.push_str(&format!("  • Files: {}\n", storage_stats.file_count));
                    metrics.push_str(&format!("  • Used Space: {:.2} GB\n", storage_stats.used_storage as f64 / 1e9));
                    metrics.push_str(&format!("  • DHT Nodes: {}\n", storage_stats.dht_nodes));
                    metrics.push_str(&format!("  • Earnings: {:.6} SOV\n", storage_stats.total_earnings));
                },
                Err(_) => metrics.push_str("\n Storage: Stats unavailable\n"),
            }
        },
        Err(_) => metrics.push_str("\n Storage: Unavailable\n"),
    }
    
    // Economics metrics
    match get_dao_status().await {
        Ok(dao_status) => {
            metrics.push_str("\nEconomics:\n");
            metrics.push_str(&format!("  • Treasury: {:.2} SOV\n", dao_status.treasury_balance));
            metrics.push_str(&format!("  • Active Proposals: {}\n", dao_status.active_proposals));
            metrics.push_str(&format!("  • Daily UBI: {:.2} SOV\n", dao_status.daily_ubi_distribution));
            metrics.push_str(&format!("  • Participation: {:.1}%\n", dao_status.participation_rate * 100.0));
        },
        Err(_) => metrics.push_str("\nEconomics: Unavailable\n"),
    }
    
    Ok(metrics)
}

async fn execute_exit() -> Result<String> {
    Ok(" Goodbye! ZHTP node shutting down...".to_string())
}

/// Parse a command string into a NodeCommand
pub fn parse_command(input: &str) -> Result<NodeCommand> {
    let parts: Vec<&str> = input.trim().split_whitespace().collect();
    if parts.is_empty() {
        return Err(anyhow::anyhow!("Empty command"));
    }

    match parts[0] {
        "start" => Ok(NodeCommand::Start),
        "stop" => Ok(NodeCommand::Stop),
        "restart" => Ok(NodeCommand::Restart),
        "status" => Ok(NodeCommand::Status),
        
        "peers" => Ok(NodeCommand::ListPeers),
        "connect" => {
            if parts.len() < 2 {
                return Err(anyhow::anyhow!("Usage: connect <peer_address>"));
            }
            Ok(NodeCommand::ConnectPeer(parts[1].to_string()))
        },
        "disconnect" => {
            if parts.len() < 2 {
                return Err(anyhow::anyhow!("Usage: disconnect <peer_address>"));
            }
            Ok(NodeCommand::DisconnectPeer(parts[1].to_string()))
        },
        "network" => Ok(NodeCommand::NetworkInfo),
        "mesh" => Ok(NodeCommand::MeshStatus),
        
        "identities" => Ok(NodeCommand::ListIdentities),
        "create-id" => {
            if parts.len() < 2 {
                return Err(anyhow::anyhow!("Usage: create-id <name>"));
            }
            Ok(NodeCommand::CreateIdentity(parts[1].to_string()))
        },
        
        "help" => Ok(NodeCommand::Help(parts.get(1).map(|s| s.to_string()))),
        "version" => Ok(NodeCommand::Version),
        "config" => Ok(NodeCommand::Config),
        "exit" | "quit" | "q" => Ok(NodeCommand::Exit),
        
        _ => Err(anyhow::anyhow!("Unknown command: {}. Type 'help' for available commands.", parts[0])),
    }
}
