//! DAO Wallet Demonstration
//! 
//! This demo shows the new NonProfit and ForProfit DAO wallet types
//! that require DIDs and provide full transaction transparency.

use anyhow::Result;
use lib_identity::wallets::{WalletManager, WalletType};
use lib_identity::wallets::wallet_types::{DaoGovernanceSettings, TransparencyLevel};
use lib_crypto::Hash;

#[tokio::main]
async fn main() -> Result<()> {
    println!("  DAO Wallet System Demo");
    println!("════════════════════════════");
    
    // Create DIDs for our demo
    let creator_did_1 = Hash([1u8; 32]); // Simulated DID
    let creator_did_2 = Hash([2u8; 32]); // Simulated DID
    let contributor_did = Hash([3u8; 32]); // Simulated DID
    
    // Create wallet manager with DID (required for DAO wallets)
    let mut manager = WalletManager::new(creator_did_1.clone());
    
    println!("\nCreating DAO Wallets (DID Required)...");
    
    // Try to create DAO wallets with a standalone manager (should fail)
    let mut standalone_manager = WalletManager::new_standalone();
    println!("\nAttempting to create DAO wallet without DID...");
    
    let governance_settings = DaoGovernanceSettings {
        min_signatures_required: 1,
        max_single_transaction: 10000, // 10K ZHTP max per transaction
        requires_governance_vote: false,
        voting_threshold_percent: 60,
    };
    
    match standalone_manager.create_dao_wallet(
        WalletType::NonProfitDAO,
        creator_did_1.clone(),
        "Invalid DAO".to_string(),
        "This should fail".to_string(),
        governance_settings.clone(),
        TransparencyLevel::Full,
    ).await {
        Ok(_) => println!(" This should not happen!"),
        Err(e) => println!("Correctly rejected: {}", e),
    }
    
    // Create NonProfit DAO wallet (creator cannot own it)
    println!("\n  Creating NonProfit DAO Wallet...");
    let nonprofit_dao = manager.create_dao_wallet(
        WalletType::NonProfitDAO,
        creator_did_1.clone(),
        "Community Education DAO".to_string(),
        "A nonprofit DAO focused on education and community development".to_string(),
        governance_settings.clone(),
        TransparencyLevel::Full,
    ).await?;
    
    println!("NonProfit DAO Created!");
    println!("   Wallet ID: {}", hex::encode(&nonprofit_dao.0));
    
    // Check ownership of nonprofit DAO
    let nonprofit_wallet = manager.get_wallet(&nonprofit_dao).unwrap();
    println!("   Owner: {}", if nonprofit_wallet.owner_id.is_some() { 
        "Has Owner (WRONG!)" 
    } else { 
        "No Owner (Correct for NonProfit)" 
    });
    
    // Create ForProfit DAO wallet (creator can own it)
    println!("\n Creating ForProfit DAO Wallet...");
    let forprofit_dao = manager.create_dao_wallet(
        WalletType::ForProfitDAO,
        creator_did_2.clone(),
        "Tech Innovation DAO".to_string(),
        "A for-profit DAO investing in technology startups".to_string(),
        DaoGovernanceSettings {
            min_signatures_required: 2,
            max_single_transaction: 50000, // 50K ZHTP max per transaction
            requires_governance_vote: true,
            voting_threshold_percent: 75,
        },
        TransparencyLevel::Partial,
    ).await?;
    
    println!("ForProfit DAO Created!");
    println!("   Wallet ID: {}", hex::encode(&forprofit_dao.0));
    
    // Check ownership of forprofit DAO
    let forprofit_wallet = manager.get_wallet(&forprofit_dao).unwrap();
    println!("   Owner: {}", if let Some(ref owner) = forprofit_wallet.owner_id { 
        format!("DID: {} (Correct for ForProfit)", hex::encode(&owner.0[..8]))
    } else { 
        "No Owner (WRONG for ForProfit)".to_string()
    });
    
    println!("\nTesting DAO Wallet Operations...");
    
    // Add funds to nonprofit DAO with public logging
    println!("\nAdding funds to NonProfit DAO...");
    manager.add_funds_to_dao_wallet(
        &nonprofit_dao,
        25000, // 25K ZHTP
        None, // No counterparty specified
        "Initial community funding from grants".to_string(),
        Some(creator_did_1.clone()),
        None,
    )?;
    
    // Add funds to forprofit DAO
    println!("Adding funds to ForProfit DAO...");
    manager.add_funds_to_dao_wallet(
        &forprofit_dao,
        100000, // 100K ZHTP
        None,
        "Initial investment capital".to_string(),
        Some(creator_did_2.clone()),
        None,
    )?;
    
    // Try to spend from nonprofit DAO (should work)
    println!("\n Spending from NonProfit DAO...");
    manager.remove_funds_from_dao_wallet(
        &nonprofit_dao,
        5000, // 5K ZHTP
        None,
        "Community education program funding".to_string(),
        Some(creator_did_1.clone()),
        None,
    )?;
    
    // Try to spend large amount from forprofit DAO (should fail due to governance rules)
    println!("\nAttempting large spend from ForProfit DAO...");
    match manager.remove_funds_from_dao_wallet(
        &forprofit_dao,
        60000, // 60K ZHTP (exceeds 50K limit)
        None,
        "Large investment (should fail)".to_string(),
        Some(creator_did_2.clone()),
        None,
    ) {
        Ok(_) => println!(" This should not happen!"),
        Err(e) => println!("Correctly blocked: {}", e),
    }
    
    // Add another controller to the forprofit DAO
    println!("\nAdding controller to ForProfit DAO...");
    manager.add_dao_controller(
        &forprofit_dao,
        contributor_did.clone(),
        creator_did_2.clone(),
    )?;
    
    println!("Added new controller to ForProfit DAO");
    
    // Show public transaction history
    println!("\nPUBLIC TRANSACTION HISTORY");
    println!("───────────────────────────────");
    
    println!("\n  NonProfit DAO Transactions (Full Transparency):");
    let nonprofit_txs = manager.get_dao_public_transactions(&nonprofit_dao)?;
    for (i, tx) in nonprofit_txs.iter().enumerate() {
        println!("  {}. {} {} ZHTP - {}", 
                i + 1,
                if tx.is_incoming { "Received" } else { "Sent" },
                tx.amount,
                tx.purpose
        );
        println!("     Hash: {}", hex::encode(&tx.tx_hash.0[..8]));
        println!("     Authorized by: {}", hex::encode(&tx.authorized_by.0[..8]));
        println!("     Time: {}", tx.timestamp);
    }
    
    println!("\n ForProfit DAO Transactions (Partial Transparency):");
    let forprofit_txs = manager.get_dao_public_transactions(&forprofit_dao)?;
    for (i, tx) in forprofit_txs.iter().enumerate() {
        println!("  {}. {} {} ZHTP - {}", 
                i + 1,
                if tx.is_incoming { "Received" } else { "Sent" },
                tx.amount,
                tx.purpose
        );
        println!("     Hash: {}", hex::encode(&tx.tx_hash.0[..8]));
        println!("     Counterparty: {}", if tx.counterparty_wallet.is_some() { "Disclosed" } else { "Private (Partial Transparency)" });
        println!("     Time: {}", tx.timestamp);
    }
    
    // Show wallet summary with DAO information
    println!("\nWALLET SUMMARY");
    println!("─────────────────");
    
    let wallets = manager.list_wallets();
    for (i, wallet) in wallets.iter().enumerate() {
        println!("\nWallet #{}", i + 1);
        println!("  Name: {}", wallet.name);
        println!("  Type: {:?}", wallet.wallet_type);
        println!("  Balance: {} ZHTP", wallet.balance);
        println!("  Is DAO: {}", if wallet.is_dao_wallet { "Yes" } else { "No" });
        if let Some(ref transparency) = wallet.dao_transparency {
            println!("  Transparency: {:?}", transparency);
        }
        println!("  Standalone: {}", if wallet.is_standalone { "Yes" } else { "No" });
    }
    
    // Show DAO-specific statistics
    let dao_wallets = manager.get_dao_wallets();
    println!("\nDAO STATISTICS");
    println!("─────────────────");
    println!("Total DAO Wallets: {}", dao_wallets.len());
    println!("NonProfit DAOs: {}", manager.get_dao_wallets_by_type(true).len());
    println!("ForProfit DAOs: {}", manager.get_dao_wallets_by_type(false).len());
    
    let total_dao_funds: u64 = dao_wallets.iter().map(|w| w.balance).sum();
    println!("Total DAO Funds: {} ZHTP", total_dao_funds);
    
    for dao_wallet in dao_wallets {
        if let Some(dao_props) = dao_wallet.get_dao_properties() {
            println!("\nDAO: {}", dao_wallet.name);
            println!("  Type: {}", if dao_props.is_nonprofit { "NonProfit" } else { "ForProfit" });
            println!("  Founded: {}", dao_props.founded_at);
            println!("  Total Received: {} ZHTP", dao_props.total_funds_received);
            println!("  Total Spent: {} ZHTP", dao_props.total_funds_spent);
            println!("  Transaction Count: {}", dao_props.transaction_count);
            println!("  Controllers: {}", dao_props.authorized_controllers.len());
            println!("  Transparency: {:?}", dao_props.transparency_level);
            println!("  Max Single Transaction: {} ZHTP", dao_props.governance_settings.max_single_transaction);
        }
    }
    
    println!("\nDAO Wallet Demo Completed!");
    println!("Key Features Demonstrated:");
    println!("  DID-required creation (cannot create 'out of thin air')");
    println!("    NonProfit DAOs have no owner (even creator cannot own)");
    println!("   ForProfit DAOs can be owned by creator");
    println!("  Full public transaction transparency");
    println!("    Governance rules enforce spending limits");
    println!("  Multi-controller authorization system");
    
    Ok(())
}
