//! Simple Wallet Demo - Shows complete wallet information
//! 
//! This is a shorter demo to ensure all output is visible

use lib_identity::{
    create_standalone_wallet, create_multi_wallet_system,
    WalletType
};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🏦 Simple Quantum Wallet Demo");
    println!("═══════════════════════════════");
    println!();

    // Create one standalone wallet
    println!("Creating standalone wallet...");
    let (wallet_id, seed_phrase) = create_standalone_wallet(
        "Test Wallet".to_string(),
        Some("test".to_string()),
    ).await?;
    
    println!("Wallet created successfully!");
    println!("   Wallet ID: {}", hex::encode(&wallet_id.0));
    println!("   Seed Words: {}", seed_phrase.words.len());
    println!("   Language: {}", seed_phrase.language);
    println!();
    
    // Show the actual seed phrase words
    println!("SEED PHRASE WORDS:");
    for (i, word) in seed_phrase.words.iter().enumerate() {
        println!("   {:2}. {}", i + 1, word);
    }
    println!();

    // Create multi-wallet system
    println!("Creating multi-wallet system...");
    let mut wallet_system = create_multi_wallet_system().await?;
    
    // Create 2 wallets
    let primary = wallet_system.create_wallet_with_seed_phrase(
        WalletType::Primary,
        "Primary Wallet".to_string(),
        Some("main".to_string()),
    ).await?;
    
    let savings = wallet_system.create_wallet_with_seed_phrase(
        WalletType::Savings,
        "Savings Wallet".to_string(),
        Some("save".to_string()),
    ).await?;
    
    println!("Multi-wallet system created:");
    println!("   Primary: {}", hex::encode(&primary.0.0));
    println!("   Savings: {}", hex::encode(&savings.0.0));
    println!();

    // Show complete wallet summaries
    println!("COMPLETE WALLET INFORMATION:");
    println!("──────────────────────────────────");
    let summaries = wallet_system.list_wallets();
    for (i, summary) in summaries.iter().enumerate() {
        println!("Wallet #{}", i + 1);
        println!("  Name: {}", summary.name);
        println!("  ID: {}", hex::encode(&summary.id.0)); // Complete wallet ID
        println!("  Type: {:?}", summary.wallet_type);
        println!("  Balance: {} ZHTP", summary.balance);
        println!("  Created: {}", summary.created_at);
        println!("  Active: {}", summary.is_active);
        println!("  Has Seed Phrase: {}", summary.has_seed_phrase);
        println!("  Is Standalone: {}", summary.is_standalone);
        println!("  Transaction Count: {}", summary.transaction_count);
        if let Some(ref alias) = summary.alias {
            println!("  Alias: {}", alias);
        }
        if let Some(last_tx) = summary.last_transaction {
            println!("  Last Transaction: {}", last_tx);
        }
        println!();
    }

    // Show system stats
    println!("SYSTEM STATISTICS:");
    println!("──────────────────────");
    println!("Total Wallets: {}", wallet_system.wallet_count());
    println!("Standalone Wallets: {}", wallet_system.standalone_wallet_count());
    println!("Total Balance: {} ZHTP", wallet_system.calculate_total_balance());
    println!();

    println!("Demo completed - All wallet information displayed!");
    
    Ok(())
}