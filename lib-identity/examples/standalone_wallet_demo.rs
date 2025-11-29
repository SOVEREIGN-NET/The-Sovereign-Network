//! Standalone Wallet Demo - Create and manage quantum wallets without zkDID
//! 
//! This example demonstrates how to:
//! 1. Create standalone quantum wallets with 20-word seed phrases
//! 2. Recover wallets from seed phrases
//! 3. Manage multiple wallets without requiring zkDID identity

use lib_identity::{
    create_standalone_wallet, recover_standalone_wallet, create_multi_wallet_system,
    WalletManager, WalletType, RecoveryPhrase
};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🏦 Standalone Quantum Wallet Demo - ZHTP Wallet Management");
    println!("════════════════════════════════════════════════════════════");
    println!("Create and manage quantum-resistant wallets without requiring zkDID identity");
    println!();

    // Step 1: Create a standalone wallet with seed phrase
    println!("1️⃣ Creating standalone quantum wallet with 20-word seed phrase...");
    let (wallet_id, seed_phrase) = create_standalone_wallet(
        "My First Quantum Wallet".to_string(),
        Some("primary".to_string()),
    ).await?;
    
    println!("Standalone wallet created:");
    println!("   Wallet ID: {}", hex::encode(&wallet_id.0[..8]));
    println!("   Seed Phrase: {} words generated", seed_phrase.words.len());
    println!();

    // Step 2: Demonstrate wallet recovery
    println!("2️⃣ Testing wallet recovery from seed phrase...");
    let recovered_wallet_id = recover_standalone_wallet(
        seed_phrase.words.clone(),
        "Recovered Quantum Wallet".to_string(),
        Some("recovered".to_string()),
    ).await?;
    
    println!("Wallet recovered successfully:");
    println!("   Recovered Wallet ID: {}", hex::encode(&recovered_wallet_id.0[..8]));
    println!();

    // Step 3: Create multi-wallet system
    println!("3️⃣ Creating multi-wallet management system...");
    let mut wallet_system = create_multi_wallet_system().await?;
    
    // Create multiple wallet types
    let primary_wallet = wallet_system.create_wallet_with_seed_phrase(
        WalletType::Primary,
        "Primary Spending Wallet".to_string(),
        Some("spend".to_string()),
    ).await?;
    
    let savings_wallet = wallet_system.create_wallet_with_seed_phrase(
        WalletType::Savings,
        "Long-term Savings Wallet".to_string(),
        Some("save".to_string()),
    ).await?;
    
    let business_wallet = wallet_system.create_wallet_with_seed_phrase(
        WalletType::Business,
        "Business Transaction Wallet".to_string(),
        Some("biz".to_string()),
    ).await?;
    
    println!("Multi-wallet system created:");
    println!("   Primary Wallet: {}", hex::encode(&primary_wallet.0.0[..8]));
    println!("   Savings Wallet: {}", hex::encode(&savings_wallet.0.0[..8]));
    println!("   Business Wallet: {}", hex::encode(&business_wallet.0.0[..8]));
    println!();

    // Step 4: Show wallet summaries
    println!("4️⃣ Wallet System Summary:");
    let wallet_summaries = wallet_system.list_wallets();
    for (i, summary) in wallet_summaries.iter().enumerate() {
        println!("   Wallet #{}: {}", i + 1, summary.name);
        println!("     Type: {:?}", summary.wallet_type);
        println!("     Balance: {} ZHTP", summary.balance);
        println!("     Has Seed Phrase: {}", summary.has_seed_phrase);
        println!("     Is Standalone: {}", summary.is_standalone);
        if let Some(ref alias) = summary.alias {
            println!("     Alias: {}", alias);
        }
        println!();
    }

    // Step 5: Demonstrate seed phrase export
    println!("5️⃣ Seed Phrase Management:");
    println!("All wallets have been created with 20-word seed phrases for maximum portability.");
    println!("Each wallet can be independently recovered on any device using its seed phrase.");
    println!();
    
    // Show seed phrase backup information
    for summary in &wallet_summaries {
        if wallet_system.wallet_has_seed_phrase(&summary.id) {
            if let Ok(Some(seed_words)) = wallet_system.export_wallet_seed_phrase(&summary.id) {
                println!(" Seed phrase for '{}': [PROTECTED - {} words]", summary.name, seed_words.len());
            }
        }
    }
    println!();

    // Step 6: Security reminders
    println!("6️⃣ Security Best Practices:");
    println!("     Each wallet has its own 20-word seed phrase");
    println!("   Write down seed phrases on paper, store offline");
    println!("    Each wallet can be recovered independently");
    println!("    Never share seed phrases digitally or online");
    println!("    Consider multiple backup copies in secure locations");
    println!("   Test recovery process before storing large amounts");
    println!();

    println!("Standalone wallet demo completed successfully!");
    println!("Your quantum wallets are now ready for use without any zkDID dependency.");
    
    Ok(())
}

/// Example of advanced wallet operations
pub async fn advanced_wallet_operations() -> Result<()> {
    println!("\nAdvanced Standalone Wallet Operations");
    println!("──────────────────────────────────────────");
    
    let mut wallet_manager = WalletManager::new_standalone();
    
    // Create wallets for different purposes
    let trading_wallet = wallet_manager.create_wallet_with_seed_phrase(
        WalletType::Standard,
        "DeFi Trading Wallet".to_string(),
        Some("defi".to_string()),
    ).await?;
    
    let stealth_wallet = wallet_manager.create_wallet_with_seed_phrase(
        WalletType::Stealth,
        "Privacy Wallet".to_string(),
        Some("private".to_string()),
    ).await?;
    
    println!("Specialized wallets created:");
    println!("   Trading Wallet: {} (for DeFi operations)", hex::encode(&trading_wallet.0.0[..8]));
    println!("   Stealth Wallet: {} (for private transactions)", hex::encode(&stealth_wallet.0.0[..8]));
    
    // Show wallet statistics
    println!("\nWallet Statistics:");
    println!("   Total Wallets: {}", wallet_manager.wallet_count());
    println!("   Standalone Wallets: {}", wallet_manager.standalone_wallet_count());
    println!("   Total Balance: {} ZHTP", wallet_manager.calculate_total_balance());
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_standalone_wallet_creation() {
        let (wallet_id, seed_phrase) = create_standalone_wallet(
            "Test Wallet".to_string(),
            None,
        ).await.expect("Failed to create standalone wallet");
        
        // Verify wallet was created
        assert!(!wallet_id.0.is_empty());
        assert_eq!(seed_phrase.words.len(), 20);
        assert_eq!(seed_phrase.language, "english");
    }
    
    #[tokio::test]
    async fn test_wallet_recovery() {
        // Create a wallet
        let (_, seed_phrase) = create_standalone_wallet(
            "Original Wallet".to_string(),
            None,
        ).await.expect("Failed to create wallet");
        
        // Recover the wallet
        let recovered_wallet_id = recover_standalone_wallet(
            seed_phrase.words,
            "Recovered Wallet".to_string(),
            None,
        ).await.expect("Failed to recover wallet");
        
        // Verify recovery worked
        assert!(!recovered_wallet_id.0.is_empty());
    }
    
    #[tokio::test]
    async fn test_multi_wallet_system() {
        let mut wallet_system = create_multi_wallet_system().await
            .expect("Failed to create multi-wallet system");
        
        // Create multiple wallets
        let wallet1 = wallet_system.create_wallet_with_seed_phrase(
            WalletType::Primary,
            "Wallet 1".to_string(),
            None,
        ).await.expect("Failed to create wallet 1");
        
        let wallet2 = wallet_system.create_wallet_with_seed_phrase(
            WalletType::Savings,
            "Wallet 2".to_string(),
            None,
        ).await.expect("Failed to create wallet 2");
        
        // Verify both wallets exist
        assert_eq!(wallet_system.wallet_count(), 2);
        assert_eq!(wallet_system.standalone_wallet_count(), 2);
        
        // Verify both have seed phrases
        assert!(wallet_system.wallet_has_seed_phrase(&wallet1.0));
        assert!(wallet_system.wallet_has_seed_phrase(&wallet2.0));
    }
}