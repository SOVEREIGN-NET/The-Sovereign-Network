//! Complete citizenship onboarding from the original identity.rs


use serde::{Deserialize, Serialize};
use crate::types::{IdentityId, AccessLevel};
use crate::wallets::WalletId;
use super::{DaoRegistration, UbiRegistration, Web4Access, WelcomeBonus};
use crate::credentials::ZkCredential;

/// Complete result of citizen onboarding process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitizenshipResult {
    /// The new citizen's identity ID
    pub identity_id: IdentityId,
    /// Primary wallet for daily transactions
    pub primary_wallet_id: WalletId,
    /// UBI wallet for automatic Universal Basic Income payouts
    pub ubi_wallet_id: WalletId,
    /// Savings wallet for long-term storage
    pub savings_wallet_id: WalletId,
    /// Recovery seed phrases for all wallets (CRITICAL TO SAVE!)
    pub wallet_seed_phrases: WalletSeedPhrases,
    /// DAO governance registration
    pub dao_registration: DaoRegistration,
    /// UBI payout registration
    pub ubi_registration: UbiRegistration,
    /// Web4 service access grants
    pub web4_access: Web4Access,
    /// Privacy-preserving credentials
    pub privacy_credentials: PrivacyCredentials,
    /// Welcome bonus details
    pub welcome_bonus: WelcomeBonus,
}

/// Wallet recovery seed phrase - MUST BE STORED SECURELY!
///
/// Single master seed phrase that derives all 3 citizen wallets via HD derivation:
/// - Index 0 → Primary wallet
/// - Index 1 → UBI wallet
/// - Index 2 → Savings wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSeedPhrases {
    /// Master 24-word seed phrase (derives all wallets)
    pub master_seed_phrase: crate::recovery::RecoveryPhrase,
}

/// Privacy-preserving credentials setup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyCredentials {
    /// Citizen's identity ID
    pub identity_id: IdentityId,
    /// List of ZK credentials created
    pub credentials: Vec<ZkCredential>,
    /// Credentials creation timestamp
    pub created_at: u64,
}

impl CitizenshipResult {
    /// Create a new citizenship result
    pub fn new(
        identity_id: IdentityId,
        primary_wallet_id: WalletId,
        ubi_wallet_id: WalletId,
        savings_wallet_id: WalletId,
        wallet_seed_phrases: WalletSeedPhrases,
        dao_registration: DaoRegistration,
        ubi_registration: UbiRegistration,
        web4_access: Web4Access,
        privacy_credentials: PrivacyCredentials,
        welcome_bonus: WelcomeBonus,
    ) -> Self {
        Self {
            identity_id,
            primary_wallet_id,
            ubi_wallet_id,
            savings_wallet_id,
            wallet_seed_phrases,
            dao_registration,
            ubi_registration,
            web4_access,
            privacy_credentials,
            welcome_bonus,
        }
    }
    
    /// Get summary of citizen benefits
    pub fn get_benefits_summary(&self) -> CitizenBenefitsSummary {
        CitizenBenefitsSummary {
            identity_id: self.identity_id.clone(),
            wallet_count: 3, // Primary, UBI, Savings
            monthly_ubi_amount: self.ubi_registration.monthly_amount,
            daily_ubi_amount: self.ubi_registration.daily_amount,
            welcome_bonus_amount: self.welcome_bonus.bonus_amount,
            dao_voting_power: self.dao_registration.voting_power,
            web4_service_count: self.web4_access.service_tokens.len(),
            access_level: self.web4_access.access_level.clone(),
            credential_count: self.privacy_credentials.credentials.len(),
            registration_timestamp: self.dao_registration.registered_at,
        }
    }
    
    /// Check if citizen has full access rights
    pub fn has_full_access(&self) -> bool {
        self.web4_access.access_level == AccessLevel::FullCitizen &&
        self.dao_registration.voting_eligibility &&
        self.dao_registration.proposal_eligibility &&
        !self.ubi_registration.eligibility_proof.is_empty()
    }
}

/// Summary of citizen benefits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitizenBenefitsSummary {
    pub identity_id: IdentityId,
    pub wallet_count: u32,
    pub monthly_ubi_amount: u64,
    pub daily_ubi_amount: u64,
    pub welcome_bonus_amount: u64,
    pub dao_voting_power: u64,
    pub web4_service_count: usize,
    pub access_level: AccessLevel,
    pub credential_count: usize,
    pub registration_timestamp: u64,
}

impl PrivacyCredentials {
    /// Create new privacy credentials
    pub fn new(identity_id: IdentityId, credentials: Vec<ZkCredential>) -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            identity_id,
            credentials,
            created_at: current_time,
        }
    }
    
    /// Add a new credential
    pub fn add_credential(&mut self, credential: ZkCredential) {
        self.credentials.push(credential);
    }
    
    /// Get credentials by type
    pub fn get_credentials_by_type(&self, credential_type: &crate::types::CredentialType) -> Vec<&ZkCredential> {
        self.credentials.iter()
            .filter(|cred| &cred.credential_type == credential_type)
            .collect()
    }
    
    /// Count valid (non-expired) credentials
    pub fn count_valid_credentials(&self) -> usize {
        self.credentials.iter()
            .filter(|cred| cred.is_valid())
            .count()
    }
}
