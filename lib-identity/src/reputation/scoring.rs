// packages/lib-identity/src/reputation/scoring.rs
// Reputation scoring system for ZHTP identities
// IMPLEMENTATIONS from original identity.rs

use crate::types::AccessLevel;
use crate::identity::ZhtpIdentity;
use crate::credentials::ZkCredential;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Reputation score breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationBreakdown {
    pub base_score: u64,           // Starting reputation
    pub credential_bonus: u64,     // Points from verified credentials
    pub citizen_bonus: u64,        // Bonus for citizenship
    pub activity_bonus: u64,       // Points from network activity
    pub verification_bonus: u64,   // Points from verifying others
    pub penalty_deductions: u64,   // Deductions from violations
    pub total_score: u64,          // Final reputation score (0-1000)
    pub reputation_tier: String,   // Reputation tier classification
}

/// Reputation tier classifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReputationTier {
    NewUser,        // 0-99
    Trusted,        // 100-299
    Verified,       // 300-499
    Established,    // 500-699
    Exemplary,      // 700-899
    Elite,          // 900-1000
}

/// Calculate reputation score for identity
/// Implementation from original identity.rs lines 800-900
pub fn calculate_reputation_score(
    identity: &ZhtpIdentity,
    network_activity: Option<&NetworkActivity>,
) -> ReputationBreakdown {
    // Base score for new identities
    let base_score = 50u32;
    
    // Calculate credential bonus - convert HashMap to Vec for processing
    let credentials_vec: Vec<ZkCredential> = identity.credentials.values().cloned().collect();
    let credential_bonus = calculate_credential_bonus(&credentials_vec);
    
    // Calculate citizen bonus
    let citizen_bonus = calculate_citizen_bonus(&identity.access_level);
    
    // Calculate activity bonus
    let activity_bonus = if let Some(activity) = network_activity {
        calculate_activity_bonus(activity)
    } else {
        0
    };
    
    // Calculate verification bonus
    let verification_bonus = calculate_verification_bonus(identity);
    
    // Calculate penalty deductions
    let penalty_deductions = calculate_penalty_deductions(identity);
    
    // Calculate total score (max 1000)
    let raw_total = base_score + credential_bonus + citizen_bonus + activity_bonus + verification_bonus;
    let total_score = if raw_total > penalty_deductions {
        std::cmp::min(raw_total - penalty_deductions, 1000)
    } else {
        0
    };
    
    // Determine reputation tier
    let reputation_tier = determine_reputation_tier(total_score);
    
    ReputationBreakdown {
        base_score: base_score as u64,
        credential_bonus: credential_bonus as u64,
        citizen_bonus: citizen_bonus as u64,
        activity_bonus: activity_bonus as u64,
        verification_bonus: verification_bonus as u64,
        penalty_deductions: penalty_deductions as u64,
        total_score: total_score as u64,
        reputation_tier: reputation_tier.to_string(),
    }
}

/// Calculate bonus points from verified credentials
fn calculate_credential_bonus(credentials: &[ZkCredential]) -> u32 {
    let mut bonus = 0u32;
    
    for credential in credentials {
        let points = match credential.credential_type.as_str() {
            "BasicIdentity" => 20,
            "EmailVerified" => 15,
            "PhoneVerified" => 20,
            "GovernmentId" => 100,
            "Biometric" => 80,
            "Education" => 60,
            "Professional" => 50,
            "Financial" => 40,
            "AgeVerification" => 30,
            "Reputation" => 25,
            _ => 10, // Default for unknown credentials
        };
        
        // For now, assume full confidence since ZkCredential doesn't have confidence field
        // In the original, attestations had confidence, not credentials
        let confidence_multiplier = 1.0; // Full confidence for ZK credentials
        bonus += (points as f64 * confidence_multiplier) as u32;
    }
    
    // Cap credential bonus at 400 points
    std::cmp::min(bonus, 400)
}

/// Calculate bonus for citizenship status
fn calculate_citizen_bonus(access_level: &AccessLevel) -> u32 {
    match access_level.to_string().as_str() {
        level if level.contains("FullCitizen") => 200,
        level if level.contains("Citizen") => 150,
        level if level.contains("Resident") => 100,
        level if level.contains("Verified") => 50,
        _ => 0,
    }
}

/// Calculate bonus from network activity
fn calculate_activity_bonus(activity: &NetworkActivity) -> u32 {
    let mut bonus = 0u32;
    
    // Bonus for transaction volume
    bonus += std::cmp::min(activity.total_transactions / 10, 50);
    
    // Bonus for successful verifications
    bonus += std::cmp::min(activity.successful_verifications * 5, 100);
    
    // Bonus for network participation
    bonus += std::cmp::min(activity.days_active, 30);
    
    // Bonus for helping others
    bonus += std::cmp::min(activity.help_provided * 3, 50);
    
    // Cap activity bonus at 150 points
    std::cmp::min(bonus, 150)
}

/// Calculate bonus for verifying other identities
fn calculate_verification_bonus(identity: &ZhtpIdentity) -> u32 {
    // In implementation, this would check verification history
    // For now, base on reputation score itself
    if identity.reputation > 500 {
        20 // Trusted verifiers get bonus
    } else {
        0
    }
}

/// Calculate penalty deductions
fn calculate_penalty_deductions(identity: &ZhtpIdentity) -> u32 {
    let mut deductions = 0u32;
    
    // Check for expired credentials
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    for (_credential_type, credential) in &identity.credentials {
        if let Some(expiry) = credential.expires_at {
            if current_time > expiry {
                deductions += 10; // Penalty for expired credentials
            }
        }
    }
    
    // Additional penalties would be added here
    // (fraud reports, network violations, etc.)
    
    deductions
}

/// Determine reputation tier from score
fn determine_reputation_tier(score: u32) -> ReputationTier {
    match score {
        0..=99 => ReputationTier::NewUser,
        100..=299 => ReputationTier::Trusted,
        300..=499 => ReputationTier::Verified,
        500..=699 => ReputationTier::Established,
        700..=899 => ReputationTier::Exemplary,
        900..=1000 => ReputationTier::Elite,
        _ => ReputationTier::NewUser,
    }
}

/// Network activity data for reputation calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkActivity {
    pub total_transactions: u32,
    pub successful_verifications: u32,
    pub days_active: u32,
    pub help_provided: u32,
    pub last_activity: u64,
}

/// Update reputation score for identity
pub fn update_reputation_score(
    identity: &mut ZhtpIdentity,
    activity: Option<&NetworkActivity>,
) -> ReputationBreakdown {
    let breakdown = calculate_reputation_score(identity, activity);
    identity.reputation = breakdown.total_score;
    breakdown
}

/// Get reputation requirements for access levels
pub fn get_reputation_requirements() -> HashMap<String, u64> {
    let mut requirements = HashMap::new();
    
    requirements.insert("BasicAccess".to_string(), 0);
    requirements.insert("VerifiedAccess".to_string(), 100);
    requirements.insert("TrustedAccess".to_string(), 300);
    requirements.insert("PremiumAccess".to_string(), 500);
    requirements.insert("ExpertAccess".to_string(), 700);
    requirements.insert("EliteAccess".to_string(), 900);
    
    requirements
}

/// Check if identity meets reputation requirement
pub fn meets_reputation_requirement(
    identity: &ZhtpIdentity,
    required_level: &str,
) -> bool {
    let requirements = get_reputation_requirements();
    if let Some(&required_score) = requirements.get(required_level) {
        identity.reputation >= required_score
    } else {
        false
    }
}

/// Generate reputation report
pub fn generate_reputation_report(breakdown: &ReputationBreakdown) -> String {
    format!(
        "Reputation Report:\n\
        ==================\n\
        Base Score: {}\n\
        Credential Bonus: {}\n\
        Citizen Bonus: {}\n\
        Activity Bonus: {}\n\
        Verification Bonus: {}\n\
        Penalty Deductions: {}\n\
        ==================\n\
        Total Score: {}/1000\n\
        Reputation Tier: {}\n\
        \n\
        {}",
        breakdown.base_score,
        breakdown.credential_bonus,
        breakdown.citizen_bonus,
        breakdown.activity_bonus,
        breakdown.verification_bonus,
        breakdown.penalty_deductions,
        breakdown.total_score,
        breakdown.reputation_tier,
        get_tier_description(&breakdown.reputation_tier)
    )
}

/// Get description for reputation tier
fn get_tier_description(tier: &str) -> String {
    match tier {
        "NewUser" => "New to the network. Build reputation by verifying credentials and participating.".to_string(),
        "Trusted" => "Trusted member with basic verification. Can access most standard services.".to_string(),
        "Verified" => "Well-verified member with strong credentials. Access to premium services.".to_string(),
        "Established" => "Established member with proven track record. High trust level.".to_string(),
        "Exemplary" => "Exemplary member with outstanding reputation. Access to exclusive services.".to_string(),
        "Elite" => "Elite member with maximum reputation. Full access to all services and features.".to_string(),
        _ => "Unknown reputation tier.".to_string(),
    }
}

impl ToString for ReputationTier {
    fn to_string(&self) -> String {
        match self {
            ReputationTier::NewUser => "NewUser".to_string(),
            ReputationTier::Trusted => "Trusted".to_string(),
            ReputationTier::Verified => "Verified".to_string(),
            ReputationTier::Established => "Established".to_string(),
            ReputationTier::Exemplary => "Exemplary".to_string(),
            ReputationTier::Elite => "Elite".to_string(),
        }
    }
}
