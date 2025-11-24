//! Access Control Policies for ZHTP
//! 
//! Comprehensive access control system with geographic restrictions,
//! time-based access, reputation scoring, and zero-knowledge privacy.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use lib_identity::IdentityId;
use lib_crypto::Hash;

/// Access control policy for ZHTP resources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Public access allowed
    pub public: bool,
    /// Required identity proofs
    pub required_proofs: Vec<String>,
    /// Minimum reputation required
    pub min_reputation: Option<u32>,
    /// Allowed identities (whitelist)
    pub allowed_identities: Vec<IdentityId>,
    /// Denied identities (blacklist)
    pub denied_identities: Vec<IdentityId>,
    /// Geographic restrictions
    pub geo_restrictions: Vec<String>,
    /// Allowed regions for geographic access control
    pub allowed_regions: Vec<String>,
    /// Time-based restrictions
    pub time_restrictions: Option<TimeRestriction>,
    /// Required DAO membership level
    pub required_dao_level: Option<u32>,
    /// Required UBI eligibility
    pub requires_ubi_eligibility: bool,
    /// Maximum simultaneous access count
    pub max_concurrent_access: Option<u32>,
    /// Rate limiting per identity
    pub rate_limit: Option<RateLimit>,
    /// Required mesh network participation score
    pub min_mesh_score: Option<f64>,
    /// Content licensing requirements
    pub license_requirements: Vec<String>,
    /// Economic access requirements (staking, fees, etc.)
    pub economic_requirements: Option<EconomicRequirements>,
}

/// Time-based access restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestriction {
    /// Start time (timestamp)
    pub start_time: u64,
    /// End time (timestamp)
    pub end_time: u64,
    /// Allowed hours of day (0-23)
    pub allowed_hours: Vec<u8>,
    /// Allowed days of week (0-6, Sunday=0)
    pub allowed_days: Vec<u8>,
    /// Timezone for time calculations
    pub timezone: Option<String>,
    /// Allowed time zones
    pub allowed_timezones: Vec<String>,
    /// Recurring schedule
    pub recurring_schedule: Option<RecurringSchedule>,
}

/// Recurring schedule for time restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecurringSchedule {
    /// Schedule type
    pub schedule_type: ScheduleType,
    /// Interval (for periodic schedules)
    pub interval: Option<u64>,
    /// Specific dates (for date-based schedules)
    pub specific_dates: Vec<u64>,
    /// Duration in seconds
    pub duration: u64,
}

/// Schedule type for recurring access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScheduleType {
    /// Daily recurring access
    Daily,
    /// Weekly recurring access
    Weekly,
    /// Monthly recurring access
    Monthly,
    /// Custom interval in seconds
    Custom,
    /// Specific dates only
    SpecificDates,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum requests per time window
    pub max_requests: u32,
    /// Time window in seconds
    pub window_seconds: u64,
    /// Burst allowance
    pub burst_size: Option<u32>,
    /// Rate limit type
    pub limit_type: RateLimitType,
}

/// Rate limiting type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitType {
    /// Per IP address
    PerIp,
    /// Per identity
    PerIdentity,
    /// Per wallet address
    PerWallet,
    /// Global rate limit
    Global,
}

/// Economic requirements for access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicRequirements {
    /// Minimum ZHTP balance required
    pub min_balance: Option<u64>,
    /// Required staking amount
    pub required_stake: Option<u64>,
    /// One-time access fee
    pub access_fee: Option<u64>,
    /// Subscription fee per month
    pub subscription_fee: Option<u64>,
    /// Required DAO participation score
    pub dao_participation_score: Option<f64>,
    /// UBI contribution requirement
    pub ubi_contribution_requirement: Option<u64>,
}

impl AccessPolicy {
    /// Create a public access policy
    pub fn public() -> Self {
        Self {
            public: true,
            required_proofs: vec![],
            min_reputation: None,
            allowed_identities: vec![],
            denied_identities: vec![],
            geo_restrictions: vec![],
            allowed_regions: vec![],
            time_restrictions: None,
            required_dao_level: None,
            requires_ubi_eligibility: false,
            max_concurrent_access: None,
            rate_limit: None,
            min_mesh_score: None,
            license_requirements: vec![],
            economic_requirements: None,
        }
    }

    /// Create a private access policy (no public access)
    pub fn private() -> Self {
        Self {
            public: false,
            required_proofs: vec!["identity".to_string()],
            min_reputation: Some(50),
            allowed_identities: vec![],
            denied_identities: vec![],
            geo_restrictions: vec![],
            allowed_regions: vec![],
            time_restrictions: None,
            required_dao_level: None,
            requires_ubi_eligibility: false,
            max_concurrent_access: None,
            rate_limit: None,
            min_mesh_score: None,
            license_requirements: vec![],
            economic_requirements: None,
        }
    }

    /// Create a DAO members only policy
    pub fn dao_members_only(min_level: u32) -> Self {
        Self {
            public: false,
            required_proofs: vec!["dao_membership".to_string()],
            min_reputation: Some(100),
            allowed_identities: vec![],
            denied_identities: vec![],
            geo_restrictions: vec![],
            allowed_regions: vec![],
            time_restrictions: None,
            required_dao_level: Some(min_level),
            requires_ubi_eligibility: true,
            max_concurrent_access: None,
            rate_limit: None,
            min_mesh_score: Some(0.8),
            license_requirements: vec![],
            economic_requirements: None,
        }
    }

    /// Create a geo-restricted policy
    pub fn geo_restricted(allowed_regions: Vec<String>) -> Self {
        Self {
            public: true,
            required_proofs: vec![],
            min_reputation: None,
            allowed_identities: vec![],
            denied_identities: vec![],
            geo_restrictions: vec![],
            allowed_regions,
            time_restrictions: None,
            required_dao_level: None,
            requires_ubi_eligibility: false,
            max_concurrent_access: None,
            rate_limit: None,
            min_mesh_score: None,
            license_requirements: vec![],
            economic_requirements: None,
        }
    }

    /// Create a time-restricted policy
    pub fn time_restricted(time_restriction: TimeRestriction) -> Self {
        Self {
            public: true,
            required_proofs: vec![],
            min_reputation: None,
            allowed_identities: vec![],
            denied_identities: vec![],
            geo_restrictions: vec![],
            allowed_regions: vec![],
            time_restrictions: Some(time_restriction),
            required_dao_level: None,
            requires_ubi_eligibility: false,
            max_concurrent_access: None,
            rate_limit: None,
            min_mesh_score: None,
            license_requirements: vec![],
            economic_requirements: None,
        }
    }

    /// Create a premium access policy with economic requirements
    pub fn premium(economic_requirements: EconomicRequirements) -> Self {
        Self {
            public: false,
            required_proofs: vec!["identity".to_string(), "payment".to_string()],
            min_reputation: Some(80),
            allowed_identities: vec![],
            denied_identities: vec![],
            geo_restrictions: vec![],
            allowed_regions: vec![],
            time_restrictions: None,
            required_dao_level: None,
            requires_ubi_eligibility: false,
            max_concurrent_access: Some(100),
            rate_limit: None,
            min_mesh_score: Some(0.7),
            license_requirements: vec!["premium".to_string()],
            economic_requirements: Some(economic_requirements),
        }
    }

    /// Add allowed identity
    pub fn with_allowed_identity(mut self, identity: IdentityId) -> Self {
        self.allowed_identities.push(identity);
        self
    }

    /// Add denied identity
    pub fn with_denied_identity(mut self, identity: IdentityId) -> Self {
        self.denied_identities.push(identity);
        self
    }

    /// Set minimum reputation
    pub fn with_min_reputation(mut self, reputation: u32) -> Self {
        self.min_reputation = Some(reputation);
        self
    }

    /// Add required proof type
    pub fn with_required_proof(mut self, proof_type: String) -> Self {
        self.required_proofs.push(proof_type);
        self
    }

    /// Set rate limiting
    pub fn with_rate_limit(mut self, rate_limit: RateLimit) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }

    /// Set maximum concurrent access
    pub fn with_max_concurrent_access(mut self, max_access: u32) -> Self {
        self.max_concurrent_access = Some(max_access);
        self
    }

    /// Check if identity has access
    pub fn check_identity_access(&self, identity: &IdentityId) -> bool {
        // Check blacklist first
        if self.denied_identities.contains(identity) {
            return false;
        }

        // If there's a whitelist and identity is not on it, deny access
        if !self.allowed_identities.is_empty() && !self.allowed_identities.contains(identity) {
            return false;
        }

        true
    }

    /// Check if current time allows access
    pub fn check_time_access(&self) -> bool {
        let Some(time_restriction) = &self.time_restrictions else {
            return true; // No time restrictions
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check basic time window
        if now < time_restriction.start_time || now > time_restriction.end_time {
            return false;
        }

        // Check allowed hours and days
        if !time_restriction.allowed_hours.is_empty() || !time_restriction.allowed_days.is_empty() {
            // This would require proper date/time parsing based on timezone
            // For now, we'll assume UTC and simplified checks
            let days_since_epoch = now / 86400; // seconds per day
            let current_day = (days_since_epoch + 4) % 7; // Adjust for epoch starting on Thursday
            let current_hour = (now % 86400) / 3600;

            if !time_restriction.allowed_days.is_empty() 
                && !time_restriction.allowed_days.contains(&(current_day as u8)) {
                return false;
            }

            if !time_restriction.allowed_hours.is_empty() 
                && !time_restriction.allowed_hours.contains(&(current_hour as u8)) {
                return false;
            }
        }

        true
    }

    /// Check geographic access (placeholder - would need IP geolocation)
    pub fn check_geo_access(&self, user_region: Option<&str>) -> bool {
        if self.allowed_regions.is_empty() {
            return true; // No geo restrictions
        }

        if let Some(region) = user_region {
            self.allowed_regions.iter().any(|allowed| allowed == region)
        } else {
            false // No region information available
        }
    }

    /// Check reputation requirements
    pub fn check_reputation(&self, user_reputation: Option<u32>) -> bool {
        if let Some(min_rep) = self.min_reputation {
            user_reputation.unwrap_or(0) >= min_rep
        } else {
            true // No reputation requirement
        }
    }

    /// Check economic requirements
    pub fn check_economic_requirements(
        &self,
        user_balance: Option<u64>,
        user_stake: Option<u64>,
    ) -> bool {
        let Some(requirements) = &self.economic_requirements else {
            return true; // No economic requirements
        };

        if let Some(min_balance) = requirements.min_balance {
            if user_balance.unwrap_or(0) < min_balance {
                return false;
            }
        }

        if let Some(required_stake) = requirements.required_stake {
            if user_stake.unwrap_or(0) < required_stake {
                return false;
            }
        }

        true
    }

    /// Perform comprehensive access check
    pub fn check_access(
        &self,
        identity: Option<&IdentityId>,
        user_region: Option<&str>,
        user_reputation: Option<u32>,
        user_balance: Option<u64>,
        user_stake: Option<u64>,
    ) -> AccessCheckResult {
        let mut result = AccessCheckResult {
            allowed: true,
            reasons: vec![],
        };

        // Check if public access is allowed and no identity provided
        if self.public && identity.is_none() {
            // Still need to check other restrictions
        } else if !self.public && identity.is_none() {
            result.allowed = false;
            result.reasons.push("Identity required for access".to_string());
            return result;
        }

        // Check identity-based access
        if let Some(id) = identity {
            if !self.check_identity_access(id) {
                result.allowed = false;
                result.reasons.push("Identity access denied".to_string());
            }
        }

        // Check time restrictions
        if !self.check_time_access() {
            result.allowed = false;
            result.reasons.push("Access not allowed at current time".to_string());
        }

        // Check geographic restrictions
        if !self.check_geo_access(user_region) {
            result.allowed = false;
            result.reasons.push("Geographic access denied".to_string());
        }

        // Check reputation requirements
        if !self.check_reputation(user_reputation) {
            result.allowed = false;
            result.reasons.push(format!(
                "Insufficient reputation. Required: {}, Current: {}",
                self.min_reputation.unwrap_or(0),
                user_reputation.unwrap_or(0)
            ));
        }

        // Check economic requirements
        if !self.check_economic_requirements(user_balance, user_stake) {
            result.allowed = false;
            result.reasons.push("Economic requirements not met".to_string());
        }

        result
    }
}

/// Result of access check
#[derive(Debug, Clone)]
pub struct AccessCheckResult {
    /// Whether access is allowed
    pub allowed: bool,
    /// Reasons for denial (if any)
    pub reasons: Vec<String>,
}

impl TimeRestriction {
    /// Create a business hours restriction (9 AM - 5 PM, weekdays)
    pub fn business_hours() -> Self {
        Self {
            start_time: 0,
            end_time: u64::MAX,
            allowed_hours: (9..17).collect(), // 9 AM to 5 PM
            allowed_days: (1..6).collect(),   // Monday to Friday
            timezone: Some("UTC".to_string()),
            allowed_timezones: vec!["UTC".to_string()],
            recurring_schedule: None,
        }
    }

    /// Create a weekend only restriction
    pub fn weekends_only() -> Self {
        Self {
            start_time: 0,
            end_time: u64::MAX,
            allowed_hours: (0..24).collect(), // All hours
            allowed_days: vec![0, 6],         // Sunday and Saturday
            timezone: Some("UTC".to_string()),
            allowed_timezones: vec!["UTC".to_string()],
            recurring_schedule: None,
        }
    }

    /// Create a time window restriction
    pub fn time_window(start: u64, end: u64) -> Self {
        Self {
            start_time: start,
            end_time: end,
            allowed_hours: (0..24).collect(),
            allowed_days: (0..7).collect(),
            timezone: Some("UTC".to_string()),
            allowed_timezones: vec!["UTC".to_string()],
            recurring_schedule: None,
        }
    }
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self::public()
    }
}

impl RateLimit {
    /// Create a standard rate limit (100 requests per minute)
    pub fn standard() -> Self {
        Self {
            max_requests: 100,
            window_seconds: 60,
            burst_size: Some(10),
            limit_type: RateLimitType::PerIdentity,
        }
    }

    /// Create a strict rate limit (10 requests per minute)
    pub fn strict() -> Self {
        Self {
            max_requests: 10,
            window_seconds: 60,
            burst_size: Some(2),
            limit_type: RateLimitType::PerIdentity,
        }
    }

    /// Create a generous rate limit (1000 requests per minute)
    pub fn generous() -> Self {
        Self {
            max_requests: 1000,
            window_seconds: 60,
            burst_size: Some(100),
            limit_type: RateLimitType::PerIdentity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_policy() {
        let policy = AccessPolicy::public();
        assert!(policy.public);
        assert!(policy.required_proofs.is_empty());
    }

    #[test]
    fn test_private_policy() {
        let policy = AccessPolicy::private();
        assert!(!policy.public);
        assert!(!policy.required_proofs.is_empty());
        assert_eq!(policy.min_reputation, Some(50));
    }

    #[test]
    fn test_identity_access_check() {
        let mut policy = AccessPolicy::private();
        let identity = Hash::from_bytes(&[1u8; 32]);
        
        // Initially no specific access
        assert!(policy.check_identity_access(&identity));
        
        // Add to blacklist
        policy.denied_identities.push(identity.clone());
        assert!(!policy.check_identity_access(&identity));
        
        // Remove from blacklist and add to whitelist
        policy.denied_identities.clear();
        policy.allowed_identities.push(identity.clone());
        assert!(policy.check_identity_access(&identity));
    }

    #[test]
    fn test_time_restrictions() {
        let time_restriction = TimeRestriction::business_hours();
        assert_eq!(time_restriction.allowed_hours, (9..17).collect::<Vec<_>>());
        assert_eq!(time_restriction.allowed_days, (1..6).collect::<Vec<_>>());
    }

    #[test]
    fn test_rate_limits() {
        let standard = RateLimit::standard();
        assert_eq!(standard.max_requests, 100);
        assert_eq!(standard.window_seconds, 60);
        
        let strict = RateLimit::strict();
        assert_eq!(strict.max_requests, 10);
    }

    #[test]
    fn test_comprehensive_access_check() {
        let policy = AccessPolicy::private()
            .with_min_reputation(100);
        
        let identity = Hash::from_bytes(&[1u8; 32]);
        
        // Should fail due to insufficient reputation
        let result = policy.check_access(
            Some(&identity),
            None,
            Some(50), // Below required 100
            None,
            None,
        );
        assert!(!result.allowed);
        assert!(!result.reasons.is_empty());
        
        // Should pass with sufficient reputation
        let result = policy.check_access(
            Some(&identity),
            None,
            Some(150), // Above required 100
            None,
            None,
        );
        assert!(result.allowed);
    }

    #[test]
    fn test_geo_restrictions() {
        let policy = AccessPolicy::geo_restricted(vec!["US".to_string(), "CA".to_string()]);
        
        assert!(policy.check_geo_access(Some("US")));
        assert!(policy.check_geo_access(Some("CA")));
        assert!(!policy.check_geo_access(Some("CN")));
        assert!(!policy.check_geo_access(None));
    }
}
