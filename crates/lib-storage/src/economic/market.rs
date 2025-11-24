//! Storage Market and Discovery System
//! 
//! Implements a decentralized marketplace for storage services including:
//! - Provider discovery and matching
//! - Service advertising and bidding
//! - Market-making and liquidity provision
//! - Geographic and performance-based routing
//! - Load balancing and capacity management

use crate::types::{StorageTier, EncryptionLevel};
use crate::economic::pricing::{StorageRequest, UrgencyLevel};
use log;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use uuid;

/// Storage marketplace for provider discovery and matching
#[derive(Debug)]
pub struct StorageMarket {
    /// Available storage providers
    providers: HashMap<String, StorageProvider>,
    /// Storage requests awaiting fulfillment
    pending_requests: HashMap<String, StorageRequest>,
    /// Active service advertisements
    service_ads: HashMap<String, ServiceAdvertisement>,
    /// Market statistics
    market_stats: MarketStatistics,
    /// Geographic regions
    regions: HashMap<String, RegionInfo>,
}

/// Market manager (alias for StorageMarket)
pub type MarketManager = StorageMarket;

/// Storage provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProvider {
    /// Provider identifier
    pub provider_id: String,
    /// Provider metadata
    pub metadata: ProviderMetadata,
    /// Available storage capacity
    pub capacity: StorageCapacity,
    /// Service capabilities
    pub capabilities: ServiceCapabilities,
    /// Pricing information
    pub pricing: ProviderPricing,
    /// Geographic location
    pub location: GeographicLocation,
    /// Reputation score
    pub reputation_score: f64,
    /// Current availability
    pub availability: ProviderAvailability,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Whether the provider is currently online
    pub is_online: bool,
}

/// Provider metadata and contact information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    /// Provider name
    pub name: String,
    /// Provider description
    pub description: String,
    /// Contact information
    pub contact_info: ContactInfo,
    /// Provider website
    pub website: Option<String>,
    /// Supported protocols
    pub protocols: Vec<String>,
    /// Provider tags/categories
    pub tags: Vec<String>,
}

/// Contact information for providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    /// Email address
    pub email: Option<String>,
    /// Support channels
    pub support_channels: Vec<String>,
    /// API endpoints
    pub api_endpoints: Vec<String>,
}

/// Storage capacity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCapacity {
    /// Total storage capacity (bytes)
    pub total_capacity: u64,
    /// Currently used capacity (bytes)
    pub used_capacity: u64,
    /// Available capacity (bytes)
    pub available_capacity: u64,
    /// Reserved capacity (bytes)
    pub reserved_capacity: u64,
    /// Capacity by storage tier
    pub tier_capacity: HashMap<StorageTier, u64>,
}

/// Service capabilities of a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCapabilities {
    /// Supported storage tiers
    pub supported_tiers: Vec<StorageTier>,
    /// Maximum file size supported
    pub max_file_size: u64,
    /// Supported replication factors
    pub replication_factors: Vec<u8>,
    /// Encryption capabilities
    pub encryption_support: Vec<EncryptionLevel>,
    /// Erasure coding support
    pub erasure_coding_support: bool,
    /// Backup and archival support
    pub backup_support: bool,
    /// CDN capabilities
    pub cdn_support: bool,
}

/// Provider pricing structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderPricing {
    /// Base pricing per tier
    pub tier_pricing: HashMap<StorageTier, u64>,
    /// Bandwidth pricing
    pub bandwidth_pricing: BandwidthPricing,
    /// Operation pricing
    pub operation_pricing: OperationPricing,
    /// Discount for long-term contracts
    pub volume_discounts: Vec<VolumeDiscount>,
    /// Pricing validity period
    pub pricing_valid_until: u64,
}

/// Bandwidth pricing structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthPricing {
    /// Upload cost per GB
    pub upload_cost_per_gb: u64,
    /// Download cost per GB
    pub download_cost_per_gb: u64,
    /// Free bandwidth allowance
    pub free_bandwidth_gb: u64,
}

/// Operation pricing structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationPricing {
    /// Cost per read operation
    pub read_operation_cost: u64,
    /// Cost per write operation
    pub write_operation_cost: u64,
    /// Cost per delete operation
    pub delete_operation_cost: u64,
    /// Cost per list operation
    pub list_operation_cost: u64,
}

/// Volume discount structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeDiscount {
    /// Minimum storage size for discount
    pub min_storage_size: u64,
    /// Minimum contract duration for discount
    pub min_contract_duration: u64,
    /// Discount percentage
    pub discount_percentage: f64,
}

/// Geographic location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicLocation {
    /// Country code
    pub country: String,
    /// Region/state
    pub region: String,
    /// City
    pub city: String,
    /// Data center location
    pub datacenter: Option<String>,
    /// Coordinates
    pub coordinates: Option<Coordinates>,
}

/// Geographic coordinates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coordinates {
    pub latitude: f64,
    pub longitude: f64,
}

/// Provider availability status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderAvailability {
    /// Overall availability status
    pub status: AvailabilityStatus,
    /// Current load percentage
    pub current_load: f64,
    /// Response time to new requests
    pub response_time: u64,
    /// Maintenance windows
    pub maintenance_windows: Vec<MaintenanceWindow>,
}

/// Provider availability status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AvailabilityStatus {
    Online,
    Busy,
    Maintenance,
    Offline,
    Limited,
}

/// Scheduled maintenance window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceWindow {
    /// Start time
    pub start_time: u64,
    /// End time
    pub end_time: u64,
    /// Maintenance description
    pub description: String,
    /// Impact level
    pub impact: MaintenanceImpact,
}

/// Maintenance impact levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaintenanceImpact {
    None,        // No service impact
    Low,         // Minimal service impact
    Medium,      // Some service degradation
    High,        // Significant service impact
    Complete,    // Complete service outage
}

/// Service advertisement by providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAdvertisement {
    /// Advertisement ID
    pub ad_id: String,
    /// Provider ID
    pub provider_id: String,
    /// Advertised services
    pub services: Vec<ServiceOffering>,
    /// Special offers
    pub special_offers: Vec<SpecialOffer>,
    /// Advertisement validity
    pub valid_until: u64,
    /// Target customer segments
    pub target_segments: Vec<CustomerSegment>,
}

/// Individual service offering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceOffering {
    /// Service name
    pub name: String,
    /// Service description
    pub description: String,
    /// Storage tier
    pub tier: StorageTier,
    /// Minimum capacity
    pub min_capacity: u64,
    /// Maximum capacity
    pub max_capacity: u64,
    /// Price per GB per month
    pub price_per_gb_month: u64,
    /// SLA guarantees
    pub sla_guarantees: ServiceSLA,
}

/// Service Level Agreement for offerings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSLA {
    /// Uptime guarantee
    pub uptime_guarantee: f64,
    /// Response time guarantee
    pub response_time_ms: u64,
    /// Data durability guarantee
    pub durability_guarantee: f64,
    /// Support response time
    pub support_response_hours: u64,
}

/// Special promotional offers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialOffer {
    /// Offer name
    pub name: String,
    /// Offer description
    pub description: String,
    /// Discount percentage
    pub discount_percentage: f64,
    /// Offer conditions
    pub conditions: Vec<String>,
    /// Offer expiry
    pub expires_at: u64,
    /// Maximum usage
    pub max_usage_count: Option<u32>,
}

/// Customer segments for targeted advertising
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CustomerSegment {
    Individual,
    SmallBusiness,
    Enterprise,
    Developer,
    Archival,
    HighPerformance,
    BudgetConsious,
}

/// Market statistics and analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketStatistics {
    /// Total number of providers
    pub total_providers: u32,
    /// Total available capacity
    pub total_capacity: u64,
    /// Total utilized capacity
    pub utilized_capacity: u64,
    /// Average price per GB
    pub avg_price_per_gb: u64,
    /// Number of active contracts
    pub active_contracts: u32,
    /// Market trends
    pub trends: MarketTrends,
    /// Last updated
    pub last_updated: u64,
}

/// Market trend information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketTrends {
    /// Price trend direction
    pub price_trend: MarketTrendDirection,
    /// Capacity trend direction
    pub capacity_trend: MarketTrendDirection,
    /// Demand trend direction
    pub demand_trend: MarketTrendDirection,
    /// Quality trend direction
    pub quality_trend: MarketTrendDirection,
}

/// Trend direction indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MarketTrendDirection {
    Increasing,
    Stable,
    Decreasing,
}

/// Regional market information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionInfo {
    /// Region identifier
    pub region_id: String,
    /// Region name
    pub region_name: String,
    /// Countries in region
    pub countries: Vec<String>,
    /// Provider count in region
    pub provider_count: u32,
    /// Average pricing in region
    pub avg_pricing: u64,
    /// Data residency requirements
    pub data_residency_rules: Vec<String>,
}

/// Provider matching criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchingCriteria {
    /// Required storage capacity
    pub required_capacity: u64,
    /// Preferred storage tier
    pub preferred_tier: StorageTier,
    /// Maximum price per GB
    pub max_price_per_gb: Option<u64>,
    /// Geographic preferences
    pub geographic_preferences: Vec<String>,
    /// Minimum reputation score
    pub min_reputation: Option<f64>,
    /// Required SLA levels
    pub required_sla: Option<ServiceSLA>,
    /// Required capabilities
    pub required_capabilities: Vec<String>,
}

/// Provider search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSearchResult {
    /// Matching providers
    pub providers: Vec<ProviderMatch>,
    /// Total matches found
    pub total_matches: u32,
    /// Search query used
    pub search_criteria: MatchingCriteria,
    /// Search timestamp
    pub search_timestamp: u64,
}

/// Individual provider match with score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMatch {
    /// Provider information
    pub provider: StorageProvider,
    /// Match score (0.0-1.0)
    pub match_score: f64,
    /// Estimated cost for request
    pub estimated_cost: u64,
    /// Why this provider matches
    pub match_reasons: Vec<String>,
    /// Potential concerns
    pub concerns: Vec<String>,
}

impl StorageMarket {
    /// Create a new storage market
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            pending_requests: HashMap::new(),
            service_ads: HashMap::new(),
            market_stats: MarketStatistics {
                total_providers: 0,
                total_capacity: 0,
                utilized_capacity: 0,
                avg_price_per_gb: 0,
                active_contracts: 0,
                trends: MarketTrends {
                    price_trend: MarketTrendDirection::Stable,
                    capacity_trend: MarketTrendDirection::Stable,
                    demand_trend: MarketTrendDirection::Stable,
                    quality_trend: MarketTrendDirection::Stable,
                },
                last_updated: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            regions: HashMap::new(),
        }
    }

    /// Register a new storage provider
    pub fn register_provider(&mut self, provider: StorageProvider) -> Result<()> {
        self.providers.insert(provider.provider_id.clone(), provider);
        self.update_market_stats();
        Ok(())
    }

    /// Update provider information
    pub fn update_provider(&mut self, provider_id: &str, updates: ProviderUpdate) -> Result<()> {
        let provider = self.providers.get_mut(provider_id)
            .ok_or_else(|| anyhow!("Provider not found"))?;

        match updates {
            ProviderUpdate::Capacity(capacity) => {
                provider.capacity = capacity;
            }
            ProviderUpdate::Pricing(pricing) => {
                provider.pricing = pricing;
            }
            ProviderUpdate::Availability(availability) => {
                provider.availability = availability;
            }
            ProviderUpdate::Reputation(score) => {
                provider.reputation_score = score;
            }
        }

        provider.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.update_market_stats();
        Ok(())
    }

    /// Search for providers based on criteria
    pub fn search_providers(&self, criteria: MatchingCriteria) -> Result<ProviderSearchResult> {
        let mut matches = Vec::new();

        for provider in self.providers.values() {
            if let Some(provider_match) = self.evaluate_provider_match(provider, &criteria) {
                matches.push(provider_match);
            }
        }

        // Sort by match score descending
        matches.sort_by(|a, b| b.match_score.partial_cmp(&a.match_score).unwrap());

        Ok(ProviderSearchResult {
            total_matches: matches.len() as u32,
            providers: matches,
            search_criteria: criteria,
            search_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Evaluate how well a provider matches criteria
    fn evaluate_provider_match(&self, provider: &StorageProvider, criteria: &MatchingCriteria) -> Option<ProviderMatch> {
        let mut score: f64 = 0.0;
        let mut reasons = Vec::new();
        let mut concerns = Vec::new();

        // Check availability
        if provider.availability.status != AvailabilityStatus::Online {
            concerns.push("Provider not currently online".to_string());
            return None; // Skip offline providers
        }

        // Check capacity
        if provider.capacity.available_capacity >= criteria.required_capacity {
            score += 0.3;
            reasons.push("Sufficient capacity available".to_string());
        } else {
            concerns.push("Insufficient available capacity".to_string());
            return None;
        }

        // Check tier support
        if provider.capabilities.supported_tiers.contains(&criteria.preferred_tier) {
            score += 0.2;
            reasons.push(format!("Supports {} tier", format!("{:?}", criteria.preferred_tier)));
        }

        // Check pricing
        if let Some(max_price) = criteria.max_price_per_gb {
            if let Some(tier_price) = provider.pricing.tier_pricing.get(&criteria.preferred_tier) {
                if *tier_price <= max_price {
                    score += 0.2;
                    reasons.push("Price within budget".to_string());
                } else {
                    concerns.push("Price exceeds budget".to_string());
                    score -= 0.1;
                }
            }
        }

        // Check reputation
        if let Some(min_reputation) = criteria.min_reputation {
            if provider.reputation_score >= min_reputation {
                score += 0.2;
                reasons.push("Meets reputation requirements".to_string());
            } else {
                concerns.push("Reputation below minimum".to_string());
                return None;
            }
        }

        // Check geographic preferences
        if !criteria.geographic_preferences.is_empty() {
            for pref in &criteria.geographic_preferences {
                if provider.location.country == *pref || provider.location.region == *pref {
                    score += 0.1;
                    reasons.push(format!("Located in preferred region: {}", pref));
                    break;
                }
            }
        }

        // Estimate cost
        let estimated_cost = self.estimate_cost(provider, criteria);

        Some(ProviderMatch {
            provider: provider.clone(),
            match_score: score.min(1.0),
            estimated_cost,
            match_reasons: reasons,
            concerns,
        })
    }

    /// Estimate cost for a storage request with a provider
    fn estimate_cost(&self, provider: &StorageProvider, criteria: &MatchingCriteria) -> u64 {
        let tier_price = provider.pricing.tier_pricing.get(&criteria.preferred_tier)
            .copied()
            .unwrap_or(100);

        let size_gb = (criteria.required_capacity as f64 / (1024.0 * 1024.0 * 1024.0)).ceil() as u64;
        tier_price * size_gb
    }

    /// Get market statistics
    pub fn get_market_stats(&self) -> &MarketStatistics {
        &self.market_stats
    }

    /// Get providers in a specific region
    pub fn get_providers_by_region(&self, region: &str) -> Vec<&StorageProvider> {
        self.providers.values()
            .filter(|p| p.location.region == region || p.location.country == region)
            .collect()
    }

    /// Get top providers by reputation
    pub fn get_top_providers(&self, limit: usize) -> Vec<&StorageProvider> {
        let mut providers: Vec<_> = self.providers.values().collect();
        providers.sort_by(|a, b| b.reputation_score.partial_cmp(&a.reputation_score).unwrap());
        providers.into_iter().take(limit).collect()
    }

    /// Add a storage request to pending queue
    pub fn add_pending_request(&mut self, request: StorageRequest) -> Result<String> {
        let request_id = format!("req_{}", uuid::Uuid::new_v4());
        self.pending_requests.insert(request_id.clone(), request);
        Ok(request_id)
    }

    /// Get pending request by ID
    pub fn get_pending_request(&self, request_id: &str) -> Option<&StorageRequest> {
        self.pending_requests.get(request_id)
    }

    /// Remove fulfilled request from pending queue
    pub fn fulfill_request(&mut self, request_id: &str) -> Option<StorageRequest> {
        self.pending_requests.remove(request_id)
    }

    /// Get all pending requests
    pub fn get_pending_requests(&self) -> &HashMap<String, StorageRequest> {
        &self.pending_requests
    }

    /// Get pending requests by criteria
    pub fn get_pending_requests_by_criteria(&self, tier: Option<StorageTier>, max_size: Option<u64>) -> Vec<(String, &StorageRequest)> {
        self.pending_requests
            .iter()
            .filter(|(_, request)| {
                let tier_match = tier.is_none() || Some(request.tier) == tier;
                let size_match = max_size.is_none() || request.size <= max_size.unwrap_or(u64::MAX);
                tier_match && size_match
            })
            .map(|(id, req)| (id.clone(), req))
            .collect()
    }

    /// Add service advertisement
    pub fn add_service_advertisement(&mut self, ad: ServiceAdvertisement) -> Result<()> {
        // Validate advertisement
        if self.providers.get(&ad.provider_id).is_none() {
            return Err(anyhow!("Provider not found for advertisement"));
        }

        // Check if advertisement is still valid
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if ad.valid_until <= current_time {
            return Err(anyhow!("Advertisement has expired"));
        }

        self.service_ads.insert(ad.ad_id.clone(), ad);
        Ok(())
    }

    /// Get active service advertisements
    pub fn get_active_advertisements(&self) -> Vec<&ServiceAdvertisement> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.service_ads
            .values()
            .filter(|ad| ad.valid_until > current_time)
            .collect()
    }

    /// Get advertisements by provider
    pub fn get_advertisements_by_provider(&self, provider_id: &str) -> Vec<&ServiceAdvertisement> {
        self.service_ads
            .values()
            .filter(|ad| ad.provider_id == provider_id)
            .collect()
    }

    /// Get advertisements for customer segment
    pub fn get_advertisements_for_segment(&self, segment: CustomerSegment) -> Vec<&ServiceAdvertisement> {
        self.service_ads
            .values()
            .filter(|ad| ad.target_segments.contains(&segment))
            .collect()
    }

    /// Clean expired advertisements
    pub fn clean_expired_advertisements(&mut self) -> usize {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let initial_count = self.service_ads.len();
        self.service_ads.retain(|_, ad| ad.valid_until > current_time);
        initial_count - self.service_ads.len()
    }

    /// Add region information
    pub fn add_region(&mut self, region: RegionInfo) -> Result<()> {
        self.regions.insert(region.region_id.clone(), region);
        Ok(())
    }

    /// Get region information
    pub fn get_region(&self, region_id: &str) -> Option<&RegionInfo> {
        self.regions.get(region_id)
    }

    /// Get all regions
    pub fn get_regions(&self) -> &HashMap<String, RegionInfo> {
        &self.regions
    }

    /// Get providers in a specific region (enhanced)
    pub fn get_providers_in_region(&self, region_id: &str) -> Vec<&StorageProvider> {
        if let Some(region_info) = self.regions.get(region_id) {
            self.providers
                .values()
                .filter(|provider| {
                    region_info.countries.contains(&provider.location.country)
                        || provider.location.region == region_info.region_name
                })
                .collect()
        } else {
            // Fallback to direct region matching
            self.providers
                .values()
                .filter(|provider| provider.location.region == region_id)
                .collect()
        }
    }

    /// Get regional market statistics
    pub fn get_regional_stats(&self, region_id: &str) -> Option<RegionalMarketStats> {
        let providers = self.get_providers_in_region(region_id);
        
        if providers.is_empty() {
            return None;
        }

        let total_capacity: u64 = providers.iter().map(|p| p.capacity.total_capacity).sum();
        let available_capacity: u64 = providers.iter().map(|p| p.capacity.available_capacity).sum();
        let avg_reputation: f64 = providers.iter().map(|p| p.reputation_score).sum::<f64>() / providers.len() as f64;
        
        // Calculate average price for Cold tier
        let cold_prices: Vec<u64> = providers
            .iter()
            .filter_map(|p| p.pricing.tier_pricing.get(&StorageTier::Cold))
            .cloned()
            .collect();
        
        let avg_price = if !cold_prices.is_empty() {
            cold_prices.iter().sum::<u64>() / cold_prices.len() as u64
        } else {
            0
        };

        Some(RegionalMarketStats {
            region_id: region_id.to_string(),
            provider_count: providers.len() as u32,
            total_capacity,
            available_capacity,
            utilization_rate: if total_capacity > 0 {
                ((total_capacity - available_capacity) as f64 / total_capacity as f64) * 100.0
            } else {
                0.0
            },
            average_price_per_gb: avg_price,
            average_reputation: avg_reputation,
            active_advertisements: self.service_ads.values()
                .filter(|ad| providers.iter().any(|p| p.provider_id == ad.provider_id))
                .count() as u32,
        })
    }

    /// Match pending requests with advertisements
    pub fn match_requests_with_ads(&self) -> Vec<RequestAdvertisementMatch> {
        let mut matches = Vec::new();
        
        for (request_id, request) in &self.pending_requests {
            for ad in self.get_active_advertisements() {
                if let Some(match_score) = self.calculate_request_ad_match(request, ad) {
                    matches.push(RequestAdvertisementMatch {
                        request_id: request_id.clone(),
                        advertisement_id: ad.ad_id.clone(),
                        match_score,
                        estimated_cost: self.estimate_request_cost(request, ad),
                        match_details: self.get_match_details(request, ad),
                    });
                }
            }
        }

        // Sort by match score descending
        matches.sort_by(|a, b| b.match_score.partial_cmp(&a.match_score).unwrap());
        matches
    }

    /// Calculate match score between request and advertisement
    fn calculate_request_ad_match(&self, request: &StorageRequest, ad: &ServiceAdvertisement) -> Option<f64> {
        let mut score: f64 = 0.0;

        // Find matching service offering
        let matching_offering = ad.services.iter().find(|service| {
            service.tier == request.tier 
            && request.size >= service.min_capacity 
            && request.size <= service.max_capacity
        })?;

        score += 0.4; // Base score for tier and capacity match

        // Check price compatibility
        if let Some(max_price) = request.urgency.get_max_price_per_gb() {
            if matching_offering.price_per_gb_month <= max_price {
                score += 0.3;
            } else {
                score -= 0.2;
            }
        }

        // Geographic preference
        if let Some(provider) = self.providers.get(&ad.provider_id) {
            if request.geographic_region.as_ref() == Some(&provider.location.region) {
                score += 0.2;
            }
        }

        // Quality requirements (use quality_level as proxy)
        if matching_offering.sla_guarantees.uptime_guarantee >= 99.0 {
            score += 0.1;
        }

        Some(score.min(1.0).max(0.0))
    }

    /// Estimate cost for a request using an advertisement
    fn estimate_request_cost(&self, request: &StorageRequest, ad: &ServiceAdvertisement) -> u64 {
        if let Some(service) = ad.services.iter().find(|s| s.tier == request.tier) {
            let size_gb = (request.size as f64 / (1024.0 * 1024.0 * 1024.0)).ceil() as u64;
            let base_cost = service.price_per_gb_month * size_gb;
            
            // Apply special offers
            let discount = ad.special_offers.iter()
                .map(|offer| offer.discount_percentage)
                .fold(0.0, f64::max);
            
            (base_cost as f64 * (1.0 - discount / 100.0)) as u64
        } else {
            u64::MAX // No matching service
        }
    }

    /// Get detailed match information
    fn get_match_details(&self, request: &StorageRequest, ad: &ServiceAdvertisement) -> MatchDetails {
        let mut reasons = Vec::new();
        let mut concerns = Vec::new();

        if let Some(service) = ad.services.iter().find(|s| s.tier == request.tier) {
            reasons.push(format!("Supports {} tier", format!("{:?}", service.tier)));
            
            if request.size >= service.min_capacity && request.size <= service.max_capacity {
                reasons.push("Capacity requirements met".to_string());
            }

            // Check SLA compatibility (simplified)
            if service.sla_guarantees.uptime_guarantee >= 99.0 {
                reasons.push("SLA requirements met".to_string());
            } else {
                concerns.push("SLA below requirements".to_string());
            }
        }

        MatchDetails {
            reasons,
            concerns,
        }
    }

    /// Find storage providers matching requirements
    pub fn find_storage_providers(
        &self,
        required_size: u64,
        min_replicas: u32,
        region_preference: Option<String>,
    ) -> Vec<String> {
        self.providers
            .iter()
            .filter(|(_, provider)| {
                provider.capacity.available_capacity >= required_size
                    && provider.is_online
                    && (region_preference.is_none() 
                        || region_preference.as_ref() == Some(&provider.location.region))
            })
            .take(min_replicas as usize)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Find storage providers using quality requirements
    pub fn find_storage_providers_with_quality(
        &self,
        required_size: u64,
        min_replicas: u32,
        quality_requirements: &crate::types::QualityRequirements,
    ) -> Vec<String> {
        use QualityRequirementsExt;
        
        // Validate quality requirements first
        if let Err(e) = quality_requirements.validate_against_limits() {
            log::warn!("Invalid quality requirements: {}", e);
            return Vec::new();
        }
        
        self.providers
            .iter()
            .filter(|(_, provider)| {
                // Basic capacity and availability check
                provider.capacity.available_capacity >= required_size
                    && provider.is_online
                    // Quality requirements check using our trait
                    && quality_requirements.meets_provider_capability(provider)
            })
            .take(min_replicas as usize)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Evaluate providers with detailed quality analysis
    pub fn evaluate_providers_with_quality(
        &self,
        quality_requirements: &crate::types::QualityRequirements,
    ) -> Vec<(String, f64)> {
        use QualityRequirementsExt;
        
        let mut provider_scores = Vec::new();
        
        for (provider_id, provider) in &self.providers {
            let mut score = 0.0;
            
            // Uptime score (0-25 points)
            if provider.reputation_score >= quality_requirements.get_min_uptime() {
                score += 25.0;
            } else {
                score += provider.reputation_score * 25.0;
            }
            
            // Geographic distribution bonus (0-20 points)
            if quality_requirements.has_geographic_constraints() {
                score += 20.0; // Assumes provider meets geo requirements
            } else {
                score += 15.0; // Default regional bonus
            }
            
            // Certification bonus (0-15 points)
            if quality_requirements.requires_certifications() {
                score += provider.reputation_score * 15.0; // High reputation = likely certified
            } else {
                score += 10.0; // Default certification score
            }
            
            // Replication capability (0-20 points)
            let replication_score = if provider.capacity.total_capacity > 
                (quality_requirements.get_min_replication() as u64 * 1_000_000) {
                20.0
            } else {
                10.0
            };
            score += replication_score;
            
            // Response time factor (0-20 points)
            let response_bonus = if quality_requirements.get_max_response_time() > 100 {
                20.0 // Generous time allowance
            } else {
                15.0 // Strict requirements
            };
            score += response_bonus;
            
            provider_scores.push((provider_id.clone(), score));
        }
        
        // Sort by score (highest first)
        provider_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        provider_scores
    }

    /// Record contract creation for market statistics
    pub async fn record_contract_creation(&mut self, _contract_id: String, _total_cost: u64) -> Result<()> {
        // Update market statistics
        self.update_market_stats();
        Ok(())
    }

    /// Update market statistics
    fn update_market_stats(&mut self) {
        self.market_stats.total_providers = self.providers.len() as u32;
        self.market_stats.total_capacity = self.providers.values()
            .map(|p| p.capacity.total_capacity)
            .sum();
        self.market_stats.utilized_capacity = self.providers.values()
            .map(|p| p.capacity.used_capacity)
            .sum();

        // Calculate average price (simplified)
        let total_prices: u64 = self.providers.values()
            .filter_map(|p| p.pricing.tier_pricing.get(&StorageTier::Cold))
            .sum();
        
        if self.market_stats.total_providers > 0 {
            self.market_stats.avg_price_per_gb = total_prices / (self.market_stats.total_providers as u64);
        }

        self.market_stats.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Provider update types
#[derive(Debug, Clone)]
pub enum ProviderUpdate {
    Capacity(StorageCapacity),
    Pricing(ProviderPricing),
    Availability(ProviderAvailability),
    Reputation(f64),
}

/// Regional market statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionalMarketStats {
    /// Region identifier
    pub region_id: String,
    /// Number of providers in region
    pub provider_count: u32,
    /// Total storage capacity in region
    pub total_capacity: u64,
    /// Available storage capacity in region
    pub available_capacity: u64,
    /// Capacity utilization rate (percentage)
    pub utilization_rate: f64,
    /// Average price per GB in region
    pub average_price_per_gb: u64,
    /// Average provider reputation in region
    pub average_reputation: f64,
    /// Number of active advertisements in region
    pub active_advertisements: u32,
}

/// Match between a storage request and advertisement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestAdvertisementMatch {
    /// Request identifier
    pub request_id: String,
    /// Advertisement identifier
    pub advertisement_id: String,
    /// Match score (0.0-1.0)
    pub match_score: f64,
    /// Estimated cost for the request
    pub estimated_cost: u64,
    /// Detailed match information
    pub match_details: MatchDetails,
}

/// Detailed match information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchDetails {
    /// Reasons why this is a good match
    pub reasons: Vec<String>,
    /// Potential concerns or limitations
    pub concerns: Vec<String>,
}

impl Default for StorageMarket {
    fn default() -> Self {
        Self::new()
    }
}

/// Extension trait for UrgencyLevel to provide pricing guidance
trait UrgencyLevelExt {
    fn get_max_price_per_gb(&self) -> Option<u64>;
}

impl UrgencyLevelExt for UrgencyLevel {
    fn get_max_price_per_gb(&self) -> Option<u64> {
        match self {
            UrgencyLevel::Low => Some(50),    // Low urgency = budget conscious
            UrgencyLevel::Normal => Some(100), // Normal urgency = standard pricing
            UrgencyLevel::High => Some(200),  // High urgency = premium acceptable
            UrgencyLevel::Critical => None,   // Critical = price no object
        }
    }
}

/// Extension trait for QualityRequirements to provide enhanced filtering capabilities
trait QualityRequirementsExt {
    fn get_min_uptime(&self) -> f64;
    fn get_max_response_time(&self) -> u64;
    fn get_min_replication(&self) -> u8;
    fn has_geographic_constraints(&self) -> bool;
    fn requires_certifications(&self) -> bool;
    fn meets_provider_capability(&self, provider: &StorageProvider) -> bool;
    fn validate_against_limits(&self) -> Result<(), String>;
}

impl QualityRequirementsExt for crate::types::QualityRequirements {
    fn get_min_uptime(&self) -> f64 {
        self.min_uptime
    }
    
    fn get_max_response_time(&self) -> u64 {
        self.max_response_time
    }
    
    fn get_min_replication(&self) -> u8 {
        self.min_replication
    }
    
    fn has_geographic_constraints(&self) -> bool {
        self.geographic_distribution.is_some() && 
        !self.geographic_distribution.as_ref().unwrap().is_empty()
    }
    
    fn requires_certifications(&self) -> bool {
        !self.required_certifications.is_empty()
    }
    
    fn meets_provider_capability(&self, provider: &StorageProvider) -> bool {
        // For this implementation, we'll use basic checks with available fields
        // In a full implementation, performance metrics would be tracked separately
        
        // Check reputation as a proxy for uptime/performance
        if provider.reputation_score < self.min_uptime {
            return false;
        }
        
        // Check replication capability (using capacity total_capacity as a simple proxy)
        if provider.capacity.total_capacity < (self.min_replication as u64 * 1_000_000) { // Minimum storage for replication
            return false;
        }
        
        // Check geographic requirements
        if let Some(required_regions) = &self.geographic_distribution {
            if !required_regions.contains(&provider.location.region) {
                return false;
            }
        }
        
        // Check certifications (simplified - could be added to metadata in full implementation)
        if !self.required_certifications.is_empty() {
            // For now, assume high reputation providers have certifications
            if provider.reputation_score < 0.8 {
                return false;
            }
        }
        
        true
    }
    
    fn validate_against_limits(&self) -> Result<(), String> {
        if self.min_uptime < 0.0 || self.min_uptime > 1.0 {
            return Err("Minimum uptime must be between 0.0 and 1.0".to_string());
        }
        
        if self.max_response_time == 0 {
            return Err("Maximum response time must be greater than 0".to_string());
        }
        
        if self.min_replication == 0 {
            return Err("Minimum replication must be at least 1".to_string());
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_market_creation() {
        let market = StorageMarket::new();
        assert_eq!(market.providers.len(), 0);
        assert_eq!(market.market_stats.total_providers, 0);
    }

    #[test]
    fn test_provider_registration() {
        let mut market = StorageMarket::new();
        
        let provider = create_test_provider();
        market.register_provider(provider).unwrap();
        
        assert_eq!(market.providers.len(), 1);
        assert_eq!(market.market_stats.total_providers, 1);
    }

    #[test]
    fn test_pending_requests() {
        let mut market = StorageMarket::new();
        
        let request = create_test_storage_request();
        let request_id = market.add_pending_request(request.clone()).unwrap();
        
        assert_eq!(market.pending_requests.len(), 1);
        assert!(market.get_pending_request(&request_id).is_some());
        
        // Test fulfillment
        let fulfilled = market.fulfill_request(&request_id);
        assert!(fulfilled.is_some());
        assert_eq!(market.pending_requests.len(), 0);
    }

    #[test]
    fn test_service_advertisements() {
        let mut market = StorageMarket::new();
        
        // Add a provider first
        let provider = create_test_provider();
        market.register_provider(provider).unwrap();
        
        // Add advertisement
        let ad = create_test_advertisement();
        market.add_service_advertisement(ad).unwrap();
        
        assert_eq!(market.service_ads.len(), 1);
        
        let active_ads = market.get_active_advertisements();
        assert_eq!(active_ads.len(), 1);
        
        let provider_ads = market.get_advertisements_by_provider("provider1");
        assert_eq!(provider_ads.len(), 1);
    }

    #[test]
    fn test_regions() {
        let mut market = StorageMarket::new();
        
        let region = create_test_region();
        market.add_region(region).unwrap();
        
        assert_eq!(market.regions.len(), 1);
        assert!(market.get_region("us-west").is_some());
        
        // Add provider in region
        let provider = create_test_provider();
        market.register_provider(provider).unwrap();
        
        let providers_in_region = market.get_providers_in_region("us-west");
        assert_eq!(providers_in_region.len(), 1);
        
        let regional_stats = market.get_regional_stats("us-west");
        assert!(regional_stats.is_some());
        
        let stats = regional_stats.unwrap();
        assert_eq!(stats.provider_count, 1);
        assert!(stats.total_capacity > 0);
    }

    #[test]
    fn test_request_ad_matching() {
        let mut market = StorageMarket::new();
        
        // Setup provider and advertisement
        let provider = create_test_provider();
        market.register_provider(provider).unwrap();
        
        let ad = create_test_advertisement();
        market.add_service_advertisement(ad).unwrap();
        
        // Add pending request
        let request = create_test_storage_request();
        market.add_pending_request(request).unwrap();
        
        // Find matches
        let matches = market.match_requests_with_ads();
        assert!(!matches.is_empty());
        
        let best_match = &matches[0];
        assert!(best_match.match_score > 0.0);
        assert!(best_match.estimated_cost > 0);
    }

    fn create_test_storage_request() -> StorageRequest {
        StorageRequest {
            size: 1024 * 1024 * 1024 * 50, // 50 GB
            tier: StorageTier::Cold,
            duration: 30 * 24 * 3600, // 30 days in seconds
            quality_level: crate::economic::pricing::QualityLevel::Basic,
            geographic_region: Some("West".to_string()),
            urgency: UrgencyLevel::Normal,
            replication_factor: 3,
        }
    }

    fn create_test_advertisement() -> ServiceAdvertisement {
        ServiceAdvertisement {
            ad_id: "ad1".to_string(),
            provider_id: "provider1".to_string(),
            services: vec![ServiceOffering {
                name: "Cold Storage Service".to_string(),
                description: "Reliable cold storage".to_string(),
                tier: StorageTier::Cold,
                min_capacity: 1024 * 1024 * 1024, // 1 GB
                max_capacity: 1024 * 1024 * 1024 * 1024, // 1 TB
                price_per_gb_month: 80,
                sla_guarantees: ServiceSLA {
                    uptime_guarantee: 99.9,
                    response_time_ms: 1000,
                    durability_guarantee: 99.999,
                    support_response_hours: 24,
                },
            }],
            special_offers: vec![SpecialOffer {
                name: "New Customer Discount".to_string(),
                description: "10% off for new customers".to_string(),
                discount_percentage: 10.0,
                conditions: vec!["First month only".to_string()],
                expires_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + 86400 * 30,
                max_usage_count: Some(100),
            }],
            valid_until: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 86400 * 7, // Valid for 7 days
            target_segments: vec![CustomerSegment::SmallBusiness, CustomerSegment::Developer],
        }
    }

    fn create_test_region() -> RegionInfo {
        RegionInfo {
            region_id: "us-west".to_string(),
            region_name: "US West".to_string(),
            countries: vec!["US".to_string()],
            provider_count: 0,
            avg_pricing: 100,
            data_residency_rules: vec!["Data must remain in US".to_string()],
        }
    }

    fn create_test_provider() -> StorageProvider {
        let mut tier_capacity = HashMap::new();
        tier_capacity.insert(StorageTier::Cold, 1024 * 1024 * 1024 * 100); // 100 GB

        let mut tier_pricing = HashMap::new();
        tier_pricing.insert(StorageTier::Cold, 100);

        StorageProvider {
            provider_id: "provider1".to_string(),
            metadata: ProviderMetadata {
                name: "Test Provider".to_string(),
                description: "A test storage provider".to_string(),
                contact_info: ContactInfo {
                    email: Some("test@provider.com".to_string()),
                    support_channels: vec!["email".to_string()],
                    api_endpoints: vec!["https://api.provider.com".to_string()],
                },
                website: Some("https://provider.com".to_string()),
                protocols: vec!["HTTPS".to_string()],
                tags: vec!["reliable".to_string()],
            },
            capacity: StorageCapacity {
                total_capacity: 1024 * 1024 * 1024 * 1000, // 1 TB
                used_capacity: 1024 * 1024 * 1024 * 200,   // 200 GB
                available_capacity: 1024 * 1024 * 1024 * 800, // 800 GB
                reserved_capacity: 0,
                tier_capacity,
            },
            capabilities: ServiceCapabilities {
                supported_tiers: vec![StorageTier::Cold, StorageTier::Warm],
                max_file_size: 1024 * 1024 * 1024 * 10, // 10 GB
                replication_factors: vec![3, 5, 7],
                encryption_support: vec![EncryptionLevel::Standard],
                erasure_coding_support: true,
                backup_support: true,
                cdn_support: false,
            },
            pricing: ProviderPricing {
                tier_pricing,
                bandwidth_pricing: BandwidthPricing {
                    upload_cost_per_gb: 10,
                    download_cost_per_gb: 5,
                    free_bandwidth_gb: 10,
                },
                operation_pricing: OperationPricing {
                    read_operation_cost: 1,
                    write_operation_cost: 2,
                    delete_operation_cost: 1,
                    list_operation_cost: 1,
                },
                volume_discounts: Vec::new(),
                pricing_valid_until: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + 86400,
            },
            location: GeographicLocation {
                country: "US".to_string(),
                region: "West".to_string(),
                city: "San Francisco".to_string(),
                datacenter: Some("DC1".to_string()),
                coordinates: Some(Coordinates {
                    latitude: 37.7749,
                    longitude: -122.4194,
                }),
            },
            reputation_score: 0.8,
            availability: ProviderAvailability {
                status: AvailabilityStatus::Online,
                current_load: 0.3,
                response_time: 100,
                maintenance_windows: Vec::new(),
            },
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            is_online: true,
        }
    }
}
