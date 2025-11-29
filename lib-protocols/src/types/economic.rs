/// Global token name configuration
/// To rebrand the token, change this constant in zhtp/src/config/aggregation.rs
pub const TOKEN_NAME: &str = "SOV";

/// Economic assessment structure for processing fees and costs
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EconomicAssessment {
    /// Network fee amount in tokens
    pub network_fee: u64,
    /// DAO fee amount in tokens
    pub dao_fee: u64,
    /// Total fee amount in tokens
    pub total_fee: u64,
    /// Storage cost estimate in tokens
    pub storage_cost: u64,
    /// Bandwidth cost estimate in tokens
    pub bandwidth_cost: u64,
    /// Processing cost estimate in tokens
    pub processing_cost: u64,
    /// Quality score multiplier (0.0 to 1.0)
    pub quality_multiplier: f64,
    /// Estimated completion time in seconds
    pub estimated_time: u64,
    /// Currency used for fees
    pub currency: String,
}

impl EconomicAssessment {
    /// Create a new economic assessment with default values
    pub fn new() -> Self {
        Self {
            network_fee: 0,
            dao_fee: 0,
            total_fee: 0,
            storage_cost: 0,
            bandwidth_cost: 0,
            processing_cost: 0,
            quality_multiplier: 1.0,
            estimated_time: 0,
            currency: TOKEN_NAME.to_string(),
        }
    }

    /// Create an assessment with basic fee structure
    pub fn with_fees(network_fee: u64, dao_fee: u64) -> Self {
        Self {
            network_fee,
            dao_fee,
            total_fee: network_fee + dao_fee,
            storage_cost: 0,
            bandwidth_cost: 0,
            processing_cost: 0,
            quality_multiplier: 1.0,
            estimated_time: 0,
            currency: TOKEN_NAME.to_string(),
        }
    }

    /// Calculate total cost including all components
    pub fn calculate_total_cost(&self) -> u64 {
        self.total_fee + self.storage_cost + self.bandwidth_cost + self.processing_cost
    }

    /// Check if the assessment includes any fees
    pub fn has_fees(&self) -> bool {
        self.total_fee > 0
    }
}

impl Default for EconomicAssessment {
    fn default() -> Self {
        Self::new()
    }
}
