//! Employment Contract Registry for DAO Employees
//!
//! Tracks employment contracts with tax, profit-sharing, and voting power integration.
//! Supports both Public Access (NP DAOs) and Employment (FP DAOs) contract types.

use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use crate::integration::crypto_integration::PublicKey;
use crate::contracts::utils::integer_sqrt;
use blake3;
use std::collections::HashMap;

/// Employment contract access types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractAccessType {
    /// Public access (NP DAOs, all verified SIDs)
    PublicAccess,
    /// Employment (FP DAOs, invite-only)
    Employment,
}

/// Employment contract status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmploymentStatus {
    /// Contract is active
    Active,
    /// Contract is suspended
    Suspended,
    /// Contract is terminated
    Terminated,
    /// Contract is completed
    Completed,
}

/// Economic period for compensation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EconomicPeriod {
    /// Monthly (approximately 175,200 blocks at 6s/block)
    Monthly,
    /// Quarterly
    Quarterly,
    /// Annually
    Annually,
}

impl EconomicPeriod {
    /// Get period duration in blocks (assuming 6s per block)
    pub fn blocks(&self) -> u64 {
        match self {
            EconomicPeriod::Monthly => 175_200,
            EconomicPeriod::Quarterly => 525_600,
            EconomicPeriod::Annually => 2_102_400,
        }
    }
}

/// Termination reason
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminationReason {
    /// Voluntary resignation
    Resignation,
    /// Performance-based termination
    Performance,
    /// Company-initiated layoff
    Layoff,
    /// Mutual agreement
    Mutual,
}

/// Employment contract details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmploymentContract {
    pub contract_id: [u8; 32],
    pub dao_id: [u8; 32],
    pub employee_sid: PublicKey,
    pub contract_type: ContractAccessType,
    pub status: EmploymentStatus,

    // Compensation
    pub compensation_amount: u64,  // In DAO tokens per period
    pub payment_period: EconomicPeriod,

    // Tax and compliance
    pub tax_rate_basis_points: u16,  // e.g., 2000 = 20%
    pub tax_jurisdiction: String,

    // Profit sharing
    pub profit_share_percentage: u16,  // Basis points, e.g., 500 = 5%

    // Governance
    pub voting_power: u64,  // Based on CBE holdings + tenure

    // Lifecycle
    pub start_height: u64,
    pub end_height: Option<u64>,
    pub last_payment_height: u64,
}

/// Payment details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentDetails {
    pub gross_amount: u64,
    pub tax_amount: u64,
    pub net_amount: u64,
    pub periods_elapsed: u64,
    pub payment_height: u64,
}

/// Profit share calculation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfitShareResult {
    pub dao_profit: u64,
    pub share_percentage: u16,
    pub share_amount: u64,
}

/// Employment Registry main contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmploymentRegistry {
    pub contracts: Vec<EmploymentContract>,
    pub contract_by_sid: HashMap<[u8; 32], Vec<[u8; 32]>>,  // SID → contract IDs
    pub contract_by_dao: HashMap<[u8; 32], Vec<[u8; 32]>>,  // DAO → contract IDs
}

impl EmploymentRegistry {
    /// Create a new employment registry
    pub fn new() -> Self {
        Self {
            contracts: Vec::new(),
            contract_by_sid: HashMap::new(),
            contract_by_dao: HashMap::new(),
        }
    }

    /// Create a new employment contract
    pub fn create_employment_contract(
        &mut self,
        dao_id: [u8; 32],
        employee_sid: PublicKey,
        contract_type: ContractAccessType,
        compensation_amount: u64,
        payment_period: EconomicPeriod,
        tax_rate_basis_points: u16,
        tax_jurisdiction: String,
        profit_share_percentage: u16,
        _caller: &PublicKey,
        current_height: u64,
    ) -> Result<[u8; 32]> {
        // Verify caller is authorized (for now, accept any call)
        // In real implementation, would check governance/HR authorization

        // Validate tax rate (max 50%)
        if tax_rate_basis_points > 5000 {
            return Err(anyhow!("Tax rate cannot exceed 50% (5000 basis points)"));
        }

        // Validate profit share (max 20%)
        if profit_share_percentage > 2000 {
            return Err(anyhow!("Profit share cannot exceed 20% (2000 basis points)"));
        }

        // For Employment contracts, require positive compensation
        if contract_type == ContractAccessType::Employment && compensation_amount == 0 {
            return Err(anyhow!("Employment contracts require positive compensation"));
        }

        // Generate contract ID
        let contract_id = derive_contract_id(&dao_id, &employee_sid.key_id, current_height);

        let contract = EmploymentContract {
            contract_id,
            dao_id,
            employee_sid: employee_sid.clone(),
            contract_type,
            status: EmploymentStatus::Active,
            compensation_amount,
            payment_period,
            tax_rate_basis_points,
            tax_jurisdiction,
            profit_share_percentage,
            voting_power: 0,
            start_height: current_height,
            end_height: None,
            last_payment_height: current_height,
        };

        // Index by SID
        let sid_key = employee_sid.key_id;
        self.contract_by_sid
            .entry(sid_key)
            .or_insert_with(Vec::new)
            .push(contract_id);

        // Index by DAO
        self.contract_by_dao
            .entry(dao_id)
            .or_insert_with(Vec::new)
            .push(contract_id);

        self.contracts.push(contract);
        Ok(contract_id)
    }

    /// Process payroll for a contract
    pub fn process_payroll(
        &mut self,
        contract_id: [u8; 32],
        current_height: u64,
    ) -> Result<PaymentDetails> {
        let contract = self.contracts
            .iter_mut()
            .find(|c| c.contract_id == contract_id)
            .ok_or_else(|| anyhow!("Employment contract not found"))?;

        // Verify contract is active
        if contract.status != EmploymentStatus::Active {
            return Err(anyhow!("Cannot process payroll for inactive contract"));
        }

        // Calculate periods elapsed
        let period_blocks = contract.payment_period.blocks();
        let blocks_since_payment = current_height.saturating_sub(contract.last_payment_height);
        let periods_elapsed = blocks_since_payment / period_blocks;

        if periods_elapsed == 0 {
            return Err(anyhow!("Not enough time has passed for payment"));
        }

        // Calculate amounts
        let gross_amount = contract.compensation_amount.saturating_mul(periods_elapsed);
        let tax_amount = (gross_amount as u128)
            .saturating_mul(contract.tax_rate_basis_points as u128)
            .saturating_div(10000) as u64;
        let net_amount = gross_amount.saturating_sub(tax_amount);

        // Update contract
        contract.last_payment_height = current_height;

        Ok(PaymentDetails {
            gross_amount,
            tax_amount,
            net_amount,
            periods_elapsed,
            payment_height: current_height,
        })
    }

    /// Calculate profit share for a contract
    pub fn calculate_profit_share(
        &self,
        contract_id: [u8; 32],
        dao_profit: u64,
    ) -> Result<ProfitShareResult> {
        let contract = self.contracts
            .iter()
            .find(|c| c.contract_id == contract_id)
            .ok_or_else(|| anyhow!("Employment contract not found"))?;

        let share_amount = (dao_profit as u128)
            .saturating_mul(contract.profit_share_percentage as u128)
            .saturating_div(10000) as u64;

        Ok(ProfitShareResult {
            dao_profit,
            share_percentage: contract.profit_share_percentage,
            share_amount,
        })
    }

    /// Update voting power based on CBE balance and tenure
    pub fn update_voting_power(
        &mut self,
        contract_id: [u8; 32],
        cbe_balance: u64,
        current_height: u64,
    ) -> Result<u64> {
        let contract = self.contracts
            .iter_mut()
            .find(|c| c.contract_id == contract_id)
            .ok_or_else(|| anyhow!("Employment contract not found"))?;

        // Calculate tenure (in blocks)
        let tenure_blocks = current_height.saturating_sub(contract.start_height);

        // Tenure bonus: sqrt(blocks) / 1000, capped at 2x
        let tenure_bonus = {
            let sqrt_tenure = integer_sqrt(tenure_blocks);
            let bonus = sqrt_tenure.saturating_div(1000).min(1000); // Cap at 100% bonus
            bonus
        };

        // Voting power = cbe_balance * (1 + tenure_bonus / 1000)
        let voting_power = (cbe_balance as u128)
            .saturating_mul(10000 + tenure_bonus as u128)
            .saturating_div(10000) as u64;

        contract.voting_power = voting_power;
        Ok(voting_power)
    }

    /// Terminate a contract
    pub fn terminate_contract(
        &mut self,
        contract_id: [u8; 32],
        _reason: TerminationReason,
        _caller: &PublicKey,
        current_height: u64,
    ) -> Result<()> {
        let contract = self.contracts
            .iter_mut()
            .find(|c| c.contract_id == contract_id)
            .ok_or_else(|| anyhow!("Employment contract not found"))?;

        if contract.status == EmploymentStatus::Terminated {
            return Err(anyhow!("Contract is already terminated"));
        }

        contract.status = EmploymentStatus::Terminated;
        contract.end_height = Some(current_height);

        Ok(())
    }

    /// Get contracts for a SID
    pub fn get_contracts_by_sid(&self, sid: &[u8; 32]) -> Vec<&EmploymentContract> {
        if let Some(ids) = self.contract_by_sid.get(sid) {
            ids.iter()
                .filter_map(|id| self.contracts.iter().find(|c| &c.contract_id == id))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get contracts for a DAO
    pub fn get_contracts_by_dao(&self, dao_id: &[u8; 32]) -> Vec<&EmploymentContract> {
        if let Some(ids) = self.contract_by_dao.get(dao_id) {
            ids.iter()
                .filter_map(|id| self.contracts.iter().find(|c| &c.contract_id == id))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get a specific contract
    pub fn get_contract(&self, contract_id: &[u8; 32]) -> Option<&EmploymentContract> {
        self.contracts.iter().find(|c| &c.contract_id == contract_id)
    }
}

/// Derive deterministic contract ID
fn derive_contract_id(dao_id: &[u8; 32], sid: &[u8; 32], height: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"employment_contract");
    hasher.update(dao_id);
    hasher.update(sid);
    hasher.update(&height.to_le_bytes());
    hasher.finalize().into()
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_public_key(id: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: vec![id; 32],
            kyber_pk: vec![id; 32],
            key_id: [id; 32],
        }
    }

    #[test]
    fn test_create_employment_contract() {
        let mut registry = EmploymentRegistry::new();

        let contract_id = registry.create_employment_contract(
            [1u8; 32],
            test_public_key(2),
            ContractAccessType::Employment,
            100_00000000,  // 100 tokens per month
            EconomicPeriod::Monthly,
            2000,  // 20% tax
            "US".to_string(),
            500,   // 5% profit share
            &test_public_key(3),
            100,
        );

        assert!(contract_id.is_ok());
        assert_eq!(registry.contracts.len(), 1);
    }

    #[test]
    fn test_create_public_access_contract() {
        let mut registry = EmploymentRegistry::new();

        let contract_id = registry.create_employment_contract(
            [1u8; 32],
            test_public_key(2),
            ContractAccessType::PublicAccess,
            0,  // No compensation for public access
            EconomicPeriod::Monthly,
            0,
            "Global".to_string(),
            0,
            &test_public_key(3),
            100,
        );

        assert!(contract_id.is_ok());
        let contract = &registry.contracts[0];
        assert_eq!(contract.contract_type, ContractAccessType::PublicAccess);
    }

    #[test]
    fn test_reject_invalid_tax_rate() {
        let mut registry = EmploymentRegistry::new();

        let result = registry.create_employment_contract(
            [1u8; 32],
            test_public_key(2),
            ContractAccessType::Employment,
            100_00000000,
            EconomicPeriod::Monthly,
            6000,  // 60% tax (exceeds limit)
            "US".to_string(),
            500,
            &test_public_key(3),
            100,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_reject_invalid_profit_share() {
        let mut registry = EmploymentRegistry::new();

        let result = registry.create_employment_contract(
            [1u8; 32],
            test_public_key(2),
            ContractAccessType::Employment,
            100_00000000,
            EconomicPeriod::Monthly,
            2000,
            "US".to_string(),
            3000,  // 30% profit share (exceeds limit)
            &test_public_key(3),
            100,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_process_payroll() {
        let mut registry = EmploymentRegistry::new();

        let contract_id = registry
            .create_employment_contract(
                [1u8; 32],
                test_public_key(2),
                ContractAccessType::Employment,
                100_00000000,
                EconomicPeriod::Monthly,
                2000,
                "US".to_string(),
                500,
                &test_public_key(3),
                100,
            )
            .unwrap();

        // Process payroll after one month
        let payment = registry
            .process_payroll(contract_id, 100 + 175_200)
            .unwrap();

        assert_eq!(payment.periods_elapsed, 1);
        assert_eq!(payment.gross_amount, 100_00000000);
        assert_eq!(payment.tax_amount, 20_00000000); // 20% tax
        assert_eq!(payment.net_amount, 80_00000000);
    }

    #[test]
    fn test_process_multiple_payroll_periods() {
        let mut registry = EmploymentRegistry::new();

        let contract_id = registry
            .create_employment_contract(
                [1u8; 32],
                test_public_key(2),
                ContractAccessType::Employment,
                100_00000000,
                EconomicPeriod::Monthly,
                0,  // No tax
                "US".to_string(),
                500,
                &test_public_key(3),
                100,
            )
            .unwrap();

        // Process payroll after three months
        let payment = registry
            .process_payroll(contract_id, 100 + 175_200 * 3)
            .unwrap();

        assert_eq!(payment.periods_elapsed, 3);
        assert_eq!(payment.gross_amount, 300_00000000);
        assert_eq!(payment.tax_amount, 0);
        assert_eq!(payment.net_amount, 300_00000000);
    }

    #[test]
    fn test_calculate_profit_share() {
        let mut registry = EmploymentRegistry::new();

        let contract_id = registry
            .create_employment_contract(
                [1u8; 32],
                test_public_key(2),
                ContractAccessType::Employment,
                100_00000000,
                EconomicPeriod::Monthly,
                2000,
                "US".to_string(),
                500,  // 5% profit share
                &test_public_key(3),
                100,
            )
            .unwrap();

        let result = registry
            .calculate_profit_share(contract_id, 1_000_00000000)
            .unwrap();

        assert_eq!(result.dao_profit, 1_000_00000000);
        assert_eq!(result.share_percentage, 500);
        assert_eq!(result.share_amount, 50_00000000); // 5% of profit
    }

    #[test]
    fn test_update_voting_power() {
        let mut registry = EmploymentRegistry::new();

        let contract_id = registry
            .create_employment_contract(
                [1u8; 32],
                test_public_key(2),
                ContractAccessType::Employment,
                100_00000000,
                EconomicPeriod::Monthly,
                2000,
                "US".to_string(),
                500,
                &test_public_key(3),
                100,
            )
            .unwrap();

        // Update voting power immediately (no tenure bonus)
        let power = registry
            .update_voting_power(contract_id, 10_000, 100)
            .unwrap();
        assert_eq!(power, 10_000);

        // Update with tenure bonus (after 1M blocks)
        let power = registry
            .update_voting_power(contract_id, 10_000, 100 + 1_000_000)
            .unwrap();
        // sqrt(1_000_000) = 1000, bonus = 1000/1000 = 1, voting power = 10_000 * (1 + 0.001) ≈ 10_010
        assert!(power > 10_000);
    }

    #[test]
    fn test_terminate_contract() {
        let mut registry = EmploymentRegistry::new();

        let contract_id = registry
            .create_employment_contract(
                [1u8; 32],
                test_public_key(2),
                ContractAccessType::Employment,
                100_00000000,
                EconomicPeriod::Monthly,
                2000,
                "US".to_string(),
                500,
                &test_public_key(3),
                100,
            )
            .unwrap();

        registry
            .terminate_contract(contract_id, TerminationReason::Resignation, &test_public_key(3), 200)
            .unwrap();

        let contract = registry.get_contract(&contract_id).unwrap();
        assert_eq!(contract.status, EmploymentStatus::Terminated);
        assert_eq!(contract.end_height, Some(200));
    }

    #[test]
    fn test_get_contracts_by_sid() {
        let mut registry = EmploymentRegistry::new();
        let sid = test_public_key(2);

        let id1 = registry
            .create_employment_contract(
                [1u8; 32],
                sid.clone(),
                ContractAccessType::Employment,
                100_00000000,
                EconomicPeriod::Monthly,
                2000,
                "US".to_string(),
                500,
                &test_public_key(3),
                100,
            )
            .unwrap();

        let id2 = registry
            .create_employment_contract(
                [2u8; 32],
                sid.clone(),
                ContractAccessType::Employment,
                100_00000000,
                EconomicPeriod::Monthly,
                2000,
                "US".to_string(),
                500,
                &test_public_key(3),
                100,
            )
            .unwrap();

        let contracts = registry.get_contracts_by_sid(&sid.key_id);
        assert_eq!(contracts.len(), 2);
        assert!(contracts.iter().any(|c| c.contract_id == id1));
        assert!(contracts.iter().any(|c| c.contract_id == id2));
    }

    #[test]
    fn test_get_contracts_by_dao() {
        let mut registry = EmploymentRegistry::new();
        let dao_id = [1u8; 32];

        let id1 = registry
            .create_employment_contract(
                dao_id,
                test_public_key(2),
                ContractAccessType::Employment,
                100_00000000,
                EconomicPeriod::Monthly,
                2000,
                "US".to_string(),
                500,
                &test_public_key(3),
                100,
            )
            .unwrap();

        let id2 = registry
            .create_employment_contract(
                dao_id,
                test_public_key(4),
                ContractAccessType::Employment,
                100_00000000,
                EconomicPeriod::Monthly,
                2000,
                "US".to_string(),
                500,
                &test_public_key(3),
                100,
            )
            .unwrap();

        let contracts = registry.get_contracts_by_dao(&dao_id);
        assert_eq!(contracts.len(), 2);
        assert!(contracts.iter().any(|c| c.contract_id == id1));
        assert!(contracts.iter().any(|c| c.contract_id == id2));
    }
}
