use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::PublicKey;
use crate::contracts::tokens::core::TokenContract;
use super::types::*;

/// Development Grants Fund Contract - Phase 2 Final Implementation
///
/// **Role (Boundary Definition):**
/// - Sink for protocol fees (exactly 10% from upstream fee router)
/// - Governance-controlled allocator (two-phase approval + execution)
/// - Immutable ledger of all disbursements
///
/// **NOT:**
/// - A treasury with arbitrary withdrawals
/// - A discretionary multisig
/// - A query interface for proposals (governance authority owns proposal data)
///
/// **Consensus-Critical Invariants:**
/// - **Auth (G1):** Only governance_authority may approve or execute grants
/// - **Binding (G2):** Recipient and amount immutably bound at approval time
/// - **Replay (G3):** Each proposal executes exactly once
/// - **Atomic (A1):** Token transfer and ledger update are inseparable
/// - **Balance (A2):** Disbursements never exceed current balance
/// - **Append-only (A3):** Disbursement records are immutable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevGrants {
    /// Governance authority (hard-bound at initialization)
    /// Only this authority can approve or execute grants
    governance_authority: PublicKey,

    /// Current available balance
    balance: u64,

    /// Total fees received (audit trail)
    total_received: u64,

    /// Total amount disbursed (audit trail)
    total_disbursed: u64,

    /// Approved grants (governance-binding payload storage)
    /// Maps proposal_id -> ApprovedGrant
    /// Once stored, recipient and amount are immutable
    approved: HashMap<ProposalId, ApprovedGrant>,

    /// Disbursement log (append-only, immutable)
    /// Each record includes actual token_burned amount
    disbursements: Vec<Disbursement>,
}

impl DevGrants {
    /// Create a new DevGrants contract with governance authority
    ///
    /// **Consensus-Critical:** governance_authority is hard-bound and immutable.
    /// Only this authority may approve or execute grants.
    ///
    /// # Arguments
    /// * `governance_authority` - The PublicKey authorized to approve/execute grants
    pub fn new(governance_authority: PublicKey) -> Self {
        Self {
            governance_authority,
            balance: 0,
            total_received: 0,
            total_disbursed: 0,
            approved: HashMap::new(),
            disbursements: vec![],
        }
    }

    /// Authority enforcement helper
    ///
    /// **Consensus-Critical:** All state-mutating operations check governance_authority.
    /// This check is NOT delegable and MUST be enforced in the contract.
    fn ensure_governance(&self, caller: &PublicKey) -> Result<(), Error> {
        if caller != &self.governance_authority {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// Recipient validation - extract key_id from PublicKey
    ///
    /// **Design Rationale:**
    /// - Only key_id is stored (fixed-width: [u8; 32])
    /// - Full PQC material (Dilithium + Kyber keys) is never stored
    /// - Keeps contract state lean and deterministic
    /// - Matches PublicKey semantics (key_id is the stable identity)
    fn validate_recipient(pk: &PublicKey) -> Result<[u8; 32], Error> {
        Ok(pk.key_id)
    }

    // ========================================================================
    // PUBLIC API
    // ========================================================================

    /// Receive protocol fees (10% already computed upstream)
    ///
    /// **Called by:** Protocol fee router (upstream)
    ///
    /// **Design Constraint:** This contract is a passive receiver.
    /// - Validates amount > 0
    /// - Updates balance
    /// - Does NOT compute percentages (upstream enforces 10% routing)
    ///
    /// # Failure modes that halt:
    /// - amount is zero
    /// - balance overflow
    pub fn receive_fees(&mut self, amount: u64) -> Result<(), Error> {
        if amount == 0 {
            return Err(Error::ZeroAmount);
        }

        self.total_received = self.total_received
            .checked_add(amount)
            .ok_or(Error::Overflow)?;

        self.balance = self.balance
            .checked_add(amount)
            .ok_or(Error::Overflow)?;

        Ok(())
    }

    /// Approve a grant (governance-binding payload)
    ///
    /// **Called by:** Governance authority only
    ///
    /// **Consensus-Critical (Payload Binding Invariant G2):**
    /// Once approved, recipient and amount are IMMUTABLE.
    /// Later execution uses ONLY these governance-approved values.
    /// This prevents parameter tampering.
    ///
    /// # Arguments
    /// * `caller` - Must equal governance_authority
    /// * `proposal_id` - Unique proposal identifier
    /// * `recipient` - PublicKey of grant recipient
    /// * `amount` - Grant amount (must be > 0)
    /// * `current_height` - Block height (audit trail)
    ///
    /// # Failure modes that halt:
    /// - caller is not governance_authority (Unauthorized)
    /// - proposal_id already approved (ProposalAlreadyApproved)
    /// - amount is zero (ZeroAmount)
    pub fn approve_grant(
        &mut self,
        caller: &PublicKey,
        proposal_id: ProposalId,
        recipient: &PublicKey,
        amount: u64,
        current_height: u64,
    ) -> Result<(), Error> {
        // Invariant G1: Authorization check
        self.ensure_governance(caller)?;

        // Invariant G3: Prevent duplicate approval
        if self.approved.contains_key(&proposal_id) {
            return Err(Error::ProposalAlreadyApproved);
        }

        // Validate amount > 0
        let amt = Amount::try_new(amount)?;

        // Validate recipient and extract key_id
        let recipient_key_id = Self::validate_recipient(recipient)?;

        // Store immutable binding
        let grant = ApprovedGrant {
            proposal_id,
            recipient_key_id,
            amount: amt,
            approved_at: current_height,
            status: ProposalStatus::Approved,
        };

        self.approved.insert(proposal_id, grant);
        Ok(())
    }

    /// Execute a grant (atomic token transfer + ledger update)
    ///
    /// **Called by:** Governance authority only
    ///
    /// **Consensus-Critical (Atomicity Invariant A1):**
    /// Token transfer and ledger update are inseparable.
    /// Either:
    /// 1. Token transfer succeeds AND ledger is updated, OR
    /// 2. Both fail (no partial state)
    ///
    /// **Consensus-Critical (Payload Binding Invariant G2):**
    /// Uses ONLY the governance-approved recipient and amount.
    /// Passed recipient.key_id must match approved grant's recipient_key_id.
    /// Caller cannot tamper with amount or destination.
    ///
    /// **Consensus-Critical (Replay Protection Invariant G3):**
    /// Each proposal executes exactly once.
    ///
    /// # Arguments
    /// * `caller` - Must equal governance_authority
    /// * `proposal_id` - Approved proposal ID
    /// * `recipient` - PublicKey of grant recipient (must match approved)
    /// * `current_height` - Block height (audit trail)
    /// * `token` - Token contract (mutable) to perform transfer
    /// * `self_address` - This contract's PublicKey (for transfer from)
    ///
    /// # Failure modes that halt:
    /// - caller is not governance_authority (Unauthorized)
    /// - proposal_id not in approved set (ProposalNotApproved)
    /// - proposal already executed (ProposalAlreadyExecuted)
    /// - recipient.key_id != approved grant's recipient_key_id (InvalidRecipient)
    /// - disbursement amount > balance (InsufficientBalance)
    /// - token transfer fails (TokenTransferFailed)
    /// - balance underflow (Overflow)
    pub fn execute_grant(
        &mut self,
        caller: &PublicKey,
        proposal_id: ProposalId,
        recipient: &PublicKey,
        current_height: u64,
        token: &mut TokenContract,
        self_address: &PublicKey,
    ) -> Result<(), Error> {
        // Invariant G1: Authorization check
        self.ensure_governance(caller)?;

        // Invariant G2: Proposal must be approved
        let grant = self.approved.get_mut(&proposal_id)
            .ok_or(Error::ProposalNotApproved)?;

        // Invariant G3: Prevent replay (proposal must not be executed)
        if grant.status != ProposalStatus::Approved {
            return Err(Error::ProposalAlreadyExecuted);
        }

        // Invariant G2: Payload binding - verify recipient matches approved
        let recipient_key_id = Self::validate_recipient(recipient)?;
        if recipient_key_id != grant.recipient_key_id {
            return Err(Error::InvalidRecipient);
        }

        // Invariant A2: Balance constraint check
        let amt = grant.amount.get();
        if self.balance < amt {
            return Err(Error::InsufficientBalance);
        }

        // ====================================================================
        // ATOMIC TRANSFER PHASE - Token transfer must succeed
        // ====================================================================
        let burned = token
            .transfer(self_address, recipient, amt)
            .map_err(|_| Error::TokenTransferFailed)?;

        // ====================================================================
        // STATE MUTATION PHASE - Only after successful token transfer
        // ====================================================================

        // Update internal balances
        self.balance = self.balance
            .checked_sub(amt)
            .ok_or(Error::Underflow)?;

        self.total_disbursed = self.total_disbursed
            .checked_add(amt)
            .ok_or(Error::Overflow)?;

        // Mark proposal as executed (replay protection)
        grant.status = ProposalStatus::Executed;

        // Create immutable disbursement record
        let disbursement = Disbursement {
            proposal_id,
            recipient_key_id: grant.recipient_key_id,
            amount: grant.amount,
            executed_at: current_height,
            token_burned: burned,
        };

        self.disbursements.push(disbursement);

        Ok(())
    }

    // ========================================================================
    // READ-ONLY VIEWS (No state mutations)
    // ========================================================================

    /// Get current available balance
    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// Get total fees received (audit trail)
    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    /// Get total amount disbursed (audit trail)
    pub fn total_disbursed(&self) -> u64 {
        self.total_disbursed
    }

    /// Get approved grant by proposal ID
    pub fn grant(&self, proposal_id: ProposalId) -> Option<&ApprovedGrant> {
        self.approved.get(&proposal_id)
    }

    /// Get immutable view of all disbursements
    ///
    /// **Invariant A3:** Append-only ledger.
    /// Returns complete history in execution order.
    /// Callers can verify:
    /// - No duplicates (by proposal_id)
    /// - Monotonic index ordering
    /// - Full auditability of fund movements
    pub fn disbursements(&self) -> &[Disbursement] {
        &self.disbursements
    }

    /// Get total disbursement count
    pub fn disbursement_count(&self) -> usize {
        self.disbursements.len()
    }
}

impl Default for DevGrants {
    fn default() -> Self {
        // Default to zero-authority for testing only
        // Production must always call new() with valid governance authority
        Self::new(PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id: [0u8; 32],
        })
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_public_key(id: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: vec![id],
            kyber_pk: vec![id],
            key_id: [id; 32],
        }
    }

    fn test_governance() -> PublicKey {
        test_public_key(99)
    }

    fn test_recipient() -> PublicKey {
        test_public_key(42)
    }

    #[test]
    fn test_new_contract_initialized() {
        let gov = test_governance();
        let dg = DevGrants::new(gov.clone());

        assert_eq!(dg.balance(), 0);
        assert_eq!(dg.total_received(), 0);
        assert_eq!(dg.total_disbursed(), 0);
        assert_eq!(dg.disbursement_count(), 0);
    }

    #[test]
    fn test_receive_fees_success() {
        let mut dg = DevGrants::new(test_governance());

        let result = dg.receive_fees(1000);
        assert!(result.is_ok());
        assert_eq!(dg.balance(), 1000);
        assert_eq!(dg.total_received(), 1000);
    }

    #[test]
    fn test_receive_fees_zero_fails() {
        let mut dg = DevGrants::new(test_governance());

        let result = dg.receive_fees(0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::ZeroAmount);
    }

    #[test]
    fn test_approve_grant_success() {
        let gov = test_governance();
        let recipient = test_recipient();
        let mut dg = DevGrants::new(gov.clone());

        let result = dg.approve_grant(&gov, 1, &recipient, 500, 100);
        assert!(result.is_ok());

        let grant = dg.grant(1).unwrap();
        assert_eq!(grant.proposal_id, 1);
        assert_eq!(grant.amount.get(), 500);
        assert_eq!(grant.status, ProposalStatus::Approved);
    }

    #[test]
    fn test_approve_grant_unauthorized_fails() {
        let gov = test_governance();
        let wrong_gov = test_public_key(88);
        let recipient = test_recipient();
        let mut dg = DevGrants::new(gov.clone());

        let result = dg.approve_grant(&wrong_gov, 1, &recipient, 500, 100);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::Unauthorized);
    }

    #[test]
    fn test_approve_grant_zero_amount_fails() {
        let gov = test_governance();
        let recipient = test_recipient();
        let mut dg = DevGrants::new(gov.clone());

        let result = dg.approve_grant(&gov, 1, &recipient, 0, 100);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::ZeroAmount);
    }

    #[test]
    fn test_approve_grant_duplicate_fails() {
        let gov = test_governance();
        let recipient = test_recipient();
        let mut dg = DevGrants::new(gov.clone());

        dg.approve_grant(&gov, 1, &recipient, 500, 100).unwrap();
        let result = dg.approve_grant(&gov, 1, &recipient, 600, 101);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::ProposalAlreadyApproved);
    }

    #[test]
    fn test_payload_binding_approved_amount_immutable() {
        let gov = test_governance();
        let recipient = test_recipient();
        let mut dg = DevGrants::new(gov.clone());

        dg.approve_grant(&gov, 1, &recipient, 500, 100).unwrap();

        // Verify approved amount is stored and immutable
        let grant = dg.grant(1).unwrap();
        assert_eq!(grant.amount.get(), 500);
        assert_eq!(grant.status, ProposalStatus::Approved);
    }

    #[test]
    fn test_payload_binding_approved_recipient_immutable() {
        let gov = test_governance();
        let recipient = test_recipient();
        let mut dg = DevGrants::new(gov.clone());

        dg.approve_grant(&gov, 1, &recipient, 500, 100).unwrap();

        // Verify approved recipient is stored and immutable
        let grant = dg.grant(1).unwrap();
        assert_eq!(grant.recipient_key_id, recipient.key_id);
    }

    // ========================================================================
    // EXECUTE_GRANT TESTS - Comprehensive coverage for atomic execution
    // ========================================================================

    fn setup_token_contract() -> TokenContract {
        let creator = test_public_key(1);
        TokenContract::new_custom(
            "TestToken".to_string(),
            "TEST".to_string(),
            100_000, // Initial supply to creator
            creator,
        )
    }

    #[test]
    fn test_execute_grant_success() {
        let gov = test_governance();
        let recipient = test_recipient();
        let contract_addr = test_public_key(10);
        let mut dg = DevGrants::new(gov.clone());
        let mut token = setup_token_contract();

        // Setup: Add fees to contract, mint tokens to contract address
        dg.receive_fees(1000).unwrap();
        token.mint(&contract_addr, 1000).unwrap();

        // Approve grant
        dg.approve_grant(&gov, 1, &recipient, 500, 100).unwrap();

        // Execute grant
        let result = dg.execute_grant(&gov, 1, &recipient, 200, &mut token, &contract_addr);
        assert!(result.is_ok());

        // Verify balance changes
        assert_eq!(dg.balance(), 500); // 1000 - 500
        assert_eq!(dg.total_disbursed(), 500);
        assert_eq!(token.balance_of(&recipient), 500);
        assert_eq!(token.balance_of(&contract_addr), 500); // 1000 - 500

        // Verify disbursement record
        assert_eq!(dg.disbursement_count(), 1);
        let disbursements = dg.disbursements();
        assert_eq!(disbursements[0].proposal_id, 1);
        assert_eq!(disbursements[0].recipient_key_id, recipient.key_id);
        assert_eq!(disbursements[0].amount.get(), 500);
        assert_eq!(disbursements[0].executed_at, 200);
        assert_eq!(disbursements[0].token_burned, 0); // Non-deflationary token

        // Verify proposal status changed
        let grant = dg.grant(1).unwrap();
        assert_eq!(grant.status, ProposalStatus::Executed);
    }

    #[test]
    fn test_execute_grant_unauthorized_fails() {
        let gov = test_governance();
        let wrong_caller = test_public_key(88);
        let recipient = test_recipient();
        let contract_addr = test_public_key(10);
        let mut dg = DevGrants::new(gov.clone());
        let mut token = setup_token_contract();

        // Setup
        dg.receive_fees(1000).unwrap();
        token.mint(&contract_addr, 1000).unwrap();
        dg.approve_grant(&gov, 1, &recipient, 500, 100).unwrap();

        // Try to execute with wrong caller
        let result = dg.execute_grant(&wrong_caller, 1, &recipient, 200, &mut token, &contract_addr);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::Unauthorized);

        // Verify no state changes occurred
        assert_eq!(dg.balance(), 1000);
        assert_eq!(dg.total_disbursed(), 0);
        assert_eq!(dg.disbursement_count(), 0);
    }

    #[test]
    fn test_execute_grant_not_approved_fails() {
        let gov = test_governance();
        let recipient = test_recipient();
        let contract_addr = test_public_key(10);
        let mut dg = DevGrants::new(gov.clone());
        let mut token = setup_token_contract();

        // Setup but don't approve
        dg.receive_fees(1000).unwrap();
        token.mint(&contract_addr, 1000).unwrap();

        // Try to execute without approval
        let result = dg.execute_grant(&gov, 1, &recipient, 200, &mut token, &contract_addr);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::ProposalNotApproved);

        // Verify no state changes occurred
        assert_eq!(dg.balance(), 1000);
        assert_eq!(dg.total_disbursed(), 0);
        assert_eq!(dg.disbursement_count(), 0);
    }

    #[test]
    fn test_execute_grant_already_executed_fails() {
        let gov = test_governance();
        let recipient = test_recipient();
        let contract_addr = test_public_key(10);
        let mut dg = DevGrants::new(gov.clone());
        let mut token = setup_token_contract();

        // Setup
        dg.receive_fees(1000).unwrap();
        token.mint(&contract_addr, 1000).unwrap();
        dg.approve_grant(&gov, 1, &recipient, 500, 100).unwrap();

        // Execute once (should succeed)
        dg.execute_grant(&gov, 1, &recipient, 200, &mut token, &contract_addr).unwrap();

        // Try to execute again (replay protection)
        let result = dg.execute_grant(&gov, 1, &recipient, 201, &mut token, &contract_addr);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::ProposalAlreadyExecuted);

        // Verify state only changed once
        assert_eq!(dg.balance(), 500);
        assert_eq!(dg.total_disbursed(), 500);
        assert_eq!(dg.disbursement_count(), 1);
    }

    #[test]
    fn test_execute_grant_recipient_mismatch_fails() {
        let gov = test_governance();
        let recipient = test_recipient();
        let wrong_recipient = test_public_key(77);
        let contract_addr = test_public_key(10);
        let mut dg = DevGrants::new(gov.clone());
        let mut token = setup_token_contract();

        // Setup - approve for one recipient
        dg.receive_fees(1000).unwrap();
        token.mint(&contract_addr, 1000).unwrap();
        dg.approve_grant(&gov, 1, &recipient, 500, 100).unwrap();

        // Try to execute with different recipient (payload binding protection)
        let result = dg.execute_grant(&gov, 1, &wrong_recipient, 200, &mut token, &contract_addr);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidRecipient);

        // Verify no state changes occurred
        assert_eq!(dg.balance(), 1000);
        assert_eq!(dg.total_disbursed(), 0);
        assert_eq!(dg.disbursement_count(), 0);
    }

    #[test]
    fn test_execute_grant_insufficient_balance_fails() {
        let gov = test_governance();
        let recipient = test_recipient();
        let contract_addr = test_public_key(10);
        let mut dg = DevGrants::new(gov.clone());
        let mut token = setup_token_contract();

        // Setup with insufficient balance
        dg.receive_fees(100).unwrap(); // Only 100, but need 500
        token.mint(&contract_addr, 1000).unwrap();
        dg.approve_grant(&gov, 1, &recipient, 500, 100).unwrap();

        // Try to execute with insufficient balance
        let result = dg.execute_grant(&gov, 1, &recipient, 200, &mut token, &contract_addr);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InsufficientBalance);

        // Verify no state changes occurred
        assert_eq!(dg.balance(), 100);
        assert_eq!(dg.total_disbursed(), 0);
        assert_eq!(dg.disbursement_count(), 0);
    }

    #[test]
    fn test_execute_grant_token_transfer_fails() {
        let gov = test_governance();
        let recipient = test_recipient();
        let contract_addr = test_public_key(10);
        let mut dg = DevGrants::new(gov.clone());
        let mut token = setup_token_contract();

        // Setup - contract has balance but no tokens
        dg.receive_fees(1000).unwrap();
        // DO NOT mint tokens to contract_addr - this will cause transfer to fail
        dg.approve_grant(&gov, 1, &recipient, 500, 100).unwrap();

        // Try to execute - token transfer will fail
        let result = dg.execute_grant(&gov, 1, &recipient, 200, &mut token, &contract_addr);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::TokenTransferFailed);

        // Verify no state changes occurred (atomicity)
        assert_eq!(dg.balance(), 1000); // Balance unchanged
        assert_eq!(dg.total_disbursed(), 0);
        assert_eq!(dg.disbursement_count(), 0);

        // Verify proposal still approved (not executed)
        let grant = dg.grant(1).unwrap();
        assert_eq!(grant.status, ProposalStatus::Approved);
    }

    #[test]
    fn test_execute_grant_records_token_burned() {
        let gov = test_governance();
        let recipient = test_recipient();
        let contract_addr = test_public_key(10);
        let mut dg = DevGrants::new(gov.clone());
        
        // Create deflationary token with burn rate
        let creator = test_public_key(1);
        let mut token = TokenContract::new(
            [1u8; 32],
            "BurnToken".to_string(),
            "BURN".to_string(),
            8,
            1_000_000,
            true,  // is_deflationary
            10,    // burn_rate per transfer
            creator,
        );
        
        // Setup
        dg.receive_fees(1000).unwrap();
        token.mint(&contract_addr, 1000).unwrap();
        dg.approve_grant(&gov, 1, &recipient, 500, 100).unwrap();

        // Execute grant
        let result = dg.execute_grant(&gov, 1, &recipient, 200, &mut token, &contract_addr);
        assert!(result.is_ok());

        // Verify token_burned was recorded
        assert_eq!(dg.disbursement_count(), 1);
        let disbursements = dg.disbursements();
        assert_eq!(disbursements[0].token_burned, 10); // burn_rate from deflationary token
    }

    #[test]
    fn test_execute_grant_disbursement_record_immutable() {
        let gov = test_governance();
        let recipient = test_recipient();
        let contract_addr = test_public_key(10);
        let mut dg = DevGrants::new(gov.clone());
        let mut token = setup_token_contract();

        // Setup
        dg.receive_fees(2000).unwrap();
        token.mint(&contract_addr, 2000).unwrap();

        // Approve and execute two grants
        dg.approve_grant(&gov, 1, &recipient, 500, 100).unwrap();
        dg.execute_grant(&gov, 1, &recipient, 200, &mut token, &contract_addr).unwrap();

        dg.approve_grant(&gov, 2, &recipient, 300, 101).unwrap();
        dg.execute_grant(&gov, 2, &recipient, 201, &mut token, &contract_addr).unwrap();

        // Verify disbursements are append-only and ordered
        assert_eq!(dg.disbursement_count(), 2);
        let disbursements = dg.disbursements();
        
        assert_eq!(disbursements[0].proposal_id, 1);
        assert_eq!(disbursements[0].amount.get(), 500);
        assert_eq!(disbursements[0].executed_at, 200);
        
        assert_eq!(disbursements[1].proposal_id, 2);
        assert_eq!(disbursements[1].amount.get(), 300);
        assert_eq!(disbursements[1].executed_at, 201);

        // Verify total accounting
        assert_eq!(dg.balance(), 1200); // 2000 - 500 - 300
        assert_eq!(dg.total_disbursed(), 800); // 500 + 300
    }
}
