//! Cap Ledger - Hard Cap Enforcement
//!
//! The Cap Ledger enforces compensation caps at multiple scope levels.
//! Caps are HARD LAW - any exceeded cap aborts the operation.
//!
//! # Cap Check Order
//!
//! All caps are checked BEFORE any value moves:
//! 1. Global pool cap
//! 2. Role period cap
//! 3. Role lifetime cap (if set)
//! 4. Assignment annual cap (from snapshot)
//! 5. Assignment lifetime cap (if set, from snapshot)
//!
//! If ANY check fails, the entire operation aborts.
//!
//! # Reservation Pattern
//!
//! The ledger uses a reserve-then-commit pattern:
//! 1. `reserve_compensation()` - checks all caps, creates pending reservation
//! 2. `commit_reservation()` - after successful payout, commits consumption
//! 3. `rollback_reservation()` - if payout fails, releases reservation
//!
//! # Consensus-Critical
//! - All arithmetic uses checked operations
//! - BTreeMap for deterministic iteration
//! - Consumption only increases (monotonic)

use super::cap_types::{
    AssignmentConsumption, CapError, CapReservation, PeriodConsumption, ReservationId, RoleCap,
};
use super::role_types::{Assignment, AssignmentId, RoleDefinition, RoleId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Cap Ledger - enforces compensation caps at all scope levels
///
/// # Storage
/// Uses BTreeMap for deterministic serialization (consensus-critical).
///
/// # Invariants
/// - Consumption counters only increase (monotonic)
/// - All cap checks occur BEFORE value movement
/// - Overflow causes hard failure, not silent truncation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapLedger {
    // ─── Global Scope ───────────────────────────────────────────────────
    /// Global pool cap (system-wide limit per period)
    global_pool_cap: u64,

    /// Global pool consumed in current period
    global_pool_consumed: u64,

    /// Current period number
    current_period: u64,

    // ─── Role Scope ─────────────────────────────────────────────────────
    /// Role caps (role_id -> RoleCap)
    role_caps: BTreeMap<RoleId, RoleCap>,

    // ─── Assignment Scope ───────────────────────────────────────────────
    /// Assignment consumption (assignment_id -> AssignmentConsumption)
    assignment_consumption: BTreeMap<AssignmentId, AssignmentConsumption>,

    // ─── Period Tracking ────────────────────────────────────────────────
    /// Historical period consumption (period -> PeriodConsumption)
    period_history: BTreeMap<u64, PeriodConsumption>,

    // ─── Reservations ───────────────────────────────────────────────────
    /// Pending reservations (reservation_id -> CapReservation)
    pending_reservations: BTreeMap<ReservationId, CapReservation>,

    /// Counter for generating unique reservation IDs
    next_reservation_counter: u64,
}

impl CapLedger {
    /// Create a new Cap Ledger
    ///
    /// # Arguments
    /// * `global_pool_cap` - System-wide cap per period
    /// * `initial_period` - Starting period number
    pub fn new(global_pool_cap: u64, initial_period: u64) -> Self {
        Self {
            global_pool_cap,
            global_pool_consumed: 0,
            current_period: initial_period,
            role_caps: BTreeMap::new(),
            assignment_consumption: BTreeMap::new(),
            period_history: BTreeMap::new(),
            pending_reservations: BTreeMap::new(),
            next_reservation_counter: 0,
        }
    }

    // ─── Period Management ──────────────────────────────────────────────

    /// Advance to a new period
    ///
    /// Resets period-based consumption counters while preserving lifetime totals.
    pub fn advance_period(&mut self, new_period: u64) {
        if new_period <= self.current_period {
            return;
        }

        // Archive current period consumption
        let period_consumption = PeriodConsumption {
            period: self.current_period,
            total_consumed: self.global_pool_consumed,
        };
        self.period_history.insert(self.current_period, period_consumption);

        // Reset global period consumption
        self.global_pool_consumed = 0;
        self.current_period = new_period;

        // Reset role period consumption
        for role_cap in self.role_caps.values_mut() {
            role_cap.reset_period(new_period);
        }

        // Reset assignment period consumption
        for consumption in self.assignment_consumption.values_mut() {
            consumption.reset_period(new_period);
        }
    }

    /// Get current period
    pub fn current_period(&self) -> u64 {
        self.current_period
    }

    // ─── Role Registration ──────────────────────────────────────────────

    /// Register a role with the cap ledger
    ///
    /// # Arguments
    /// * `role` - Role definition
    /// * `period_cap` - Per-period cap for this role (may differ from role.annual_cap)
    pub fn register_role(&mut self, role: &RoleDefinition, period_cap: u64) {
        let role_cap = RoleCap::new(
            role.role_id,
            period_cap,
            role.lifetime_cap,
            self.current_period,
        );
        self.role_caps.insert(role.role_id, role_cap);
    }

    /// Update role caps
    ///
    /// Only affects future reservations, not existing assignments.
    pub fn update_role_caps(
        &mut self,
        role_id: &RoleId,
        new_period_cap: u64,
        new_lifetime_cap: Option<u64>,
    ) -> Result<(), CapError> {
        let role_cap = self
            .role_caps
            .get_mut(role_id)
            .ok_or(CapError::RoleNotFound(*role_id))?;

        role_cap.period_cap = new_period_cap;
        role_cap.lifetime_cap = new_lifetime_cap;
        Ok(())
    }

    /// Get role cap info
    pub fn get_role_cap(&self, role_id: &RoleId) -> Option<&RoleCap> {
        self.role_caps.get(role_id)
    }

    // ─── Assignment Registration ────────────────────────────────────────

    /// Register an assignment with the cap ledger
    ///
    /// Uses snapshotted caps from the assignment.
    pub fn register_assignment(&mut self, assignment: &Assignment) {
        let consumption = AssignmentConsumption::new(
            assignment.assignment_id,
            assignment.role_id,
            assignment.snap_annual_cap,
            assignment.snap_lifetime_cap,
            self.current_period,
        );
        self.assignment_consumption.insert(assignment.assignment_id, consumption);
    }

    /// Get assignment consumption info
    pub fn get_assignment_consumption(
        &self,
        assignment_id: &AssignmentId,
    ) -> Option<&AssignmentConsumption> {
        self.assignment_consumption.get(assignment_id)
    }

    // ─── Cap Checks ─────────────────────────────────────────────────────

    /// Check global pool cap
    fn check_global_cap(&self, amount: u64) -> Result<(), CapError> {
        let new_total = self
            .global_pool_consumed
            .checked_add(amount)
            .ok_or(CapError::Overflow)?;

        if new_total > self.global_pool_cap {
            return Err(CapError::GlobalCapExceeded {
                cap: self.global_pool_cap,
                consumed: self.global_pool_consumed,
                requested: amount,
            });
        }
        Ok(())
    }

    /// Check role caps (period and lifetime)
    fn check_role_caps(&self, role_id: &RoleId, amount: u64) -> Result<(), CapError> {
        let role_cap = self
            .role_caps
            .get(role_id)
            .ok_or(CapError::RoleNotFound(*role_id))?;

        // Period cap
        let new_period = role_cap
            .period_consumed
            .checked_add(amount)
            .ok_or(CapError::Overflow)?;

        if new_period > role_cap.period_cap {
            return Err(CapError::RolePeriodCapExceeded {
                role_id: *role_id,
                cap: role_cap.period_cap,
                consumed: role_cap.period_consumed,
                requested: amount,
            });
        }

        // Lifetime cap (if set)
        if let Some(lifetime_cap) = role_cap.lifetime_cap {
            let new_lifetime = role_cap
                .lifetime_consumed
                .checked_add(amount)
                .ok_or(CapError::Overflow)?;

            if new_lifetime > lifetime_cap {
                return Err(CapError::RoleLifetimeCapExceeded {
                    role_id: *role_id,
                    cap: lifetime_cap,
                    consumed: role_cap.lifetime_consumed,
                    requested: amount,
                });
            }
        }

        Ok(())
    }

    /// Check assignment caps (annual and lifetime from snapshots)
    fn check_assignment_caps(
        &self,
        consumption: &AssignmentConsumption,
        amount: u64,
    ) -> Result<(), CapError> {
        // Annual cap (from snapshot)
        let new_period = consumption
            .current_period_consumed
            .checked_add(amount)
            .ok_or(CapError::Overflow)?;

        if new_period > consumption.snap_annual_cap {
            return Err(CapError::AssignmentAnnualCapExceeded {
                assignment_id: consumption.assignment_id,
                cap: consumption.snap_annual_cap,
                consumed: consumption.current_period_consumed,
                requested: amount,
            });
        }

        // Lifetime cap (if set, from snapshot)
        if let Some(lifetime_cap) = consumption.snap_lifetime_cap {
            let new_lifetime = consumption
                .total_consumed
                .checked_add(amount)
                .ok_or(CapError::Overflow)?;

            if new_lifetime > lifetime_cap {
                return Err(CapError::AssignmentLifetimeCapExceeded {
                    assignment_id: consumption.assignment_id,
                    cap: lifetime_cap,
                    consumed: consumption.total_consumed,
                    requested: amount,
                });
            }
        }

        Ok(())
    }

    // ─── Reservation Pattern ────────────────────────────────────────────

    /// Generate unique reservation ID
    fn generate_reservation_id(&mut self, assignment_id: &AssignmentId) -> ReservationId {
        use blake3::Hasher;

        // Use Blake3 for deterministic, consensus-safe hashing
        let mut hasher = Hasher::new();
        // Hash all bytes of the assignment ID to bind the reservation to this assignment
        hasher.update(assignment_id);
        // Include the current reservation counter and period so IDs are unique over time
        hasher.update(&self.next_reservation_counter.to_le_bytes());
        hasher.update(&self.current_period.to_le_bytes());

        // Preserve existing semantics: the counter value used in the ID field
        // is the incremented one
        self.next_reservation_counter += 1;

        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();

        let mut id = [0u8; 32];
        // First 8 bytes from the Blake3 hash output
        id[..8].copy_from_slice(&hash_bytes[..8]);
        // Next 8 bytes: incremented reservation counter
        id[8..16].copy_from_slice(&self.next_reservation_counter.to_le_bytes());
        // Next 8 bytes: prefix of assignment ID for traceability
        id[16..24].copy_from_slice(&assignment_id[..8]);
        // Last 8 bytes: current period for additional domain separation
        id[24..32].copy_from_slice(&self.current_period.to_le_bytes());
        id
    }

    /// Reserve compensation
    ///
    /// Checks ALL cap levels before creating reservation.
    /// If ANY cap would be exceeded, returns error and no reservation is created.
    ///
    /// # Arguments
    /// * `assignment_id` - Assignment to pay
    /// * `amount` - Amount to reserve
    /// * `current_epoch` - Current epoch (for audit)
    ///
    /// # Returns
    /// Ok(CapReservation) if within all caps
    /// Err(CapError) if any cap exceeded
    pub fn reserve_compensation(
        &mut self,
        assignment_id: &AssignmentId,
        amount: u64,
        current_epoch: u64,
    ) -> Result<CapReservation, CapError> {
        // Get assignment consumption
        let consumption = self
            .assignment_consumption
            .get(assignment_id)
            .ok_or(CapError::AssignmentNotFound(*assignment_id))?
            .clone();

        let role_id = consumption.role_id;

        // Check ALL cap levels - abort if ANY exceeded
        // Order matters for deterministic error reporting
        self.check_global_cap(amount)?;
        self.check_role_caps(&role_id, amount)?;
        self.check_assignment_caps(&consumption, amount)?;

        // All checks passed - create reservation
        let reservation_id = self.generate_reservation_id(assignment_id);
        let reservation = CapReservation::new(
            reservation_id,
            *assignment_id,
            role_id,
            amount,
            self.current_period,
            current_epoch,
        );

        self.pending_reservations.insert(reservation_id, reservation.clone());

        Ok(reservation)
    }

    /// Commit a reservation after successful payout
    ///
    /// Updates all consumption counters (monotonic increase).
    ///
    /// # Arguments
    /// * `reservation_id` - Reservation to commit
    ///
    /// # Returns
    /// Ok(()) if committed successfully
    /// Err if reservation not found or already consumed
    pub fn commit_reservation(&mut self, reservation_id: &ReservationId) -> Result<(), CapError> {
        // Remove reservation (consumed)
        let reservation = self
            .pending_reservations
            .remove(reservation_id)
            .ok_or(CapError::ReservationNotFound(*reservation_id))?;

        // Verify period matches
        if reservation.period != self.current_period {
            // Reservation from old period - reject
            return Err(CapError::PeriodMismatch {
                expected: self.current_period,
                actual: reservation.period,
            });
        }

        // Update global consumption
        self.global_pool_consumed = self
            .global_pool_consumed
            .saturating_add(reservation.amount);

        // Update role consumption
        if let Some(role_cap) = self.role_caps.get_mut(&reservation.role_id) {
            role_cap.record_consumption(reservation.amount);
        }

        // Update assignment consumption
        if let Some(consumption) = self.assignment_consumption.get_mut(&reservation.assignment_id) {
            consumption.record_consumption(reservation.amount);
        }

        Ok(())
    }

    /// Rollback a reservation (payout failed)
    ///
    /// Simply removes the pending reservation without updating counters.
    pub fn rollback_reservation(&mut self, reservation_id: &ReservationId) -> Result<(), CapError> {
        self.pending_reservations
            .remove(reservation_id)
            .ok_or(CapError::ReservationNotFound(*reservation_id))?;
        Ok(())
    }

    /// Get pending reservation
    pub fn get_pending_reservation(
        &self,
        reservation_id: &ReservationId,
    ) -> Option<&CapReservation> {
        self.pending_reservations.get(reservation_id)
    }

    // ─── Query Methods ──────────────────────────────────────────────────

    /// Get global pool remaining capacity
    pub fn global_remaining(&self) -> u64 {
        self.global_pool_cap.saturating_sub(self.global_pool_consumed)
    }

    /// Get global pool consumed
    pub fn global_consumed(&self) -> u64 {
        self.global_pool_consumed
    }

    /// Get global pool cap
    pub fn global_cap(&self) -> u64 {
        self.global_pool_cap
    }

    /// Calculate maximum payable for an assignment
    ///
    /// Returns the minimum of all applicable caps.
    pub fn max_payable(&self, assignment_id: &AssignmentId) -> Result<u64, CapError> {
        let consumption = self
            .assignment_consumption
            .get(assignment_id)
            .ok_or(CapError::AssignmentNotFound(*assignment_id))?;

        let role_cap = self
            .role_caps
            .get(&consumption.role_id)
            .ok_or(CapError::RoleNotFound(consumption.role_id))?;

        // Start with global remaining
        let mut max = self.global_remaining();

        // Role period remaining
        max = max.min(role_cap.remaining_period());

        // Role lifetime remaining (if set)
        if let Some(lifetime_remaining) = role_cap.remaining_lifetime() {
            max = max.min(lifetime_remaining);
        }

        // Assignment annual remaining
        max = max.min(consumption.remaining_annual());

        // Assignment lifetime remaining (if set)
        if let Some(lifetime_remaining) = consumption.remaining_lifetime() {
            max = max.min(lifetime_remaining);
        }

        Ok(max)
    }

    /// Get number of pending reservations
    pub fn pending_reservation_count(&self) -> usize {
        self.pending_reservations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_role_id() -> RoleId {
        [1u8; 32]
    }

    fn test_role_id_2() -> RoleId {
        [2u8; 32]
    }

    fn test_assignment_id(n: u8) -> AssignmentId {
        [n; 32]
    }

    fn setup_ledger() -> CapLedger {
        CapLedger::new(1_000_000, 1)
    }

    fn setup_ledger_with_role(ledger: &mut CapLedger, role_id: RoleId, period_cap: u64) {
        let role = RoleDefinition {
            role_id,
            name: "Test Role".to_string(),
            description: "Test".to_string(),
            annual_cap: period_cap,
            lifetime_cap: None,
            per_epoch_cap: period_cap,
            created_at_epoch: 1,
            is_active: true,
            requires_attestation: false,
        };
        ledger.register_role(&role, period_cap);
    }

    fn setup_ledger_with_assignment(
        ledger: &mut CapLedger,
        assignment_id: AssignmentId,
        role_id: RoleId,
        annual_cap: u64,
        lifetime_cap: Option<u64>,
    ) {
        let assignment = Assignment {
            assignment_id,
            person_id: [99u8; 32],
            role_id,
            snap_annual_cap: annual_cap,
            snap_lifetime_cap: lifetime_cap,
            snap_per_epoch_cap: annual_cap,
            total_paid: 0,
            current_year_paid: 0,
            current_epoch_paid: 0,
            last_payment_epoch: None,
            status: super::super::role_types::AssignmentStatus::Active,
            assigned_at_epoch: 1,
            assigned_in_year: 2024,
            current_year: 2024,
            suspended_at_epoch: None,
            terminated_at_epoch: None,
        };
        ledger.register_assignment(&assignment);
    }

    #[test]
    fn test_over_cap_payout_fails() {
        let mut ledger = setup_ledger();
        setup_ledger_with_role(&mut ledger, test_role_id(), 200_000);
        setup_ledger_with_assignment(&mut ledger, test_assignment_id(10), test_role_id(), 100_000, None);

        // Try to pay 150k against 100k annual cap
        let result = ledger.reserve_compensation(&test_assignment_id(10), 150_000, 100);

        assert!(matches!(
            result,
            Err(CapError::AssignmentAnnualCapExceeded { .. })
        ));
    }

    #[test]
    fn test_global_cap_prevents_payout() {
        let mut ledger = CapLedger::new(100_000, 1); // 100k global cap
        setup_ledger_with_role(&mut ledger, test_role_id(), 200_000);
        setup_ledger_with_assignment(&mut ledger, test_assignment_id(10), test_role_id(), 100_000, None);
        setup_ledger_with_assignment(&mut ledger, test_assignment_id(11), test_role_id(), 100_000, None);

        // Pay 90k to Alice
        let reservation = ledger.reserve_compensation(&test_assignment_id(10), 90_000, 100).unwrap();
        ledger.commit_reservation(&reservation.id).unwrap();

        // Try to pay 20k to Bob (would exceed global 100k)
        let result = ledger.reserve_compensation(&test_assignment_id(11), 20_000, 101);

        assert!(matches!(result, Err(CapError::GlobalCapExceeded { .. })));
    }

    #[test]
    fn test_rounding_cannot_bypass_caps() {
        let mut ledger = CapLedger::new(1_000_000, 1);
        setup_ledger_with_role(&mut ledger, test_role_id(), 1_000_000);
        setup_ledger_with_assignment(&mut ledger, test_assignment_id(10), test_role_id(), 100, None);

        // Pay 99
        let r1 = ledger.reserve_compensation(&test_assignment_id(10), 99, 100).unwrap();
        ledger.commit_reservation(&r1.id).unwrap();

        // Pay 1 more - should succeed (exactly at cap)
        let r2 = ledger.reserve_compensation(&test_assignment_id(10), 1, 101).unwrap();
        ledger.commit_reservation(&r2.id).unwrap();

        // Pay 1 more - should fail (over cap)
        let result = ledger.reserve_compensation(&test_assignment_id(10), 1, 102);
        assert!(result.is_err());
    }

    #[test]
    fn test_cap_consumption_is_monotonic() {
        let mut ledger = setup_ledger();
        setup_ledger_with_role(&mut ledger, test_role_id(), 200_000);
        setup_ledger_with_assignment(&mut ledger, test_assignment_id(10), test_role_id(), 100_000, None);

        // Pay 50k
        let r1 = ledger.reserve_compensation(&test_assignment_id(10), 50_000, 100).unwrap();
        ledger.commit_reservation(&r1.id).unwrap();

        let consumption = ledger.get_assignment_consumption(&test_assignment_id(10)).unwrap();
        assert_eq!(consumption.total_consumed, 50_000);

        // Pay 25k more
        let r2 = ledger.reserve_compensation(&test_assignment_id(10), 25_000, 101).unwrap();
        ledger.commit_reservation(&r2.id).unwrap();

        let consumption = ledger.get_assignment_consumption(&test_assignment_id(10)).unwrap();
        assert_eq!(consumption.total_consumed, 75_000); // Only increases

        // There's no API to decrease consumption - by design
    }

    #[test]
    fn test_role_cap_shared_across_assignments() {
        let mut ledger = setup_ledger();
        // Role with 100k period cap
        setup_ledger_with_role(&mut ledger, test_role_id(), 100_000);
        // Alice and Bob both in this role, each with 80k individual cap
        setup_ledger_with_assignment(&mut ledger, test_assignment_id(10), test_role_id(), 80_000, None);
        setup_ledger_with_assignment(&mut ledger, test_assignment_id(11), test_role_id(), 80_000, None);

        // Pay Alice 60k
        let r1 = ledger.reserve_compensation(&test_assignment_id(10), 60_000, 100).unwrap();
        ledger.commit_reservation(&r1.id).unwrap();

        // Try to pay Bob 60k (would exceed role period cap of 100k)
        let result = ledger.reserve_compensation(&test_assignment_id(11), 60_000, 101);
        assert!(matches!(
            result,
            Err(CapError::RolePeriodCapExceeded { .. })
        ));

        // Pay Bob 40k (within role cap)
        let r2 = ledger.reserve_compensation(&test_assignment_id(11), 40_000, 102);
        assert!(r2.is_ok());
    }

    #[test]
    fn test_lifetime_cap_enforcement() {
        let mut ledger = setup_ledger();
        setup_ledger_with_role(&mut ledger, test_role_id(), 100_000);
        // Assignment with 100k annual cap but only 150k lifetime cap
        setup_ledger_with_assignment(
            &mut ledger,
            test_assignment_id(10),
            test_role_id(),
            100_000,
            Some(150_000),
        );

        // Period 1: Pay 100k
        let r1 = ledger.reserve_compensation(&test_assignment_id(10), 100_000, 100).unwrap();
        ledger.commit_reservation(&r1.id).unwrap();

        // Advance to period 2 (resets annual)
        ledger.advance_period(2);

        // Period 2: Pay 50k (within annual, within lifetime 150k)
        let r2 = ledger.reserve_compensation(&test_assignment_id(10), 50_000, 200).unwrap();
        ledger.commit_reservation(&r2.id).unwrap();

        // Period 2: Try to pay 10k more (would exceed 150k lifetime)
        let result = ledger.reserve_compensation(&test_assignment_id(10), 10_000, 201);
        assert!(matches!(
            result,
            Err(CapError::AssignmentLifetimeCapExceeded { .. })
        ));
    }

    #[test]
    fn test_period_advance_resets_annual_not_lifetime() {
        let mut ledger = setup_ledger();
        setup_ledger_with_role(&mut ledger, test_role_id(), 100_000);
        setup_ledger_with_assignment(
            &mut ledger,
            test_assignment_id(10),
            test_role_id(),
            50_000,
            Some(200_000),
        );

        // Period 1: Pay 50k (full annual)
        let r1 = ledger.reserve_compensation(&test_assignment_id(10), 50_000, 100).unwrap();
        ledger.commit_reservation(&r1.id).unwrap();

        // Can't pay more in period 1
        assert!(ledger.reserve_compensation(&test_assignment_id(10), 1, 101).is_err());

        // Advance period
        ledger.advance_period(2);

        // Period 2: Can pay again (annual reset)
        let r2 = ledger.reserve_compensation(&test_assignment_id(10), 50_000, 200);
        assert!(r2.is_ok());
        ledger.commit_reservation(&r2.unwrap().id).unwrap();

        // But lifetime tracks across periods
        let consumption = ledger.get_assignment_consumption(&test_assignment_id(10)).unwrap();
        assert_eq!(consumption.total_consumed, 100_000);
    }

    #[test]
    fn test_reservation_rollback() {
        let mut ledger = setup_ledger();
        setup_ledger_with_role(&mut ledger, test_role_id(), 100_000);
        setup_ledger_with_assignment(&mut ledger, test_assignment_id(10), test_role_id(), 100_000, None);

        // Reserve 50k
        let reservation = ledger.reserve_compensation(&test_assignment_id(10), 50_000, 100).unwrap();
        assert_eq!(ledger.pending_reservation_count(), 1);

        // Rollback
        ledger.rollback_reservation(&reservation.id).unwrap();
        assert_eq!(ledger.pending_reservation_count(), 0);

        // Consumption not affected
        let consumption = ledger.get_assignment_consumption(&test_assignment_id(10)).unwrap();
        assert_eq!(consumption.total_consumed, 0);

        // Can still reserve (wasn't consumed)
        let r2 = ledger.reserve_compensation(&test_assignment_id(10), 50_000, 101);
        assert!(r2.is_ok());
    }

    #[test]
    fn test_max_payable_calculation() {
        let mut ledger = CapLedger::new(100_000, 1); // 100k global
        setup_ledger_with_role(&mut ledger, test_role_id(), 80_000); // 80k role
        setup_ledger_with_assignment(
            &mut ledger,
            test_assignment_id(10),
            test_role_id(),
            50_000,      // 50k annual
            Some(60_000), // 60k lifetime
        );

        // Max is min(global, role, annual, lifetime) = 50k
        let max = ledger.max_payable(&test_assignment_id(10)).unwrap();
        assert_eq!(max, 50_000);

        // After paying 40k
        let r1 = ledger.reserve_compensation(&test_assignment_id(10), 40_000, 100).unwrap();
        ledger.commit_reservation(&r1.id).unwrap();

        // Max is now min(60k global, 40k role, 10k annual, 20k lifetime) = 10k
        let max = ledger.max_payable(&test_assignment_id(10)).unwrap();
        assert_eq!(max, 10_000);
    }

    #[test]
    fn test_role_lifetime_cap() {
        let mut ledger = setup_ledger();

        // Role with lifetime cap
        let role = RoleDefinition {
            role_id: test_role_id(),
            name: "Limited Role".to_string(),
            description: "Role with lifetime cap".to_string(),
            annual_cap: 100_000,
            lifetime_cap: Some(150_000),
            per_epoch_cap: 100_000,
            created_at_epoch: 1,
            is_active: true,
            requires_attestation: false,
        };
        ledger.register_role(&role, 100_000);
        setup_ledger_with_assignment(&mut ledger, test_assignment_id(10), test_role_id(), 100_000, None);

        // Pay 100k
        let r1 = ledger.reserve_compensation(&test_assignment_id(10), 100_000, 100).unwrap();
        ledger.commit_reservation(&r1.id).unwrap();

        // Advance period
        ledger.advance_period(2);

        // Pay 50k (within role lifetime of 150k)
        let r2 = ledger.reserve_compensation(&test_assignment_id(10), 50_000, 200).unwrap();
        ledger.commit_reservation(&r2.id).unwrap();

        // Try to pay 10k more (would exceed role lifetime)
        let result = ledger.reserve_compensation(&test_assignment_id(10), 10_000, 201);
        assert!(matches!(
            result,
            Err(CapError::RoleLifetimeCapExceeded { .. })
        ));
    }

    #[test]
    fn test_multiple_roles_independent() {
        let mut ledger = setup_ledger();
        setup_ledger_with_role(&mut ledger, test_role_id(), 50_000);
        setup_ledger_with_role(&mut ledger, test_role_id_2(), 50_000);
        setup_ledger_with_assignment(&mut ledger, test_assignment_id(10), test_role_id(), 50_000, None);
        setup_ledger_with_assignment(&mut ledger, test_assignment_id(11), test_role_id_2(), 50_000, None);

        // Pay 50k to role 1
        let r1 = ledger.reserve_compensation(&test_assignment_id(10), 50_000, 100).unwrap();
        ledger.commit_reservation(&r1.id).unwrap();

        // Role 2 still has full capacity
        let r2 = ledger.reserve_compensation(&test_assignment_id(11), 50_000, 101);
        assert!(r2.is_ok());
    }
}
