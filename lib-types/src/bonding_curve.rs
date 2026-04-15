use serde::{Deserialize, Serialize};

// ── Pool ceiling constants (in 18-decimal atoms) ───────────────────────────
// These are duplicated here so lib-types stays self-contained (no dep on
// lib-blockchain).  The canonical copies live in
// lib-blockchain::contracts::bonding_curve::canonical.
const POOL_SCALE: u128 = 1_000_000_000_000_000_000;
const COMPENSATION_POOL_CEILING: u128 = 400_000_000 * POOL_SCALE;
const TREASURY_POOL_CEILING: u128 = 200_000_000 * POOL_SCALE;
const LIQUIDITY_POOL_CEILING: u128 = 200_000_000 * POOL_SCALE;
const INCENTIVE_POOL_CEILING: u128 = 100_000_000 * POOL_SCALE;
const STRATEGIC_RESERVE_CEILING: u128 = 100_000_000 * POOL_SCALE;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PoolState {
    pub balance: u128,
    pub ceiling: u128,
}

impl PoolState {
    pub fn can_mint(&self, amount: u128) -> bool {
        self.balance
            .checked_add(amount)
            .map_or(false, |new| new <= self.ceiling)
    }
    pub fn mint(&mut self, amount: u128) -> Result<(), &'static str> {
        let new = self
            .balance
            .checked_add(amount)
            .ok_or("pool balance overflow")?;
        if new > self.ceiling {
            return Err("would exceed pool ceiling");
        }
        self.balance = new;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingCurveBand {
    pub index: u64,
    pub start_supply: u128,
    pub end_supply: u128,
    pub slope_num: u128,
    pub slope_den: u128,
    pub p_start: u128,
}

/// 48-bit nonce packed as six big-endian bytes.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Nonce48(pub [u8; 6]);

impl Nonce48 {
    pub const MAX: u64 = (1u64 << 48) - 1;

    pub const fn zero() -> Self {
        Self([0; 6])
    }

    pub fn from_u64(value: u64) -> Option<Self> {
        if value > Self::MAX {
            return None;
        }

        Some(Self([
            ((value >> 40) & 0xff) as u8,
            ((value >> 32) & 0xff) as u8,
            ((value >> 24) & 0xff) as u8,
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]))
    }

    pub const fn to_u64(self) -> u64 {
        ((self.0[0] as u64) << 40)
            | ((self.0[1] as u64) << 32)
            | ((self.0[2] as u64) << 24)
            | ((self.0[3] as u64) << 16)
            | ((self.0[4] as u64) << 8)
            | (self.0[5] as u64)
    }

    pub const fn to_be_bytes(self) -> [u8; 6] {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingCurveEconomicState {
    /// Circulating CBE supply (18-decimal bonding curve atoms).
    pub s_c: u128,
    /// Locked strategic reserve — 32% of each deposit (40% of the 80% DAO portion).
    /// Backs the floor price: floor = reserve_balance / s_c.
    pub reserve_balance: u128,
    /// SOV treasury's CBE holdings — 20% of each deposit (network tax).
    /// Held as CBE tokens (not swapped). SOV treasury NAV includes this
    /// valued at current CBE price.
    #[serde(alias = "treasury_balance")]
    pub sov_treasury_cbe_balance: u128,
    /// Liquidity pool — 48% of each deposit (60% of the 80% DAO portion).
    /// Kept for backwards compatibility; mirrors `liquidity_pool.balance`.
    #[serde(default)]
    pub liquidity_pool_balance: u128,
    /// Total SOV minted from on-ramp deposits (event-driven, priced at NAV model).
    #[serde(default)]
    pub total_sov_minted: u128,
    pub graduated: bool,
    pub sell_enabled: bool,

    // ── Five pool ceilings (Feature #2126) ─────────────────────────────────
    #[serde(default)]
    pub compensation_pool: PoolState,
    #[serde(default)]
    pub treasury_pool: PoolState,
    #[serde(default)]
    pub liquidity_pool: PoolState,
    #[serde(default)]
    pub incentive_pool: PoolState,
    #[serde(default)]
    pub strategic_reserve: PoolState,

    // ── PRE_BACKED FIFO queue (Feature #2124) ──────────────────────────────
    #[serde(default)]
    pub outstanding_pre_backed: u128,
    #[serde(default)]
    pub pre_backed_queue: Vec<PreBackedEntry>,

    // ── Debt ceiling (Feature #2125) ───────────────────────────────────────
    #[serde(default)]
    pub debt_state: DebtState,

    // ── Genesis treasury allocation (Feature #2127) ───────────────────────
    /// 20B CBE minted off-curve to SOV treasury at genesis (Config B).
    /// Set once during genesis init; does NOT affect S_c.
    #[serde(default)]
    pub genesis_treasury_allocation: u128,

    // ── SOVRN audit token (Feature #2129) ─────────────────────────────────
    /// Cumulative SOVRN supply — value-weighted audit record of SOV flowing
    /// into the liquidity pool (on BUY_CBE) and CBE-valued obligations from
    /// payroll mints.  Denominated in SOV atoms.
    #[serde(default)]
    pub sovrn_total_supply: u128,
}

impl Default for BondingCurveEconomicState {
    fn default() -> Self {
        Self {
            s_c: 0,
            reserve_balance: 0,
            sov_treasury_cbe_balance: 0,
            liquidity_pool_balance: 0,
            total_sov_minted: 0,
            graduated: false,
            sell_enabled: false,
            compensation_pool: PoolState {
                balance: 0,
                ceiling: COMPENSATION_POOL_CEILING,
            },
            treasury_pool: PoolState {
                balance: 0,
                ceiling: TREASURY_POOL_CEILING,
            },
            liquidity_pool: PoolState {
                balance: 0,
                ceiling: LIQUIDITY_POOL_CEILING,
            },
            incentive_pool: PoolState {
                balance: 0,
                ceiling: INCENTIVE_POOL_CEILING,
            },
            strategic_reserve: PoolState {
                balance: 0,
                ceiling: STRATEGIC_RESERVE_CEILING,
            },
            outstanding_pre_backed: 0,
            pre_backed_queue: Vec::new(),
            debt_state: DebtState::Green,
            genesis_treasury_allocation: 0,
            sovrn_total_supply: 0,
        }
    }
}

impl BondingCurveEconomicState {
    /// Create a new economic state with pool ceilings initialised from constants.
    pub fn new() -> Self {
        Self::default()
    }

    /// Satisfy PRE_BACKED entries in FIFO order using the given amount.
    pub fn satisfy_pre_backed(&mut self, amount: u128) {
        let mut remaining = amount;
        for entry in &mut self.pre_backed_queue {
            if entry.satisfied || remaining == 0 {
                continue;
            }
            if remaining >= entry.amount_cbe {
                remaining -= entry.amount_cbe;
                self.outstanding_pre_backed = self
                    .outstanding_pre_backed
                    .saturating_sub(entry.amount_cbe);
                entry.satisfied = true;
            } else {
                // partial satisfaction not supported — skip
                break;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreBackedEntry {
    pub block_height: u64,
    pub amount_cbe: u128,
    pub recipient: [u8; 32],
    pub deliverable_hash: [u8; 32],
    pub satisfied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DebtState {
    #[default]
    Green,
    Yellow,
    Orange,
    Red,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BondingCurveAccountState {
    pub key_id: [u8; 32],
    pub balance_cbe: u128,
    pub balance_sov: u128,
    pub next_nonce: Nonce48,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingCurveBuyTx {
    pub action: u8,
    pub chain_id: u8,
    pub nonce: Nonce48,
    pub sender: [u8; 32],
    pub amount_in: u128,
    pub max_price: u128,
    pub expected_s_c: u128,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingCurveSellTx {
    pub action: u8,
    pub chain_id: u8,
    pub nonce: Nonce48,
    pub sender: [u8; 32],
    pub amount_cbe: u128,
    pub min_payout: u128,
    pub expected_s_c: u128,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingCurveBuyReceipt {
    pub delta_s: u128,
    pub reserve_credit: u128,
    pub treasury_credit: u128,
    pub new_supply: u128,
    pub price_post: u128,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingCurveSellReceipt {
    pub sov_out: u128,
    pub new_supply: u128,
    pub new_reserve: u128,
    pub price_post: u128,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_AMOUNT_PER_TX: u128 = 100_000_000_000u128 * 1_000_000_000_000_000_000u128;

    #[test]
    fn nonce48_round_trip_through_u64() {
        let nonce = Nonce48::from_u64(42).unwrap();
        assert_eq!(nonce.to_u64(), 42);
        assert_eq!(nonce.to_be_bytes(), [0, 0, 0, 0, 0, 42]);
    }

    #[test]
    fn nonce48_rejects_values_above_max() {
        assert!(Nonce48::from_u64(Nonce48::MAX).is_some());
        assert!(Nonce48::from_u64(Nonce48::MAX + 1).is_none());
    }

    #[test]
    fn buy_tx_bincode_size_is_fixed_to_payload_width() {
        let a = BondingCurveBuyTx {
            action: 0x01,
            chain_id: 0x02,
            nonce: Nonce48::from_u64(3).unwrap(),
            sender: [1u8; 32],
            amount_in: 1,
            max_price: 2,
            expected_s_c: 4,
        };
        let b = BondingCurveBuyTx {
            action: 0x01,
            chain_id: 0xff,
            nonce: Nonce48::from_u64(Nonce48::MAX).unwrap(),
            sender: [9u8; 32],
            amount_in: MAX_AMOUNT_PER_TX,
            max_price: MAX_AMOUNT_PER_TX - 1,
            expected_s_c: MAX_AMOUNT_PER_TX - 2,
        };

        assert_eq!(bincode::serialize(&a).unwrap().len(), 88);
        assert_eq!(bincode::serialize(&b).unwrap().len(), 88);
    }

    #[test]
    fn sell_tx_bincode_size_is_fixed_to_payload_width() {
        let a = BondingCurveSellTx {
            action: 0x02,
            chain_id: 0x03,
            nonce: Nonce48::from_u64(3).unwrap(),
            sender: [1u8; 32],
            amount_cbe: 1,
            min_payout: 2,
            expected_s_c: 4,
        };
        let b = BondingCurveSellTx {
            action: 0x02,
            chain_id: 0xfe,
            nonce: Nonce48::from_u64(Nonce48::MAX).unwrap(),
            sender: [9u8; 32],
            amount_cbe: MAX_AMOUNT_PER_TX,
            min_payout: MAX_AMOUNT_PER_TX - 1,
            expected_s_c: MAX_AMOUNT_PER_TX - 2,
        };

        assert_eq!(bincode::serialize(&a).unwrap().len(), 88);
        assert_eq!(bincode::serialize(&b).unwrap().len(), 88);
    }

    #[test]
    fn economic_state_round_trips_through_bincode() {
        let state = BondingCurveEconomicState {
            s_c: 1,
            reserve_balance: 2,
            sov_treasury_cbe_balance: 3,
            graduated: true,
            sell_enabled: false,
            ..Default::default()
        };

        let encoded = bincode::serialize(&state).unwrap();
        let decoded: BondingCurveEconomicState = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded, state);
    }

    #[test]
    fn account_state_round_trips_through_bincode() {
        let account = BondingCurveAccountState {
            key_id: [7u8; 32],
            balance_cbe: 8,
            balance_sov: 9,
            next_nonce: Nonce48::from_u64(10).unwrap(),
        };

        let encoded = bincode::serialize(&account).unwrap();
        let decoded: BondingCurveAccountState = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded, account);
    }

    #[test]
    fn receipts_have_fixed_bincode_size() {
        let buy = BondingCurveBuyReceipt {
            delta_s: 1,
            reserve_credit: 2,
            treasury_credit: 3,
            new_supply: 4,
            price_post: 5,
        };
        let sell = BondingCurveSellReceipt {
            sov_out: 1,
            new_supply: 2,
            new_reserve: 3,
            price_post: 4,
        };

        assert_eq!(bincode::serialize(&buy).unwrap().len(), 80);
        assert_eq!(bincode::serialize(&sell).unwrap().len(), 64);
    }

    // ── Pool ceiling tests (Feature #2126) ─────────────────────────────────

    #[test]
    fn pool_mint_up_to_ceiling_succeeds() {
        let mut pool = PoolState {
            balance: 0,
            ceiling: 1000,
        };
        assert!(pool.can_mint(1000));
        assert!(pool.mint(500).is_ok());
        assert_eq!(pool.balance, 500);
        assert!(pool.mint(500).is_ok());
        assert_eq!(pool.balance, 1000);
    }

    #[test]
    fn pool_mint_over_ceiling_fails() {
        let mut pool = PoolState {
            balance: 0,
            ceiling: 1000,
        };
        assert!(!pool.can_mint(1001));
        assert!(pool.mint(1001).is_err());
        assert_eq!(pool.balance, 0); // unchanged
    }

    #[test]
    fn pool_mint_incremental_over_ceiling_fails() {
        let mut pool = PoolState {
            balance: 999,
            ceiling: 1000,
        };
        assert!(pool.can_mint(1));
        assert!(!pool.can_mint(2));
        assert!(pool.mint(2).is_err());
        assert_eq!(pool.balance, 999); // unchanged
    }

    #[test]
    fn pool_can_mint_overflow_returns_false() {
        let pool = PoolState {
            balance: u128::MAX,
            ceiling: u128::MAX,
        };
        assert!(!pool.can_mint(1));
    }

    #[test]
    fn default_economic_state_has_pool_ceilings() {
        let econ = BondingCurveEconomicState::default();
        assert_eq!(econ.compensation_pool.ceiling, COMPENSATION_POOL_CEILING);
        assert_eq!(econ.treasury_pool.ceiling, TREASURY_POOL_CEILING);
        assert_eq!(econ.liquidity_pool.ceiling, LIQUIDITY_POOL_CEILING);
        assert_eq!(econ.incentive_pool.ceiling, INCENTIVE_POOL_CEILING);
        assert_eq!(econ.strategic_reserve.ceiling, STRATEGIC_RESERVE_CEILING);
        assert_eq!(econ.compensation_pool.balance, 0);
    }

    // ── PRE_BACKED FIFO tests (Feature #2124) ─────────────────────────────

    #[test]
    fn satisfy_pre_backed_fifo_order() {
        let mut econ = BondingCurveEconomicState::default();
        econ.pre_backed_queue = vec![
            PreBackedEntry {
                block_height: 1,
                amount_cbe: 100,
                recipient: [1u8; 32],
                deliverable_hash: [0xAA; 32],
                satisfied: false,
            },
            PreBackedEntry {
                block_height: 2,
                amount_cbe: 200,
                recipient: [2u8; 32],
                deliverable_hash: [0xBB; 32],
                satisfied: false,
            },
            PreBackedEntry {
                block_height: 3,
                amount_cbe: 50,
                recipient: [3u8; 32],
                deliverable_hash: [0xCC; 32],
                satisfied: false,
            },
        ];
        econ.outstanding_pre_backed = 350;

        // Satisfy with 150: covers entry 0 (100) fully, entry 1 (200) not enough → skip
        econ.satisfy_pre_backed(150);
        assert!(econ.pre_backed_queue[0].satisfied);
        assert!(!econ.pre_backed_queue[1].satisfied);
        assert!(!econ.pre_backed_queue[2].satisfied);
        assert_eq!(econ.outstanding_pre_backed, 250);
    }

    #[test]
    fn satisfy_pre_backed_clears_all_when_enough() {
        let mut econ = BondingCurveEconomicState::default();
        econ.pre_backed_queue = vec![
            PreBackedEntry {
                block_height: 1,
                amount_cbe: 100,
                recipient: [1u8; 32],
                deliverable_hash: [0xAA; 32],
                satisfied: false,
            },
            PreBackedEntry {
                block_height: 2,
                amount_cbe: 200,
                recipient: [2u8; 32],
                deliverable_hash: [0xBB; 32],
                satisfied: false,
            },
        ];
        econ.outstanding_pre_backed = 300;

        econ.satisfy_pre_backed(500);
        assert!(econ.pre_backed_queue[0].satisfied);
        assert!(econ.pre_backed_queue[1].satisfied);
        assert_eq!(econ.outstanding_pre_backed, 0);
    }

    #[test]
    fn satisfy_pre_backed_skips_already_satisfied() {
        let mut econ = BondingCurveEconomicState::default();
        econ.pre_backed_queue = vec![
            PreBackedEntry {
                block_height: 1,
                amount_cbe: 100,
                recipient: [1u8; 32],
                deliverable_hash: [0xAA; 32],
                satisfied: true, // already done
            },
            PreBackedEntry {
                block_height: 2,
                amount_cbe: 50,
                recipient: [2u8; 32],
                deliverable_hash: [0xBB; 32],
                satisfied: false,
            },
        ];
        econ.outstanding_pre_backed = 50;

        econ.satisfy_pre_backed(50);
        assert!(econ.pre_backed_queue[1].satisfied);
        assert_eq!(econ.outstanding_pre_backed, 0);
    }
}
