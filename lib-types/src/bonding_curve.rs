use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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
    /// Accumulates toward graduation; becomes CBE side of AMM seed at graduation.
    #[serde(default)]
    pub liquidity_pool_balance: u128,
    /// Total SOV minted from on-ramp deposits (event-driven, priced at NAV model).
    #[serde(default)]
    pub total_sov_minted: u128,
    pub graduated: bool,
    pub sell_enabled: bool,
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
            treasury_balance: 3,
            graduated: true,
            sell_enabled: false,
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
}
