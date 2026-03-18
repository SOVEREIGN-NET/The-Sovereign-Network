use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingCurveBand {
    pub index: u8,
    pub start_supply: u128,
    pub end_supply: u128,
    pub slope_num: u128,
    pub slope_den: u128,
    pub intercept: i128,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingCurveBuyTx {
    pub sender: [u8; 32],
    pub gross_sov: u128,
    pub min_cbe: u128,
    pub nonce: u64,
    pub deadline: u64,
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondingCurveSellTx {
    pub sender: [u8; 32],
    pub delta_s: u128,
    pub min_sov: u128,
    pub nonce: u64,
    pub deadline: u64,
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
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

mod signature_serde {
    use super::*;

    pub fn serialize<S>(data: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(64)?;
        for byte in data {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignatureVisitor;

        impl<'de> Visitor<'de> for SignatureVisitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a 64-byte signature")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = [0u8; 64];
                for (i, byte) in out.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }

        deserializer.deserialize_tuple(64, SignatureVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_GROSS_SOV_PER_TX: u128 = 1_000_000_000_000_000_000_000_000;
    const MAX_DELTA_S_PER_TX: u128 = 100_000_000_000u128 * 1_000_000_000_000_000_000u128;

    #[test]
    fn buy_tx_bincode_size_is_fixed() {
        let a = BondingCurveBuyTx {
            sender: [1u8; 32],
            gross_sov: 1,
            min_cbe: 2,
            nonce: 3,
            deadline: 4,
            signature: [5u8; 64],
        };
        let b = BondingCurveBuyTx {
            sender: [9u8; 32],
            gross_sov: MAX_GROSS_SOV_PER_TX,
            min_cbe: MAX_DELTA_S_PER_TX,
            nonce: u64::MAX,
            deadline: u64::MAX - 1,
            signature: [7u8; 64],
        };

        assert_eq!(bincode::serialize(&a).unwrap().len(), 144);
        assert_eq!(bincode::serialize(&b).unwrap().len(), 144);
    }

    #[test]
    fn sell_tx_bincode_size_is_fixed() {
        let a = BondingCurveSellTx {
            sender: [1u8; 32],
            delta_s: 1,
            min_sov: 2,
            nonce: 3,
            deadline: 4,
            signature: [5u8; 64],
        };
        let b = BondingCurveSellTx {
            sender: [9u8; 32],
            delta_s: MAX_DELTA_S_PER_TX,
            min_sov: MAX_GROSS_SOV_PER_TX,
            nonce: u64::MAX,
            deadline: u64::MAX - 1,
            signature: [7u8; 64],
        };

        assert_eq!(bincode::serialize(&a).unwrap().len(), 144);
        assert_eq!(bincode::serialize(&b).unwrap().len(), 144);
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
