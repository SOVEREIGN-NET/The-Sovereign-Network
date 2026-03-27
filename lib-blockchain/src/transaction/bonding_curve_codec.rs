use crate::integration::crypto_integration::Signature;
use lib_types::{BondingCurveBuyTx, BondingCurveSellTx, Nonce48};
use thiserror::Error;

pub const BONDING_CURVE_TX_PAYLOAD_LEN: usize = 88;
pub const BONDING_CURVE_TX_SIGNED_REGION_END: usize = 88;
pub const BONDING_CURVE_BUY_ACTION: u8 = 0x01;
pub const BONDING_CURVE_SELL_ACTION: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalBondingCurveTx {
    Buy(BondingCurveBuyTx),
    Sell(BondingCurveSellTx),
}

#[derive(Debug, Clone)]
pub struct CanonicalBondingCurveEnvelope {
    pub payload: [u8; BONDING_CURVE_TX_PAYLOAD_LEN],
    pub signature: Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BondingCurveCodecError {
    #[error("invalid payload length: expected 88 bytes, got {0}")]
    InvalidLength(usize),
    #[error("invalid buy action byte: {0:#04x}")]
    InvalidBuyAction(u8),
    #[error("invalid sell action byte: {0:#04x}")]
    InvalidSellAction(u8),
    #[error("unknown action byte: {0:#04x}")]
    UnknownAction(u8),
}

pub fn bonding_curve_signed_region(payload: &[u8]) -> Result<&[u8], BondingCurveCodecError> {
    if payload.len() != BONDING_CURVE_TX_PAYLOAD_LEN {
        return Err(BondingCurveCodecError::InvalidLength(payload.len()));
    }
    Ok(&payload[..BONDING_CURVE_TX_SIGNED_REGION_END])
}

pub fn encode_bonding_curve_buy(tx: &BondingCurveBuyTx) -> [u8; BONDING_CURVE_TX_PAYLOAD_LEN] {
    let mut payload = [0u8; BONDING_CURVE_TX_PAYLOAD_LEN];
    payload[0] = tx.action;
    payload[1] = tx.chain_id;
    payload[2..8].copy_from_slice(&tx.nonce.to_be_bytes());
    payload[8..40].copy_from_slice(&tx.sender);
    payload[40..56].copy_from_slice(&tx.amount_in.to_be_bytes());
    payload[56..72].copy_from_slice(&tx.max_price.to_be_bytes());
    payload[72..88].copy_from_slice(&tx.expected_s_c.to_be_bytes());
    payload
}

pub fn decode_bonding_curve_buy(
    payload: &[u8],
) -> Result<BondingCurveBuyTx, BondingCurveCodecError> {
    if payload.len() != BONDING_CURVE_TX_PAYLOAD_LEN {
        return Err(BondingCurveCodecError::InvalidLength(payload.len()));
    }
    if payload[0] != BONDING_CURVE_BUY_ACTION {
        return Err(BondingCurveCodecError::InvalidBuyAction(payload[0]));
    }

    let mut sender = [0u8; 32];
    sender.copy_from_slice(&payload[8..40]);

    Ok(BondingCurveBuyTx {
        action: payload[0],
        chain_id: payload[1],
        nonce: Nonce48(
            payload[2..8]
                .try_into()
                .expect("nonce slice length is fixed"),
        ),
        sender,
        amount_in: u128::from_be_bytes(payload[40..56].try_into().expect("amount slice length")),
        max_price: u128::from_be_bytes(payload[56..72].try_into().expect("price slice length")),
        expected_s_c: u128::from_be_bytes(payload[72..88].try_into().expect("supply slice length")),
    })
}

pub fn encode_bonding_curve_sell(tx: &BondingCurveSellTx) -> [u8; BONDING_CURVE_TX_PAYLOAD_LEN] {
    let mut payload = [0u8; BONDING_CURVE_TX_PAYLOAD_LEN];
    payload[0] = tx.action;
    payload[1] = tx.chain_id;
    payload[2..8].copy_from_slice(&tx.nonce.to_be_bytes());
    payload[8..40].copy_from_slice(&tx.sender);
    payload[40..56].copy_from_slice(&tx.amount_cbe.to_be_bytes());
    payload[56..72].copy_from_slice(&tx.min_payout.to_be_bytes());
    payload[72..88].copy_from_slice(&tx.expected_s_c.to_be_bytes());
    payload
}

pub fn decode_bonding_curve_sell(
    payload: &[u8],
) -> Result<BondingCurveSellTx, BondingCurveCodecError> {
    if payload.len() != BONDING_CURVE_TX_PAYLOAD_LEN {
        return Err(BondingCurveCodecError::InvalidLength(payload.len()));
    }
    if payload[0] != BONDING_CURVE_SELL_ACTION {
        return Err(BondingCurveCodecError::InvalidSellAction(payload[0]));
    }

    let mut sender = [0u8; 32];
    sender.copy_from_slice(&payload[8..40]);

    Ok(BondingCurveSellTx {
        action: payload[0],
        chain_id: payload[1],
        nonce: Nonce48(
            payload[2..8]
                .try_into()
                .expect("nonce slice length is fixed"),
        ),
        sender,
        amount_cbe: u128::from_be_bytes(payload[40..56].try_into().expect("amount slice length")),
        min_payout: u128::from_be_bytes(payload[56..72].try_into().expect("payout slice length")),
        expected_s_c: u128::from_be_bytes(payload[72..88].try_into().expect("supply slice length")),
    })
}

pub fn encode_canonical_bonding_curve_tx(
    tx: &CanonicalBondingCurveTx,
) -> [u8; BONDING_CURVE_TX_PAYLOAD_LEN] {
    match tx {
        CanonicalBondingCurveTx::Buy(tx) => encode_bonding_curve_buy(tx),
        CanonicalBondingCurveTx::Sell(tx) => encode_bonding_curve_sell(tx),
    }
}

pub fn canonical_curve_sender(tx: &CanonicalBondingCurveTx) -> [u8; 32] {
    match tx {
        CanonicalBondingCurveTx::Buy(tx) => tx.sender,
        CanonicalBondingCurveTx::Sell(tx) => tx.sender,
    }
}

pub fn decode_canonical_bonding_curve_tx(
    payload: &[u8],
) -> Result<CanonicalBondingCurveTx, BondingCurveCodecError> {
    if payload.len() != BONDING_CURVE_TX_PAYLOAD_LEN {
        return Err(BondingCurveCodecError::InvalidLength(payload.len()));
    }

    match payload[0] {
        BONDING_CURVE_BUY_ACTION => {
            decode_bonding_curve_buy(payload).map(CanonicalBondingCurveTx::Buy)
        }
        BONDING_CURVE_SELL_ACTION => {
            decode_bonding_curve_sell(payload).map(CanonicalBondingCurveTx::Sell)
        }
        action => Err(BondingCurveCodecError::UnknownAction(action)),
    }
}

pub fn envelope_signer_matches_sender(
    envelope: &CanonicalBondingCurveEnvelope,
) -> Result<bool, BondingCurveCodecError> {
    let tx = decode_canonical_bonding_curve_tx(&envelope.payload)?;
    Ok(envelope.signature.public_key.key_id == canonical_curve_sender(&tx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buy_payload_round_trips_with_fixed_offsets() {
        let tx = BondingCurveBuyTx {
            action: BONDING_CURVE_BUY_ACTION,
            chain_id: 0x03,
            nonce: Nonce48::from_u64(0x0102_0304_0506).unwrap(),
            sender: [0x11; 32],
            amount_in: 7,
            max_price: 8,
            expected_s_c: 9,
        };

        let encoded = encode_bonding_curve_buy(&tx);
        assert_eq!(encoded.len(), BONDING_CURVE_TX_PAYLOAD_LEN);
        assert_eq!(&encoded[2..8], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(decode_bonding_curve_buy(&encoded).unwrap(), tx);
    }

    #[test]
    fn sell_payload_round_trips_with_fixed_offsets() {
        let tx = BondingCurveSellTx {
            action: BONDING_CURVE_SELL_ACTION,
            chain_id: 0x03,
            nonce: Nonce48::from_u64(0x0a0b_0c0d_0e0f).unwrap(),
            sender: [0x22; 32],
            amount_cbe: 17,
            min_payout: 18,
            expected_s_c: 19,
        };

        let encoded = encode_bonding_curve_sell(&tx);
        assert_eq!(encoded.len(), BONDING_CURVE_TX_PAYLOAD_LEN);
        assert_eq!(&encoded[2..8], &[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        assert_eq!(decode_bonding_curve_sell(&encoded).unwrap(), tx);
    }

    #[test]
    fn decode_rejects_wrong_payload_length() {
        assert_eq!(
            decode_bonding_curve_buy(&[0u8; 87]),
            Err(BondingCurveCodecError::InvalidLength(87))
        );
        assert_eq!(
            decode_bonding_curve_sell(&[0u8; 89]),
            Err(BondingCurveCodecError::InvalidLength(89))
        );
    }

    #[test]
    fn decode_rejects_wrong_action_byte() {
        let mut buy_payload = [0u8; BONDING_CURVE_TX_PAYLOAD_LEN];
        buy_payload[0] = BONDING_CURVE_SELL_ACTION;
        assert_eq!(
            decode_bonding_curve_buy(&buy_payload),
            Err(BondingCurveCodecError::InvalidBuyAction(
                BONDING_CURVE_SELL_ACTION
            ))
        );

        let mut sell_payload = [0u8; BONDING_CURVE_TX_PAYLOAD_LEN];
        sell_payload[0] = BONDING_CURVE_BUY_ACTION;
        assert_eq!(
            decode_bonding_curve_sell(&sell_payload),
            Err(BondingCurveCodecError::InvalidSellAction(
                BONDING_CURVE_BUY_ACTION
            ))
        );
    }

    #[test]
    fn signed_region_is_the_full_payload_prefix() {
        let payload = [0x55u8; BONDING_CURVE_TX_PAYLOAD_LEN];
        let signed = bonding_curve_signed_region(&payload).unwrap();
        assert_eq!(signed.len(), BONDING_CURVE_TX_SIGNED_REGION_END);
        assert_eq!(signed, &payload[..]);
    }

    #[test]
    fn canonical_decoder_dispatches_buy_and_sell_by_action_byte() {
        let buy = CanonicalBondingCurveTx::Buy(BondingCurveBuyTx {
            action: BONDING_CURVE_BUY_ACTION,
            chain_id: 0x03,
            nonce: Nonce48::from_u64(1).unwrap(),
            sender: [0x33; 32],
            amount_in: 21,
            max_price: 22,
            expected_s_c: 23,
        });
        let sell = CanonicalBondingCurveTx::Sell(BondingCurveSellTx {
            action: BONDING_CURVE_SELL_ACTION,
            chain_id: 0x03,
            nonce: Nonce48::from_u64(2).unwrap(),
            sender: [0x44; 32],
            amount_cbe: 31,
            min_payout: 32,
            expected_s_c: 33,
        });

        assert_eq!(
            decode_canonical_bonding_curve_tx(&encode_canonical_bonding_curve_tx(&buy)).unwrap(),
            buy
        );
        assert_eq!(
            decode_canonical_bonding_curve_tx(&encode_canonical_bonding_curve_tx(&sell)).unwrap(),
            sell
        );
    }

    #[test]
    fn canonical_decoder_rejects_unknown_action_byte() {
        let mut payload = [0u8; BONDING_CURVE_TX_PAYLOAD_LEN];
        payload[0] = 0xff;
        assert_eq!(
            decode_canonical_bonding_curve_tx(&payload),
            Err(BondingCurveCodecError::UnknownAction(0xff))
        );
    }

    #[test]
    fn envelope_signer_must_match_payload_sender() {
        let keypair = lib_crypto::KeyPair::generate().unwrap();
        let tx = CanonicalBondingCurveTx::Buy(BondingCurveBuyTx {
            action: BONDING_CURVE_BUY_ACTION,
            chain_id: 0x03,
            nonce: Nonce48::from_u64(7).unwrap(),
            sender: keypair.public_key.key_id,
            amount_in: 55,
            max_price: 66,
            expected_s_c: 77,
        });
        let payload = encode_canonical_bonding_curve_tx(&tx);
        let signature = keypair.sign(&payload).unwrap();
        let envelope = CanonicalBondingCurveEnvelope { payload, signature };

        assert!(envelope_signer_matches_sender(&envelope).unwrap());
    }

    #[test]
    fn envelope_signer_mismatch_is_rejected() {
        let signer = lib_crypto::KeyPair::generate().unwrap();
        let other = lib_crypto::KeyPair::generate().unwrap();
        let tx = CanonicalBondingCurveTx::Sell(BondingCurveSellTx {
            action: BONDING_CURVE_SELL_ACTION,
            chain_id: 0x03,
            nonce: Nonce48::from_u64(8).unwrap(),
            sender: other.public_key.key_id,
            amount_cbe: 88,
            min_payout: 99,
            expected_s_c: 111,
        });
        let payload = encode_canonical_bonding_curve_tx(&tx);
        let signature = signer.sign(&payload).unwrap();
        let envelope = CanonicalBondingCurveEnvelope { payload, signature };

        assert!(!envelope_signer_matches_sender(&envelope).unwrap());
    }
}
