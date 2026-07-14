//! Sovereign Asset `AssetLaunch` transaction builder (#2878).
//!
//! Mirrors `zhtp-cli dao launch` manifest hashing and payload encoding so mobile
//! clients can POST `signed_tx` to `/api/v1/assets/launch` without server-held keys.

use crate::identity::Identity;
use crate::token_tx::create_public_key_with_kyber;
use lib_blockchain::contracts::sovereign_asset::{DaoClass, SupplyMode};
use lib_blockchain::integration::crypto_integration::Signature;
use lib_blockchain::transaction::asset_tx::{
    AssetLaunchPayloadV1, GovernanceLaunchConfig, RewardsLaunchConfig,
};
use lib_blockchain::Transaction;
use lib_crypto::types::signatures::SignatureAlgorithm;

pub use lib_blockchain::transaction::asset_tx::{
    build_dao_launch_manifest, build_dao_launch_manifest_bytes, manifest_cid_hash_from_bytes,
};

/// Parameters for building a signed `AssetLaunch` transaction.
#[derive(Debug, Clone)]
pub struct AssetLaunchBuildParams {
    pub name: String,
    pub symbol: String,
    pub initial_supply: u128,
    pub decimals: u8,
    pub treasury_key_id: [u8; 32],
    pub dao_class: DaoClass,
    pub burn_bps: u16,
    pub supply_mode: SupplyMode,
    pub manifest_cid: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub chain_id: u8,
    pub rewards: Option<RewardsLaunchConfig>,
    pub governance: Option<GovernanceLaunchConfig>,
    pub transfer_authority: bool,
}

impl Default for AssetLaunchBuildParams {
    fn default() -> Self {
        Self {
            name: String::new(),
            symbol: String::new(),
            initial_supply: 0,
            decimals: 18,
            treasury_key_id: [0u8; 32],
            dao_class: DaoClass::Fp,
            burn_bps: 0,
            supply_mode: SupplyMode::Fixed,
            manifest_cid: [0u8; 32],
            manifest_hash: [0u8; 32],
            chain_id: 0x02,
            rewards: None,
            governance: None,
            transfer_authority: false,
        }
    }
}

/// Build and sign an `AssetLaunch` transaction.
///
/// Returns hex-encoded bincode `Transaction` for `POST /api/v1/assets/launch`.
pub fn build_asset_launch_tx(
    identity: &Identity,
    params: &AssetLaunchBuildParams,
) -> Result<String, String> {
    if params.treasury_key_id == [0u8; 32] {
        return Err("treasury_key_id must be non-zero".to_string());
    }
    if params.initial_supply == 0 {
        return Err("initial_supply must be non-zero".to_string());
    }
    if params.transfer_authority && params.governance.is_none() {
        return Err("transfer_authority requires governance module".to_string());
    }

    let sender_pk =
        create_public_key_with_kyber(identity.public_key.clone(), identity.kyber_public_key.clone());
    if params.treasury_key_id == sender_pk.key_id {
        return Err("treasury_key_id must differ from creator".to_string());
    }

    let payload = AssetLaunchPayloadV1 {
        name: params.name.clone(),
        symbol: params.symbol.clone(),
        decimals: params.decimals,
        initial_supply: params.initial_supply,
        treasury_key_id: params.treasury_key_id,
        treasury_bps: params.dao_class.treasury_bps(),
        supply_mode: params.supply_mode,
        manifest_cid: params.manifest_cid,
        manifest_hash: params.manifest_hash,
        curve: None,
        rewards: params.rewards.clone(),
        governance: params.governance.clone(),
        transfer_authority: params.transfer_authority,
        dao_class: params.dao_class,
        burn_bps: params.burn_bps,
    };
    payload
        .validate_dao_launch_ui_constraints()
        .map_err(|e| format!("DAO launch validation failed: {e}"))?;

    let memo = payload
        .encode_memo()
        .map_err(|e| format!("encode asset launch payload: {e}"))?;

    let mut tx = Transaction::new_asset_launch_with_chain_id(
        params.chain_id,
        Signature {
            signature: vec![],
            public_key: sender_pk.clone(),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 0,
        },
        memo,
    );

    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign AssetLaunch: {e}"))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: sender_pk,
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let bytes =
        bincode::serialize(&tx).map_err(|e| format!("Failed to serialize AssetLaunch tx: {e}"))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_blockchain::contracts::sovereign_asset::GovernanceVerifierState;
    use lib_blockchain::transaction::asset_tx::AssetLaunchPayloadV1;
    use lib_blockchain::types::transaction_type::TransactionType;

    #[test]
    fn manifest_round_trip_matches_canonical_schema() {
        let bytes = build_dao_launch_manifest_bytes("Bubble", "BUBL", 18);
        let (cid, hash) = manifest_cid_hash_from_bytes(&bytes, None).unwrap();
        assert_ne!(cid, [0u8; 32]);
        assert_ne!(hash, [0u8; 32]);
        let (cid2, hash2) = build_dao_launch_manifest("Bubble", "BUBL", 18).unwrap();
        assert_eq!(cid, cid2);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn build_asset_launch_tx_round_trip() {
        use crate::identity::generate_identity;

        let identity = generate_identity("test-device".to_string()).unwrap();
        let treasury = [0x42u8; 32];
        let (cid, hash) = build_dao_launch_manifest("Test DAO", "TDAO", 18).unwrap();

        let signed = build_asset_launch_tx(
            &identity,
            &AssetLaunchBuildParams {
                name: "Test DAO".to_string(),
                symbol: "TDAO".to_string(),
                initial_supply: 1_000_000_000_000_000_000_000,
                decimals: 18,
                treasury_key_id: treasury,
                dao_class: DaoClass::Fp,
                burn_bps: 0,
                supply_mode: SupplyMode::Fixed,
                manifest_cid: cid,
                manifest_hash: hash,
                chain_id: 2,
                rewards: None,
                governance: None,
                transfer_authority: false,
            },
        )
        .expect("builder ok");

        let tx_bytes = hex::decode(signed).expect("hex");
        let tx: Transaction = bincode::deserialize(&tx_bytes).expect("tx");
        assert_eq!(tx.transaction_type, TransactionType::AssetLaunch);

        let payload = AssetLaunchPayloadV1::decode_memo(&tx.memo).expect("memo");
        payload.validate_dao_launch_ui_constraints().unwrap();
        assert_eq!(payload.symbol, "TDAO");
        assert_eq!(payload.dao_class, DaoClass::Fp);
        assert_eq!(payload.treasury_bps, DaoClass::Fp.treasury_bps());
    }

    #[test]
    fn np_launch_uses_full_treasury_split() {
        use crate::identity::generate_identity;

        let identity = generate_identity("np-device".to_string()).unwrap();
        let (cid, hash) = build_dao_launch_manifest("Mission", "MSN", 18).unwrap();
        let supply = 1_000_000_000_000_000_000_000u128;

        let signed = build_asset_launch_tx(
            &identity,
            &AssetLaunchBuildParams {
                name: "Mission".to_string(),
                symbol: "MSN".to_string(),
                initial_supply: supply,
                decimals: 18,
                treasury_key_id: [0x55u8; 32],
                dao_class: DaoClass::Np,
                burn_bps: 0,
                supply_mode: SupplyMode::Fixed,
                manifest_cid: cid,
                manifest_hash: hash,
                chain_id: 2,
                rewards: None,
                governance: None,
                transfer_authority: false,
            },
        )
        .unwrap();

        let tx: Transaction =
            bincode::deserialize(&hex::decode(signed).unwrap()).unwrap();
        let payload = AssetLaunchPayloadV1::decode_memo(&tx.memo).unwrap();
        let (creator, treasury) = payload.split_initial_supply();
        assert_eq!(creator, 0);
        assert_eq!(treasury, supply);
    }

    #[test]
    fn transfer_authority_requires_governance() {
        use crate::identity::generate_identity;

        let identity = generate_identity("gov-device".to_string()).unwrap();
        let (cid, hash) = build_dao_launch_manifest("Gov", "GOV", 18).unwrap();
        let err = build_asset_launch_tx(
            &identity,
            &AssetLaunchBuildParams {
                name: "Gov".to_string(),
                symbol: "GOV".to_string(),
                initial_supply: 1_000_000_000_000_000_000_000,
                decimals: 18,
                treasury_key_id: [0x66u8; 32],
                dao_class: DaoClass::Fp,
                burn_bps: 0,
                supply_mode: SupplyMode::Fixed,
                manifest_cid: cid,
                manifest_hash: hash,
                chain_id: 2,
                rewards: None,
                governance: None,
                transfer_authority: true,
            },
        )
        .unwrap_err();
        assert!(err.contains("transfer_authority requires governance"));
    }

    #[test]
    fn transfer_authority_with_governance_succeeds() {
        use crate::identity::generate_identity;

        let identity = generate_identity("gov-ok".to_string()).unwrap();
        let (cid, hash) = build_dao_launch_manifest("Gov", "GOV", 18).unwrap();
        let signed = build_asset_launch_tx(
            &identity,
            &AssetLaunchBuildParams {
                name: "Gov".to_string(),
                symbol: "GOV".to_string(),
                initial_supply: 1_000_000_000_000_000_000_000,
                decimals: 18,
                treasury_key_id: [0x77u8; 32],
                dao_class: DaoClass::Fp,
                burn_bps: 0,
                supply_mode: SupplyMode::Fixed,
                manifest_cid: cid,
                manifest_hash: hash,
                chain_id: 2,
                rewards: None,
                governance: Some(GovernanceLaunchConfig {
                    verifier: GovernanceVerifierState::Single {
                        signer_key_id: [0x88; 32],
                    },
                    threshold: None,
                }),
                transfer_authority: true,
            },
        )
        .expect("governance launch ok");
        let tx: Transaction =
            bincode::deserialize(&hex::decode(signed).unwrap()).unwrap();
        let payload = AssetLaunchPayloadV1::decode_memo(&tx.memo).unwrap();
        assert!(payload.transfer_authority);
        assert!(payload.governance.is_some());
    }
}