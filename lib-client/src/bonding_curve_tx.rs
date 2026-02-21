//! Bonding Curve Transaction Builder
//!
//! Provides FFI-exportable functions for building signed bonding curve transactions.
//! iOS/Android clients call these to get hex-encoded transactions ready for the API.

use lib_blockchain::Transaction;
use lib_blockchain::TransactionType;
use lib_blockchain::transaction::{
    BondingCurveDeployData, BondingCurveBuyData, BondingCurveSellData, BondingCurveGraduateData,
};
use lib_blockchain::integration::crypto_integration::{Signature, PublicKey};
use lib_crypto::types::SignatureAlgorithm;

/// Build a signed bonding curve deploy transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/curve/deploy
pub fn build_bonding_curve_deploy_tx(
    identity: &crate::Identity,
    name: &str,
    symbol: &str,
    curve_type: u8,           // 0=Linear, 1=Exponential, 2=Sigmoid
    base_price: u64,
    curve_param: u64,
    midpoint_supply: Option<u64>,
    threshold_type: u8,       // 0=ReserveAmount, 1=SupplyAmount, 2=TimeAndReserve, 3=TimeAndSupply
    threshold_value: u64,
    threshold_time_seconds: Option<u64>,
    sell_enabled: bool,
    chain_id: u8,
    nonce: u64,
) -> Result<String, String> {
    let public_key = crate::token_tx::create_public_key(identity.public_key.clone());
    let mut creator_key_id = [0u8; 32];
    creator_key_id.copy_from_slice(&public_key.key_id[..32]);

    let deploy_data = BondingCurveDeployData {
        name: name.to_string(),
        symbol: symbol.to_string(),
        curve_type,
        base_price,
        curve_param,
        midpoint_supply,
        threshold_type,
        threshold_value,
        threshold_time_seconds,
        sell_enabled,
        creator: creator_key_id,
        nonce,
    };

    // Calculate fee
    let estimated_tx_size = 500; // Base + deploy data
    let min_fee = ((estimated_tx_size as u64 * 10 + 83) / 84) + 50;

    let mut tx = Transaction::new_bonding_curve_deploy_with_chain_id(
        chain_id,
        deploy_data,
        Signature {
            signature: vec![],
            public_key: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: 0,
        },
        b"ZHTP_BONDING_CURVE_DEPLOY".to_vec(),
    );
    tx.fee = min_fee;

    // Sign
    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}

/// Build a signed bonding curve buy transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/curve/buy
pub fn build_bonding_curve_buy_tx(
    identity: &crate::Identity,
    token_id: &[u8; 32],
    stable_amount: u64,
    min_tokens_out: u64,
    chain_id: u8,
    nonce: u64,
) -> Result<String, String> {
    let public_key = crate::token_tx::create_public_key(identity.public_key.clone());
    let mut buyer_key_id = [0u8; 32];
    buyer_key_id.copy_from_slice(&public_key.key_id[..32]);

    let buy_data = BondingCurveBuyData {
        token_id: *token_id,
        stable_amount,
        min_tokens_out,
        buyer: buyer_key_id,
        nonce,
    };

    let estimated_tx_size = 400;
    let min_fee = ((estimated_tx_size as u64 * 10 + 83) / 84) + 50;

    let mut tx = Transaction::new_bonding_curve_buy_with_chain_id(
        chain_id,
        buy_data,
        Signature {
            signature: vec![],
            public_key: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: 0,
        },
        b"ZHTP_BONDING_CURVE_BUY".to_vec(),
    );
    tx.fee = min_fee;

    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}

/// Build a signed bonding curve sell transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/curve/sell
pub fn build_bonding_curve_sell_tx(
    identity: &crate::Identity,
    token_id: &[u8; 32],
    token_amount: u64,
    min_stable_out: u64,
    chain_id: u8,
    nonce: u64,
) -> Result<String, String> {
    let public_key = crate::token_tx::create_public_key(identity.public_key.clone());
    let mut seller_key_id = [0u8; 32];
    seller_key_id.copy_from_slice(&public_key.key_id[..32]);

    let sell_data = BondingCurveSellData {
        token_id: *token_id,
        token_amount,
        min_stable_out,
        seller: seller_key_id,
        nonce,
    };

    let estimated_tx_size = 400;
    let min_fee = ((estimated_tx_size as u64 * 10 + 83) / 84) + 50;

    let mut tx = Transaction::new_bonding_curve_sell_with_chain_id(
        chain_id,
        sell_data,
        Signature {
            signature: vec![],
            public_key: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: 0,
        },
        b"ZHTP_BONDING_CURVE_SELL".to_vec(),
    );
    tx.fee = min_fee;

    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}

/// Build a signed bonding curve graduate transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/curve/graduate
pub fn build_bonding_curve_graduate_tx(
    identity: &crate::Identity,
    token_id: &[u8; 32],
    pool_id: &[u8; 32],
    sov_seed_amount: u64,
    token_seed_amount: u64,
    chain_id: u8,
    nonce: u64,
) -> Result<String, String> {
    let public_key = crate::token_tx::create_public_key(identity.public_key.clone());
    let mut graduator_key_id = [0u8; 32];
    graduator_key_id.copy_from_slice(&public_key.key_id[..32]);

    let graduate_data = BondingCurveGraduateData {
        token_id: *token_id,
        pool_id: *pool_id,
        sov_seed_amount,
        token_seed_amount,
        graduator: graduator_key_id,
        nonce,
    };

    let estimated_tx_size = 450;
    let min_fee = ((estimated_tx_size as u64 * 10 + 83) / 84) + 50;

    let mut tx = Transaction::new_bonding_curve_graduate_with_chain_id(
        chain_id,
        graduate_data,
        Signature {
            signature: vec![],
            public_key: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: 0,
        },
        b"ZHTP_BONDING_CURVE_GRADUATE".to_vec(),
    );
    tx.fee = min_fee;

    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}

/// Build a signed AMM swap transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/swap
/// Note: This uses ContractExecution transaction type with AMM call data
pub fn build_swap_tx(
    identity: &crate::Identity,
    token_id: &[u8; 32],
    pool_id: &[u8; 32],
    amount_in: u64,
    min_amount_out: u64,
    token_to_sov: bool,
    chain_id: u8,
    nonce: u64,
) -> Result<String, String> {
    // For AMM swaps, we use ContractExecution with encoded call data
    use lib_blockchain::types::{ContractType, ContractCall, CallPermissions};

    let public_key = crate::token_tx::create_public_key(identity.public_key.clone());
    let mut swapper_key_id = [0u8; 32];
    swapper_key_id.copy_from_slice(&public_key.key_id[..32]);

    // Encode swap call data
    let call_data = bincode::serialize(&("swap", token_id, pool_id, amount_in, min_amount_out, token_to_sov, nonce))
        .map_err(|e| format!("Failed to encode swap data: {}", e))?;

    let contract_call = ContractCall {
        contract_type: ContractType::Token,
        method: "swap".to_string(),
        params: call_data,
        permissions: CallPermissions::Public,
    };

    let estimated_tx_size = 500 + contract_call.params.len();
    let min_fee = ((estimated_tx_size as u64 * 10 + 83) / 84) + 50;

    // Build transaction using contract execution path
    let mut memo = b"ZHTP".to_vec();
    memo.extend(bincode::serialize(&contract_call).map_err(|e| e.to_string())?);

    let mut tx = Transaction {
        version: 3,
        chain_id,
        transaction_type: TransactionType::ContractExecution,
        inputs: vec![],
        outputs: vec![],
        fee: min_fee,
        signature: Signature {
            signature: vec![],
            public_key: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: 0,
        },
        memo,
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        token_mint_data: None,
        governance_config_data: None,
        bonding_curve_deploy_data: None,
        bonding_curve_buy_data: None,
        bonding_curve_sell_data: None,
        bonding_curve_graduate_data: None,
    };

    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}

/// Build a signed add liquidity transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/swap/liquidity/add
pub fn build_add_liquidity_tx(
    identity: &crate::Identity,
    token_id: &[u8; 32],
    pool_id: &[u8; 32],
    token_amount: u64,
    sov_amount: u64,
    chain_id: u8,
    nonce: u64,
) -> Result<String, String> {
    use lib_blockchain::types::{ContractType, ContractCall, CallPermissions};

    let public_key = crate::token_tx::create_public_key(identity.public_key.clone());

    let call_data = bincode::serialize(&("add_liquidity", token_id, pool_id, token_amount, sov_amount, nonce))
        .map_err(|e| format!("Failed to encode add liquidity data: {}", e))?;

    let contract_call = ContractCall {
        contract_type: ContractType::Token,
        method: "add_liquidity".to_string(),
        params: call_data,
        permissions: CallPermissions::Public,
    };

    let estimated_tx_size = 500 + contract_call.params.len();
    let min_fee = ((estimated_tx_size as u64 * 10 + 83) / 84) + 50;

    let mut memo = b"ZHTP".to_vec();
    memo.extend(bincode::serialize(&contract_call).map_err(|e| e.to_string())?);

    let mut tx = Transaction {
        version: 3,
        chain_id,
        transaction_type: TransactionType::ContractExecution,
        inputs: vec![],
        outputs: vec![],
        fee: min_fee,
        signature: Signature {
            signature: vec![],
            public_key: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: 0,
        },
        memo,
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        token_mint_data: None,
        governance_config_data: None,
        bonding_curve_deploy_data: None,
        bonding_curve_buy_data: None,
        bonding_curve_sell_data: None,
        bonding_curve_graduate_data: None,
    };

    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}

/// Build a signed remove liquidity transaction.
/// Returns hex-encoded transaction ready to POST to /api/v1/swap/liquidity/remove
pub fn build_remove_liquidity_tx(
    identity: &crate::Identity,
    token_id: &[u8; 32],
    pool_id: &[u8; 32],
    lp_amount: u64,
    chain_id: u8,
    nonce: u64,
) -> Result<String, String> {
    use lib_blockchain::types::{ContractType, ContractCall, CallPermissions};

    let public_key = crate::token_tx::create_public_key(identity.public_key.clone());

    let call_data = bincode::serialize(&("remove_liquidity", token_id, pool_id, lp_amount, nonce))
        .map_err(|e| format!("Failed to encode remove liquidity data: {}", e))?;

    let contract_call = ContractCall {
        contract_type: ContractType::Token,
        method: "remove_liquidity".to_string(),
        params: call_data,
        permissions: CallPermissions::Public,
    };

    let estimated_tx_size = 450 + contract_call.params.len();
    let min_fee = ((estimated_tx_size as u64 * 10 + 83) / 84) + 50;

    let mut memo = b"ZHTP".to_vec();
    memo.extend(bincode::serialize(&contract_call).map_err(|e| e.to_string())?);

    let mut tx = Transaction {
        version: 3,
        chain_id,
        transaction_type: TransactionType::ContractExecution,
        inputs: vec![],
        outputs: vec![],
        fee: min_fee,
        signature: Signature {
            signature: vec![],
            public_key: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: 0,
        },
        memo,
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: None,
        token_mint_data: None,
        governance_config_data: None,
        bonding_curve_deploy_data: None,
        bonding_curve_buy_data: None,
        bonding_curve_sell_data: None,
        bonding_curve_graduate_data: None,
    };

    let tx_hash = tx.signing_hash();
    let signature_bytes = crate::identity::sign_message(identity, tx_hash.as_bytes())
        .map_err(|e| format!("Failed to sign: {}", e))?;

    tx.signature = Signature {
        signature: signature_bytes,
        public_key: public_key.clone(),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let final_tx_bytes = bincode::serialize(&tx)
        .map_err(|e| format!("Failed to serialize: {}", e))?;

    Ok(hex::encode(final_tx_bytes))
}
