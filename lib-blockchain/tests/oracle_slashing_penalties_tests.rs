use lib_blockchain::{
    Blockchain, OraclePriceAttestation, OracleSlashingEvidence, OracleSlashingOutcome,
    ValidatorInfo,
};
use lib_crypto::keypair::generation::KeyPair;

fn make_validator(identity_id: &str, keypair: &KeyPair, stake: u64) -> ValidatorInfo {
    ValidatorInfo {
        identity_id: identity_id.to_string(),
        stake,
        storage_provided: 1_000_000,
        consensus_key: {
            let mut bytes = keypair.public_key.dilithium_pk.clone();
            bytes.extend_from_slice(&keypair.public_key.kyber_pk);
            bytes
        },
        networking_key: vec![7u8; 32],
        rewards_key: vec![8u8; 32],
        network_address: "127.0.0.1:9334".to_string(),
        commission_rate: 5,
        status: "active".to_string(),
        registered_at: 1_700_000_000,
        last_activity: 1_700_000_000,
        blocks_validated: 0,
        slash_count: 0,
        admission_source: "test".to_string(),
        governance_proposal_id: None,
    }
}

fn signed_attestation(keypair: &KeyPair, epoch: u64, price: u128) -> OraclePriceAttestation {
    let mut att = OraclePriceAttestation {
        epoch_id: epoch,
        sov_usd_price: price,
        timestamp: 1_700_000_000 + epoch,
        validator_pubkey: keypair.public_key.key_id,
        signature: Vec::new(),
    };
    let digest = att.signing_digest().expect("digest");
    att.signature = keypair.sign(&digest).expect("sign").signature;
    att
}

#[test]
fn oracle_slash_reduces_stake_is_idempotent_and_removes_next_epoch() {
    let mut blockchain = Blockchain::new().expect("blockchain init");
    let offender = KeyPair::generate().expect("offender keypair");
    let peer = KeyPair::generate().expect("peer keypair");

    blockchain.validator_registry.insert(
        "offender".to_string(),
        make_validator("offender", &offender, 1_000_000_000),
    );
    blockchain.validator_registry.insert(
        "peer".to_string(),
        make_validator("peer", &peer, 2_000_000_000),
    );

    blockchain.oracle_state.committee.members = vec![
        offender.public_key.key_id,
        peer.public_key.key_id,
        [9u8; 32],
    ];

    let evidence = OracleSlashingEvidence::DoubleSign {
        first: signed_attestation(&offender, 5, 200_000_000),
        second: signed_attestation(&offender, 5, 201_000_000),
    };

    let first = blockchain
        .apply_oracle_slashing_evidence(&evidence, 5)
        .expect("first evidence apply");
    assert!(matches!(first, OracleSlashingOutcome::Applied(_)));

    let after_first = blockchain.get_validator("offender").expect("validator exists");
    assert_eq!(after_first.stake, 950_000_000);
    assert_eq!(after_first.slash_count, 1);

    let second = blockchain
        .apply_oracle_slashing_evidence(&evidence, 5)
        .expect("duplicate evidence apply");
    assert!(matches!(second, OracleSlashingOutcome::DuplicateEvidence { .. }));

    let after_duplicate = blockchain.get_validator("offender").expect("validator exists");
    assert_eq!(after_duplicate.stake, 950_000_000);
    assert_eq!(after_duplicate.slash_count, 1);

    blockchain.oracle_state.apply_pending_updates(5);
    assert!(blockchain
        .oracle_state
        .committee
        .members
        .contains(&offender.public_key.key_id));

    blockchain.oracle_state.apply_pending_updates(6);
    assert!(!blockchain
        .oracle_state
        .committee
        .members
        .contains(&offender.public_key.key_id));
}
