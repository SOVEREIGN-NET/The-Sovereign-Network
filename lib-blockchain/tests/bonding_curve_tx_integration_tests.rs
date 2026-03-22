//! Bonding Curve Transaction Integration Tests
//!
//! The legacy user-deployable bonding curve execution path has been removed (#1945).
//! The canonical CBE curve is initialized at genesis and executed via the
//! fixed-width memo payload lane (BondingCurveBuy/Sell canonical path).

use lib_blockchain::{contracts::bonding_curve::Phase, contracts::tokens::CBE_SYMBOL, Blockchain};

// ============================================================================
// CBE Genesis Initialization Test
// ============================================================================

#[test]
fn test_cbe_genesis_initialization() {
    let blockchain = Blockchain::new().expect("Failed to create blockchain");

    // CBE should be automatically initialized at genesis
    let cbe_token_id = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        "CBE Equity".hash(&mut hasher);
        CBE_SYMBOL.hash(&mut hasher);
        let hash = hasher.finish();
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&hash.to_le_bytes());
        for i in 8..32 {
            id[i] = ((hash >> (i % 8)) & 0xFF) as u8;
        }
        id
    };

    assert!(
        blockchain.bonding_curve_registry.contains(&cbe_token_id),
        "CBE should be initialized at genesis"
    );

    let cbe = blockchain.bonding_curve_registry.get(&cbe_token_id).unwrap();
    assert_eq!(cbe.name, "CBE Equity");
    assert_eq!(cbe.symbol, CBE_SYMBOL);
    assert_eq!(cbe.phase, Phase::Curve);
    assert!(cbe.sell_enabled);
}
