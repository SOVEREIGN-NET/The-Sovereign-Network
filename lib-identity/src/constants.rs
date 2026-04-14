//! Network-wide constants for ZHTP identity and network configuration
//!
//! This module contains shared constants used across the ZHTP ecosystem
//! to ensure consistency in network identification and configuration.

/// Testnet genesis hash for network replay protection
///
/// This is the genesis block hash for the ZHTP testnet. It's used to:
/// - Initialize network genesis in CLI for replay protection
/// - Bind NodeId generation to the specific network
/// - Prevent cross-chain replay attacks
///
/// Format: 32-byte hash where first byte (0x02) indicates testnet version
///
/// # Usage
///
/// ```ignore
/// use lib_identity::constants::TESTNET_GENESIS_HASH;
/// use lib_identity::types::node_id::try_set_network_genesis;
///
/// // Initialize at application startup
/// let _ = try_set_network_genesis(TESTNET_GENESIS_HASH);
/// ```
pub const TESTNET_GENESIS_HASH: [u8; 32] = [
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// SOV atomic units (18 decimals): 1 SOV = 10^18 units
pub const SOV_ATOMIC_UNITS: u128 = lib_types::sov::SCALE;

/// Welcome bonus amount in SOV (human units)
pub const SOV_WELCOME_BONUS_SOV: u128 = 5_000;

/// Welcome bonus in atomic units (18-decimal)
pub const SOV_WELCOME_BONUS: u128 = lib_types::sov::atoms(5_000);

/// Monthly UBI amount in SOV (human units)
pub const SOV_UBI_MONTHLY_SOV: u128 = 1_000;

/// Monthly UBI in atomic units (18-decimal)
pub const SOV_UBI_MONTHLY: u128 = lib_types::sov::atoms(1_000);
