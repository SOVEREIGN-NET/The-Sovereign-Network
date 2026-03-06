//! Oracle Protocol Version and Activation Gate
//!
//! Implements R6: Protocol Upgrade mechanism for safe Oracle remediation rollout.
//!
//! This module provides deterministic activation boundaries for protocol behavior changes,
//! ensuring:
//! - Legacy behavior before activation point (height/epoch)
//! - Strict-spec behavior after activation point
//! - Deterministic, replay-safe activation decisions
//! - Governance-controlled activation scheduling
//!
//! # Activation Gate Semantics
//!
//! The activation gate uses block height as the canonical trigger because:
//! - Block height is deterministic across all nodes
//! - Block height survives restarts and replays identically
//! - Governance can schedule activation at a future block height
//! - Easy to coordinate across the network

use serde::{Deserialize, Serialize};
use tracing::info;

/// Oracle protocol version for behavior selection.
///
/// This enum represents the major protocol versions. New variants should be added
/// when there are breaking changes to oracle consensus behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleProtocolVersion {
    /// Original protocol version (legacy behavior).
    ///
    /// This version maintains backward compatibility with existing deployments.
    /// Used before any activation point is reached.
    V0Legacy,

    /// Strict spec compliance version (remediation target).
    ///
    /// This version enables all remediation changes:
    /// - Canonical attestation execution path
    /// - Strict CBE graduation formula
    /// - Normalized epoch tracking
    /// - Aligned slashing semantics
    /// - Hardened API/runtime boundaries
    V1StrictSpec,
}

impl Default for OracleProtocolVersion {
    fn default() -> Self {
        Self::V0Legacy
    }
}

impl OracleProtocolVersion {
    /// Returns true if this version enables strict spec behavior.
    pub fn is_strict_spec(&self) -> bool {
        matches!(self, Self::V1StrictSpec)
    }

    /// Returns true if this version uses legacy behavior.
    pub fn is_legacy(&self) -> bool {
        matches!(self, Self::V0Legacy)
    }

    /// Get the protocol version number as u16.
    pub fn as_u16(&self) -> u16 {
        match self {
            Self::V0Legacy => 0,
            Self::V1StrictSpec => 1,
        }
    }

    /// Create from u16, returning None for unknown versions.
    pub fn from_u16(version: u16) -> Option<Self> {
        match version {
            0 => Some(Self::V0Legacy),
            1 => Some(Self::V1StrictSpec),
            _ => None,
        }
    }
}

/// Governance-scheduled protocol activation.
///
/// Represents a pending protocol upgrade that will activate at a specific block height.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingProtocolActivation {
    /// Block height at which the protocol upgrade activates.
    pub activate_at_height: u64,

    /// Target protocol version after activation.
    pub target_version: OracleProtocolVersion,

    /// Block height when this activation was scheduled (for audit trail).
    pub scheduled_at_height: u64,

    /// Governance proposal ID that authorized this activation (optional).
    pub source_proposal_id: Option<[u8; 32]>,
}

/// Protocol version configuration and activation state.
///
/// This struct tracks the current protocol version and any pending activation.
/// It is part of OracleState and is persisted with the blockchain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleProtocolConfig {
    /// Current active protocol version.
    #[serde(default)]
    pub current_version: OracleProtocolVersion,

    /// Pending protocol activation, if scheduled.
    #[serde(default)]
    pub pending_activation: Option<PendingProtocolActivation>,

    /// Height at which current version was activated (for audit trail).
    #[serde(default)]
    pub activated_at_height: u64,
}

impl Default for OracleProtocolConfig {
    fn default() -> Self {
        Self {
            current_version: OracleProtocolVersion::V0Legacy,
            pending_activation: None,
            activated_at_height: 0,
        }
    }
}

impl OracleProtocolConfig {
    /// Create a new protocol config starting at genesis with legacy version.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a config with a specific initial version (for testing).
    #[cfg(test)]
    pub fn with_version(version: OracleProtocolVersion) -> Self {
        Self {
            current_version: version,
            pending_activation: None,
            activated_at_height: 0,
        }
    }

    /// Get the current effective protocol version.
    pub fn current_version(&self) -> OracleProtocolVersion {
        self.current_version
    }

    /// Check if strict spec behavior is active.
    pub fn is_strict_spec_active(&self) -> bool {
        self.current_version.is_strict_spec()
    }

    /// Schedule a protocol upgrade to activate at a future block height.
    ///
    /// # Arguments
    /// * `target_version` - The protocol version to activate
    /// * `activate_at_height` - Block height when upgrade activates (must be > current_height)
    /// * `current_height` - Current block height (for validation)
    /// * `source_proposal_id` - Optional governance proposal ID
    ///
    /// # Errors
    /// Returns error if activate_at_height is not in the future.
    pub fn schedule_activation(
        &mut self,
        target_version: OracleProtocolVersion,
        activate_at_height: u64,
        current_height: u64,
        source_proposal_id: Option<[u8; 32]>,
    ) -> Result<(), ProtocolScheduleError> {
        // Validate activation height is in the future
        if activate_at_height <= current_height {
            return Err(ProtocolScheduleError::InvalidActivationHeight {
                activate_at_height,
                current_height,
            });
        }

        // Validate we're not scheduling a downgrade
        if (target_version.as_u16()) < (self.current_version.as_u16()) {
            return Err(ProtocolScheduleError::DowngradeNotAllowed {
                current: self.current_version.as_u16(),
                requested: target_version.as_u16(),
            });
        }

        // Validate we're not scheduling the same version
        if target_version == self.current_version {
            return Err(ProtocolScheduleError::AlreadyActive);
        }

        // Check if there's already a pending activation
        if let Some(ref pending) = self.pending_activation {
            return Err(ProtocolScheduleError::AlreadyScheduled {
                existing_height: pending.activate_at_height,
            });
        }

        self.pending_activation = Some(PendingProtocolActivation {
            activate_at_height,
            target_version,
            scheduled_at_height: current_height,
            source_proposal_id,
        });

        info!(
            "🔮 Oracle protocol upgrade scheduled: v{} -> v{} at height {}",
            self.current_version.as_u16(),
            target_version.as_u16(),
            activate_at_height
        );

        Ok(())
    }

    /// Cancel any pending protocol activation.
    ///
    /// Returns true if an activation was cancelled, false if nothing was pending.
    pub fn cancel_pending_activation(&mut self) -> bool {
        if self.pending_activation.is_some() {
            let pending = self.pending_activation.take().unwrap();
            info!(
                "🔮 Oracle protocol upgrade cancelled (was scheduled for height {})",
                pending.activate_at_height
            );
            true
        } else {
            false
        }
    }

    /// Apply pending activation if the activation height has been reached.
    ///
    /// This should be called at the beginning of block processing for each block.
    ///
    /// # Arguments
    /// * `current_height` - The current block height
    ///
    /// # Returns
    /// * `Some(OracleProtocolVersion)` if activation occurred (new version)
    /// * `None` if no activation occurred
    pub fn apply_pending_activation(&mut self, current_height: u64) -> Option<OracleProtocolVersion> {
        if let Some(pending) = self.pending_activation.take() {
            if current_height >= pending.activate_at_height {
                // Activation point reached - apply the upgrade
                let old_version = self.current_version;
                self.current_version = pending.target_version;
                self.activated_at_height = current_height;

                info!(
                    "🔮 Oracle protocol upgraded: v{} -> v{} at height {} (scheduled at {})",
                    old_version.as_u16(),
                    self.current_version.as_u16(),
                    current_height,
                    pending.scheduled_at_height
                );

                Some(self.current_version)
            } else {
                // Not yet time - put it back
                self.pending_activation = Some(pending);
                None
            }
        } else {
            None
        }
    }

    /// Check if there's a pending activation.
    pub fn has_pending_activation(&self) -> bool {
        self.pending_activation.is_some()
    }

    /// Get pending activation details if any.
    pub fn pending_activation(&self) -> Option<&PendingProtocolActivation> {
        self.pending_activation.as_ref()
    }

    /// Get the block height when current version was activated.
    pub fn activated_at_height(&self) -> u64 {
        self.activated_at_height
    }
}

/// Errors that can occur when scheduling protocol activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolScheduleError {
    /// Activation height must be in the future.
    InvalidActivationHeight {
        activate_at_height: u64,
        current_height: u64,
    },

    /// Downgrading protocol version is not allowed.
    DowngradeNotAllowed { current: u16, requested: u16 },

    /// Target version is already active.
    AlreadyActive,

    /// Another activation is already scheduled.
    AlreadyScheduled { existing_height: u64 },
}

impl std::fmt::Display for ProtocolScheduleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidActivationHeight {
                activate_at_height,
                current_height,
            } => write!(
                f,
                "activation height {} must be greater than current height {}",
                activate_at_height, current_height
            ),
            Self::DowngradeNotAllowed { current, requested } => write!(
                f,
                "protocol downgrade from v{} to v{} is not allowed",
                current, requested
            ),
            Self::AlreadyActive => write!(f, "target protocol version is already active"),
            Self::AlreadyScheduled { existing_height } => write!(
                f,
                "protocol upgrade already scheduled for height {}",
                existing_height
            ),
        }
    }
}

impl std::error::Error for ProtocolScheduleError {}

/// Feature flags for fine-grained behavior control within a protocol version.
///
/// These flags allow individual remediation features to be toggled independently,
/// providing maximum flexibility for testing and gradual rollout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleFeatureFlags {
    /// Enable canonical attestation execution path (R3)
    pub canonical_attestation_path: bool,

    /// Enable strict CBE graduation formula (R3)
    pub strict_cbe_graduation_formula: bool,

    /// Enable normalized epoch tracking (R4)
    pub normalized_epoch_tracking: bool,

    /// Enable on-chain config for producer policy (R8)
    pub on_chain_producer_policy: bool,

    /// Enable aligned slashing semantics (R1)
    pub aligned_slashing_semantics: bool,

    /// Enable hardened API/runtime boundaries (R9)
    pub hardened_write_boundaries: bool,

    /// Enable shadow mode for parity monitoring (R8)
    pub shadow_mode_parity: bool,
}

impl Default for OracleFeatureFlags {
    fn default() -> Self {
        Self {
            canonical_attestation_path: false,
            strict_cbe_graduation_formula: false,
            normalized_epoch_tracking: false,
            on_chain_producer_policy: false,
            aligned_slashing_semantics: false,
            hardened_write_boundaries: false,
            shadow_mode_parity: false,
        }
    }
}

impl OracleFeatureFlags {
    /// All flags disabled (legacy behavior)
    pub fn all_disabled() -> Self {
        Self::default()
    }

    /// All flags enabled (strict spec behavior)
    pub fn all_enabled() -> Self {
        Self {
            canonical_attestation_path: true,
            strict_cbe_graduation_formula: true,
            normalized_epoch_tracking: true,
            on_chain_producer_policy: true,
            aligned_slashing_semantics: true,
            hardened_write_boundaries: true,
            shadow_mode_parity: true,
        }
    }

    /// Get effective feature flags for a given protocol version.
    pub fn for_version(version: OracleProtocolVersion) -> Self {
        match version {
            OracleProtocolVersion::V0Legacy => Self::all_disabled(),
            OracleProtocolVersion::V1StrictSpec => Self::all_enabled(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_default_is_legacy() {
        let version = OracleProtocolVersion::default();
        assert!(version.is_legacy());
        assert!(!version.is_strict_spec());
    }

    #[test]
    fn protocol_version_u16_roundtrip() {
        assert_eq!(OracleProtocolVersion::V0Legacy.as_u16(), 0);
        assert_eq!(OracleProtocolVersion::V1StrictSpec.as_u16(), 1);

        assert_eq!(
            OracleProtocolVersion::from_u16(0),
            Some(OracleProtocolVersion::V0Legacy)
        );
        assert_eq!(
            OracleProtocolVersion::from_u16(1),
            Some(OracleProtocolVersion::V1StrictSpec)
        );
        assert_eq!(OracleProtocolVersion::from_u16(99), None);
    }

    #[test]
    fn schedule_activation_success() {
        let mut config = OracleProtocolConfig::new();
        assert_eq!(config.current_version(), OracleProtocolVersion::V0Legacy);

        let result = config.schedule_activation(
            OracleProtocolVersion::V1StrictSpec,
            1000, // activate at height 1000
            100,  // current height is 100
            None,
        );

        assert!(result.is_ok());
        assert!(config.has_pending_activation());
        assert_eq!(
            config.pending_activation().unwrap().target_version,
            OracleProtocolVersion::V1StrictSpec
        );
    }

    #[test]
    fn schedule_activation_requires_future_height() {
        let mut config = OracleProtocolConfig::new();

        let result = config.schedule_activation(
            OracleProtocolVersion::V1StrictSpec,
            100, // activate at height 100
            100, // current height is 100 (same)
            None,
        );

        assert!(matches!(
            result,
            Err(ProtocolScheduleError::InvalidActivationHeight { .. })
        ));

        let result = config.schedule_activation(
            OracleProtocolVersion::V1StrictSpec,
            50,   // activate at height 50
            100,  // current height is 100 (past)
            None,
        );

        assert!(matches!(
            result,
            Err(ProtocolScheduleError::InvalidActivationHeight { .. })
        ));
    }

    #[test]
    fn schedule_activation_prevents_downgrade() {
        let mut config = OracleProtocolConfig::with_version(OracleProtocolVersion::V1StrictSpec);

        let result = config.schedule_activation(
            OracleProtocolVersion::V0Legacy, // try to downgrade
            1000,
            100,
            None,
        );

        assert!(matches!(
            result,
            Err(ProtocolScheduleError::DowngradeNotAllowed { current: 1, requested: 0 })
        ));
    }

    #[test]
    fn schedule_activation_prevents_same_version() {
        let mut config = OracleProtocolConfig::new();

        let result = config.schedule_activation(
            OracleProtocolVersion::V0Legacy, // same as current
            1000,
            100,
            None,
        );

        assert!(matches!(result, Err(ProtocolScheduleError::AlreadyActive)));
    }

    #[test]
    fn schedule_activation_prevents_duplicate() {
        let mut config = OracleProtocolConfig::new();

        config
            .schedule_activation(OracleProtocolVersion::V1StrictSpec, 1000, 100, None)
            .unwrap();

        let result = config.schedule_activation(
            OracleProtocolVersion::V1StrictSpec,
            2000, // different height
            150,  // current moved forward
            None,
        );

        assert!(matches!(
            result,
            Err(ProtocolScheduleError::AlreadyScheduled { existing_height: 1000 })
        ));
    }

    #[test]
    fn apply_pending_activation_at_exact_height() {
        let mut config = OracleProtocolConfig::new();

        config
            .schedule_activation(OracleProtocolVersion::V1StrictSpec, 1000, 100, None)
            .unwrap();

        // Before activation height
        let result = config.apply_pending_activation(999);
        assert!(result.is_none());
        assert!(config.has_pending_activation());
        assert_eq!(config.current_version(), OracleProtocolVersion::V0Legacy);

        // At activation height
        let result = config.apply_pending_activation(1000);
        assert_eq!(result, Some(OracleProtocolVersion::V1StrictSpec));
        assert!(!config.has_pending_activation());
        assert_eq!(config.current_version(), OracleProtocolVersion::V1StrictSpec);
        assert_eq!(config.activated_at_height(), 1000);
    }

    #[test]
    fn apply_pending_activation_after_height() {
        let mut config = OracleProtocolConfig::new();

        config
            .schedule_activation(OracleProtocolVersion::V1StrictSpec, 1000, 100, None)
            .unwrap();

        // Skip past activation height (node was offline)
        let result = config.apply_pending_activation(1500);
        assert_eq!(result, Some(OracleProtocolVersion::V1StrictSpec));
        assert_eq!(config.current_version(), OracleProtocolVersion::V1StrictSpec);
    }

    #[test]
    fn cancel_pending_activation() {
        let mut config = OracleProtocolConfig::new();

        assert!(!config.cancel_pending_activation()); // nothing to cancel

        config
            .schedule_activation(OracleProtocolVersion::V1StrictSpec, 1000, 100, None)
            .unwrap();

        assert!(config.cancel_pending_activation());
        assert!(!config.has_pending_activation());
        assert_eq!(config.current_version(), OracleProtocolVersion::V0Legacy);
    }

    #[test]
    fn feature_flags_for_legacy_version() {
        let flags = OracleFeatureFlags::for_version(OracleProtocolVersion::V0Legacy);
        assert!(!flags.canonical_attestation_path);
        assert!(!flags.strict_cbe_graduation_formula);
        assert!(!flags.normalized_epoch_tracking);
    }

    #[test]
    fn feature_flags_for_strict_spec_version() {
        let flags = OracleFeatureFlags::for_version(OracleProtocolVersion::V1StrictSpec);
        assert!(flags.canonical_attestation_path);
        assert!(flags.strict_cbe_graduation_formula);
        assert!(flags.normalized_epoch_tracking);
        assert!(flags.on_chain_producer_policy);
        assert!(flags.aligned_slashing_semantics);
        assert!(flags.hardened_write_boundaries);
        assert!(flags.shadow_mode_parity);
    }

    #[test]
    fn protocol_config_serialization_roundtrip() {
        let mut config = OracleProtocolConfig::new();
        config
            .schedule_activation(OracleProtocolVersion::V1StrictSpec, 1000, 100, Some([1u8; 32]))
            .unwrap();

        let serialized = bincode::serialize(&config).unwrap();
        let deserialized: OracleProtocolConfig = bincode::deserialize(&serialized).unwrap();

        assert_eq!(config.current_version, deserialized.current_version);
        assert_eq!(config.pending_activation, deserialized.pending_activation);
        assert_eq!(config.activated_at_height, deserialized.activated_at_height);
    }
}
