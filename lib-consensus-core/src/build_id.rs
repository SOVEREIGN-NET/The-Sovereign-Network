//! Binary epoch + build revision for mixed-binary detection.
//!
//! **Gated (consensus admission):** [`CONSENSUS_BUILD_ID`] — a human-bumped
//! binary epoch. Bump it when validator wire format or consensus rules require
//! a homogeneous cluster. Stable across ordinary commits that do not touch
//! consensus.
//!
//! **Advisory (telemetry only):** [`BUILD_REVISION`] — git short hash embedded at
//! compile time. Surfaced on heartbeats, API, and CLI for ops visibility. Never
//! used to reject peer messages.
//!
//! **Safety net, not security:** `build_id` on proposals/votes is outside the
//! inner signature. It stops accidental mixed-binary deploys, not adversarial
//! peers claiming a false epoch.

/// Human-bumped binary epoch. All validators in a cluster must match.
///
/// Bump when:
/// - Consensus wire codec version changes (see `CONSENSUS_CODEC_VERSION`)
/// - Consensus admission rules change in a way that requires homogeneous binaries
///
/// Do **not** bump for docs-only, CLI-only, or unrelated crate changes.
pub const CONSENSUS_BUILD_ID: &str = "1";

/// Marker assigned when decoding codec v1 frames (no epoch field on wire).
pub const LEGACY_BUILD_ID: &str = "";

/// Git short hash (+ `-dirty`) compiled into this binary. Advisory only.
pub const BUILD_REVISION: &str = env!("BUILD_REVISION");

/// Gated epoch carried on outbound consensus messages.
#[inline]
pub fn local_build_id() -> &'static str {
    CONSENSUS_BUILD_ID
}

/// Advisory git revision for heartbeats / API / CLI.
#[inline]
pub fn local_build_revision() -> &'static str {
    BUILD_REVISION
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildIdRejectReason {
    /// Peer sent codec v1 / pre-epoch wire (empty epoch).
    LegacyPeer,
    /// Peer epoch does not match our [`CONSENSUS_BUILD_ID`].
    EpochMismatch,
}

impl BuildIdRejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyPeer => "legacy peer (codec v1, no binary epoch)",
            Self::EpochMismatch => "binary epoch mismatch",
        }
    }
}

/// Returns `Ok(())` when `peer_build_id` matches [`CONSENSUS_BUILD_ID`].
pub fn validate_peer_build_id(peer_build_id: &str) -> Result<(), BuildIdRejectReason> {
    if peer_build_id.is_empty() {
        return Err(BuildIdRejectReason::LegacyPeer);
    }
    if peer_build_id != CONSENSUS_BUILD_ID {
        return Err(BuildIdRejectReason::EpochMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_build_id_is_stable_epoch() {
        assert_eq!(local_build_id(), "1");
    }

    #[test]
    fn build_revision_is_nonempty() {
        assert!(!BUILD_REVISION.is_empty());
        assert_ne!(BUILD_REVISION, "unknown");
    }

    #[test]
    fn validate_peer_build_id_accepts_local_epoch() {
        assert!(validate_peer_build_id(CONSENSUS_BUILD_ID).is_ok());
    }

    #[test]
    fn validate_peer_build_id_rejects_legacy_empty() {
        assert_eq!(
            validate_peer_build_id(LEGACY_BUILD_ID),
            Err(BuildIdRejectReason::LegacyPeer)
        );
    }

    #[test]
    fn validate_peer_build_id_rejects_epoch_mismatch() {
        assert_eq!(
            validate_peer_build_id("99"),
            Err(BuildIdRejectReason::EpochMismatch)
        );
    }
}