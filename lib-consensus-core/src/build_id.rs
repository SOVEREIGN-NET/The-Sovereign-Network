//! Compile-time validator build identity for mixed-binary detection.
//!
//! Every validator binary embeds the git short hash it was built from.
//! Consensus messages carry this value so peers can reject traffic from
//! nodes running a different build before it affects quorum.

/// Git short hash (12 hex chars) of the commit this binary was built from.
/// Appends `-dirty` when the working tree had uncommitted changes at build time.
pub const CONSENSUS_BUILD_ID: &str = env!("CONSENSUS_BUILD_ID");

/// Local build id for outbound consensus messages.
#[inline]
pub fn local_build_id() -> &'static str {
    CONSENSUS_BUILD_ID
}

/// Returns `Ok(())` when `peer_build_id` matches this binary.
///
/// Empty peer ids are rejected — pre-build-id nodes must upgrade before
/// joining a cluster that enforces homogeneous builds.
pub fn validate_peer_build_id(peer_build_id: &str) -> Result<(), &'static str> {
    if peer_build_id.is_empty() {
        return Err("missing build_id");
    }
    if peer_build_id != CONSENSUS_BUILD_ID {
        return Err("build_id mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_build_id_matches_constant() {
        assert_eq!(local_build_id(), CONSENSUS_BUILD_ID);
    }

    #[test]
    fn validate_peer_build_id_accepts_local() {
        assert!(validate_peer_build_id(CONSENSUS_BUILD_ID).is_ok());
    }

    #[test]
    fn validate_peer_build_id_rejects_empty() {
        assert_eq!(validate_peer_build_id(""), Err("missing build_id"));
    }

    #[test]
    fn validate_peer_build_id_rejects_mismatch() {
        assert_eq!(
            validate_peer_build_id("deadbeef0000"),
            Err("build_id mismatch")
        );
    }
}