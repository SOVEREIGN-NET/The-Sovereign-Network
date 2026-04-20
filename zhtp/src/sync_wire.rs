use serde::{Deserialize, Serialize};

/// Legacy block page wire format: raw bincode(Vec<Block>) at
/// `/api/v1/blockchain/blocks/{start}/{end}`.
pub const BLOCK_PAGE_WIRE_V1_BINCODERAW: &str = "v1-bincode-raw";

/// Current transaction wire bounds supported by this node binary.
pub const TX_WIRE_MIN_VERSION: u32 = 8;
pub const TX_WIRE_MAX_VERSION: u32 = 8;

/// Local preference order for block page wire versions.
pub const LOCAL_BLOCK_PAGE_WIRE_PREFERENCE: [&str; 1] = [BLOCK_PAGE_WIRE_V1_BINCODERAW];

/// Response shape for `GET /api/v1/blockchain/sync-capabilities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCapabilities {
    pub block_page_wire_versions: Vec<String>,
    pub tx_wire_min_version: u32,
    pub tx_wire_max_version: u32,
    pub node_software_version: String,
}

impl SyncCapabilities {
    pub fn local() -> Self {
        Self {
            block_page_wire_versions: LOCAL_BLOCK_PAGE_WIRE_PREFERENCE
                .iter()
                .map(|v| (*v).to_string())
                .collect(),
            tx_wire_min_version: TX_WIRE_MIN_VERSION,
            tx_wire_max_version: TX_WIRE_MAX_VERSION,
            node_software_version: crate::VERSION.to_string(),
        }
    }
}

/// Select the highest mutually supported block page wire version according to
/// local preference ordering. Returns `None` when there is no overlap.
pub fn select_preferred_block_page_wire(
    local_preference: &[&str],
    peer_supported: &[String],
) -> Option<String> {
    local_preference
        .iter()
        .find(|local| peer_supported.iter().any(|peer| peer == *local))
        .map(|selected| (*selected).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_highest_mutual_by_local_preference() {
        let local = ["v2-cbor-envelope", "v1-bincode-raw"];
        let peer = vec!["v1-bincode-raw".to_string()];
        let selected = select_preferred_block_page_wire(&local, &peer);
        assert_eq!(selected.as_deref(), Some("v1-bincode-raw"));
    }

    #[test]
    fn returns_none_when_no_wire_overlap() {
        let local = ["v2-cbor-envelope", "v1-bincode-raw"];
        let peer = vec!["v3-unknown".to_string()];
        let selected = select_preferred_block_page_wire(&local, &peer);
        assert!(selected.is_none());
    }
}
