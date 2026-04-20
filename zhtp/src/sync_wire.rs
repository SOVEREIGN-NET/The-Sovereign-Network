use serde::{Deserialize, Serialize};

/// Legacy block page wire format: raw bincode(Vec<Block>) at
/// `/api/v1/blockchain/blocks/{start}/{end}`.
pub const BLOCK_PAGE_WIRE_V1_BINCODERAW: &str = "v1-bincode-raw";
/// Versioned block page wire format: CBOR envelope + encoded payload at
/// `/api/v2/blockchain/blocks/{start}/{end}`.
pub const BLOCK_PAGE_WIRE_V2_CBORENVELOPE: &str = "v2-cbor-envelope";

pub const BLOCK_PAGE_V2_ENCODING_BINCODE: &str = "bincode";
pub const BLOCK_PAGE_V2_TX_ENCODING_V8: &str = "v8-payload";

/// Current transaction wire bounds supported by this node binary.
pub const TX_WIRE_MIN_VERSION: u32 = 8;
pub const TX_WIRE_MAX_VERSION: u32 = 8;

/// Local preference order for block page wire versions.
pub const LOCAL_BLOCK_PAGE_WIRE_PREFERENCE: [&str; 2] = [
    BLOCK_PAGE_WIRE_V2_CBORENVELOPE,
    BLOCK_PAGE_WIRE_V1_BINCODERAW,
];

/// Response shape for `GET /api/v1/blockchain/sync-capabilities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCapabilities {
    pub block_page_wire_versions: Vec<String>,
    pub tx_wire_min_version: u32,
    pub tx_wire_max_version: u32,
    pub node_software_version: String,
}

/// Wire envelope for v2 block page responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPageEnvelopeV2 {
    pub wire_version: String,
    pub block_encoding: String,
    pub tx_encoding: String,
    pub start: u64,
    pub end: u64,
    pub count: usize,
    pub payload: Vec<u8>,
}

pub fn validate_block_page_envelope_v2(
    envelope: &BlockPageEnvelopeV2,
    expected_start: u64,
    expected_end: u64,
) -> anyhow::Result<()> {
    if envelope.wire_version != BLOCK_PAGE_WIRE_V2_CBORENVELOPE {
        return Err(anyhow::anyhow!(
            "BlockPageEnvelopeMalformed: wire_version={}, expected={}",
            envelope.wire_version,
            BLOCK_PAGE_WIRE_V2_CBORENVELOPE
        ));
    }
    if envelope.block_encoding != BLOCK_PAGE_V2_ENCODING_BINCODE {
        return Err(anyhow::anyhow!(
            "BlockPageEnvelopeMalformed: block_encoding={}, expected={}",
            envelope.block_encoding,
            BLOCK_PAGE_V2_ENCODING_BINCODE
        ));
    }
    if envelope.tx_encoding != BLOCK_PAGE_V2_TX_ENCODING_V8 {
        return Err(anyhow::anyhow!(
            "BlockPageEnvelopeMalformed: tx_encoding={}, expected={}",
            envelope.tx_encoding,
            BLOCK_PAGE_V2_TX_ENCODING_V8
        ));
    }
    if envelope.start != expected_start || envelope.end != expected_end {
        return Err(anyhow::anyhow!(
            "BlockPageEnvelopeMalformed: range={}..{} expected={}..{}",
            envelope.start,
            envelope.end,
            expected_start,
            expected_end
        ));
    }
    Ok(())
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

    #[test]
    fn validates_v2_envelope_metadata() {
        let envelope = BlockPageEnvelopeV2 {
            wire_version: BLOCK_PAGE_WIRE_V2_CBORENVELOPE.to_string(),
            block_encoding: BLOCK_PAGE_V2_ENCODING_BINCODE.to_string(),
            tx_encoding: BLOCK_PAGE_V2_TX_ENCODING_V8.to_string(),
            start: 10,
            end: 20,
            count: 0,
            payload: Vec::new(),
        };
        assert!(validate_block_page_envelope_v2(&envelope, 10, 20).is_ok());
    }

    #[test]
    fn rejects_v2_envelope_with_wrong_range() {
        let envelope = BlockPageEnvelopeV2 {
            wire_version: BLOCK_PAGE_WIRE_V2_CBORENVELOPE.to_string(),
            block_encoding: BLOCK_PAGE_V2_ENCODING_BINCODE.to_string(),
            tx_encoding: BLOCK_PAGE_V2_TX_ENCODING_V8.to_string(),
            start: 11,
            end: 20,
            count: 0,
            payload: Vec::new(),
        };
        assert!(validate_block_page_envelope_v2(&envelope, 10, 20).is_err());
    }
}
