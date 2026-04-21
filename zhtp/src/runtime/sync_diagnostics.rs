use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SyncDecodeErrorClass {
    UnsupportedPeerWireVersion,
    LegacyTxVariantUnsupported,
    BlockPageEnvelopeMalformed,
    PayloadDecodeFailed,
}

impl SyncDecodeErrorClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPeerWireVersion => "UnsupportedPeerWireVersion",
            Self::LegacyTxVariantUnsupported => "LegacyTxVariantUnsupported",
            Self::BlockPageEnvelopeMalformed => "BlockPageEnvelopeMalformed",
            Self::PayloadDecodeFailed => "PayloadDecodeFailed",
        }
    }
}

#[derive(Default)]
struct SyncDecodeMetrics {
    // key: (peer, wire_version)
    wire_selection_counts: HashMap<(String, String), u64>,
    // key: (peer, wire_version, error_class)
    decode_failure_counts: HashMap<(String, String, &'static str), u64>,
}

fn metrics() -> &'static Mutex<SyncDecodeMetrics> {
    static METRICS: OnceLock<Mutex<SyncDecodeMetrics>> = OnceLock::new();
    METRICS.get_or_init(|| Mutex::new(SyncDecodeMetrics::default()))
}

pub(crate) fn classify_sync_decode_error(err: &anyhow::Error) -> SyncDecodeErrorClass {
    let s = err.to_string();
    if s.contains("UnsupportedPeerWireVersion") {
        SyncDecodeErrorClass::UnsupportedPeerWireVersion
    } else if s.contains("IncompatibleLegacyTx") || s.contains("unsupported legacy transaction type") {
        SyncDecodeErrorClass::LegacyTxVariantUnsupported
    } else if s.contains("BlockPageEnvelopeMalformed") {
        SyncDecodeErrorClass::BlockPageEnvelopeMalformed
    } else {
        SyncDecodeErrorClass::PayloadDecodeFailed
    }
}

pub(crate) fn record_wire_selection(peer: &str, wire_version: &str) {
    let mut guard = metrics()
        .lock()
        .expect("sync diagnostics mutex poisoned while recording wire selection");
    let key = (peer.to_string(), wire_version.to_string());
    *guard.wire_selection_counts.entry(key).or_insert(0) += 1;
}

pub(crate) fn record_decode_failure(peer: &str, wire_version: &str, class: SyncDecodeErrorClass) {
    let mut guard = metrics()
        .lock()
        .expect("sync diagnostics mutex poisoned while recording decode failure");
    let key = (
        peer.to_string(),
        wire_version.to_string(),
        class.as_str(),
    );
    *guard.decode_failure_counts.entry(key).or_insert(0) += 1;
}
