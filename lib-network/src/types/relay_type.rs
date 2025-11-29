use serde::{Deserialize, Serialize};

/// Types of long-range relays
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LongRangeRelayType {
    /// LoRaWAN gateway for long-range low-power communication
    LoRaWAN,
    /// Satellite uplink for global coverage
    Satellite,
    /// Cellular tower integration
    Cellular,
    /// High-power WiFi relay
    WiFiRelay,
    /// Mesh backbone connection
    BackboneRelay,
}
