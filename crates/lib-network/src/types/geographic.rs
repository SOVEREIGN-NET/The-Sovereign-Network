use serde::{Deserialize, Serialize};

/// Geographic location for mesh routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicLocation {
    /// Latitude
    pub lat: f64,
    /// Longitude
    pub lon: f64,
    /// Approximate altitude in meters
    pub altitude_m: Option<f32>,
}
