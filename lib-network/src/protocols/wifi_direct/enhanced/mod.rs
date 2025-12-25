//! Enhanced WiFi Direct implementations with FCIS architecture
//!
//! - `core.rs` - Pure functional algorithms (no I/O, side-effect free)
//! - `macos/` - macOS platform integration (stateful, I/O operations)
//! - `wps/` - WPS security management (state + pure algorithms)

pub mod core;
pub mod macos;
pub mod wps;

pub use macos::MacOSWiFiDirectManager;
pub use macos::MacOSWiFiInterface;
pub use macos::MacOSP2PGroup;
pub use wps::AdvancedWPSSecurity;
pub use wps::WPSPinInfo;
pub use wps::WPSNFCInfo;
