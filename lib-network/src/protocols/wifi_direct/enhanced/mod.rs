//! Enhanced WiFi Direct implementations with FCIS architecture
//!
//! - `core.rs` - Pure functional algorithms (no I/O, side-effect free)
//! - `macos/` - macOS platform integration (stateful, I/O operations)
//! - `wps/` - WPS security management (state + pure algorithms)

pub mod core;

#[cfg(target_os = "macos")]
pub mod macos;

pub mod wps;

#[cfg(target_os = "macos")]
pub use macos::MacOSWiFiDirectManager;
#[cfg(target_os = "macos")]
pub use macos::MacOSWiFiInterface;
#[cfg(target_os = "macos")]
pub use macos::MacOSP2PGroup;

pub use wps::AdvancedWPSSecurity;
pub use wps::WPSPinInfo;
pub use wps::WPSNFCInfo;
