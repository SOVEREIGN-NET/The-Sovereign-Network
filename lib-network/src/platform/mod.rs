pub mod windows;
pub mod linux;
pub mod macos;
pub mod hardware_detection;

pub use windows::*;
pub use linux::*;
pub use macos::*;
pub use hardware_detection::*;

// Platform-specific implementations for hardware discovery
