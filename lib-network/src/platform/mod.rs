pub mod windows;
pub mod linux;
pub mod macos;

pub use windows::*;
pub use linux::*;
pub use macos::*;

// Platform-specific implementations for hardware discovery
