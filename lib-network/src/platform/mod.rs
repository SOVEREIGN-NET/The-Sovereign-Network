pub mod windows;
pub mod linux;
pub mod macos;

pub use windows::{init_windows_networking, scan_windows_bluetooth, get_windows_interfaces};
pub use linux::{init_linux_networking, scan_linux_bluetooth, get_linux_interfaces};
pub use macos::{init_macos_networking, scan_macos_bluetooth, get_macos_interfaces};

// Platform-specific implementations for hardware discovery
