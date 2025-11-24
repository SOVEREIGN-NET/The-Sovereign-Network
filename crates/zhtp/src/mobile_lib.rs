//! ZHTP Mobile Library Entry Point
//!
//! This file provides the library entry point for mobile platforms.
//! It re-exports the FFI bindings from lib-network for use in Android and iOS apps.
//!
//! Build Instructions:
//! 
//! Android:
//!   cargo build --target aarch64-linux-android --release --features android
//!   cargo build --target armv7-linux-androideabi --release --features android
//!   cargo build --target x86_64-linux-android --release --features android
//!
//! iOS:
//!   cargo build --target aarch64-apple-ios --release --features ios
//!   cargo build --target aarch64-apple-ios-sim --release --features ios
//!   cargo build --target x86_64-apple-ios --release --features ios

// Re-export lib-network's mobile FFI bindings
pub use lib_network::mobile::*;

// Initialize logging for mobile platforms
#[cfg(target_os = "android")]
pub fn init_mobile_logging() {
    use android_logger::{Config, FilterBuilder};
    use log::LevelFilter;
    
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Debug)
            .with_tag("RustZHTP")
            .with_filter(
                FilterBuilder::new()
                    .parse("debug,lib_network=debug,zhtp=debug")
                    .build(),
            ),
    );
}

#[cfg(target_os = "ios")]
pub fn init_mobile_logging() {
    use oslog::OsLogger;
    use log::LevelFilter;
    
    OsLogger::new("net.sovereign.zhtp")
        .level_filter(LevelFilter::Debug)
        .init()
        .ok();
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn init_mobile_logging() {
    // No-op for non-mobile platforms
}

// Convenience function to initialize logging when library loads
#[cfg(any(target_os = "android", target_os = "ios"))]
#[ctor::ctor]
fn init() {
    init_mobile_logging();
    log::info!("ZHTP mobile library initialized");
}
