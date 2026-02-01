// Build script to link macOS Core Bluetooth framework

#[cfg(target_os = "macos")]
fn main() {
    // Link Core Bluetooth framework on macOS
    println!("cargo:rustc-link-lib=framework=CoreBluetooth");
    println!("cargo:rustc-link-lib=framework=Foundation");
}

#[cfg(not(target_os = "macos"))]
fn main() {
    // No framework linking needed on non-macOS platforms
}
