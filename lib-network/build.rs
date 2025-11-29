// Build script to link macOS Core Bluetooth framework

fn main() {
    // Link Core Bluetooth framework on macOS
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-lib=framework=CoreBluetooth");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
}
