// Build script to link macOS Core Bluetooth framework

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();

    // Only link frameworks when targeting macOS
    if target.contains("darwin") || target.contains("macos") {
        println!("cargo:rustc-link-lib=framework=CoreBluetooth");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
}
