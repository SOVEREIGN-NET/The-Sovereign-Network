use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Only run on macOS
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rerun-if-changed=Info.plist");

        let out_dir = env::var("OUT_DIR").unwrap();
        let info_plist_path = PathBuf::from("Info.plist");

        if info_plist_path.exists() {
            // Copy Info.plist to output directory
            let dest_path = PathBuf::from(&out_dir).join("Info.plist");
            fs::copy(&info_plist_path, &dest_path)
                .expect("Failed to copy Info.plist");

            println!("cargo:rustc-env=MACOSX_DEPLOYMENT_TARGET=10.15");

            // Tell the linker to embed the Info.plist
            // This creates a __TEXT,__info_plist section in the binary
            println!("cargo:rustc-link-arg=-sectcreate");
            println!("cargo:rustc-link-arg=__TEXT");
            println!("cargo:rustc-link-arg=__info_plist");
            println!("cargo:rustc-link-arg={}", dest_path.display());

            println!("cargo:warning=Embedded Info.plist into macOS binary for Bluetooth permissions");
        }
    }
}
