// Build script for lib-client
//
// When the `uniffi` feature is enabled, this generates:
// - Rust scaffolding code from the UDL file
// - Swift bindings for iOS/macOS
// - Kotlin bindings for Android

fn main() {
    println!("cargo:rerun-if-changed=uniffi/zhtp_client.udl");

    if std::env::var_os("CARGO_FEATURE_UNIFFI").is_some() {
        uniffi::generate_scaffolding("uniffi/zhtp_client.udl")
            .expect("Failed to generate UniFFI scaffolding");
    }
}
