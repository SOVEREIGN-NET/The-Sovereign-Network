// Build script for lib-client
//
// When the `uniffi` feature is enabled, this generates:
// - Rust scaffolding code from the UDL file
// - Swift bindings for iOS/macOS
// - Kotlin bindings for Android

fn main() {
    #[cfg(feature = "uniffi")]
    {
        uniffi::generate_scaffolding("uniffi/zhtp_client.udl")
            .expect("Failed to generate UniFFI scaffolding");
    }
}
