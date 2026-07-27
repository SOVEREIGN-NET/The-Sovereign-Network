//! One-shot OPAQUE server-setup generator for `genesis.toml`.
//!
//! Outputs a base64-encoded `ServerSetup<LobbyAuthCipherSuite>` blob to stdout.
//! Pipe into the `[opaque] server_setup_b64 = ...` field of `genesis.toml`.
//!
//! Run:  `cargo run --example gen_opaque_server_setup -p lib-client --release`

use base64::Engine as _;
use opaque_ke::ServerSetup;
use rand::rngs::OsRng;

use zhtp_client::opaque::LobbyAuthCipherSuite;

fn main() {
    let mut rng = OsRng;
    let setup: ServerSetup<LobbyAuthCipherSuite> =
        ServerSetup::<LobbyAuthCipherSuite>::new(&mut rng);
    let bytes = setup.serialize();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    println!("{}", b64);
}
