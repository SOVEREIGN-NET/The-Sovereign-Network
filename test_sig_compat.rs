// Quick test: crystals-dilithium sign vs pqcrypto-dilithium verify
// Run: cargo run --bin test_sig_compat

use crystals_dilithium::dilithium5::{Keypair, SecretKey, PublicKey};
use pqcrypto_dilithium::dilithium5 as pq_d5;
use pqcrypto_traits::sign::DetachedSignature;

fn main() {
    // 1. Generate keypair with crystals-dilithium (what lib-client does)
    let seed = [0u8; 32]; // deterministic seed
    let keypair = Keypair::generate(Some(&seed));
    let pk_bytes = keypair.public.to_bytes();
    let sk_bytes = keypair.secret.to_bytes();

    println!("crystals-dilithium keypair:");
    println!("  pk_len: {}", pk_bytes.len());
    println!("  sk_len: {}", sk_bytes.len());

    // 2. Sign with crystals-dilithium (what lib-client does)
    let message = b"SEED_MIGRATE:supertramp:abc123:1234567890";
    let sk = SecretKey::from_bytes(&sk_bytes);
    let signature = sk.sign(message);

    println!("crystals-dilithium signature:");
    println!("  sig_len: {}", signature.len());

    // 3. Try to verify with pqcrypto-dilithium (what server does)
    println!("\nVerifying with pqcrypto-dilithium...");

    let pq_pk = match pq_d5::PublicKey::from_bytes(&pk_bytes) {
        Ok(pk) => { println!("  ✅ pk parsed OK"); pk }
        Err(e) => { println!("  ❌ pk parse failed: {:?}", e); return; }
    };

    let pq_sig = match pq_d5::DetachedSignature::from_bytes(&signature) {
        Ok(sig) => { println!("  ✅ sig parsed OK"); sig }
        Err(e) => { println!("  ❌ sig parse failed: {:?}", e); return; }
    };

    match pq_d5::verify_detached_signature(&pq_sig, message, &pq_pk) {
        Ok(()) => println!("  ✅ SIGNATURE VALID"),
        Err(e) => println!("  ❌ SIGNATURE INVALID: {:?}", e),
    }
}
