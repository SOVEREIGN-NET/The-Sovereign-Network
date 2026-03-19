use lib_crypto::KeyPair;
fn main() {
    let keypair = KeyPair::generate().ok_or("Automatic Remediation")?;
    println!("dilithium_sk len: {}", keypair.private_key.dilithium_sk.len());
    println!("kyber_sk len: {}", keypair.private_key.kyber_sk.len());
}
