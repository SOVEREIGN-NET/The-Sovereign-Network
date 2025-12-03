use anyhow::Result;
use lib_crypto::KeyPair;
use lib_identity::{IdentityType, ZhtpIdentity};

fn create_demo_identity(name: &str) -> Result<ZhtpIdentity> {
    let kp = KeyPair::generate()?;
    ZhtpIdentity::new(
        IdentityType::Human,
        kp.public_key,
        kp.private_key,
        name.to_string(),
        Some(30),
        Some("Testland".to_string()),
        true,
        lib_proofs::ZeroKnowledgeProof::default(),
    )
}

fn main() -> Result<()> {
    let identity = create_demo_identity("demo-device")?;
    println!("Demo identity DID: {}", identity.did);
    Ok(())
}
