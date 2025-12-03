use anyhow::Result;
use lib_crypto::KeyPair;
use lib_identity::{IdentityType, ZhtpIdentity};

fn create_demo_identity(label: &str) -> Result<ZhtpIdentity> {
    let kp = KeyPair::generate()?;
    ZhtpIdentity::new(
        IdentityType::Human,
        kp.public_key,
        kp.private_key,
        label.to_string(),
        Some(30),
        Some("Testland".to_string()),
        true,
        lib_proofs::ZeroKnowledgeProof::default(),
    )
}

fn main() -> Result<()> {
    let identity = create_demo_identity("demo-user")?;
    println!("Generated demo identity DID: {}", identity.did);
    Ok(())
}
