/// Regenerate CBE holder key from backup master_seed
/// Run: cargo run --bin regen_cbe_key

fn main() -> anyhow::Result<()> {
    let pk_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            format!("{}/.zhtp/keystores/prod/user_private_key.json.prev_bak",
                dirs::home_dir().unwrap().display())
        )?
    )?;

    let seed_arr: Vec<u8> = pk_json["master_seed"].as_array().unwrap()
        .iter().map(|v| v.as_u64().unwrap() as u8).collect();
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&seed_arr);

    eprintln!("Seed prefix: {}", hex::encode(&seed[..8]));

    let identity = lib_identity::ZhtpIdentity::new_unified(
        lib_identity::IdentityType::Device,
        None,
        None,
        "regen",
        Some(seed),
    )?;

    let key_id_hex = hex::encode(identity.public_key.key_id);
    eprintln!("Regenerated DID: {}", identity.did);
    eprintln!("Key ID: {}", key_id_hex);

    if key_id_hex.starts_with("b8b099a1") {
        eprintln!("MATCH! Saving...");

        let private_key = identity.private_key.as_ref().unwrap();
        let keystore_key = serde_json::json!({
            "dilithium_sk": hex::encode(private_key.dilithium_sk),
            "dilithium_pk": hex::encode(private_key.dilithium_pk),
            "kyber_sk": hex::encode(private_key.kyber_sk),
            "master_seed": hex::encode(private_key.master_seed),
        });
        let out = format!("{}/.zhtp/keystores/prod/user_private_key.json.recovered",
            dirs::home_dir().unwrap().display());
        std::fs::write(&out, serde_json::to_string_pretty(&keystore_key)?)?;
        eprintln!("Private key saved to {}", out);
    } else {
        eprintln!("NO MATCH. Expected b8b099a1, got {}", &key_id_hex[..16]);
        eprintln!("The seed may have been from a different key generation.");
    }

    Ok(())
}
