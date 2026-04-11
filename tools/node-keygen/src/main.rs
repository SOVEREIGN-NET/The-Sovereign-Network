/// Generate a new crystals-dilithium5 node keypair.
/// Outputs node_private_key.json and prints the new DID + consensus_key for config.toml.
use crystals_dilithium::dilithium5::Keypair as DilithiumKeypair;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct KeystorePrivateKey {
    #[serde(with = "hex_serde")]
    dilithium_sk: [u8; 4896],
    #[serde(with = "hex_serde")]
    dilithium_pk: [u8; 2592],
    #[serde(with = "hex_serde")]
    kyber_sk: [u8; 3168],
    #[serde(with = "hex_serde")]
    master_seed: [u8; 64],
}

mod hex_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_path = args.get(1).map(|s| s.as_str()).unwrap_or("node_private_key_new.json");

    // Generate crystals-dilithium5 keypair
    let dilithium_kp = DilithiumKeypair::generate(None);
    let dilithium_pk_bytes = dilithium_kp.public.to_bytes();
    let dilithium_sk_bytes = dilithium_kp.secret.to_bytes(); // 4864 bytes

    // Zero-pad SK to 4896 bytes for storage compatibility
    let mut dilithium_sk_array = [0u8; 4896];
    dilithium_sk_array[..dilithium_sk_bytes.len()].copy_from_slice(&dilithium_sk_bytes);

    let dilithium_pk_array: [u8; 2592] = dilithium_pk_bytes.try_into().expect("PK must be 2592 bytes");

    // Generate Kyber1024 keypair
    let mut rng = OsRng;
    let kyber_keys = pqc_kyber::keypair(&mut rng).expect("Kyber keygen failed");
    let kyber_sk_array: [u8; 3168] = kyber_keys.secret.try_into().expect("Kyber SK must be 3168 bytes");
    let kyber_pk_array: [u8; 1568] = kyber_keys.public.try_into().expect("Kyber PK must be 1568 bytes");

    // Generate master seed
    let mut master_seed = [0u8; 64];
    use rand::RngCore;
    rng.fill_bytes(&mut master_seed);

    // Compute DID = blake3(dilithium_pk)
    let pk_hash = blake3::hash(&dilithium_pk_array);
    let did = format!("did:zhtp:{}", hex::encode(pk_hash.as_bytes()));
    let identity_id_hex = hex::encode(pk_hash.as_bytes());
    let consensus_key_hex = hex::encode(&dilithium_pk_array);

    // key_id = blake3(dilithium_pk || kyber_pk)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&dilithium_pk_array);
    hasher.update(&kyber_pk_array);
    let key_id: [u8; 32] = *hasher.finalize().as_bytes();

    let keystore = KeystorePrivateKey {
        dilithium_sk: dilithium_sk_array,
        dilithium_pk: dilithium_pk_array,
        kyber_sk: kyber_sk_array,
        master_seed,
    };

    // Warn if output path already exists
    if std::path::Path::new(out_path).exists() {
        eprintln!("Warning: output file '{}' already exists and will be overwritten", out_path);
    }

    let json = serde_json::to_string_pretty(&keystore).expect("json failed");
    
    // Write with restrictive permissions (0o600) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(out_path)
            .expect("write failed");
        use std::io::Write;
        file.write_all(json.as_bytes()).expect("write failed");
    }
    #[cfg(not(unix))]
    {
        std::fs::write(out_path, &json).expect("write failed");
    }

    println!("=== NEW NODE KEY GENERATED ===");
    println!("Saved to: {}", out_path);
    println!();
    println!("New DID (identity_id): {}", did);
    println!();
    println!("New consensus_key (hex):");
    println!("{}", consensus_key_hex);
    println!();
    println!("key_id (blake3 of dilithium_pk || kyber_pk): {}", hex::encode(key_id));
    println!("pk_hash (blake3 of dilithium_pk only): {}", identity_id_hex);
    println!();
    println!("Dilithium PK bytes (as JSON array, for node_identity.json):");
    let pk_array: Vec<u8> = dilithium_pk_array.to_vec();
    println!("{}", serde_json::to_string(&pk_array).unwrap());
    println!();
    println!("Kyber PK bytes (as JSON array, for node_identity.json):");
    let kyber_pk_vec: Vec<u8> = kyber_pk_array.to_vec();
    println!("{}", serde_json::to_string(&kyber_pk_vec).unwrap());
    println!();
    println!("key_id bytes (as JSON array, for node_identity.json):");
    println!("{}", serde_json::to_string(&key_id.to_vec()).unwrap());
    println!();
    println!("DID hash bytes (as JSON array, for node_identity.json id/private_data_id):");
    println!("{}", serde_json::to_string(&pk_hash.as_bytes().to_vec()).unwrap());
}
