/// Looks up a specific wallet in a sled backup and prints its owner_identity_id.
/// Usage: sled-wallet-lookup <sled-dir> <wallet-id-hex>
///
/// Also checks token_balances tree for SOV balance.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: sled-wallet-lookup <sled-dir> <wallet-id-hex>");
        std::process::exit(1);
    }
    let sled_path = &args[1];
    let wallet_hex = &args[2];

    let wallet_bytes = hex::decode(wallet_hex).expect("Invalid wallet hex");
    if wallet_bytes.len() != 32 {
        eprintln!("Wallet ID must be 32 bytes (64 hex chars)");
        std::process::exit(1);
    }
    let mut wallet_key = [0u8; 32];
    wallet_key.copy_from_slice(&wallet_bytes);

    // sled 0.34 has no read-only API — opening will create/update snap.* files.
    // ALWAYS run this tool on a COPY of the backup, never on the original.
    println!("Opening sled (WARNING: sled 0.34 has no read-only mode — use a copy!): {}", sled_path);
    let db = sled::open(sled_path).expect("Failed to open sled");

    // --- wallets tree: WalletProjectionRecord (bincode) ---
    let wallets_tree = db.open_tree("wallets").expect("open wallets tree");
    println!("wallets tree entries: {}", wallets_tree.len());

    match wallets_tree.get(&wallet_key) {
        Ok(Some(value)) => {
            println!("Found wallet {} in wallets tree ({} bytes)", wallet_hex, value.len());
            // Try bincode deserialization as WalletProjectionRecord
            // WalletProjectionRecord = { wallet_data: WalletTransactionData, committed_at_height: u64 }
            // WalletTransactionData fields (in order):
            //   wallet_id: Hash([u8;32])
            //   wallet_type: String
            //   wallet_name: String
            //   alias: Option<String>
            //   public_key: Vec<u8>
            //   owner_identity_id: Option<Hash([u8;32])>
            //   seed_commitment: Hash([u8;32])
            //   created_at: u64
            //   registration_fee: u64
            //   capabilities: u64
            //   initial_balance: u64
            //   then: committed_at_height: u64
            //
            // Hash is serialized as [u8;32] directly (not length-prefixed).
            // Let's try to parse manually.
            let bytes = value.as_ref();
            println!("Raw bytes (first 128): {}", hex::encode(&bytes[..bytes.len().min(128)]));

            // Try reading wallet_id (32 bytes) then wallet_type (string with u64 length prefix in bincode)
            if bytes.len() >= 32 {
                let wid = &bytes[0..32];
                println!("  wallet_id bytes: {}", hex::encode(wid));
                // bincode string: u64 le length + bytes
                if bytes.len() >= 40 {
                    let wtype_len = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
                    if wtype_len < 256 && bytes.len() >= 40 + wtype_len {
                        let wtype = std::str::from_utf8(&bytes[40..40+wtype_len]).unwrap_or("?");
                        println!("  wallet_type: '{}'", wtype);
                        let mut pos = 40 + wtype_len;
                        // wallet_name
                        if bytes.len() >= pos + 8 {
                            let wname_len = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()) as usize;
                            pos += 8;
                            if wname_len < 256 && bytes.len() >= pos + wname_len {
                                let wname = std::str::from_utf8(&bytes[pos..pos+wname_len]).unwrap_or("?");
                                println!("  wallet_name: '{}'", wname);
                                pos += wname_len;
                                // alias: Option<String> — bincode Option is 0u8 for None, 1u8 for Some
                                if bytes.len() > pos {
                                    let has_alias = bytes[pos];
                                    pos += 1;
                                    if has_alias == 1 && bytes.len() >= pos + 8 {
                                        let alias_len = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()) as usize;
                                        pos += 8;
                                        if alias_len < 256 && bytes.len() >= pos + alias_len {
                                            let alias = std::str::from_utf8(&bytes[pos..pos+alias_len]).unwrap_or("?");
                                            println!("  alias: Some('{}')", alias);
                                            pos += alias_len;
                                        }
                                    } else {
                                        println!("  alias: None");
                                    }
                                    // public_key: Vec<u8> — bincode Vec is u64 len + bytes
                                    if bytes.len() >= pos + 8 {
                                        let pk_len = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()) as usize;
                                        pos += 8;
                                        println!("  public_key len: {}", pk_len);
                                        if bytes.len() >= pos + pk_len {
                                            pos += pk_len;
                                            // owner_identity_id: Option<Hash([u8;32])>
                                            if bytes.len() > pos {
                                                let has_owner = bytes[pos];
                                                pos += 1;
                                                if has_owner == 1 && bytes.len() >= pos + 32 {
                                                    let owner = &bytes[pos..pos+32];
                                                    println!("  owner_identity_id: Some({})", hex::encode(owner));
                                                    pos += 32;
                                                } else {
                                                    println!("  owner_identity_id: None (has_owner={})", has_owner);
                                                }
                                                // seed_commitment: Hash([u8;32])
                                                if bytes.len() >= pos + 32 {
                                                    let sc = &bytes[pos..pos+32];
                                                    println!("  seed_commitment: {}", hex::encode(sc));
                                                    pos += 32;
                                                }
                                                // created_at: u64
                                                if bytes.len() >= pos + 8 {
                                                    let ts = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap());
                                                    println!("  created_at: {}", ts);
                                                    pos += 8;
                                                }
                                                // registration_fee: u64
                                                if bytes.len() >= pos + 8 {
                                                    let fee = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap());
                                                    println!("  registration_fee: {}", fee);
                                                    pos += 8;
                                                }
                                                // capabilities: u64
                                                if bytes.len() >= pos + 8 {
                                                    let cap = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap());
                                                    println!("  capabilities: 0x{:x}", cap);
                                                    pos += 8;
                                                }
                                                // initial_balance: u64
                                                if bytes.len() >= pos + 8 {
                                                    let bal = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap());
                                                    println!("  initial_balance: {} ({})", bal, bal / 100_000_000);
                                                    pos += 8;
                                                }
                                                // committed_at_height: u64
                                                if bytes.len() >= pos + 8 {
                                                    let h = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap());
                                                    println!("  committed_at_height: {}", h);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(None) => {
            println!("Wallet {} NOT found in wallets tree", wallet_hex);
        }
        Err(e) => {
            println!("Error reading wallet: {}", e);
        }
    }

    // --- token_balances tree: SOV balance ---
    // key = token_id (32 bytes) || wallet_key_id (32 bytes), value = u64 le
    // SOV token_id: generate_lib_token_id() = blake3(b"SOVN_NATIVE_TOKEN_v1")
    let sov_token_id = {
        let hash = blake3::hash(b"ZHTP_NATIVE_TOKEN");
        *hash.as_bytes()
    };
    println!("\nSOV token_id: {}", hex::encode(&sov_token_id));

    let token_balances_tree = db.open_tree("token_balances").expect("open token_balances");
    println!("token_balances entries: {}", token_balances_tree.len());

    // Key = sov_token_id (32) || wallet_key_id (32) where wallet_key_id == wallet_id
    let mut balance_key = [0u8; 64];
    balance_key[0..32].copy_from_slice(&sov_token_id);
    balance_key[32..64].copy_from_slice(&wallet_key);

    match token_balances_tree.get(&balance_key) {
        Ok(Some(v)) if v.len() == 8 => {
            let bal = u64::from_le_bytes(v.as_ref().try_into().unwrap());
            println!("SOV balance for wallet {}: {} nSOV = {} SOV", &wallet_hex[..16], bal, bal / 100_000_000);
        }
        Ok(Some(v)) if v.len() == 16 => {
            let bal = u128::from_be_bytes(v.as_ref().try_into().unwrap());
            println!("SOV balance for wallet {}: {} nSOV = {} SOV", &wallet_hex[..16], bal, bal / 100_000_000);
        }
        Ok(Some(v)) => {
            println!("SOV balance entry found but unexpected length: {} bytes = {}", v.len(), hex::encode(v.as_ref()));
        }
        Ok(None) => {
            println!("SOV balance for wallet {} NOT found in token_balances", &wallet_hex[..16]);
            // Try scanning all entries with wallet_key suffix
            println!("Scanning all token_balances entries for wallet suffix...");
            let mut found = 0;
            for item in token_balances_tree.iter() {
                if let Ok((k, v)) = item {
                    if k.len() >= 32 && k[k.len()-32..] == wallet_key {
                        let bal = if v.len() == 8 {
                            u64::from_le_bytes(v.as_ref().try_into().unwrap())
                        } else { 0 };
                        println!("  token={} wallet={} balance={}", hex::encode(&k[..32.min(k.len())]), &wallet_hex[..16], bal);
                        found += 1;
                    }
                }
            }
            if found == 0 {
                println!("  No balance entries found for this wallet");
            }
        }
        Err(e) => println!("Error reading token_balances: {}", e),
    }
}
