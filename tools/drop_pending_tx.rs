//! Remove pending transaction(s) from sled recovery storage (operator tool).
//!
//! Non-consensus only — does not touch chain blocks/state.
//!
//! Usage:
//!   drop_pending_tx <sled-dir> <tx-hash-hex>
//!   drop_pending_tx <sled-dir> --all
//!   drop_pending_tx <sled-dir> --list

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: drop_pending_tx <sled-dir> <tx-hash-hex|--all|--list>");
        std::process::exit(1);
    }
    let sled_path = PathBuf::from(&args[1]);
    let action = args[2].as_str();

    let db = sled::open(&sled_path).expect("open sled");
    let tree = db
        .open_tree("pending_transactions")
        .expect("open pending_transactions tree");
    let before = tree.len();

    match action {
        "--list" => {
            println!("pending_transactions: {} entries", before);
            for item in tree.iter() {
                let (k, v) = item.expect("iter");
                println!(
                    "  key={} bytes={}",
                    hex::encode(k.as_ref()),
                    v.len()
                );
            }
        }
        "--all" => {
            tree.clear().expect("clear pending_transactions");
            db.flush().expect("flush sled");
            println!(
                "pending_transactions: cleared {} entries (non-consensus mempool only)",
                before
            );
        }
        hash_hex => {
            let hash_bytes = hex::decode(hash_hex).expect("invalid tx hash hex");
            if hash_bytes.len() != 32 {
                eprintln!("tx hash must be 32 bytes (64 hex chars)");
                std::process::exit(1);
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&hash_bytes);
            let removed = tree.remove(&key).expect("remove pending tx");
            db.flush().expect("flush sled");
            println!(
                "pending_transactions: {} entries before, removed={}",
                before,
                removed.is_some()
            );
        }
    }
}