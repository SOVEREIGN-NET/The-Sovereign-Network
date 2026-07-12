//! Remove a pending transaction from sled recovery storage (operator tool).
//!
//! Usage: drop_pending_tx <sled-dir> <tx-hash-hex>

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: drop_pending_tx <sled-dir> <tx-hash-hex>");
        std::process::exit(1);
    }
    let sled_path = PathBuf::from(&args[1]);
    let hash_bytes = hex::decode(&args[2]).expect("invalid tx hash hex");
    if hash_bytes.len() != 32 {
        eprintln!("tx hash must be 32 bytes (64 hex chars)");
        std::process::exit(1);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes);

    let db = sled::open(&sled_path).expect("open sled");
    let tree = db
        .open_tree("pending_transactions")
        .expect("open pending_transactions tree");
    let before = tree.len();
    let removed = tree.remove(&key).expect("remove pending tx");
    db.flush().expect("flush sled");
    println!(
        "pending_transactions: {} entries before, removed={}",
        before,
        removed.is_some()
    );
}