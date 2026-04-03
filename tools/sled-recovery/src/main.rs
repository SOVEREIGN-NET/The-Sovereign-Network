/// Sled backup recovery tool
/// Scans blocks_by_height tree to find the actual maximum block height,
/// then updates LATEST_HEIGHT metadata so load_from_store works correctly.

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: sled-recovery <sled-dir>");
        std::process::exit(1);
    }
    let sled_path = PathBuf::from(&args[1]);

    println!("Opening sled at {:?}", sled_path);
    let db = sled::open(&sled_path).expect("Failed to open sled");

    // Open trees
    let blocks_by_height = db.open_tree("blocks_by_height").expect("Failed to open blocks_by_height tree");
    let meta = db.open_tree("meta").expect("Failed to open meta tree");

    // Read current LATEST_HEIGHT
    let current = match meta.get(b"latest_height").expect("meta read error") {
        Some(v) => {
            let arr: [u8; 8] = v.as_ref().try_into().expect("bad latest_height bytes");
            u64::from_be_bytes(arr)
        }
        None => {
            println!("LATEST_HEIGHT not set in meta");
            0
        }
    };
    println!("Current LATEST_HEIGHT: {}", current);

    // Find max height by scanning blocks_by_height (keys are 8-byte BE u64)
    let count = blocks_by_height.len();
    println!("blocks_by_height entries: {}", count);

    let max_height = match blocks_by_height.iter().keys().last() {
        Some(Ok(k)) => {
            let arr: [u8; 8] = k.as_ref().try_into().expect("bad block height key");
            u64::from_be_bytes(arr)
        }
        _ => {
            println!("No blocks found in blocks_by_height tree!");
            return;
        }
    };

    println!("Actual max block height in store: {}", max_height);

    if max_height == current {
        println!("LATEST_HEIGHT is already correct, no fix needed.");
        return;
    }

    // Fix LATEST_HEIGHT
    meta.insert(b"latest_height", &max_height.to_be_bytes())
        .expect("Failed to write LATEST_HEIGHT");
    db.flush().expect("flush failed");

    println!("✅ Fixed LATEST_HEIGHT: {} → {}", current, max_height);
}
