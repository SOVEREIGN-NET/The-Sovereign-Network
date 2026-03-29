/// Sled Block Format Migration Tool
///
/// Fixes blocks stored in sled by old binaries that serialized `difficulty`,
/// `nonce`, and `cumulative_difficulty` fields before they were marked
/// `#[serde(skip)]`.
///
/// OLD wire format header (174 bytes):
///   version(4) prev_hash(32) merkle_root(32) timestamp(8)
///   difficulty(4) nonce(8) height(8) block_hash(32)
///   tx_count(4) block_size(4) cumulative_difficulty(4)
///   fee_model_version(2) state_root(32)
///
/// NEW wire format header (158 bytes):
///   version(4) prev_hash(32) merkle_root(32) timestamp(8)
///   height(8) block_hash(32)
///   tx_count(4) block_size(4)
///   fee_model_version(2) state_root(32)
///
/// Format detection: check `height` at old offset [88..96] vs new offset [76..84].
/// Transaction bytes are passed through UNCHANGED — no Transaction deserialization.

use anyhow::{Context, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/opt/zhtp/data/testnet/sled".to_string());

    let dry_run = std::env::args().any(|a| a == "--dry-run");

    println!("Opening sled at: {}", path);
    if dry_run {
        println!("DRY RUN — no changes will be written");
    }

    let db = sled::open(PathBuf::from(&path))
        .with_context(|| format!("Failed to open sled at {}", path))?;

    let blocks_by_height = db
        .open_tree("blocks_by_height")
        .context("Failed to open blocks_by_height tree")?;
    let blocks_by_hash = db
        .open_tree("blocks_by_hash")
        .context("Failed to open blocks_by_hash tree")?;
    let meta = db
        .open_tree("meta")
        .context("Failed to open meta tree")?;

    // Read latest height from meta
    let latest_height: u64 = match meta.get(b"latest_height")? {
        Some(bytes) if bytes.len() == 8 => {
            u64::from_be_bytes(bytes.as_ref().try_into().unwrap())
        }
        _ => {
            println!("No latest_height in meta — nothing to migrate.");
            return Ok(());
        }
    };

    println!("Chain height: {}", latest_height);
    println!("Scanning {} blocks...", latest_height + 1);

    let mut already_new = 0u64;
    let mut migrated = 0u64;
    let mut errors = 0u64;

    for h in 0..=latest_height {
        let height_key = h.to_be_bytes();

        let hash_bytes = match blocks_by_height.get(&height_key)? {
            Some(b) => b,
            None => {
                eprintln!("  ERROR: No hash entry for height {}", h);
                errors += 1;
                continue;
            }
        };

        let raw = match blocks_by_hash.get(hash_bytes.as_ref())? {
            Some(b) => b,
            None => {
                eprintln!("  ERROR: No block data for height {} (hash {:?})", h, &hash_bytes[..8.min(hash_bytes.len())]);
                errors += 1;
                continue;
            }
        };

        let block_bytes: &[u8] = raw.as_ref();

        // ── Format detection ──────────────────────────────────────────────────
        //
        // New format: height is at bytes [76..84]
        // Old format: height is at bytes [88..96]  (difficulty+nonce pushed it 12 bytes later;
        //             difficulty=u32=4 bytes, nonce=u64=8 bytes → total 12-byte shift after [76])
        //
        // We check new offset first; if it matches h the block is already migrated.

        let height_at_new_offset: u64 = if block_bytes.len() >= 84 {
            u64::from_le_bytes(block_bytes[76..84].try_into().unwrap())
        } else {
            u64::MAX
        };

        if height_at_new_offset == h {
            already_new += 1;
            continue;
        }

        let height_at_old_offset: u64 = if block_bytes.len() >= 96 {
            u64::from_le_bytes(block_bytes[88..96].try_into().unwrap())
        } else {
            u64::MAX
        };

        if height_at_old_offset != h {
            eprintln!(
                "  ERROR: Block at height {} unrecognized format \
                 (height@new_offset={}, height@old_offset={})",
                h, height_at_new_offset, height_at_old_offset
            );
            errors += 1;
            continue;
        }

        // Old format confirmed — need full 174-byte header
        if block_bytes.len() < 174 {
            eprintln!(
                "  ERROR: Old-format block at height {} is too short: {} bytes",
                h,
                block_bytes.len()
            );
            errors += 1;
            continue;
        }

        // ── Rebuild header bytes ──────────────────────────────────────────────
        //
        // Old layout offsets (skip difficulty[76..80], nonce[80..88], cumul_diff[136..140]):
        //
        //   [0..4]    version
        //   [4..36]   prev_hash
        //   [36..68]  merkle_root
        //   [68..76]  timestamp
        //   [76..80]  difficulty   ← DROP
        //   [80..88]  nonce        ← DROP
        //   [88..96]  height
        //   [96..128] block_hash
        //   [128..132] tx_count
        //   [132..136] block_size
        //   [136..140] cumul_diff  ← DROP
        //   [140..142] fee_model_version
        //   [142..174] state_root
        //   [174..]   transaction bytes (pass through unchanged)

        let tx_bytes = &block_bytes[174..];

        let mut new_bytes: Vec<u8> = Vec::with_capacity(158 + tx_bytes.len());
        new_bytes.extend_from_slice(&block_bytes[0..4]);     // version
        new_bytes.extend_from_slice(&block_bytes[4..36]);    // prev_hash
        new_bytes.extend_from_slice(&block_bytes[36..68]);   // merkle_root
        new_bytes.extend_from_slice(&block_bytes[68..76]);   // timestamp
        // skip difficulty [76..80]
        // skip nonce [80..88]
        new_bytes.extend_from_slice(&block_bytes[88..96]);   // height
        new_bytes.extend_from_slice(&block_bytes[96..128]);  // block_hash
        new_bytes.extend_from_slice(&block_bytes[128..132]); // tx_count
        new_bytes.extend_from_slice(&block_bytes[132..136]); // block_size
        // skip cumul_diff [136..140]
        new_bytes.extend_from_slice(&block_bytes[140..142]); // fee_model_version
        new_bytes.extend_from_slice(&block_bytes[142..174]); // state_root
        new_bytes.extend_from_slice(tx_bytes);               // transactions unchanged

        if h < 3 {
            println!(
                "  Block {}: old_bytes={} new_bytes={} tx_bytes={}",
                h,
                block_bytes.len(),
                new_bytes.len(),
                tx_bytes.len()
            );
        }

        if !dry_run {
            blocks_by_hash
                .insert(hash_bytes.as_ref(), new_bytes.as_slice())
                .with_context(|| format!("Failed to write migrated block at height {}", h))?;
        }

        migrated += 1;

        if migrated % 1000 == 0 {
            println!("  Progress: {}/{} migrated", migrated, latest_height + 1);
        }
    }

    if !dry_run {
        db.flush().context("Failed to flush sled after migration")?;
    }

    println!();
    println!("=== MIGRATION COMPLETE ===");
    println!("  Already new format: {}", already_new);
    println!("  Migrated:           {}", migrated);
    println!("  Errors:             {}", errors);

    if dry_run {
        println!();
        println!("  (DRY RUN — no changes written)");
    }

    Ok(())
}
