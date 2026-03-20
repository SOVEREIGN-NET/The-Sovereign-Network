//! Genesis configuration commands (GENESIS-1, #1909)

use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::argument_parsing::{GenesisArgs, GenesisCommand, ZhtpCli};

pub async fn handle_genesis_command(args: GenesisArgs, _cli: &ZhtpCli) -> Result<()> {
    match args.command {
        GenesisCommand::Build { config, output } => cmd_build(config, output),
        GenesisCommand::ExportState { sled_dir, dat_file, output } => {
            cmd_export_state(sled_dir, dat_file, output)
        }
        GenesisCommand::MigrateState {
            snapshot,
            config,
            output,
        } => cmd_migrate_state(snapshot, config, output),
    }
}

/// Build block 0 from a genesis.toml and print (or save) its hash.
fn cmd_build(config: Option<PathBuf>, output: Option<PathBuf>) -> Result<()> {
    let cfg = match config {
        Some(ref path) => lib_blockchain::genesis::GenesisConfig::load(path)?,
        None => lib_blockchain::genesis::GenesisConfig::from_embedded()?,
    };

    let bc = cfg.build_block0().context("Failed to build genesis block")?;
    let block0 = bc.blocks.first().context("No genesis block")?;
    let hash = block0.header.block_hash;
    let hash_hex = hex::encode(hash.as_bytes());

    if let Some(out_path) = output {
        std::fs::write(&out_path, &hash_hex)
            .with_context(|| format!("Failed to write hash to {}", out_path.display()))?;
        println!("Genesis block 0 hash written to: {}", out_path.display());
    }

    println!("Genesis block 0 hash: {}", hash_hex);
    println!(
        "\nTo lock this as CANONICAL_GENESIS_HASH, set the following in\n\
         lib-blockchain/src/genesis/mod.rs:\n\n  \
         pub const CANONICAL_GENESIS_HASH: &str = \"{}\";\n\n\
         Then commit and tag: git tag mainnet-genesis-v1",
        hash_hex
    );
    Ok(())
}

/// Export the full blockchain state to a JSON snapshot.
///
/// Prefers SledStore (live-node data directory) when `sled_dir` is supplied.
/// Falls back to legacy `blockchain.dat` when only `dat_file` is given (or the
/// default ~/.zhtp path).
fn cmd_export_state(
    sled_dir: Option<PathBuf>,
    dat_file: Option<PathBuf>,
    output: PathBuf,
) -> Result<()> {
    let bc = if let Some(ref sled_path) = sled_dir {
        println!("Loading blockchain from SledStore: {}", sled_path.display());
        println!(
            "NOTE: SledStore does not support concurrent access. \
             Ensure the node is stopped (or this is a copy of the sled directory) \
             before running export-state."
        );
        let store = std::sync::Arc::new(
            lib_blockchain::storage::SledStore::open(sled_path)
                .with_context(|| format!("Failed to open SledStore at {}", sled_path.display()))?,
        );
        lib_blockchain::Blockchain::load_from_store(store)
            .with_context(|| format!("Failed to load blockchain from SledStore at {}", sled_path.display()))?
            .with_context(|| format!("SledStore at {} appears empty — no blocks found", sled_path.display()))?
    } else {
        let dat_path = dat_file.unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".zhtp/data/testnet/blockchain.dat")
        });
        println!("Loading blockchain from: {}", dat_path.display());
        lib_blockchain::Blockchain::load_from_file(&dat_path)
            .with_context(|| format!("Failed to load {}", dat_path.display()))?
    };

    println!(
        "Loaded blockchain: height={}, wallets={}, identities={}, web4={}",
        bc.height,
        bc.wallet_registry.len(),
        bc.identity_registry.len(),
        bc.web4_contracts.len(),
    );

    let snapshot = lib_blockchain::genesis::GenesisStateSnapshot::from_blockchain(&bc);

    let json =
        serde_json::to_string_pretty(&snapshot).context("Failed to serialize state snapshot")?;
    std::fs::write(&output, &json)
        .with_context(|| format!("Failed to write snapshot to {}", output.display()))?;

    println!(
        "State snapshot written to: {}\n\
         Wallets: {}\nIdentities: {}\nWeb4 contracts: {}\nSOV balances: {}",
        output.display(),
        snapshot.wallets.len(),
        snapshot.identities.len(),
        snapshot.web4_contracts.len(),
        snapshot.sov_balances.len(),
    );
    Ok(())
}

/// Merge a state snapshot into genesis.toml, producing a migration-ready genesis config.
fn cmd_migrate_state(
    snapshot: PathBuf,
    config: Option<PathBuf>,
    output: PathBuf,
) -> Result<()> {
    // Load snapshot
    let snap_json = std::fs::read_to_string(&snapshot)
        .with_context(|| format!("Failed to read snapshot: {}", snapshot.display()))?;
    let snap: lib_blockchain::genesis::GenesisStateSnapshot =
        serde_json::from_str(&snap_json).context("Failed to parse state snapshot")?;

    // Load base genesis.toml text
    let base_toml: String = match config {
        Some(ref path) => std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?,
        None => String::from_utf8(include_bytes!("../../../genesis.toml").to_vec())
            .context("Embedded genesis.toml is not valid UTF-8")?,
    };

    // Strip any existing [allocations] section, then append the new one
    let base_without_alloc = strip_allocations_section(&base_toml);

    let alloc = lib_blockchain::genesis::GenesisAllocations {
        wallets: snap.wallets,
        identities: snap.identities,
        web4_contracts: snap.web4_contracts,
        sov_balances: snap.sov_balances,
    };

    let final_toml = format!(
        "{}\n# -- Migrated state from snapshot (height {}, exported {}) --\n{}",
        base_without_alloc.trim_end(),
        snap.chain_height,
        snap.exported_at,
        alloc_toml_inline(&alloc),
    );

    std::fs::write(&output, &final_toml)
        .with_context(|| format!("Failed to write output to {}", output.display()))?;

    println!(
        "Migration complete. Output written to: {}\n\
         Wallets: {}\nIdentities: {}\nWeb4 contracts: {}\nSOV balances: {}",
        output.display(),
        alloc.wallets.len(),
        alloc.identities.len(),
        alloc.web4_contracts.len(),
        alloc.sov_balances.len(),
    );
    println!(
        "\nNext steps:\n\
         1. Review {}\n\
         2. zhtp-cli genesis build --config {} to verify block 0 hash\n\
         3. Set CANONICAL_GENESIS_HASH and commit",
        output.display(),
        output.display(),
    );
    Ok(())
}

/// Remove the `[allocations]` section (and all its sub-sections) from a TOML string.
fn strip_allocations_section(toml: &str) -> String {
    let mut out = String::new();
    let mut in_alloc = false;
    for line in toml.lines() {
        let trimmed = line.trim();
        if trimmed == "[allocations]" || trimmed.starts_with("[allocations.") {
            in_alloc = true;
            continue;
        }
        if trimmed.starts_with("[[allocations") {
            in_alloc = true;
            continue;
        }
        if in_alloc && trimmed.starts_with('[') && !trimmed.starts_with("[[allocations") {
            in_alloc = false;
        }
        if !in_alloc {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Serialize allocations as TOML arrays suitable for embedding in genesis.toml.
fn toml_basic_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn alloc_toml_inline(alloc: &lib_blockchain::genesis::GenesisAllocations) -> String {
    let mut out = String::new();

    if alloc.wallets.is_empty()
        && alloc.identities.is_empty()
        && alloc.web4_contracts.is_empty()
        && alloc.sov_balances.is_empty()
    {
        out.push_str("[allocations]\n");
        out.push_str("wallets         = []\n");
        out.push_str("identities      = []\n");
        out.push_str("web4_contracts  = []\n");
        out.push_str("sov_balances    = []\n");
        return out;
    }

    for w in &alloc.wallets {
        out.push_str("[[allocations.wallets]]\n");
        out.push_str(&format!("wallet_id = \"{}\"\n", toml_basic_escape(&w.wallet_id)));
        out.push_str(&format!("wallet_type = \"{}\"\n", toml_basic_escape(&w.wallet_type)));
        out.push_str(&format!("public_key = \"{}\"\n", toml_basic_escape(&w.public_key)));
        if let Some(ref oid) = w.owner_identity_id {
            out.push_str(&format!("owner_identity_id = \"{}\"\n", toml_basic_escape(oid)));
        }
        out.push_str(&format!("created_at = {}\n\n", w.created_at));
    }

    for id in &alloc.identities {
        out.push_str("[[allocations.identities]]\n");
        out.push_str(&format!("did = \"{}\"\n", toml_basic_escape(&id.did)));
        out.push_str(&format!(
            "display_name = \"{}\"\n",
            toml_basic_escape(&id.display_name)
        ));
        out.push_str(&format!("public_key = \"{}\"\n", toml_basic_escape(&id.public_key)));
        out.push_str(&format!("identity_type = \"{}\"\n", toml_basic_escape(&id.identity_type)));
        out.push_str(&format!("created_at = {}\n\n", id.created_at));
    }

    for c in &alloc.web4_contracts {
        out.push_str("[[allocations.web4_contracts]]\n");
        out.push_str(&format!("contract_id = \"{}\"\n", toml_basic_escape(&c.contract_id)));
        out.push_str(&format!("domain = \"{}\"\n", toml_basic_escape(&c.domain)));
        out.push_str(&format!("owner = \"{}\"\n", toml_basic_escape(&c.owner)));
        out.push_str(&format!("created_at = {}\n", c.created_at));
        let escaped = toml_basic_escape(&c.contract_json);
        out.push_str(&format!("contract_json = \"{}\"\n\n", escaped));
    }

    for b in &alloc.sov_balances {
        out.push_str("[[allocations.sov_balances]]\n");
        out.push_str(&format!("wallet_id = \"{}\"\n", toml_basic_escape(&b.wallet_id)));
        out.push_str(&format!("public_key = \"{}\"\n", toml_basic_escape(&b.public_key)));
        out.push_str(&format!("balance = {}\n\n", b.balance));
    }

    out
}
