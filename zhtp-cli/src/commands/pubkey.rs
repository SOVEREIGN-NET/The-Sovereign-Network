use crate::argument_parsing::{PubkeyArgs, PubkeyAction, ZhtpCli};

/// Handle the pubkey CLI command
pub async fn handle_pubkey_command(args: PubkeyArgs, _cli: &ZhtpCli) -> Result<(), crate::error::CliError> {
    match args.action {
        PubkeyAction::ToBase64 { pubkey } => {
            let base64 = handle_pubkey_to_base64(&pubkey)?;
            println!("{}", base64);
            Ok(())
        }
    }
}


use crate::error::{CliError, CliResult};
use base64::{engine::general_purpose, Engine as _};

/// Convert a public key (hex or base64) to base64 encoding
pub fn handle_pubkey_to_base64(pubkey: &str) -> CliResult<String> {
    let pubkey_bytes = if pubkey.chars().all(|c| c.is_ascii_hexdigit()) && pubkey.len() % 2 == 0 {
        hex::decode(pubkey).map_err(|e| CliError::ConfigError(format!("Invalid hex: {}", e)))?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(pubkey)
            .map_err(|e| CliError::ConfigError(format!("Invalid base64: {}", e)))?
    };
    Ok(general_purpose::STANDARD.encode(pubkey_bytes))
}
