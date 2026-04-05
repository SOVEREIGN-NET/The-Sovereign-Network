//! CBE token commands for ZHTP CLI
//!
//! Provides Bootstrap Council and operator commands for CBE token infrastructure:
//! - `init-pools`      — Assign 4 pool wallet addresses and distribute full CBE supply (one-time)
//! - `create-contract` — Create an on-chain employment contract
//! - `payroll`         — Process a payroll period, triggering CBE transfer to employee

use crate::argument_parsing::{CbeAction, CbeArgs, ZhtpCli};
use crate::commands::web4_utils::{connect_default, load_identity_from_keystore};
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_network::client::ZhtpClient;
use serde_json::json;
use std::path::PathBuf;
use zhtp_client::cbe_tx::{
    build_create_employment_contract_tx, build_init_cbe_token_tx, build_process_payroll_tx,
};

fn default_keystore_path() -> CliResult<PathBuf> {
    dirs::home_dir()
        .map(|h| h.join(".zhtp").join("keystore"))
        .ok_or_else(|| CliError::ConfigError("Cannot determine home directory".to_string()))
}

fn load_identity() -> CliResult<zhtp_client::Identity> {
    let keystore = default_keystore_path()?;
    let loaded = load_identity_from_keystore(&keystore)?;
    Ok(zhtp_client::Identity {
        did: loaded.identity.did.clone(),
        public_key: loaded.identity.public_key.dilithium_pk.to_vec(),
        private_key: loaded.keypair.private_key.dilithium_sk.to_vec(),
        kyber_public_key: loaded.identity.public_key.kyber_pk.to_vec(),
        kyber_secret_key: loaded.keypair.private_key.kyber_sk.to_vec(),
        node_id: loaded.identity.node_id.as_bytes().to_vec(),
        device_id: loaded.identity.primary_device.clone(),
        recovery_entropy: loaded.keypair.private_key.master_seed.to_vec(),
        created_at: loaded.identity.created_at,
    })
}

fn parse_hex32(value: &str, field: &str) -> CliResult<[u8; 32]> {
    let s = value.strip_prefix("0x").unwrap_or(value);
    let bytes =
        hex::decode(s).map_err(|_| CliError::ConfigError(format!("{} is not valid hex", field)))?;
    bytes
        .try_into()
        .map_err(|_| CliError::ConfigError(format!("{} must be exactly 32 bytes", field)))
}

async fn post_tx<O: Output>(
    cli: &ZhtpCli,
    output: &O,
    endpoint: &str,
    signed_tx_hex: String,
) -> CliResult<()> {
    let body = json!({ "signed_tx": signed_tx_hex });
    let client = connect_default(&cli.server).await?;
    let response =
        client
            .post_json(endpoint, &body)
            .await
            .map_err(|e| CliError::ApiCallFailed {
                endpoint: endpoint.to_string(),
                status: 0,
                reason: e.to_string(),
            })?;
    let resp: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;
    if resp
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        output.success("Transaction accepted")?;
    } else {
        let err = resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        output.error(&format!("Transaction rejected: {}", err))?;
    }
    let formatted = crate::argument_parsing::format_output(&resp, &cli.format)?;
    output.print(&formatted)?;
    Ok(())
}

pub async fn handle_cbe_command(args: CbeArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_cbe_command_with_output(args, cli, &output).await
}

pub async fn handle_cbe_command_with_output<O: Output>(
    args: CbeArgs,
    cli: &ZhtpCli,
    output: &O,
) -> CliResult<()> {
    match args.action {
        CbeAction::InitPools {
            compensation,
            operational,
            performance,
            strategic,
            height,
        } => {
            let identity = load_identity()?;
            let comp_key = parse_hex32(&compensation, "--compensation")?;
            let ops_key = parse_hex32(&operational, "--operational")?;
            let perf_key = parse_hex32(&performance, "--performance")?;
            let strat_key = parse_hex32(&strategic, "--strategic")?;

            output.info("Building InitCbeToken transaction...")?;
            let tx_hex = build_init_cbe_token_tx(
                &identity, comp_key, ops_key, perf_key, strat_key,
                3, // chain_id = 3 (testnet)
                height,
            )
            .map_err(|e| CliError::ConfigError(e))?;

            output.info("Submitting to node...")?;
            post_tx(cli, output, "/api/v1/cbe/init", tx_hex).await
        }

        CbeAction::CreateContract {
            dao_id,
            employee,
            contract_type,
            compensation,
            period,
            tax_bp,
            jurisdiction,
            profit_share_bp,
        } => {
            let identity = load_identity()?;
            let dao_id_bytes = parse_hex32(&dao_id, "--dao-id")?;
            let employee_key = parse_hex32(&employee, "--employee")?;

            output.info("Building CreateEmploymentContract transaction...")?;
            let tx_hex = build_create_employment_contract_tx(
                &identity,
                dao_id_bytes,
                employee_key,
                contract_type,
                compensation,
                period,
                tax_bp,
                jurisdiction,
                profit_share_bp,
                3, // chain_id = 3 (testnet)
            )
            .map_err(|e| CliError::ConfigError(e))?;

            output.info("Submitting to node...")?;
            post_tx(cli, output, "/api/v1/cbe/employment/create", tx_hex).await
        }

        CbeAction::Payroll { contract_id } => {
            let identity = load_identity()?;
            let contract_id_bytes = parse_hex32(&contract_id, "--contract-id")?;

            output.info("Building ProcessPayroll transaction...")?;
            let tx_hex = build_process_payroll_tx(&identity, contract_id_bytes, 3) // chain_id = 3
                .map_err(|e| CliError::ConfigError(e))?;

            output.info("Submitting to node...")?;
            post_tx(cli, output, "/api/v1/cbe/payroll/process", tx_hex).await
        }
    }
}
