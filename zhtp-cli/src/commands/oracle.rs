//! Oracle governance commands for ZHTP CLI.

use crate::argument_parsing::{format_output, OracleAction, OracleArgs, ZhtpCli};
use crate::commands::transaction_utils::parse_hex_32;
use crate::commands::web4_utils::connect_default;
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_network::client::ZhtpClient;

const ORACLE_COMMITTEE_PROPOSE_ENDPOINT: &str = "/api/v1/oracle/committee/propose";
const ORACLE_CONFIG_PROPOSE_ENDPOINT: &str = "/api/v1/oracle/config/propose";

pub async fn handle_oracle_command(args: OracleArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_oracle_command_impl(args, cli, &output).await
}

async fn handle_oracle_command_impl(
    args: OracleArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let client = connect_default(&cli.server).await?;
    match args.action {
        OracleAction::CommitteeUpdate {
            members,
            pubkeys,
            activate_epoch,
            reason,
            title: _,
            description: _,
            voting_period_days: _,
        } => {
            if members.is_empty() {
                return Err(CliError::ConfigError("members cannot be empty".to_string()));
            }
            let normalized_members = members
                .iter()
                .map(|m| parse_hex_32("member", m).map(hex::encode))
                .collect::<CliResult<Vec<String>>>()?;
            let request = serde_json::json!({
                "new_members": normalized_members,
                "signing_pubkeys": pubkeys,
                "activate_at_epoch": activate_epoch,
                "reason": reason,
            });
            output.info("Bootstrapping oracle committee...")?;
            submit_oracle_request(
                &client,
                cli,
                output,
                ORACLE_COMMITTEE_PROPOSE_ENDPOINT,
                request,
                "Oracle Committee Bootstrap",
            )
            .await
        }
        OracleAction::ConfigUpdate {
            epoch_duration,
            max_source_age,
            max_deviation_bps,
            max_price_staleness_epochs,
            activate_epoch,
            reason,
            title: _,
            description: _,
            voting_period_days: _,
        } => {
            let request = serde_json::json!({
                "epoch_duration_secs": epoch_duration,
                "max_source_age_secs": max_source_age,
                "max_deviation_bps": max_deviation_bps,
                "max_price_staleness_epochs": max_price_staleness_epochs,
                "activate_at_epoch": activate_epoch,
                "reason": reason,
            });
            output.info("Submitting oracle config update...")?;
            submit_oracle_request(
                &client,
                cli,
                output,
                ORACLE_CONFIG_PROPOSE_ENDPOINT,
                request,
                "Oracle Config Update",
            )
            .await
        }
        OracleAction::Status => {
            fetch_oracle(
                &client,
                cli,
                output,
                "/api/v1/oracle/status",
                "Oracle Status",
            )
            .await
        }
        OracleAction::Price => {
            fetch_oracle(&client, cli, output, "/api/v1/oracle/price", "Oracle Price").await
        }
        OracleAction::Config => {
            fetch_oracle(
                &client,
                cli,
                output,
                "/api/v1/oracle/config",
                "Oracle Config",
            )
            .await
        }
        OracleAction::PendingUpdates => {
            fetch_oracle(
                &client,
                cli,
                output,
                "/api/v1/oracle/pending-updates",
                "Oracle Pending Updates",
            )
            .await
        }
        OracleAction::SlashingEvents => {
            fetch_oracle(
                &client,
                cli,
                output,
                "/api/v1/oracle/slashing-events",
                "Oracle Slashing Events",
            )
            .await
        }
        OracleAction::BannedValidators => {
            fetch_oracle(
                &client,
                cli,
                output,
                "/api/v1/oracle/banned-validators",
                "Oracle Banned Validators",
            )
            .await
        }
    }
}

async fn fetch_oracle(
    client: &ZhtpClient,
    cli: &ZhtpCli,
    output: &dyn crate::output::Output,
    endpoint: &str,
    title: &str,
) -> CliResult<()> {
    let response = client
        .get(endpoint)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let result: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.to_string(),
            status: 0,
            reason: format!("Failed to parse response: {e}"),
        })?;
    output.header(title)?;
    output.print(&format_output(&result, &cli.format)?)?;
    Ok(())
}

async fn submit_oracle_request(
    client: &ZhtpClient,
    cli: &ZhtpCli,
    output: &dyn Output,
    endpoint: &str,
    request: serde_json::Value,
    title: &str,
) -> CliResult<()> {
    let response =
        client
            .post_json(endpoint, &request)
            .await
            .map_err(|e| CliError::ApiCallFailed {
                endpoint: endpoint.to_string(),
                status: 0,
                reason: e.to_string(),
            })?;

    let result: serde_json::Value =
        ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint.to_string(),
            status: 0,
            reason: format!("Failed to parse response: {e}"),
        })?;

    output.header(title)?;
    output.print(&format_output(&result, &cli.format)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_update_payload_contains_required_fields() {
        let members = vec!["11".repeat(32), "22".repeat(32)];
        let body = build_committee_update_request(
            members,
            9_u64,
            "Committee rotation".to_string(),
            None,
            None,
            None,
        )
        .expect("committee request should build");

        assert_eq!(
            body.get("proposal_type").and_then(|v| v.as_str()),
            Some("update_oracle_committee")
        );
        assert_eq!(
            body.get("oracle_committee_members")
                .and_then(|v| v.as_array())
                .map(|v| v.len()),
            Some(2)
        );
        assert_eq!(
            body.get("description").and_then(|v| v.as_str()),
            Some("Committee rotation")
        );
    }

    #[test]
    fn config_update_payload_contains_required_fields() {
        let body = build_config_update_request(
            600_u64,
            120_u64,
            900_u32,
            10_u64,
            9_u64,
            "Tune oracle config".to_string(),
            None,
            None,
            Some(7),
        );

        assert_eq!(
            body.get("proposal_type").and_then(|v| v.as_str()),
            Some("update_oracle_config")
        );
        assert_eq!(
            body.get("oracle_max_deviation_bps")
                .and_then(|v| v.as_u64()),
            Some(900)
        );
        assert_eq!(
            body.get("voting_period_days").and_then(|v| v.as_u64()),
            Some(7)
        );
    }

    #[test]
    fn committee_update_payload_rejects_empty_members() {
        let result = build_committee_update_request(
            Vec::new(),
            9_u64,
            "Committee rotation".to_string(),
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }
}
