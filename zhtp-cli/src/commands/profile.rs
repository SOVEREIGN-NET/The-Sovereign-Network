//! Profile management commands.

use crate::argument_parsing::{ProfileAction, ProfileArgs, ZhtpCli};
use crate::cli_config::{self, TrustProfile};
use crate::error::{CliError, CliResult};
use crate::output::Output;

pub async fn handle_profile_command(args: ProfileArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_profile_command_impl(args, cli, &output).await
}

async fn handle_profile_command_impl(
    args: ProfileArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    match args.action {
        ProfileAction::List => list_profiles(cli, output).await,
        ProfileAction::Show { name } => show_profile(cli, output, &name).await,
        ProfileAction::Use { name } => use_profile(cli, output, &name).await,
        ProfileAction::Set {
            name,
            server,
            keystore,
            identity,
            api_key,
            user_id,
            pin_spki,
            node_did,
            tofu,
            trust_node,
        } => set_profile(
            cli,
            output,
            name,
            server,
            keystore,
            identity,
            api_key,
            user_id,
            pin_spki,
            node_did,
            tofu,
            trust_node,
        )
        .await,
    }
}

async fn list_profiles(cli: &ZhtpCli, output: &dyn Output) -> CliResult<()> {
    let config = cli_config::load_config(cli.config.as_deref())?;
    let default_profile = config.default_profile.unwrap_or_default();

    if config.profiles.is_empty() {
        output.info("No profiles configured")?;
        return Ok(());
    }

    output.header("Profiles")?;
    for name in config.profiles.keys() {
        if *name == default_profile {
            output.print(&format!("* {} (default)", name))?;
        } else {
            output.print(&format!("  {}", name))?;
        }
    }
    Ok(())
}

async fn show_profile(cli: &ZhtpCli, output: &dyn Output, name: &str) -> CliResult<()> {
    let config = cli_config::load_config(cli.config.as_deref())?;
    let profile = config
        .profiles
        .get(name)
        .ok_or_else(|| CliError::ConfigError(format!("Profile '{}' not found", name)))?;

    output.header(&format!("Profile: {}", name))?;
    if let Some(server) = &profile.server {
        output.print(&format!("Server: {}", server))?;
    }
    if let Some(keystore) = &profile.keystore {
        output.print(&format!("Keystore: {}", keystore))?;
    }
    if let Some(identity) = &profile.identity {
        output.print(&format!("Identity: {}", identity))?;
    }
    if let Some(api_key) = &profile.api_key {
        output.print(&format!("API Key: {}", redact(api_key)))?;
    }
    if let Some(user_id) = &profile.user_id {
        output.print(&format!("User ID: {}", user_id))?;
    }
    if let Some(trust) = &profile.trust {
        output.subheader("Trust")?;
        if let Some(pin) = &trust.pin_spki {
            output.print(&format!("Pin SPKI: {}", pin))?;
        }
        if let Some(did) = &trust.node_did {
            output.print(&format!("Node DID: {}", did))?;
        }
        if trust.tofu.unwrap_or(false) {
            output.print("TOFU: enabled")?;
        }
        if trust.trust_node.unwrap_or(false) {
            output.print("Trust Node: enabled (insecure)")?;
        }
    }
    Ok(())
}

async fn use_profile(cli: &ZhtpCli, output: &dyn Output, name: &str) -> CliResult<()> {
    let mut config = cli_config::load_config(cli.config.as_deref())?;
    if !config.profiles.contains_key(name) {
        return Err(CliError::ConfigError(format!(
            "Profile '{}' not found",
            name
        )));
    }
    config.default_profile = Some(name.to_string());
    cli_config::save_config(cli.config.as_deref(), &config)?;
    output.success(&format!("Default profile set to '{}'", name))?;
    Ok(())
}

async fn set_profile(
    cli: &ZhtpCli,
    output: &dyn Output,
    name: String,
    server: Option<String>,
    keystore: Option<String>,
    identity: Option<String>,
    api_key: Option<String>,
    user_id: Option<String>,
    pin_spki: Option<String>,
    node_did: Option<String>,
    tofu: bool,
    trust_node: bool,
) -> CliResult<()> {
    let mut config = cli_config::load_config(cli.config.as_deref())?;
    let mut profile = config
        .profiles
        .remove(&name)
        .unwrap_or_default();

    if let Some(server) = server {
        profile.server = Some(server);
    }
    if let Some(keystore) = keystore {
        profile.keystore = Some(keystore);
    }
    if let Some(identity) = identity {
        profile.identity = Some(identity);
    }
    if let Some(api_key) = api_key {
        profile.api_key = Some(api_key);
    }
    if let Some(user_id) = user_id {
        profile.user_id = Some(user_id);
    }

    let trust_override = pin_spki.is_some() || node_did.is_some() || tofu || trust_node;
    if trust_override {
        let trust = TrustProfile {
            pin_spki,
            node_did,
            tofu: if tofu { Some(true) } else { profile.trust.as_ref().and_then(|t| t.tofu) },
            trust_node: if trust_node {
                Some(true)
            } else {
                profile.trust.as_ref().and_then(|t| t.trust_node)
            },
        };
        profile.trust = Some(trust);
    }

    config.profiles.insert(name.clone(), profile);
    cli_config::save_config(cli.config.as_deref(), &config)?;
    output.success(&format!("Profile '{}' updated", name))?;
    Ok(())
}

fn redact(value: &str) -> String {
    if value.len() <= 6 {
        return "******".to_string();
    }
    let prefix = &value[..3];
    let suffix = &value[value.len() - 3..];
    format!("{}...{}", prefix, suffix)
}
