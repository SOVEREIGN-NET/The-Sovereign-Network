//! Authentication and profile onboarding commands.

use crate::argument_parsing::{AuthAction, AuthArgs, ZhtpCli};
use crate::cli_config::{self, ProfileConfig, TrustProfile};
use crate::error::{CliError, CliResult};
use crate::output::Output;

use std::io::{self, Write};

pub async fn handle_auth_command(args: AuthArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_auth_command_impl(args, cli, &output).await
}

async fn handle_auth_command_impl(
    args: AuthArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    match args.action {
        AuthAction::Login {
            profile,
            server,
            keystore,
            identity,
            api_key,
            user_id,
            pin_spki,
            node_did,
            tofu,
            trust_node,
            set_default,
            non_interactive,
        } => {
            handle_login(
                cli,
                output,
                profile,
                server,
                keystore,
                identity,
                api_key,
                user_id,
                pin_spki,
                node_did,
                tofu,
                trust_node,
                set_default,
                non_interactive,
            )
            .await
        }
    }
}

async fn handle_login(
    cli: &ZhtpCli,
    output: &dyn Output,
    profile: Option<String>,
    server: Option<String>,
    keystore: Option<String>,
    identity: Option<String>,
    api_key: Option<String>,
    user_id: Option<String>,
    pin_spki: Option<String>,
    node_did: Option<String>,
    tofu: bool,
    trust_node: bool,
    set_default: bool,
    non_interactive: bool,
) -> CliResult<()> {
    output.header("Auth Login")?;

    let mut config = cli_config::load_config(cli.config.as_deref())?;

    let profile_name = resolve_required(
        "Profile name",
        profile,
        non_interactive,
        Some("default"),
    )?;

    let server_addr = resolve_required(
        "Server address (host:port)",
        server,
        non_interactive,
        None,
    )?;

    let keystore_path = resolve_optional("Keystore path", keystore, non_interactive)?;
    let identity_id = resolve_optional("Identity (DID)", identity, non_interactive)?;
    let api_key_value = resolve_optional_secret("API key", api_key, non_interactive)?;
    let user_id_value = resolve_optional("User ID", user_id, non_interactive)?;

    let trust = resolve_trust_profile(
        pin_spki,
        node_did,
        tofu,
        trust_node,
        non_interactive,
    )?;

    let profile_config = ProfileConfig {
        server: Some(server_addr),
        keystore: keystore_path,
        identity: identity_id,
        api_key: api_key_value,
        user_id: user_id_value,
        trust,
    };

    config.profiles.insert(profile_name.clone(), profile_config);

    let should_default = if set_default {
        true
    } else if non_interactive {
        false
    } else {
        prompt_yes_no("Set as default profile?", true)?
    };

    if should_default {
        config.default_profile = Some(profile_name.clone());
    }

    cli_config::save_config(cli.config.as_deref(), &config)?;
    output.success(&format!("Profile '{}' saved", profile_name))?;
    if should_default {
        output.info(&format!("Default profile set to '{}'", profile_name))?;
    }
    Ok(())
}

fn resolve_required(
    label: &str,
    value: Option<String>,
    non_interactive: bool,
    default: Option<&str>,
) -> CliResult<String> {
    if let Some(value) = value {
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }

    if non_interactive {
        return Err(CliError::ConfigError(format!(
            "{} is required in non-interactive mode",
            label
        )));
    }

    prompt_input(label, default)
}

fn resolve_optional(
    label: &str,
    value: Option<String>,
    non_interactive: bool,
) -> CliResult<Option<String>> {
    if let Some(value) = value {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            return Ok(None);
        }
        return Ok(Some(trimmed));
    }

    if non_interactive {
        return Ok(None);
    }

    let entered = prompt_input(label, Some(""))?;
    let trimmed = entered.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn resolve_optional_secret(
    label: &str,
    value: Option<String>,
    non_interactive: bool,
) -> CliResult<Option<String>> {
    if let Some(value) = value {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            return Ok(None);
        }
        return Ok(Some(trimmed));
    }

    if non_interactive {
        return Ok(None);
    }

    let entered = prompt_secret_input(label)?;
    let trimmed = entered.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn resolve_trust_profile(
    pin_spki: Option<String>,
    node_did: Option<String>,
    tofu: bool,
    trust_node: bool,
    non_interactive: bool,
) -> CliResult<Option<TrustProfile>> {
    let mut trust = TrustProfile {
        pin_spki,
        node_did,
        tofu: if tofu { Some(true) } else { None },
        trust_node: if trust_node { Some(true) } else { None },
    };

    let has_any = trust.pin_spki.is_some()
        || trust.node_did.is_some()
        || trust.tofu.is_some()
        || trust.trust_node.is_some();

    if has_any || non_interactive {
        return Ok(if has_any { Some(trust) } else { None });
    }

    let mode = prompt_input(
        "Trust mode (pin/tofu/insecure/none)",
        Some("none"),
    )?
    .to_lowercase();

    match mode.as_str() {
        "pin" => {
            let spki = prompt_input("SPKI pin (hex)", None)?;
            if spki.trim().is_empty() {
                return Err(CliError::ConfigError(
                    "SPKI pin is required for pin mode".to_string(),
                ));
            }
            trust.pin_spki = Some(spki);
            Ok(Some(trust))
        }
        "tofu" => {
            trust.tofu = Some(true);
            Ok(Some(trust))
        }
        "insecure" => {
            trust.trust_node = Some(true);
            Ok(Some(trust))
        }
        "none" | "" => Ok(None),
        _ => Err(CliError::ConfigError(
            "Invalid trust mode. Use pin, tofu, insecure, or none".to_string(),
        )),
    }
}

fn prompt_input(label: &str, default: Option<&str>) -> CliResult<String> {
    let prompt = match default {
        Some(default) if !default.is_empty() => format!("{} [{}]: ", label, default),
        _ => format!("{}: ", label),
    };

    print!("{}", prompt);
    io::stdout().flush().map_err(CliError::IoError)?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(CliError::IoError)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.unwrap_or_default().to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_secret_input(label: &str) -> CliResult<String> {
    let prompt = format!("{}: ", label);
    rpassword::prompt_password(prompt).map_err(CliError::IoError)
}

fn prompt_yes_no(label: &str, default: bool) -> CliResult<bool> {
    let suffix = if default { "Y/n" } else { "y/N" };
    let prompt = format!("{} [{}]: ", label, suffix);

    print!("{}", prompt);
    io::stdout().flush().map_err(CliError::IoError)?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(CliError::IoError)?;
    let trimmed = input.trim().to_lowercase();

    if trimmed.is_empty() {
        return Ok(default);
    }

    match trimmed.as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Ok(default),
    }
}
