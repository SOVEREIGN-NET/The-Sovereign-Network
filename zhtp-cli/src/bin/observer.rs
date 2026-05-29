//! zhtp-observer — Non-technical observer node onboarding daemon.
//!
//! No CLI subcommands. Environment variables only.
//! The webview at http://127.0.0.1:{port} is the sole interaction surface.
//!
//! For CLI control of observer nodes, use `zhtp-cli observer` instead.

use std::path::PathBuf;

/// Configuration read from the environment (no clap, no subcommands).
struct ObserverConfig {
    port: u16,
    keystore: PathBuf,
    bootstrap: String,
}

impl ObserverConfig {
    fn from_env() -> Self {
        Self {
            port: std::env::var("ZHTP_OBSERVER_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(7840),
            keystore: std::env::var("ZHTP_OBSERVER_KEYSTORE")
                .ok()
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    dirs::home_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join(".zhtp")
                        .join("keystore")
                        .join("observer")
                }),
            bootstrap: std::env::var("ZHTP_OBSERVER_BOOTSTRAP")
                .unwrap_or_else(|_| "g3.thesovereignnetwork.org:9334".to_string()),
        }
    }
}

fn print_help() {
    println!("zhtp-observer {}", env!("CARGO_PKG_VERSION"));
    println!("Non-technical observer node onboarding daemon.");
    println!();
    println!("USAGE:");
    println!("  zhtp-observer              Start the observer setup webview");
    println!("  zhtp-observer --help       Show this help");
    println!("  zhtp-observer --version    Show version");
    println!();
    println!("ENVIRONMENT VARIABLES:");
    println!("  ZHTP_OBSERVER_PORT         HTTP port (default: 7840)");
    println!("  ZHTP_OBSERVER_KEYSTORE     Observer keystore directory");
    println!("                             (default: ~/.zhtp/keystore/observer/)");
    println!("  ZHTP_OBSERVER_BOOTSTRAP    Bootstrap node address");
    println!("                             (default: g3.thesovereignnetwork.org:9334)");
    println!();
    println!("DESCRIPTION:");
    println!("  Starts the observer admission web panel and opens it in the");
    println!("  browser at http://127.0.0.1:<port>.");
    println!("  The desktop never holds a user identity; the phone is the sole");
    println!("  signer.");
    println!();
    println!("  For CLI control of observer nodes, use 'zhtp-cli observer' instead.");
}

#[tokio::main]
async fn main() {
    // --help / --version (manual, one-shot) — no clap derive
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        print_help();
        std::process::exit(0);
    }
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("zhtp-observer {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    // Reject any unrecognized flags — "cannot accidentally trigger validator-mode"
    let unknown: Vec<_> = std::env::args()
        .skip(1) // skip binary name
        .filter(|a| a.starts_with('-'))
        .collect();
    if !unknown.is_empty() {
        eprintln!(
            "zhtp-observer: unrecognized flag(s): {}",
            unknown.join(" ")
        );
        eprintln!("zhtp-observer accepts no CLI flags. Use --help for documentation.");
        std::process::exit(1);
    }

    let config = ObserverConfig::from_env();

    // Startup banner
    eprintln!("══════════════════════════════════════════════");
    eprintln!("  ZHTP Observer Node — Setup");
    eprintln!("══════════════════════════════════════════════");
    eprintln!("  Port:      {}", config.port);
    eprintln!("  Keystore:  {}", config.keystore.display());
    eprintln!("  Bootstrap: {}", config.bootstrap);
    eprintln!("══════════════════════════════════════════════");

    match zhtp_cli::commands::setup_ui::run_observer_ui(
        config.port,
        &config.keystore,
        &config.bootstrap,
    )
    .await
    {
        Ok(()) => {
            eprintln!("zhtp-observer: shutdown complete.");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("zhtp-observer: fatal error: {}", e);
            std::process::exit(1);
        }
    }
}