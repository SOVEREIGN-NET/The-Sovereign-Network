//! Operator-settable maintenance / status banner surfaced to clients.
//!
//! An operator (Council or InfraAdmin role) sets a short message via
//! `POST /api/v1/network/maintenance`. It is included in the
//! `GET /api/v1/network/directory` payload the app already polls, so clients
//! can show a downtime / operations banner without a node restart, and cleared
//! via `DELETE /api/v1/network/maintenance`.
//!
//! This is **process-local runtime state**, not consensus state and not
//! persisted: each node carries its own banner (set it on the gateway the app
//! talks to). Seed an initial banner at startup with `ZHTP_MAINTENANCE_MESSAGE`
//! (severity from `ZHTP_MAINTENANCE_SEVERITY`, default `warning`).

use serde::{Deserialize, Serialize};
use std::sync::{OnceLock, RwLock};

/// Maximum banner length (characters) surfaced to clients. Keeps the directory
/// payload small; longer messages are rejected rather than truncated.
pub const MAX_MAINTENANCE_MESSAGE_LEN: usize = 500;

/// Severities a client can style on. `info` (blue), `warning` (amber),
/// `critical` (red).
pub const VALID_SEVERITIES: [&str; 3] = ["info", "warning", "critical"];

/// An active operator maintenance / status notice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaintenanceNotice {
    /// Human-readable banner text shown in the app.
    pub message: String,
    /// One of [`VALID_SEVERITIES`]. Drives client styling.
    pub severity: String,
    /// Unix seconds when the notice was set.
    pub since: u64,
}

/// Whether `s` is an accepted severity token.
pub fn valid_severity(s: &str) -> bool {
    VALID_SEVERITIES.contains(&s)
}

static MAINTENANCE_NOTICE: OnceLock<RwLock<Option<MaintenanceNotice>>> = OnceLock::new();
static SEEDED: OnceLock<()> = OnceLock::new();

fn cell() -> &'static RwLock<Option<MaintenanceNotice>> {
    MAINTENANCE_NOTICE.get_or_init(|| RwLock::new(None))
}

/// The active maintenance notice, if any. `None` means "no banner".
pub fn get_maintenance_notice() -> Option<MaintenanceNotice> {
    cell().read().ok().and_then(|guard| guard.clone())
}

/// Set (or replace) the active maintenance notice. Returns the stored notice.
///
/// `message` is trimmed. Rejects an empty message (callers should clear via
/// [`clear_maintenance_notice`] instead), a message longer than
/// [`MAX_MAINTENANCE_MESSAGE_LEN`] characters, or an unknown severity.
pub fn set_maintenance_notice(
    message: &str,
    severity: &str,
    now: u64,
) -> Result<MaintenanceNotice, String> {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return Err("maintenance message must not be empty (use DELETE to clear)".to_string());
    }
    if trimmed.chars().count() > MAX_MAINTENANCE_MESSAGE_LEN {
        return Err(format!(
            "maintenance message too long ({} chars, max {})",
            trimmed.chars().count(),
            MAX_MAINTENANCE_MESSAGE_LEN
        ));
    }
    if !valid_severity(severity) {
        return Err(format!(
            "severity must be one of {}, got '{severity}'",
            VALID_SEVERITIES.join("|")
        ));
    }
    let notice = MaintenanceNotice {
        message: trimmed.to_string(),
        severity: severity.to_string(),
        since: now,
    };
    if let Ok(mut guard) = cell().write() {
        *guard = Some(notice.clone());
    }
    Ok(notice)
}

/// Clear any active maintenance notice. Returns `true` if one was cleared.
pub fn clear_maintenance_notice() -> bool {
    match cell().write() {
        Ok(mut guard) => guard.take().is_some(),
        Err(_) => false,
    }
}

/// Seed an initial banner from `ZHTP_MAINTENANCE_MESSAGE` if set. Runs at most
/// once per process, so an operator who later clears the banner does not have
/// it resurrected. No-op when the env var is unset or blank.
pub fn seed_from_env(now: u64) {
    if SEEDED.set(()).is_err() {
        return; // already seeded
    }
    let Ok(message) = std::env::var("ZHTP_MAINTENANCE_MESSAGE") else {
        return;
    };
    if message.trim().is_empty() {
        return;
    }
    let severity = std::env::var("ZHTP_MAINTENANCE_SEVERITY")
        .ok()
        .filter(|s| valid_severity(s))
        .unwrap_or_else(|| "warning".to_string());
    if let Err(e) = set_maintenance_notice(&message, &severity, now) {
        tracing::warn!("ignoring ZHTP_MAINTENANCE_MESSAGE: {e}");
    } else {
        tracing::info!("seeded maintenance banner from ZHTP_MAINTENANCE_MESSAGE");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serialize access to the process-global notice so parallel tests don't
    // race on the shared cell.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn set_get_clear_roundtrip() {
        let _g = lock();
        clear_maintenance_notice();

        assert!(get_maintenance_notice().is_none());

        let notice = set_maintenance_notice("Scheduled upgrade 22:00 UTC", "warning", 1_700_000_000)
            .expect("set");
        assert_eq!(notice.message, "Scheduled upgrade 22:00 UTC");
        assert_eq!(notice.severity, "warning");
        assert_eq!(notice.since, 1_700_000_000);

        let got = get_maintenance_notice().expect("active");
        assert_eq!(got, notice);

        assert!(clear_maintenance_notice(), "clear returns true when one existed");
        assert!(get_maintenance_notice().is_none());
        assert!(!clear_maintenance_notice(), "clear returns false when none active");
    }

    #[test]
    fn set_trims_and_rejects_empty() {
        let _g = lock();
        clear_maintenance_notice();

        assert!(set_maintenance_notice("   ", "info", 1).is_err());
        assert!(set_maintenance_notice("", "info", 1).is_err());

        let n = set_maintenance_notice("  padded  ", "info", 1).expect("set");
        assert_eq!(n.message, "padded");
        clear_maintenance_notice();
    }

    #[test]
    fn rejects_bad_severity_and_overlong_message() {
        let _g = lock();
        clear_maintenance_notice();

        assert!(set_maintenance_notice("hi", "urgent", 1).is_err());
        assert!(set_maintenance_notice("hi", "", 1).is_err());

        let long = "x".repeat(MAX_MAINTENANCE_MESSAGE_LEN + 1);
        assert!(set_maintenance_notice(&long, "info", 1).is_err());

        let at_limit = "y".repeat(MAX_MAINTENANCE_MESSAGE_LEN);
        assert!(set_maintenance_notice(&at_limit, "info", 1).is_ok());
        clear_maintenance_notice();
    }

    #[test]
    fn notice_serializes_to_expected_json() {
        let notice = MaintenanceNotice {
            message: "Down for maintenance".to_string(),
            severity: "critical".to_string(),
            since: 42,
        };
        let v = serde_json::to_value(&notice).unwrap();
        assert_eq!(v["message"], "Down for maintenance");
        assert_eq!(v["severity"], "critical");
        assert_eq!(v["since"], 42);
        // Inactive state serializes as JSON null (safe for old mobile clients).
        assert!(serde_json::to_value(Option::<MaintenanceNotice>::None).unwrap().is_null());
    }
}
