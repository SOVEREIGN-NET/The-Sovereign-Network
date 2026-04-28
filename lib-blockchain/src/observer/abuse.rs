//! Anti-abuse counter & escalation policy (observer-admission-8).
//!
//! When the network/API layer detects a policy violation against an
//! admitted observer (rate-limit overflow, malformed sync request,
//! repeated bad-handshake, etc.) it calls [`record_violation`] to
//! produce an updated [`ObserverAdmissionActionMeta`] carrying an
//! incremented `abuse_counter`. The caller persists the meta on the
//! observer record (e.g. via a `SuspendObserver` / `RevokeObserver`
//! transaction whose `actor_did` is `did:zhtp:system`).
//!
//! [`evaluate_escalation`] is a pure function returning the action the
//! policy would mandate at the current counter level.
//!
//! # Determinism
//!
//! All functions are pure; no I/O, no clock. Callers supply `now`.

use lib_types::{ObserverAdmissionActionMeta, ObserverAdmissionPolicy};

/// Action mandated by policy at the current abuse counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationAction {
    /// Counter below `abuse_suspend_threshold`. Continue monitoring.
    None,
    /// Counter has reached `abuse_suspend_threshold` but is below
    /// `abuse_revoke_threshold`. The observer should be suspended.
    Suspend,
    /// Counter has reached `abuse_revoke_threshold`. The observer
    /// should be revoked.
    Revoke,
}

/// Build (or update) the action-meta after a policy violation.
///
/// Increments `abuse_counter` saturatingly and stamps the violation
/// timestamp. Pre-existing actor / reason fields are overwritten with
/// the supplied values (the latest violation is the authoritative one).
pub fn record_violation(
    previous: Option<&ObserverAdmissionActionMeta>,
    actor_did: &str,
    reason: &str,
    now: u64,
) -> ObserverAdmissionActionMeta {
    let prior_count = previous.map(|m| m.abuse_counter).unwrap_or(0);
    ObserverAdmissionActionMeta {
        actor_did: actor_did.to_string(),
        reason: reason.to_string(),
        timestamp: now,
        abuse_counter: prior_count.saturating_add(1),
        last_violation_at: Some(now),
    }
}

/// Evaluate whether the current `abuse_counter` triggers escalation.
///
/// Revoke takes precedence over Suspend. If both thresholds are zero,
/// escalation is disabled (returns [`EscalationAction::None`]).
pub fn evaluate_escalation(
    meta: &ObserverAdmissionActionMeta,
    policy: &ObserverAdmissionPolicy,
) -> EscalationAction {
    let count = meta.abuse_counter;
    if policy.abuse_revoke_threshold > 0 && count >= policy.abuse_revoke_threshold {
        EscalationAction::Revoke
    } else if policy.abuse_suspend_threshold > 0 && count >= policy.abuse_suspend_threshold {
        EscalationAction::Suspend
    } else {
        EscalationAction::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::default_policy;

    fn meta(counter: u32) -> ObserverAdmissionActionMeta {
        ObserverAdmissionActionMeta {
            actor_did: "did:zhtp:system".into(),
            reason: "test".into(),
            timestamp: 100,
            abuse_counter: counter,
            last_violation_at: Some(100),
        }
    }

    #[test]
    fn record_violation_initializes_counter_to_one() {
        let m = record_violation(None, "did:zhtp:system", "rate-limit overflow", 100);
        assert_eq!(m.abuse_counter, 1);
        assert_eq!(m.last_violation_at, Some(100));
        assert_eq!(m.actor_did, "did:zhtp:system");
    }

    #[test]
    fn record_violation_increments_existing_counter() {
        let prev = meta(2);
        let next = record_violation(Some(&prev), "did:zhtp:system", "again", 200);
        assert_eq!(next.abuse_counter, 3);
        assert_eq!(next.last_violation_at, Some(200));
    }

    #[test]
    fn record_violation_saturates_at_u32_max() {
        let prev = meta(u32::MAX);
        let next = record_violation(Some(&prev), "did:zhtp:system", "again", 0);
        assert_eq!(next.abuse_counter, u32::MAX);
    }

    #[test]
    fn escalation_none_below_suspend_threshold() {
        let policy = default_policy();
        assert_eq!(evaluate_escalation(&meta(0), &policy), EscalationAction::None);
        assert_eq!(evaluate_escalation(&meta(2), &policy), EscalationAction::None);
    }

    #[test]
    fn escalation_suspend_at_threshold() {
        let policy = default_policy(); // suspend=3, revoke=5
        assert_eq!(
            evaluate_escalation(&meta(3), &policy),
            EscalationAction::Suspend
        );
        assert_eq!(
            evaluate_escalation(&meta(4), &policy),
            EscalationAction::Suspend
        );
    }

    #[test]
    fn escalation_revoke_at_threshold() {
        let policy = default_policy();
        assert_eq!(
            evaluate_escalation(&meta(5), &policy),
            EscalationAction::Revoke
        );
        assert_eq!(
            evaluate_escalation(&meta(99), &policy),
            EscalationAction::Revoke
        );
    }

    #[test]
    fn zero_thresholds_disable_escalation() {
        let mut policy = default_policy();
        policy.abuse_suspend_threshold = 0;
        policy.abuse_revoke_threshold = 0;
        assert_eq!(
            evaluate_escalation(&meta(1_000), &policy),
            EscalationAction::None
        );
    }

    #[test]
    fn revoke_takes_precedence_over_suspend() {
        let mut policy = default_policy();
        policy.abuse_suspend_threshold = 2;
        policy.abuse_revoke_threshold = 2;
        assert_eq!(
            evaluate_escalation(&meta(2), &policy),
            EscalationAction::Revoke
        );
    }
}
