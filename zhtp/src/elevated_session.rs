//! Short-lived elevated sessions after dual-auth grant exercise.
//!
//! Personal DID session remains baseline. After `POST .../grants/elevate`,
//! verified ScopedGrants attach for a short TTL keyed by (did, session_binding).

use lib_access_control::ScopedGrant;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default elevated session lifetime (seconds). Independent of personal session.
pub const DEFAULT_ELEVATED_TTL_SECS: u64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct ElevatedSession {
    pub did: String,
    pub session_binding: String,
    pub grants: Vec<ScopedGrant>,
    pub expires_at_unix: u64,
}

#[derive(Clone, Default)]
pub struct ElevatedSessionStore {
    inner: Arc<Mutex<HashMap<String, ElevatedSession>>>,
}

fn key(did: &str, session_binding: &str) -> String {
    format!("{did}|{session_binding}")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl ElevatedSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(
        &self,
        did: impl Into<String>,
        session_binding: impl Into<String>,
        grants: Vec<ScopedGrant>,
        ttl_secs: u64,
    ) -> ElevatedSession {
        let did = did.into();
        let session_binding = session_binding.into();
        let expires_at_unix = now_unix().saturating_add(ttl_secs);
        let entry = ElevatedSession {
            did: did.clone(),
            session_binding: session_binding.clone(),
            grants,
            expires_at_unix,
        };
        self.inner
            .lock()
            .expect("elevated session lock")
            .insert(key(&did, &session_binding), entry.clone());
        entry
    }

    pub fn get(&self, did: &str, session_binding: &str) -> Option<ElevatedSession> {
        let mut map = self.inner.lock().expect("elevated session lock");
        let k = key(did, session_binding);
        let now = now_unix();
        if let Some(e) = map.get(&k) {
            if e.expires_at_unix < now {
                map.remove(&k);
                return None;
            }
            return Some(e.clone());
        }
        None
    }

    pub fn clear(&self, did: &str, session_binding: &str) {
        self.inner
            .lock()
            .expect("elevated session lock")
            .remove(&key(did, session_binding));
    }
}

static GLOBAL_ELEVATED: OnceLock<ElevatedSessionStore> = OnceLock::new();

pub fn get_global_elevated_sessions() -> &'static ElevatedSessionStore {
    GLOBAL_ELEVATED.get_or_init(ElevatedSessionStore::new)
}

/// Resolve session binding for grant exercise / elevate attach.
///
/// Prefer explicit `X-Grant-Session-Binding`, then Bearer token, else a
/// DID-scoped synthetic binding (QUIC-only callers without bearer).
pub fn session_binding_from_request(request: &lib_protocols::types::ZhtpRequest) -> String {
    if let Some(b) = request.headers.get("x-grant-session-binding") {
        let t = b.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if let Some(auth) = request.headers.get("authorization") {
        if let Some(token) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
        {
            let t = token.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    if let Some(ref id) = request.requester {
        return format!("did-session:{}", hex::encode(&id.0));
    }
    "anonymous".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_access_control::ScopedGrant;
    use lib_access_control::{AccessDomain, AccessOperation};

    #[test]
    fn put_get_ttl() {
        let store = ElevatedSessionStore::new();
        let g = ScopedGrant::new(
            "g1",
            "did:zhtp:a",
            "did:zhtp:c",
            vec![AccessDomain::WalletGraph],
            vec![AccessOperation::Read],
        );
        store.put("did:zhtp:a", "bind-1", vec![g], 60);
        assert!(store.get("did:zhtp:a", "bind-1").is_some());
        assert!(store.get("did:zhtp:a", "other").is_none());
    }
}
