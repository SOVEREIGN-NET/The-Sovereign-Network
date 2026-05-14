//! Lobby ACL — default-deny allowlist for Password (OPAQUE lobby) sessions.
//!
//! Server-side authorization model (S5 of epic #2554):
//!
//! - **Key sessions** (Dilithium-authenticated): full access, unchanged.
//! - **Password sessions** (issued via OPAQUE lobby login): default-deny.
//!   May only call URIs that match an entry in `ALLOWLIST`. Anything else
//!   returns 403 `Forbidden`.
//!
//! Adding or removing a route from the lobby surface = edit one constant
//! in this file. No scattered `is_request_password_session` checks needed
//! at the handler level (those exist for belt-and-suspenders and can be
//! removed once this middleware has been stable for one release).

use lib_protocols::types::ZhtpMethod;

/// A single allowlist entry. `path` is matched as a literal **prefix** —
/// e.g. `/api/v1/chain/blocks/` allows any sub-path beneath it. Use a
/// trailing `/` to indicate prefix-style match; omit it for exact-match.
#[derive(Debug, Clone, Copy)]
pub struct AllowEntry {
    pub method: ZhtpMethod,
    pub path: &'static str,
    /// If true, `path` is a prefix — any request URI that `starts_with(path)`
    /// matches. If false, the URI must equal `path` exactly.
    pub prefix: bool,
}

/// Routes that Password (lobby) sessions are allowed to call.
///
/// Anything not in this list returns 403 for a Password session. Key
/// sessions are unaffected.
pub const ALLOWLIST: &[AllowEntry] = &[
    // --- Chain reads ---
    AllowEntry { method: ZhtpMethod::Get, path: "/api/v1/chain/info", prefix: false },
    AllowEntry { method: ZhtpMethod::Get, path: "/api/v1/chain/blocks/", prefix: true },
    AllowEntry { method: ZhtpMethod::Get, path: "/api/v1/blockchain/blocks/", prefix: true },
    // --- Identity reads (public, returns DID metadata + display_name only) ---
    AllowEntry { method: ZhtpMethod::Get, path: "/api/v1/identity/get/", prefix: true },
    AllowEntry { method: ZhtpMethod::Get, path: "/api/v1/identity/username/available/", prefix: true },
    // --- DAO reads ---
    AllowEntry { method: ZhtpMethod::Get, path: "/api/v1/dao/proposals", prefix: true },
    AllowEntry { method: ZhtpMethod::Get, path: "/api/v1/dao/votes", prefix: true },
    // --- Oracle ---
    AllowEntry { method: ZhtpMethod::Get, path: "/api/v1/oracle/price", prefix: true },
    // --- Observer admission (own info) ---
    AllowEntry { method: ZhtpMethod::Get, path: "/api/v1/observer/admission/by-sponsor", prefix: true },
    // --- OPAQUE auth endpoints (the only writes a Password session can issue) ---
    AllowEntry { method: ZhtpMethod::Post, path: "/api/v1/auth/opaque/register/start", prefix: false },
    AllowEntry { method: ZhtpMethod::Post, path: "/api/v1/auth/opaque/register/finish", prefix: false },
    AllowEntry { method: ZhtpMethod::Post, path: "/api/v1/auth/opaque/login/start", prefix: false },
    AllowEntry { method: ZhtpMethod::Post, path: "/api/v1/auth/opaque/login/finish", prefix: false },
    // --- Legacy credentials recovery (kept until migration sweep is complete) ---
    AllowEntry { method: ZhtpMethod::Post, path: "/api/v1/auth/credentials/recover", prefix: false },
];

/// Is this method+URI permitted for a Password (lobby) session?
pub fn is_lobby_allowed(method: &ZhtpMethod, uri: &str) -> bool {
    // Normalize: ignore query string.
    let path = match uri.find('?') {
        Some(i) => &uri[..i],
        None => uri,
    };
    for entry in ALLOWLIST {
        if &entry.method != method {
            continue;
        }
        if entry.prefix {
            if path.starts_with(entry.path) {
                return true;
            }
        } else if path == entry.path {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_chain_info() {
        assert!(is_lobby_allowed(&ZhtpMethod::Get, "/api/v1/chain/info"));
    }

    #[test]
    fn allows_chain_blocks_subpath() {
        assert!(is_lobby_allowed(
            &ZhtpMethod::Get,
            "/api/v1/chain/blocks/12345"
        ));
    }

    #[test]
    fn denies_wallet_balances() {
        assert!(!is_lobby_allowed(
            &ZhtpMethod::Get,
            "/api/v1/wallet/balances"
        ));
    }

    #[test]
    fn denies_arbitrary_post() {
        assert!(!is_lobby_allowed(
            &ZhtpMethod::Post,
            "/api/v1/wallet/transfer"
        ));
    }

    #[test]
    fn allows_opaque_login_start() {
        assert!(is_lobby_allowed(
            &ZhtpMethod::Post,
            "/api/v1/auth/opaque/login/start"
        ));
    }

    #[test]
    fn denies_opaque_login_start_with_wrong_method() {
        assert!(!is_lobby_allowed(
            &ZhtpMethod::Get,
            "/api/v1/auth/opaque/login/start"
        ));
    }

    #[test]
    fn allows_with_query_string() {
        assert!(is_lobby_allowed(
            &ZhtpMethod::Get,
            "/api/v1/chain/info?foo=bar"
        ));
    }

    #[test]
    fn denies_path_traversal_attempt() {
        // /api/v1/chain/info-but-not-really should NOT match exact entry.
        assert!(!is_lobby_allowed(
            &ZhtpMethod::Get,
            "/api/v1/chain/information"
        ));
    }

    #[test]
    fn allows_identity_get_subpath() {
        assert!(is_lobby_allowed(
            &ZhtpMethod::Get,
            "/api/v1/identity/get/did:zhtp:abc123"
        ));
    }

    #[test]
    fn denies_identity_post() {
        assert!(!is_lobby_allowed(
            &ZhtpMethod::Post,
            "/api/v1/identity/register"
        ));
    }
}
