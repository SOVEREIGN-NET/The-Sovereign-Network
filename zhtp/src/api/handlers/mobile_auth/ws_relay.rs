//! Session event polling for real-time auth relay (Phase 4 — Issue #2077)
//!
//! All traffic stays on the QUIC/ZHTP path — no separate HTTP server.
//! Clients poll `GET /api/v1/auth/session/events?session_id=X&since=N`
//! to retrieve new session events since sequence N.
//!
//! # Poll loop (web app)
//! ```text
//! let since = 0;
//! loop {
//!     let resp = GET /api/v1/auth/session/events?session_id=<sid>&since=<since>
//!     for event in resp.events {
//!         handle(event);
//!         since = event.seq + 1;
//!         if event.type == "session_approved" { break; }
//!     }
//!     sleep(1s);
//! }
//! ```

/// Marker so the module is non-empty if nothing else references it.
pub const POLL_ENDPOINT: &str = "/api/v1/auth/session/events";
