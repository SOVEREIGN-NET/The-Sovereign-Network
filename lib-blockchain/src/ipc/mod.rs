//! IPC protocol for blockchain engine ↔ services communication.
//!
//! Enables running the blockchain engine as a separate process, with services
//! connecting via Unix domain socket. All messages are length-prefixed bincode.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    Unix Socket    ┌──────────────────┐
//! │  Services Layer  │ ◄──────────────► │ Blockchain Engine │
//! │  (API, ZDNS,     │   IpcRequest /   │  (Consensus,      │
//! │   rewards, ...)  │   IpcResponse    │   sled, mempool)  │
//! └─────────────────┘                   └──────────────────┘
//! ```

pub mod protocol;
pub mod server;
pub mod client;
