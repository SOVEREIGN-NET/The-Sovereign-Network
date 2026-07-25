//! IPC protocol for blockchain engine ↔ services communication.
//!
//! Enables running the blockchain engine as a separate process, with services
//! connecting via platform-native transport:
//! - **Unix**: Unix domain sockets
//! - **Windows**: TCP loopback (127.0.0.1) with port discovery via path file
//!
//! All messages are length-prefixed bincode.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    Transport        ┌──────────────────┐
//! │  Services Layer  │ ◄────────────────► │ Blockchain Engine │
//! │  (API, ZDNS,     │   IpcRequest /    │  (Consensus,      │
//! │   rewards, ...)  │   IpcResponse     │   sled, mempool)  │
//! └─────────────────┘                    └──────────────────┘
//! ```

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(not(unix))]
use tokio::net::{TcpListener, TcpStream};

/// Platform-specific transport stream type.
///
/// - On Unix: `UnixStream` (Unix domain socket)
/// - On Windows: `TcpStream` (loopback TCP)
#[cfg(unix)]
pub type TransportStream = UnixStream;

/// Platform-specific transport stream type.
///
/// - On Unix: `UnixStream` (Unix domain socket)
/// - On Windows: `TcpStream` (loopback TCP)
#[cfg(not(unix))]
pub type TransportStream = TcpStream;

/// Platform-specific transport listener type.
///
/// - On Unix: `UnixListener` (Unix domain socket)
/// - On Windows: `TcpListener` (loopback TCP)
#[cfg(unix)]
pub type TransportListener = UnixListener;

/// Platform-specific transport listener type.
///
/// - On Unix: `UnixListener` (Unix domain socket)
/// - On Windows: `TcpListener` (loopback TCP)
#[cfg(not(unix))]
pub type TransportListener = TcpListener;

pub mod protocol;
pub mod server;
pub mod client;
