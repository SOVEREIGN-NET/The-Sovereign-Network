//! Panic recovery utilities for network services
//!
//! This module provides panic recovery mechanisms to prevent node crashes
//! when individual handlers panic. It wraps async handlers with catch_unwind
//! to catch panics and log them with context, allowing the node to continue
//! serving other connections.
//!
//! # Usage
//!
//! ```ignore
//! use crate::panic_recovery::catch_unwind_handler;
//!
//! // Wrap a connection handler
//! tokio::spawn(async move {
//!     catch_unwind_handler(
//!         "connection_handler",
//!         handle_connection(stream),
//!         |panic_msg| {
//!             error!("Connection handler panicked: {}", panic_msg);
//!         }
//!     ).await;
//! });
//! ```

use futures::FutureExt;
use std::any::Any;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use tracing::error;

/// Result of a panic catch operation
#[derive(Debug)]
pub enum PanicCatchResult<T> {
    /// Future completed successfully
    Success(T),
    /// Future panicked with the given message
    Panicked(String),
}

/// Catch panics in an async handler and log them with context
///
/// This function wraps a future with panic recovery. If the future panics,
/// the panic is caught, logged, and the error is returned instead of
/// crashing the entire node.
///
/// # Arguments
///
/// * `handler_name` - Name of the handler for logging purposes
/// * `future` - The async future to execute with panic recovery
/// * `on_panic` - Optional callback to invoke when a panic occurs
///
/// # Returns
///
/// * `PanicCatchResult::Success(T)` if the future completed successfully
/// * `PanicCatchResult::Panicked(String)` if the future panicked
///
/// # Example
///
/// ```ignore
/// let result = catch_unwind_handler(
///     "message_handler",
///     process_message(msg),
///     |msg| error!("Handler panicked: {}", msg)
/// ).await;
///
/// match result {
///     PanicCatchResult::Success(value) => { /* handle success */ }
///     PanicCatchResult::Panicked(msg) => { /* handle panic */ }
/// }
/// ```
pub async fn catch_unwind_handler<F, T, C>(
    handler_name: &str,
    future: F,
    on_panic: C,
) -> PanicCatchResult<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
    C: FnOnce(&str),
{
    let result = AssertUnwindSafe(future).catch_unwind().await;

    match result {
        Ok(value) => PanicCatchResult::Success(value),
        Err(panic_info) => {
            let panic_msg = extract_panic_message(&panic_info);
            error!(
                target: "panic_recovery",
                "Handler '{}' panicked: {}. Node continues operating.",
                handler_name,
                panic_msg
            );
            on_panic(&panic_msg);
            PanicCatchResult::Panicked(panic_msg)
        }
    }
}

/// Catch panics in a spawn task with automatic logging
///
/// This is a convenience wrapper for spawning tasks with panic recovery.
/// The panic is logged with the handler name and context.
///
/// # Arguments
///
/// * `handler_name` - Name of the handler for logging
/// * `future` - The async future to spawn
///
/// # Returns
///
/// A join handle that returns `PanicCatchResult<T>`
///
/// # Example
///
/// ```ignore
/// let handle = spawn_with_panic_recovery(
///     "connection_handler",
///     handle_connection(stream)
/// );
///
/// let result = handle.await;
/// ```
pub fn spawn_with_panic_recovery<F, T>(
    handler_name: &'static str,
    future: F,
) -> tokio::task::JoinHandle<PanicCatchResult<T>>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(async move {
        catch_unwind_handler(
            handler_name,
            future,
            |_| {}, // No-op callback, logging is done automatically
        )
        .await
    })
}

/// Extract a human-readable message from panic info
fn extract_panic_message(panic_info: &Box<dyn Any + Send>) -> String {
    if let Some(s) = panic_info.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = panic_info.downcast_ref::<String>() {
        s.clone()
    } else {
        "Unknown panic (non-string payload)".to_string()
    }
}

/// Macro to wrap a handler spawn with panic recovery
///
/// This macro simplifies the common pattern of spawning a handler
/// with panic recovery.
///
/// # Example
///
/// ```ignore
/// spawn_handler!("connection_handler", async move {
///     handle_connection(stream).await?;
///     Ok::<_, anyhow::Error>(())
/// });
/// ```
#[macro_export]
macro_rules! spawn_handler {
    ($name:expr, $future:expr) => {
        $crate::panic_recovery::spawn_with_panic_recovery($name, $future)
    };
    ($name:expr, $future:expr, $on_panic:expr) => {
        tokio::spawn(async move {
            $crate::panic_recovery::catch_unwind_handler($name, $future, $on_panic).await
        })
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_catch_unwind_success() {
        let result = catch_unwind_handler("test_handler", async { 42 }, |_| {}).await;

        match result {
            PanicCatchResult::Success(value) => assert_eq!(value, 42),
            PanicCatchResult::Panicked(_) => panic!("Should not have panicked"),
        }
    }

    #[tokio::test]
    async fn test_catch_unwind_panic_string() {
        let result = catch_unwind_handler(
            "test_handler",
            async { panic!("test panic message") },
            |_| {},
        )
        .await;

        match result {
            PanicCatchResult::Success(_) => panic!("Should have panicked"),
            PanicCatchResult::Panicked(msg) => {
                assert!(msg.contains("test panic message"));
            }
        }
    }

    #[tokio::test]
    async fn test_catch_unwind_panic_str() {
        let result = catch_unwind_handler(
            "test_handler",
            async { panic!("static string panic") },
            |_| {},
        )
        .await;

        match result {
            PanicCatchResult::Success(_) => panic!("Should have panicked"),
            PanicCatchResult::Panicked(msg) => {
                assert!(msg.contains("static string panic"));
            }
        }
    }

    #[tokio::test]
    async fn test_spawn_with_panic_recovery() {
        let handle = spawn_with_panic_recovery("test_spawn", async { "success" });

        let result = handle.await.ok();
        match result {
            PanicCatchResult::Success(value) => assert_eq!(value, "success"),
            PanicCatchResult::Panicked(_) => panic!("Should not have panicked"),
        }
    }

    #[tokio::test]
    async fn test_spawn_with_panic_recovery_catches_panic() {
        let handle = spawn_with_panic_recovery("test_spawn_panic", async {
            panic!("intentional test panic")
        });

        let result = handle.await.ok();
        match result {
            PanicCatchResult::Success(_) => panic!("Should have panicked"),
            PanicCatchResult::Panicked(msg) => {
                assert!(msg.contains("intentional test panic"));
            }
        }
    }
}
