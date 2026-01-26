//! Routing Error Classification (Phase 3 - Ticket 2.6)
//!
//! Distinguishes between error types so broadcast/routing can handle them appropriately

use std::fmt;

/// Classification of routing errors for appropriate recovery strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingErrorClass {
    /// Network-level transient error (timeout, connection reset)
    /// Recovery: Retry or skip peer temporarily, continue with others
    Transient,

    /// Identity verification failed (sender/receiver not in blockchain)
    /// Recovery: Permanently skip peer, log warning
    IdentityViolation,

    /// Configuration/initialization error (missing identity, no connections)
    /// Recovery: FAIL - this is a programmer error, fail fast
    Configuration,
}

impl fmt::Display for RoutingErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient => write!(f, "TRANSIENT"),
            Self::IdentityViolation => write!(f, "IDENTITY_VIOLATION"),
            Self::Configuration => write!(f, "CONFIGURATION"),
        }
    }
}

/// Routing error with classification for handler to decide recovery
#[derive(Debug, Clone)]
pub struct RoutingError {
    pub class: RoutingErrorClass,
    pub message: String,
}

impl RoutingError {
    pub fn transient(msg: impl Into<String>) -> Self {
        Self {
            class: RoutingErrorClass::Transient,
            message: msg.into(),
        }
    }

    pub fn identity_violation(msg: impl Into<String>) -> Self {
        Self {
            class: RoutingErrorClass::IdentityViolation,
            message: msg.into(),
        }
    }

    pub fn configuration(msg: impl Into<String>) -> Self {
        Self {
            class: RoutingErrorClass::Configuration,
            message: msg.into(),
        }
    }
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.class, self.message)
    }
}

impl std::error::Error for RoutingError {}
