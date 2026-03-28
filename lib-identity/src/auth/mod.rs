//! Authentication module for ZHTP identities
//!
//! - `password`: password-based signin for seed-phrase-imported identities
//! - `session`: core session token (IP/UA-bound, 256-bit CSPRNG)
//! - `mobile_delegation`: Issue #1877 — mobile-to-web challenge/delegation auth

pub mod mobile_delegation;
pub mod password;
pub mod session;

pub use mobile_delegation::{
    AuditEventKind, AuditLogEntry, Capability, CrossDeviceSessionBinder, DelegationCertificate,
    MobileAuthChallenge, MobileAuthStore, MobileDelegatedSession,
};
pub use password::{PasswordError, PasswordManager, PasswordStrength, PasswordValidation};
pub use session::SessionToken;
