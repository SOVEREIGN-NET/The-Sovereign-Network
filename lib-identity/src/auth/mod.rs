//! Authentication module for password-based signin
//! 
//! This module handles password authentication for identities that have been
//! imported using 20-word seed phrases. Passwords only work after identity import.

pub mod password;
pub mod session;

pub use password::{PasswordManager, PasswordError, PasswordValidation, PasswordStrength};
pub use session::SessionToken;