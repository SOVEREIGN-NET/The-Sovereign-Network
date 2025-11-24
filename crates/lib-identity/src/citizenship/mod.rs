//! Complete citizenship system - feature from the original identity.rs

pub mod onboarding;
pub mod dao_registration;
pub mod ubi_registration;
pub mod web4_access;
pub mod welcome_bonus;

// Re-exports
pub use onboarding::CitizenshipResult;
pub use dao_registration::DaoRegistration;
pub use ubi_registration::UbiRegistration;
pub use web4_access::Web4Access;
pub use welcome_bonus::WelcomeBonus;
pub use crate::types::AccessLevel;
