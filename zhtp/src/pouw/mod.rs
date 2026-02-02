//! Proof-of-Useful-Work (PoUW) Backend Implementation
//!
//! This module implements the node-side functionality for the PoUW protocol:
//! - Challenge token generation (Phase 1)
//! - Receipt validation (Phase 2)
//! - Reward calculation (Phase 3)
//! - Security hardening and monitoring (Phase 4)
//! - Stress testing and production readiness (Phase 5)
//!
//! Reference: docs/dapps_auth/pouw-protocol-spec.md

pub mod challenge;
pub mod disputes;
pub mod health;
pub mod load_test;
pub mod metrics;
pub mod rate_limiter;
pub mod rewards;
pub mod types;
pub mod validation;

pub use challenge::ChallengeGenerator;
pub use disputes::{DisputeService, Dispute, DisputeType, DisputeStatus, DisputeError};
pub use health::{PouwHealthChecker, HealthCheckResponse, HealthStatus, HealthCheck};
pub use load_test::{SyntheticReceiptGenerator, LoadTestConfig, LoadTestResults, run_load_test};
pub use metrics::{PouwMetrics, PouwMetricsSnapshot, RejectionType};
pub use rate_limiter::{PouwRateLimiter, RateLimitConfig, RateLimitResult, RateLimitReason};
pub use rewards::{RewardCalculator, Reward, PayoutStatus, EpochClientStats};
pub use types::*;
pub use validation::{ReceiptValidator, ReceiptValidationResult, SubmitResponse, RejectionReason};
