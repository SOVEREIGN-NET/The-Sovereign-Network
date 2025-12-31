//! Testing utilities for lib-consensus
//!
//! This module provides mock implementations and test helpers for consensus testing.

use crate::types::{MessageBroadcaster, ValidatorMessage};
use async_trait::async_trait;
use lib_identity::IdentityId;

/// No-op message broadcaster for use in tests and development
///
/// This implementation ignores all broadcast calls and always succeeds.
/// Use this when message broadcasting is not relevant to the test.
#[derive(Debug)]
pub struct NoOpBroadcaster;

#[async_trait]
impl MessageBroadcaster for NoOpBroadcaster {
    async fn broadcast_to_validators(
        &self,
        _message: ValidatorMessage,
        _validator_ids: &[IdentityId],
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}
