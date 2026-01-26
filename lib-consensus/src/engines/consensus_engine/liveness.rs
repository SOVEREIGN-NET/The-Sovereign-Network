use super::*;

impl ConsensusEngine {
    /// Initialize the heartbeat sender with default 3-second interval
    ///
    /// Call this before `run_consensus_loop()` to enable periodic heartbeat sending.
    pub fn initialize_heartbeat_sender(&mut self) {
        let interval = tokio::time::interval(Duration::from_secs(3));
        self.heartbeat_interval = Some(interval);
    }

    /// Initialize the liveness monitor for consensus stall detection
    ///
    /// Call this after `register_validator()` to enable periodic liveness monitoring.
    /// Sets up a 5-second check interval and initializes with current validator set.
    pub fn initialize_liveness_monitor(&mut self) {
        let interval = tokio::time::interval(Duration::from_secs(5));
        self.liveness_check_interval = Some(interval);

        // Initialize with current validator set
        let active_validators: Vec<_> = self
            .validator_manager
            .get_active_validators()
            .iter()
            .map(|v| v.identity.clone())
            .collect();
        self.liveness_monitor.update_validator_set(&active_validators);
    }

    /// Check if a validator is currently alive based on heartbeat presence
    ///
    /// A validator is considered alive if a valid heartbeat has been received
    /// within the configured liveness timeout period (default: 10 seconds).
    pub fn is_validator_alive(&self, validator_id: &IdentityId) -> bool {
        self.heartbeat_tracker.is_validator_alive(validator_id)
    }

    /// Get the age of the last heartbeat received from a validator
    ///
    /// Returns None if no heartbeat has been received from the validator.
    /// Returns Some(duration) with the elapsed time since the last heartbeat.
    pub fn last_heartbeat_age(&self, validator_id: &IdentityId) -> Option<Duration> {
        self.heartbeat_tracker.last_heartbeat_age(validator_id)
    }

    /// Set the liveness timeout duration for heartbeat tracking
    ///
    /// Validators not sending heartbeats within this duration will be
    /// considered not alive. Default is 10 seconds.
    pub fn set_liveness_timeout(&mut self, timeout: Duration) {
        self.heartbeat_tracker.set_liveness_timeout(timeout);
    }

    /// Get list of validators currently considered alive based on heartbeats
    ///
    /// Returns a vector of IdentityIds for all active validators who have
    /// sent a heartbeat within the liveness timeout period.
    pub fn get_alive_validators(&self) -> Vec<IdentityId> {
        self.validator_manager
            .get_active_validators()
            .iter()
            .filter(|v| self.heartbeat_tracker.is_validator_alive(&v.identity))
            .map(|v| v.identity.clone())
            .collect()
    }
}
