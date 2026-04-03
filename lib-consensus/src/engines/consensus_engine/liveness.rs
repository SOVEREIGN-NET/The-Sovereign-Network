use super::*;

impl ConsensusEngine {
    /// Initialize the heartbeat sender with default 3-second interval.
    ///
    /// Call this before `run_consensus_loop()` to enable periodic heartbeat sending.
    pub fn initialize_heartbeat_sender(&mut self) {
        let interval = tokio::time::interval(Duration::from_secs(3));
        self.heartbeat_interval = Some(interval);
    }

    /// Initialize the liveness monitor for consensus stall detection.
    ///
    /// Call this after `register_validator()` to enable periodic liveness monitoring.
    /// Sets up a 5-second check interval and initializes with current validator set.
    pub fn initialize_liveness_monitor(&mut self) {
        let interval = tokio::time::interval(Duration::from_secs(5));
        self.liveness_check_interval = Some(interval);

        let active_validators: Vec<_> = self
            .validator_manager
            .get_active_validators()
            .iter()
            .map(|v| v.identity.clone())
            .collect();
        self.liveness_monitor
            .update_validator_set(&active_validators);
    }
}
