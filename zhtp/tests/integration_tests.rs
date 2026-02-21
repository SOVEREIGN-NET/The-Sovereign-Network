use zhtp::config::{NodeConfig, RuntimeRole};
use zhtp::config::validation::validate_complete_configuration;

#[tokio::test]
async fn validator_and_non_validator_configs_pass_gate_validation() {
    let mut validator_config = NodeConfig::default();
    validator_config.runtime_role = RuntimeRole::Validator;
    validator_config.consensus_config.validator_enabled = true;

    let mut full_config = NodeConfig::default();
    full_config.runtime_role = RuntimeRole::Full;
    full_config.consensus_config.validator_enabled = false;

    let mut edge_config = NodeConfig::default();
    edge_config.runtime_role = RuntimeRole::Edge;
    edge_config.consensus_config.validator_enabled = false;

    let mut relay_config = NodeConfig::default();
    relay_config.runtime_role = RuntimeRole::Relay;
    relay_config.consensus_config.validator_enabled = false;

    let mut bootstrap_config = NodeConfig::default();
    bootstrap_config.runtime_role = RuntimeRole::Bootstrap;
    bootstrap_config.consensus_config.validator_enabled = false;

    for (name, config) in [
        ("validator", validator_config),
        ("full", full_config),
        ("edge", edge_config),
        ("relay", relay_config),
        ("bootstrap", bootstrap_config),
    ] {
        let result = validate_complete_configuration(&config).await;
        assert!(result.is_ok(), "{} config must pass readiness validation", name);
    }
}
