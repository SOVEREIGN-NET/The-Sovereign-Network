use zhtp::config::{NodeConfig, RuntimeRole};
use zhtp::config::validation::validate_complete_configuration;

#[tokio::test]
async fn rejects_validator_on_non_validator_runtime_roles() {
    let forbidden_roles = [
        RuntimeRole::Edge,
        RuntimeRole::Relay,
        RuntimeRole::Bootstrap,
        RuntimeRole::Service,
    ];

    for role in forbidden_roles {
        let mut config = NodeConfig::default();
        config.runtime_role = role;
        config.consensus_config.validator_enabled = true;
        let result = validate_complete_configuration(&config).await;
        assert!(
            result.is_err(),
            "validator role should be rejected for runtime role {:?}",
            role
        );
    }
}

#[tokio::test]
async fn rejects_gateway_on_non_service_runtime() {
    let mut config = NodeConfig::default();
    config.runtime_role = RuntimeRole::Full;
    config.protocols_config.gateway_enabled = true;
    let result = validate_complete_configuration(&config).await;
    assert!(result.is_err(), "gateway must be service-only");
}

#[tokio::test]
async fn accepts_validator_runtime_with_validator_enabled() {
    let mut config = NodeConfig::default();
    config.runtime_role = RuntimeRole::Validator;
    config.consensus_config.validator_enabled = true;
    let result = validate_complete_configuration(&config).await;
    assert!(
        result.is_ok(),
        "validator_enabled=true should be accepted for RuntimeRole::Validator"
    );
}
