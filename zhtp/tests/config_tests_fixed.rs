mod config_test_utils;

use config_test_utils::load_template;

#[test]
fn non_service_templates_keep_gateway_disabled() {
    let templates = [
        "configs/full-node.toml",
        "configs/validator-node.toml",
        "configs/edge-node.toml",
        "configs/storage-node.toml",
        "configs/mainnet-bootstrap-node.toml",
    ];

    for template in templates {
        let config = load_template(template);
        let gateway_enabled = config
            .get("protocols_config")
            .and_then(|p| p.get("gateway_enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert!(
            !gateway_enabled,
            "template {} must not enable gateway outside SERVICE runtime",
            template
        );
    }
}
