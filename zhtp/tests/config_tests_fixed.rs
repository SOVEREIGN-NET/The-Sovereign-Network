fn load_template(path: &str) -> toml::Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let content = std::fs::read_to_string(root.join(path))
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path, e));
    toml::from_str(&content).unwrap_or_else(|e| panic!("failed to parse {}: {}", path, e))
}

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
