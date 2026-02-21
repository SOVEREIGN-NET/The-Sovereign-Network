mod config_test_utils;

use config_test_utils::load_template;

#[test]
fn templates_include_runtime_role() {
    let templates = [
        "configs/full-node.toml",
        "configs/validator-node.toml",
        "configs/edge-node.toml",
        "configs/storage-node.toml",
        "configs/mainnet-bootstrap-node.toml",
    ];

    for template in templates {
        let config = load_template(template);
        let role = config.get("runtime_role").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            !role.is_empty(),
            "template {} must define runtime_role",
            template
        );
    }
}

#[test]
fn templates_forbid_legacy_transports() {
    let templates = [
        "configs/full-node.toml",
        "configs/validator-node.toml",
        "configs/edge-node.toml",
        "configs/storage-node.toml",
        "configs/mainnet-bootstrap-node.toml",
    ];

    for template in templates {
        let config = load_template(template);
        let protocols_raw = config
            .get("network_config")
            .and_then(|n| n.get("protocols"))
            .and_then(|p| p.as_array())
            .cloned()
            .unwrap_or_default();
        let protocols: Vec<String> = protocols_raw
            .iter()
            .filter_map(|p| p.as_str())
            .map(|p| p.to_lowercase())
            .collect();
        assert!(
            protocols.contains(&"quic".to_string()),
            "template {} must include quic transport",
            template
        );
        for forbidden in ["tcp", "http", "https", "ws", "websocket", "grpc", "udp"] {
            assert!(
                !protocols.contains(&forbidden.to_string()),
                "template {} must not include forbidden transport {}",
                template,
                forbidden
            );
        }
    }
}
