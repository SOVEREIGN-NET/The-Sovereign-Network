pub fn load_template(path: &str) -> toml::Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let content = std::fs::read_to_string(root.join(path))
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path, e));
    toml::from_str(&content).unwrap_or_else(|e| panic!("failed to parse {}: {}", path, e))
}
