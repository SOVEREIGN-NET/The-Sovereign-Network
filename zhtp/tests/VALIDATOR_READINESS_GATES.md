# Validator Readiness Gate Suite

Use this gate list for release go/no-go decisions.

## Gate Commands

1. `cargo test -p zhtp --test config_tests -- --nocapture`
2. `cargo test -p zhtp --test runtime_tests -- --nocapture`
3. `cargo test -p zhtp --test integration_tests -- --nocapture`
4. `cargo test -p zhtp --test config_tests_fixed -- --nocapture`
5. `cargo test -p zhtp --lib config::validation::tests -- --nocapture`
6. `bash zhtp/configs/validate-config.sh zhtp/configs/validator-node.toml`
7. `bash zhtp/configs/validate-config.sh zhtp/configs/full-node.toml`
8. `bash zhtp/configs/validate-config.sh zhtp/configs/edge-node.toml`

## Expected Coverage

- Runtime role and consensus role compatibility.
- Forbidden transport rejection and QUIC requirement.
- Gateway-to-service runtime constraint.
- Template-level invariant conformance for validator and non-validator nodes.
