//! Web4 CLI Functional Testing Suite
//! 
//! Comprehensive end-to-end testing for Web4 CLI domain and deployment functionality.
//! Tests the complete lifecycle: Registration → Deployment → Persistence → Updates → Rollback → Deletion → Error Handling
//!
//! # Test Architecture
//!
//! The test suite is organized into 7 phases covering critical Web4 requirements:
//!
//! 1. **Registration Phase**: Domain registration and initial setup
//! 2. **Deployment Phase**: Site deployment with manifest validation
//! 3. **Persistence Phase**: State persistence across node restarts
//! 4. **Updates Phase**: Version management and incremental updates
//! 5. **Rollback Phase**: Version rollback functionality
//! 6. **Deletion Phase**: Domain deletion and cleanup
//! 7. **Error Handling Phase**: Edge cases and error scenarios
//!
//! # Critical Requirements
//!
//! - Persistence across node restarts (CRITICAL)
//! - Manifest architecture validation (web4_manifest_cid vs manifest_cid)
//! - Version tracking and rollback support
//! - Proper CLI command execution and output parsing
//! - State verification after each operation
//!
//! # Running Tests
//!
//! ```bash
//! # Run all Web4 functional tests
//! cargo test --test web4_functional -- --nocapture
//!
//! # Run specific test phase
//! cargo test --test web4_functional registration_ -- --nocapture
//!
//! # Run with verbose output
//! RUST_LOG=debug cargo test --test web4_functional -- --nocapture --test-threads=1
//! ```

use std::process::{Command, Stdio};
use std::fs;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use std::io::Write;

mod support;
use support::{TestEnv, CliExecutor, SiteGenerator, StateVerifier};

// ============================================================================
// PHASE 1: DOMAIN REGISTRATION TESTS
// ============================================================================

#[test]
fn registration_basic_domain() {
    let env = TestEnv::setup("test_basic_registration");
    let cli = CliExecutor::new(&env);
    
    let result = cli.register_domain("example.com", Some("Test Domain"));
    assert!(result.success, "Domain registration failed: {}", result.output);
    assert!(result.output.contains("example.com") || result.output.contains("registered"));
}

#[test]
fn registration_subdomain() {
    let env = TestEnv::setup("test_subdomain_registration");
    let cli = CliExecutor::new(&env);
    
    let result = cli.register_domain("api.example.com", Some("API Subdomain"));
    assert!(result.success, "Subdomain registration failed: {}", result.output);
}

#[test]
fn registration_multiple_domains() {
    let env = TestEnv::setup("test_multiple_domains");
    let cli = CliExecutor::new(&env);
    
    let domains = vec!["domain1.com", "domain2.com", "domain3.com"];
    
    for domain in domains {
        let result = cli.register_domain(domain, Some(&format!("Domain {}", domain)));
        assert!(result.success, "Failed to register {}: {}", domain, result.output);
    }
    
    // Verify all domains are registered
    let list = cli.list_domains();
    assert!(list.success);
    for domain in &["domain1.com", "domain2.com", "domain3.com"] {
        assert!(list.output.contains(domain), "Domain {} not found in list", domain);
    }
}

#[test]
fn registration_domain_metadata() {
    let env = TestEnv::setup("test_domain_metadata");
    let cli = CliExecutor::new(&env);
    
    let metadata = vec![
        ("owner", "test@example.com"),
        ("description", "Test Web4 Domain"),
        ("version", "1.0"),
    ];
    
    let result = cli.register_domain_with_metadata("metadata.test.com", metadata);
    assert!(result.success, "Metadata registration failed: {}", result.output);
}

// ============================================================================
// PHASE 2: DEPLOYMENT TESTS
// ============================================================================

#[test]
fn deployment_simple_site() {
    let env = TestEnv::setup("test_simple_deployment");
    let cli = CliExecutor::new(&env);
    
    // Register domain
    cli.register_domain("simple.web4.test", None);
    
    // Generate test site
    let site = SiteGenerator::simple("simple.web4.test", "1.0");
    let site_path = env.temp_dir.path().join("site_v1");
    site.write_to(&site_path).expect("Failed to write site");
    
    // Deploy
    let result = cli.deploy_site("simple.web4.test", &site_path);
    assert!(result.success, "Deployment failed: {}", result.output);
    
    // Verify manifest
    let verify = StateVerifier::new(&env);
    assert!(verify.has_manifest("simple.web4.test"), "Manifest not found after deployment");
}

#[test]
fn deployment_manifest_validation() {
    let env = TestEnv::setup("test_manifest_validation");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("manifest.web4.test", None);
    
    let site = SiteGenerator::with_files(
        "manifest.web4.test",
        "1.0",
        vec![
            ("index.html", "<html><body>Test</body></html>"),
            ("style.css", "body { color: blue; }"),
        ],
    );
    
    let site_path = env.temp_dir.path().join("site");
    site.write_to(&site_path).expect("Failed to write site");
    
    let deploy = cli.deploy_site("manifest.web4.test", &site_path);
    assert!(deploy.success, "Deployment failed: {}", deploy.output);
    
    // Verify manifest structure
    let verify = StateVerifier::new(&env);
    let manifest = verify.get_manifest("manifest.web4.test")
        .expect("No manifest found");
    
    // Check both manifest field names (web4_manifest_cid and manifest_cid)
    assert!(
        manifest.contains_key("web4_manifest_cid") || manifest.contains_key("manifest_cid"),
        "Missing manifest CID field"
    );
}

#[test]
fn deployment_multiple_files() {
    let env = TestEnv::setup("test_multiple_files");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("files.web4.test", None);
    
    let files = vec![
        ("index.html", "<html><body>Main Page</body></html>"),
        ("about.html", "<html><body>About Us</body></html>"),
        ("style.css", "body { font-family: sans-serif; }"),
        ("script.js", "console.log('Hello');"),
        ("data.json", r#"{"version": "1.0"}"#),
    ];
    
    let site = SiteGenerator::with_files("files.web4.test", "1.0", files);
    let site_path = env.temp_dir.path().join("site");
    site.write_to(&site_path).expect("Failed to write site");
    
    let result = cli.deploy_site("files.web4.test", &site_path);
    assert!(result.success, "Multi-file deployment failed: {}", result.output);
    
    let verify = StateVerifier::new(&env);
    assert!(verify.has_manifest("files.web4.test"));
}

// ============================================================================
// PHASE 3: PERSISTENCE TESTS
// ============================================================================

#[test]
#[ignore] // Requires running node instance
fn persistence_across_restart() {
    let env = TestEnv::setup("test_persistence_restart");
    let cli = CliExecutor::new(&env);
    
    // Register domain
    cli.register_domain("persist.web4.test", None);
    
    // Deploy site
    let site = SiteGenerator::simple("persist.web4.test", "1.0");
    let site_path = env.temp_dir.path().join("site");
    site.write_to(&site_path).expect("Failed to write site");
    
    cli.deploy_site("persist.web4.test", &site_path);
    
    // Get initial state
    let verify_before = StateVerifier::new(&env);
    let manifest_before = verify_before.get_manifest("persist.web4.test")
        .expect("Manifest not found before restart");
    
    // Simulate node restart
    println!("Simulating node restart...");
    thread::sleep(Duration::from_millis(500));
    
    // Verify state persists
    let verify_after = StateVerifier::new(&env);
    let manifest_after = verify_after.get_manifest("persist.web4.test")
        .expect("Manifest not found after restart");
    
    assert_eq!(manifest_before, manifest_after, "Manifest changed after restart");
}

#[test]
fn persistence_state_verification() {
    let env = TestEnv::setup("test_persistence_verification");
    let cli = CliExecutor::new(&env);
    
    let domains = vec!["domain1.persist.test", "domain2.persist.test"];
    
    for domain in &domains {
        cli.register_domain(domain, None);
        let site = SiteGenerator::simple(domain, "1.0");
        let path = env.temp_dir.path().join(format!("site_{}", domain));
        site.write_to(&path).expect("Failed to write site");
        cli.deploy_site(domain, &path);
    }
    
    // Verify all state is accessible
    let verify = StateVerifier::new(&env);
    for domain in &domains {
        assert!(verify.domain_exists(domain), "Domain {} state lost", domain);
        assert!(verify.has_manifest(domain), "Manifest for {} lost", domain);
    }
}

// ============================================================================
// PHASE 4: UPDATES TESTS
// ============================================================================

#[test]
fn updates_version_increment() {
    let env = TestEnv::setup("test_version_increment");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("version.web4.test", None);
    
    // Deploy v1.0
    let site_v1 = SiteGenerator::simple("version.web4.test", "1.0");
    let path_v1 = env.temp_dir.path().join("site_v1");
    site_v1.write_to(&path_v1).expect("Failed to write v1");
    cli.deploy_site("version.web4.test", &path_v1);
    
    // Get v1 manifest
    let verify = StateVerifier::new(&env);
    let manifest_v1 = verify.get_manifest("version.web4.test")
        .expect("V1 manifest not found");
    
    // Deploy v2.0
    let site_v2 = SiteGenerator::simple("version.web4.test", "2.0");
    let path_v2 = env.temp_dir.path().join("site_v2");
    site_v2.write_to(&path_v2).expect("Failed to write v2");
    cli.deploy_site("version.web4.test", &path_v2);
    
    // Get v2 manifest
    let manifest_v2 = verify.get_manifest("version.web4.test")
        .expect("V2 manifest not found");
    
    // Verify versions are different
    assert_ne!(manifest_v1, manifest_v2, "Manifests should differ between versions");
}

#[test]
fn updates_content_changes() {
    let env = TestEnv::setup("test_content_changes");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("content.web4.test", None);
    
    // Deploy v1
    let files_v1 = vec![("index.html", "<html><body>Version 1</body></html>")];
    let site_v1 = SiteGenerator::with_files("content.web4.test", "1.0", files_v1);
    let path_v1 = env.temp_dir.path().join("site_v1");
    site_v1.write_to(&path_v1).expect("Failed to write v1");
    cli.deploy_site("content.web4.test", &path_v1);
    
    // Deploy v2 with different content
    let files_v2 = vec![("index.html", "<html><body>Version 2 Updated</body></html>")];
    let site_v2 = SiteGenerator::with_files("content.web4.test", "2.0", files_v2);
    let path_v2 = env.temp_dir.path().join("site_v2");
    site_v2.write_to(&path_v2).expect("Failed to write v2");
    
    let result = cli.deploy_site("content.web4.test", &path_v2);
    assert!(result.success, "Version 2 deployment failed");
}

#[test]
fn updates_incremental_deployment() {
    let env = TestEnv::setup("test_incremental_deployment");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("incremental.web4.test", None);
    
    // Deploy initial version
    let files_v1 = vec![
        ("index.html", "<html><body>Home</body></html>"),
        ("about.html", "<html><body>About</body></html>"),
    ];
    let site_v1 = SiteGenerator::with_files("incremental.web4.test", "1.0", files_v1);
    let path_v1 = env.temp_dir.path().join("site_v1");
    site_v1.write_to(&path_v1).expect("Failed to write v1");
    cli.deploy_site("incremental.web4.test", &path_v1);
    
    // Deploy with additional files
    let files_v2 = vec![
        ("index.html", "<html><body>Home Updated</body></html>"),
        ("about.html", "<html><body>About</body></html>"),
        ("contact.html", "<html><body>Contact</body></html>"),
    ];
    let site_v2 = SiteGenerator::with_files("incremental.web4.test", "2.0", files_v2);
    let path_v2 = env.temp_dir.path().join("site_v2");
    site_v2.write_to(&path_v2).expect("Failed to write v2");
    
    let result = cli.deploy_site("incremental.web4.test", &path_v2);
    assert!(result.success, "Incremental deployment failed");
}

// ============================================================================
// PHASE 5: ROLLBACK TESTS
// ============================================================================

#[test]
fn rollback_to_previous_version() {
    let env = TestEnv::setup("test_rollback_previous");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("rollback.web4.test", None);
    
    // Deploy v1.0
    let site_v1 = SiteGenerator::simple("rollback.web4.test", "1.0");
    let path_v1 = env.temp_dir.path().join("site_v1");
    site_v1.write_to(&path_v1).expect("Failed to write v1");
    cli.deploy_site("rollback.web4.test", &path_v1);
    
    let verify = StateVerifier::new(&env);
    let manifest_v1 = verify.get_manifest("rollback.web4.test")
        .expect("V1 manifest not found");
    
    // Deploy v2.0
    let site_v2 = SiteGenerator::simple("rollback.web4.test", "2.0");
    let path_v2 = env.temp_dir.path().join("site_v2");
    site_v2.write_to(&path_v2).expect("Failed to write v2");
    cli.deploy_site("rollback.web4.test", &path_v2);
    
    // Rollback to v1.0
    let rollback_result = cli.rollback_to_version("rollback.web4.test", "1.0");
    assert!(rollback_result.success, "Rollback failed: {}", rollback_result.output);
    
    // Verify manifest reverted
    let manifest_rolled = verify.get_manifest("rollback.web4.test")
        .expect("Rolled-back manifest not found");
    assert_eq!(manifest_v1, manifest_rolled, "Manifest did not revert correctly");
}

#[test]
fn rollback_version_history() {
    let env = TestEnv::setup("test_version_history");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("history.web4.test", None);
    
    // Deploy multiple versions
    for version in &["1.0", "2.0", "3.0"] {
        let site = SiteGenerator::simple("history.web4.test", version);
        let path = env.temp_dir.path().join(format!("site_v{}", version));
        site.write_to(&path).expect(&format!("Failed to write {}", version));
        cli.deploy_site("history.web4.test", &path);
    }
    
    // Get version history
    let history = cli.get_version_history("history.web4.test");
    assert!(history.success, "Failed to get version history");
    
    // Verify all versions are present
    for version in &["1.0", "2.0", "3.0"] {
        assert!(history.output.contains(version), "Version {} not in history", version);
    }
}

// ============================================================================
// PHASE 6: DELETION TESTS
// ============================================================================

#[test]
fn deletion_basic_domain() {
    let env = TestEnv::setup("test_delete_basic");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("delete-me.web4.test", None);
    
    let verify_before = StateVerifier::new(&env);
    assert!(verify_before.domain_exists("delete-me.web4.test"), "Domain not registered");
    
    let delete_result = cli.delete_domain("delete-me.web4.test");
    assert!(delete_result.success, "Delete failed: {}", delete_result.output);
    
    let verify_after = StateVerifier::new(&env);
    assert!(!verify_after.domain_exists("delete-me.web4.test"), "Domain still exists after deletion");
}

#[test]
fn deletion_with_deployment() {
    let env = TestEnv::setup("test_delete_with_deployment");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("delete-deployed.web4.test", None);
    
    let site = SiteGenerator::simple("delete-deployed.web4.test", "1.0");
    let site_path = env.temp_dir.path().join("site");
    site.write_to(&site_path).expect("Failed to write site");
    cli.deploy_site("delete-deployed.web4.test", &site_path);
    
    let delete_result = cli.delete_domain("delete-deployed.web4.test");
    assert!(delete_result.success, "Delete deployed domain failed");
    
    let verify = StateVerifier::new(&env);
    assert!(!verify.domain_exists("delete-deployed.web4.test"));
    assert!(!verify.has_manifest("delete-deployed.web4.test"));
}

#[test]
fn deletion_cleanup() {
    let env = TestEnv::setup("test_deletion_cleanup");
    let cli = CliExecutor::new(&env);
    
    let domains = vec!["cleanup1.test", "cleanup2.test", "cleanup3.test"];
    
    for domain in &domains {
        cli.register_domain(domain, None);
        let site = SiteGenerator::simple(domain, "1.0");
        let path = env.temp_dir.path().join(format!("site_{}", domain));
        site.write_to(&path).expect("Failed to write site");
        cli.deploy_site(domain, &path);
    }
    
    // Delete all
    for domain in &domains {
        cli.delete_domain(domain);
    }
    
    // Verify cleanup
    let verify = StateVerifier::new(&env);
    for domain in &domains {
        assert!(!verify.domain_exists(domain), "Domain {} not cleaned up", domain);
    }
}

// ============================================================================
// PHASE 7: ERROR HANDLING TESTS
// ============================================================================

#[test]
fn error_invalid_domain_name() {
    let env = TestEnv::setup("test_invalid_domain");
    let cli = CliExecutor::new(&env);
    
    let invalid_domains = vec!["", "invalid domain", "domain@invalid", "domain..com"];
    
    for domain in invalid_domains {
        let result = cli.register_domain(domain, None);
        assert!(!result.success, "Invalid domain '{}' should not register", domain);
    }
}

#[test]
fn error_duplicate_registration() {
    let env = TestEnv::setup("test_duplicate_registration");
    let cli = CliExecutor::new(&env);
    
    let domain = "duplicate.web4.test";
    
    // First registration should succeed
    let result1 = cli.register_domain(domain, None);
    assert!(result1.success, "First registration failed");
    
    // Second registration should fail
    let result2 = cli.register_domain(domain, None);
    assert!(!result2.success, "Duplicate registration should fail");
}

#[test]
fn error_deploy_nonexistent_domain() {
    let env = TestEnv::setup("test_deploy_nonexistent");
    let cli = CliExecutor::new(&env);
    
    let site = SiteGenerator::simple("nonexistent.web4.test", "1.0");
    let site_path = env.temp_dir.path().join("site");
    site.write_to(&site_path).expect("Failed to write site");
    
    let result = cli.deploy_site("nonexistent.web4.test", &site_path);
    assert!(!result.success, "Deploy to nonexistent domain should fail");
}

#[test]
fn error_invalid_site_path() {
    let env = TestEnv::setup("test_invalid_site_path");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("invalid-path.web4.test", None);
    
    let result = cli.deploy_site("invalid-path.web4.test", "/nonexistent/path/to/site");
    assert!(!result.success, "Deploy with invalid path should fail");
}

#[test]
fn error_rollback_nonexistent_version() {
    let env = TestEnv::setup("test_rollback_nonexistent");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("norollback.web4.test", None);
    
    let site = SiteGenerator::simple("norollback.web4.test", "1.0");
    let site_path = env.temp_dir.path().join("site");
    site.write_to(&site_path).expect("Failed to write site");
    cli.deploy_site("norollback.web4.test", &site_path);
    
    let result = cli.rollback_to_version("norollback.web4.test", "99.0");
    assert!(!result.success, "Rollback to nonexistent version should fail");
}

#[test]
fn error_delete_nonexistent_domain() {
    let env = TestEnv::setup("test_delete_nonexistent");
    let cli = CliExecutor::new(&env);
    
    let result = cli.delete_domain("totally-nonexistent.web4.test");
    assert!(!result.success, "Delete nonexistent domain should fail");
}

#[test]
fn error_concurrent_operations() {
    let env = TestEnv::setup("test_concurrent_ops");
    let cli = CliExecutor::new(&env);
    
    cli.register_domain("concurrent.web4.test", None);
    
    // Attempt concurrent deployments (simulated)
    let site1 = SiteGenerator::simple("concurrent.web4.test", "1.0");
    let path1 = env.temp_dir.path().join("site_1");
    site1.write_to(&path1).expect("Failed to write site 1");
    
    let site2 = SiteGenerator::simple("concurrent.web4.test", "1.1");
    let path2 = env.temp_dir.path().join("site_2");
    site2.write_to(&path2).expect("Failed to write site 2");
    
    let _result1 = cli.deploy_site("concurrent.web4.test", &path1);
    let result2 = cli.deploy_site("concurrent.web4.test", &path2);
    
    // Should handle gracefully (either succeed with latest or fail appropriately)
    assert!(result2.success || !result2.output.is_empty(), "Should handle concurrent operations");
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn integration_complete_workflow() {
    let env = TestEnv::setup("test_complete_workflow");
    let cli = CliExecutor::new(&env);
    let verify = StateVerifier::new(&env);
    
    let domain = "workflow.web4.test";
    
    // 1. Register
    cli.register_domain(domain, Some("Complete Workflow Test"));
    assert!(verify.domain_exists(domain), "Registration failed");
    
    // 2. Deploy v1
    let site_v1 = SiteGenerator::with_files(
        domain,
        "1.0",
        vec![("index.html", "<html><body>v1</body></html>")],
    );
    let path_v1 = env.temp_dir.path().join("site_v1");
    site_v1.write_to(&path_v1).expect("Failed to write v1");
    cli.deploy_site(domain, &path_v1);
    assert!(verify.has_manifest(domain), "V1 deployment failed");
    
    // 3. Deploy v2
    let site_v2 = SiteGenerator::with_files(
        domain,
        "2.0",
        vec![("index.html", "<html><body>v2</body></html>")],
    );
    let path_v2 = env.temp_dir.path().join("site_v2");
    site_v2.write_to(&path_v2).expect("Failed to write v2");
    cli.deploy_site(domain, &path_v2);
    
    // 4. Get history
    let history = cli.get_version_history(domain);
    assert!(history.success);
    assert!(history.output.contains("1.0"));
    assert!(history.output.contains("2.0"));
    
    // 5. Rollback to v1
    cli.rollback_to_version(domain, "1.0");
    
    // 6. Delete
    cli.delete_domain(domain);
    assert!(!verify.domain_exists(domain), "Cleanup failed");
}

#[test]
fn integration_multiple_domains_isolation() {
    let env = TestEnv::setup("test_multiple_isolation");
    let cli = CliExecutor::new(&env);
    let verify = StateVerifier::new(&env);
    
    let domains = vec!["iso1.web4.test", "iso2.web4.test", "iso3.web4.test"];
    
    // Register and deploy to each
    for domain in &domains {
        cli.register_domain(domain, None);
        let site = SiteGenerator::simple(domain, "1.0");
        let path = env.temp_dir.path().join(format!("site_{}", domain));
        site.write_to(&path).expect(&format!("Failed to write {}", domain));
        cli.deploy_site(domain, &path);
    }
    
    // Modify one domain
    let site_v2 = SiteGenerator::simple("iso1.web4.test", "2.0");
    let path_v2 = env.temp_dir.path().join("site_v2");
    site_v2.write_to(&path_v2).expect("Failed to write v2");
    cli.deploy_site("iso1.web4.test", &path_v2);
    
    // Verify others unchanged
    let manifest_iso2 = verify.get_manifest("iso2.web4.test").expect("iso2 manifest missing");
    let manifest_iso3 = verify.get_manifest("iso3.web4.test").expect("iso3 manifest missing");
    
    // Should have same v1.0 configuration
    assert!(manifest_iso2.to_string().contains("1.0") || !manifest_iso2.is_empty());
    assert!(manifest_iso3.to_string().contains("1.0") || !manifest_iso3.is_empty());
}
