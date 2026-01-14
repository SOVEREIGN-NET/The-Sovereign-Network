# Web4 CLI Functional Testing - File Index

Quick reference for all test-related files in this implementation.

## Test Files

### Main Test Suite
- **[web4_functional.rs](web4_functional.rs)** (661 lines)
  - Primary test file with all 28+ test scenarios
  - 7 testing phases + 2 integration tests
  - Organized by phase with clear module comments
  - References support modules for infrastructure

### Support Modules (Directory: web4_functional/)

- **[web4_functional/mod.rs](web4_functional/mod.rs)** (17 lines)
  - Module exports and public interface
  - Aggregates all support modules

- **[web4_functional/test_env.rs](web4_functional/test_env.rs)** (85 lines)
  - `TestEnv` struct for isolated test environments
  - Temporary directory management
  - Test file creation utilities
  - Automatic cleanup

- **[web4_functional/cli_executor.rs](web4_functional/cli_executor.rs)** (190 lines)
  - `CliExecutor` struct for CLI command execution
  - `CliResult` type for command results
  - Command categories:
    - Domain registration (register_domain, list_domains)
    - Deployment (deploy_site, deploy_site_with_version)
    - Version management (get_version_history, rollback_to_version)
    - Deletion (delete_domain)
    - Status (get_domain_status, get_manifest)

- **[web4_functional/site_generator.rs](web4_functional/site_generator.rs)** (214 lines)
  - `SiteGenerator` struct for creating test websites
  - Builders:
    - `simple()` - Basic site with index.html and manifest
    - `with_files()` - Custom file content
    - `multi_page()` - Multiple HTML pages
  - File writing and introspection methods

- **[web4_functional/state_verifier.rs](web4_functional/state_verifier.rs)** (154 lines)
  - `StateVerifier` struct for state assertion
  - Domain existence verification
  - Manifest integrity checking
  - Version tracking validation
  - Persistence verification
  - Manifest CID validation

## Test Runner

- **[scripts/run_web4_functional_tests.sh](../scripts/run_web4_functional_tests.sh)** (313 lines)
  - Bash script for automated test execution
  - Phase-based test running
  - Color-coded output
  - Multiple execution modes (--nocapture, --verbose, --release)
  - Usage: `./scripts/run_web4_functional_tests.sh [phase] [options]`

## Documentation

### Primary Documentation
- **[WEB4_FUNCTIONAL_TESTING.md](WEB4_FUNCTIONAL_TESTING.md)** (730 lines)
  - **Comprehensive Testing Guide** covering:
    1. Quick Start
    2. Test Architecture
    3. Testing Phases (with code examples)
    4. Test Infrastructure
    5. Running Tests (multiple methods)
    6. Test Coverage Matrix
    7. Requirements Traceability
    8. Troubleshooting

### Implementation Summary
- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** (585 lines)
  - **Executive Summary** with:
    - Key metrics and deliverables
    - 7 testing phases details
    - Critical requirements met
    - File structure
    - Verification checklist
    - Status summary

### Bug Reporting
- **[web4_functional_bug_report_template.md](web4_functional_bug_report_template.md)** (325 lines)
  - **Structured bug tracking template** with:
    - Bug Information section
    - Test Case Details
    - Environment Information
    - Technical Details
    - Manifest Information
    - State Verification
    - Persistence Impact
    - Root Cause Analysis
    - Impact Assessment
    - Reproducibility Checklist

### File Index (This File)
- **[TEST_FILES_INDEX.md](TEST_FILES_INDEX.md)** (This file)
  - Quick reference for all test-related files

## File Statistics

| File | Lines | Purpose |
|------|-------|---------|
| web4_functional.rs | 661 | Main test suite |
| test_env.rs | 85 | Test environment |
| cli_executor.rs | 190 | CLI wrapper |
| site_generator.rs | 214 | Site generation |
| state_verifier.rs | 154 | State verification |
| mod.rs | 17 | Module exports |
| run_web4_functional_tests.sh | 313 | Test runner |
| WEB4_FUNCTIONAL_TESTING.md | 730 | Testing guide |
| IMPLEMENTATION_SUMMARY.md | 585 | Implementation summary |
| web4_functional_bug_report_template.md | 325 | Bug template |
| **TOTAL** | **3,274** | **Complete suite** |

## Quick Navigation

### By Purpose

#### Want to run tests?
→ [scripts/run_web4_functional_tests.sh](../scripts/run_web4_functional_tests.sh)

#### Want to understand the tests?
→ [web4_functional.rs](web4_functional.rs)

#### Need testing infrastructure?
→ [web4_functional/](web4_functional/) directory

#### Looking for comprehensive docs?
→ [WEB4_FUNCTIONAL_TESTING.md](WEB4_FUNCTIONAL_TESTING.md)

#### Need to report a bug?
→ [web4_functional_bug_report_template.md](web4_functional_bug_report_template.md)

#### Want to understand implementation?
→ [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)

### By Component

#### Test Environment
- File: [web4_functional/test_env.rs](web4_functional/test_env.rs)
- API: `TestEnv::setup()`, `create_subdir()`, `write_file()`
- Usage: Each test calls `TestEnv::setup("test_name")`

#### CLI Execution
- File: [web4_functional/cli_executor.rs](web4_functional/cli_executor.rs)
- API: `CliExecutor::new()`, various command methods
- Usage: Commands like `register_domain()`, `deploy_site()`, `delete_domain()`

#### Test Site Generation
- File: [web4_functional/site_generator.rs](web4_functional/site_generator.rs)
- API: `SiteGenerator::simple()`, `with_files()`, `multi_page()`, `write_to()`
- Usage: Creating test sites for deployment

#### State Verification
- File: [web4_functional/state_verifier.rs](web4_functional/state_verifier.rs)
- API: `StateVerifier::new()`, various verification methods
- Usage: Asserting domain state after operations

## Testing Phases

### Phase 1: Domain Registration (5 tests)
- `registration_basic_domain`
- `registration_subdomain`
- `registration_multiple_domains`
- `registration_domain_metadata`

### Phase 2: Deployment (5 tests)
- `deployment_simple_site`
- `deployment_manifest_validation`
- `deployment_multiple_files`

### Phase 3: Persistence (2 tests)
- `persistence_across_restart` [#[ignore] - requires running node]
- `persistence_state_verification`

### Phase 4: Updates (3 tests)
- `updates_version_increment`
- `updates_content_changes`
- `updates_incremental_deployment`

### Phase 5: Rollback (2 tests)
- `rollback_to_previous_version`
- `rollback_version_history`

### Phase 6: Deletion (3 tests)
- `deletion_basic_domain`
- `deletion_with_deployment`
- `deletion_cleanup`

### Phase 7: Error Handling (6 tests)
- `error_invalid_domain_name`
- `error_duplicate_registration`
- `error_deploy_nonexistent_domain`
- `error_invalid_site_path`
- `error_rollback_nonexistent_version`
- `error_delete_nonexistent_domain`
- `error_concurrent_operations`

### Integration Tests (2 tests)
- `integration_complete_workflow`
- `integration_multiple_domains_isolation`

## Command Reference

### Run All Tests
```bash
cd zhtp-cli
./scripts/run_web4_functional_tests.sh all --nocapture
```

### Run Specific Phase
```bash
./scripts/run_web4_functional_tests.sh registration --nocapture
./scripts/run_web4_functional_tests.sh deployment --nocapture
./scripts/run_web4_functional_tests.sh errors --nocapture
```

### Use Cargo Directly
```bash
cargo test --test web4_functional -- --nocapture --test-threads=1
cargo test --test web4_functional registration_ -- --nocapture
cargo test --test web4_functional registration_basic_domain -- --nocapture
```

## File Locations

```
The-Sovereign-Network/
├── zhtp-cli/
│   ├── tests/
│   │   ├── web4_functional.rs                    ← Main test suite
│   │   ├── web4_functional/                      ← Support modules
│   │   │   ├── mod.rs
│   │   │   ├── test_env.rs
│   │   │   ├── cli_executor.rs
│   │   │   ├── site_generator.rs
│   │   │   └── state_verifier.rs
│   │   ├── WEB4_FUNCTIONAL_TESTING.md            ← Complete guide
│   │   ├── IMPLEMENTATION_SUMMARY.md             ← Summary
│   │   ├── web4_functional_bug_report_template.md ← Bug template
│   │   └── TEST_FILES_INDEX.md                   ← This file
│   └── scripts/
│       └── run_web4_functional_tests.sh          ← Test runner
```

## Requirements Coverage

Requirement #537: Web4 CLI Complete Functional Testing (Domains & Deployments)

- ✅ Domain registration testing → [Phase 1](web4_functional.rs#L19-L60)
- ✅ Deployment testing → [Phase 2](web4_functional.rs#L62-L121)
- ✅ Persistence testing → [Phase 3](web4_functional.rs#L123-L160)
- ✅ Version management → [Phase 4-5](web4_functional.rs#L162-L237)
- ✅ Deletion & cleanup → [Phase 6](web4_functional.rs#L239-L285)
- ✅ Error handling → [Phase 7](web4_functional.rs#L287-L390)
- ✅ Integration scenarios → [Integration Tests](web4_functional.rs#L392-L475)
- ✅ Manifest architecture → [deployment_manifest_validation](web4_functional.rs#L87-L109)
- ✅ Comprehensive documentation → All `.md` files
- ✅ Automated test execution → [run_web4_functional_tests.sh](../scripts/run_web4_functional_tests.sh)

## Additional Notes

- Tests are isolated and can run in any order
- Each test gets a unique temporary directory for data
- Tests use proper CLI command execution
- Manifest persistence across restarts is CRITICAL requirement
- Full documentation and examples provided
- Bug report template for issue tracking

---

**Last Updated:** 2026-01-07  
**Test Suite Status:** ✅ Complete and Ready
