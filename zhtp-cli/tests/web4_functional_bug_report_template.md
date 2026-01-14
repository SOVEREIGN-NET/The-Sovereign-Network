# Web4 CLI Functional Testing - Bug Report Template

Use this template to document any issues found during Web4 CLI functional testing.

## Bug Information

**Bug ID:** [Auto-assigned]  
**Test Phase:** [Select one: Registration | Deployment | Persistence | Updates | Rollback | Deletion | Error Handling | Integration]  
**Severity:** [Critical | High | Medium | Low]  
**Status:** [New | Investigating | Reproduced | Fixed | Verified]  

---

## Summary

**Title:** [Brief description of the bug]

**Description:** [Detailed explanation of the issue]

---

## Test Case Details

### Phase Information
- **Phase:** [Which testing phase was active]
- **Test Name:** [Specific test function name]
- **Test Domain:** [Domain name used in test]
- **Duration:** [How long test ran before failure]

### Steps to Reproduce
1. [First step]
2. [Second step]
3. [Continue as needed]

### Expected Behavior
[What should have happened]

### Actual Behavior
[What actually happened]

---

## Environment Information

### System Details
- **OS:** [Linux | macOS | Windows]
- **OS Version:** [e.g., Ubuntu 24.04 LTS]
- **Rust Version:** [Output of `rustc --version`]
- **Cargo Version:** [Output of `cargo --version`]

### Web4 CLI Information
- **CLI Version:** [From zhtp-cli --version]
- **Build Date:** [When binary was built]
- **Build Mode:** [Debug | Release]

### Test Environment
- **Test Runner:** [run_web4_functional_tests.sh]
- **Test Timestamp:** [When test ran]
- **Test Isolation:** [Single thread | Parallel]

---

## Technical Details

### Error Messages
```
[Paste exact error output here]
[Include stack trace if available]
```

### CLI Command Executed
```bash
[The exact zhtp-cli command that triggered the bug]
```

### Output Logs
```
[Full output from test execution]
[Use --nocapture flag for complete output]
```

---

## Manifest Information

### Current Manifest
```json
[Paste the manifest.json content if available]
```

### Expected Manifest Structure
```json
{
  "web4_manifest_cid": "Qm...",
  "manifest_cid": "Qm...",
  "domain": "example.com",
  "version": "1.0",
  "created": "2026-01-07T00:00:00Z"
}
```

### Manifest Field Analysis
- **web4_manifest_cid:** [Present | Missing | Incorrect]
- **manifest_cid:** [Present | Missing | Incorrect]
- **version tracking:** [Working | Issue: ...]

---

## State Verification

### Pre-Failure State
- Domain exists: [Yes | No]
- Manifest exists: [Yes | No]
- Version history: [Available | Missing]

### Post-Failure State
- Domain state: [Consistent | Corrupted | Lost]
- Manifest accessibility: [OK | Inaccessible | Partial]
- Recovery needed: [Yes | No]

---

## Persistence Impact

**Critical Requirement:** Manifest persistence across node restarts

- [ ] Does this bug affect persistence?
- [ ] Does this require a node restart to diagnose?
- [ ] Is state recoverable after restart?

### Persistence Test Result
```
[Describe what happens if node is restarted with bug condition]
```

---

## Version-Specific Information

### Version Involved
- **Deployed Version:** [e.g., 1.0, 2.0]
- **Rolled Back Version:** [If applicable]
- **Current Version:** [What version after bug]

### Rollback Compatibility
- Can rollback from affected version: [Yes | No]
- History remains intact: [Yes | No]

---

## Domain Isolation Impact

**Testing Requirement:** Operations on one domain shouldn't affect others

- **Affected Domain:** [domain1.test]
- **Other Domains:** [domain2.test, domain3.test]
- **Cross-domain impact:** [Yes | No]

### Domain State After Bug
- Affected domain: [State description]
- Other domains: [State description]

---

## Related Test Cases

**May be related to:**
- [ ] Registration tests
- [ ] Deployment tests
- [ ] Persistence tests
- [ ] Update/rollback tests
- [ ] Error handling tests
- [ ] Integration tests

**Similar known issues:** [Link to related issues or PRs]

---

## Attachment Information

### Files to Attach
- [ ] Test output log (`test_output.log`)
- [ ] CLI command history (`cli_history.txt`)
- [ ] Manifest copies (`manifest_*.json`)
- [ ] Screenshots or video (for GUI-related issues)

---

## Investigation Details

### Root Cause Analysis

**Hypothesis 1:**
[Potential cause]

**Hypothesis 2:**
[Alternative cause]

**Most Likely Cause:**
[Based on evidence]

### Code References
- File: [path/to/file.rs]
- Lines: [Line numbers]
- Component: [Which library/module]

---

## Workaround (if available)

**Is there a temporary workaround?** [Yes | No]

**Workaround Steps:**
1. [Step 1]
2. [Step 2]

**Limitations:**
- [Workaround limitation 1]
- [Workaround limitation 2]

---

## Reproducibility

**Reproducibility Rate:**
- [ ] 100% (Always reproduces)
- [ ] >90% (Almost always)
- [ ] 50-90% (Sometimes)
- [ ] <50% (Rarely)

**Conditions Required for Reproduction:**
- [Condition 1]
- [Condition 2]

**Test Script:**
```bash
#!/bin/bash
# Script to reproduce the issue
[Provide exact commands to reproduce]
```

---

## Impact Assessment

### Affected Users
- [Who is impacted by this bug]

### Feature Impact
- **Registration:** [Affected | Not affected]
- **Deployment:** [Affected | Not affected]
- **Persistence:** [Affected | Not affected]
- **Version Management:** [Affected | Not affected]
- **Rollback:** [Affected | Not affected]
- **Deletion:** [Affected | Not affected]

### Data Impact
- **Data Loss:** [Possible | Not possible]
- **State Corruption:** [Possible | Not possible]
- **Recovery:** [Possible | Not possible]

---

## Resolution Target

**Priority for Fix:** [Blocker | Critical | High | Medium | Low]

**Target Release:** [Next patch | Next minor | Next major]

**Fix Estimate:** [Hours | Days | Weeks] (if known)

---

## Additional Notes

[Any other relevant information, observations, or context]

---

## Checklist

- [ ] Bug title is clear and descriptive
- [ ] Reproduction steps are detailed and complete
- [ ] Expected vs. actual behavior is clearly stated
- [ ] Manifest/state information is included (if relevant)
- [ ] Test phase is clearly identified
- [ ] Environment details are complete
- [ ] Error messages/logs are included
- [ ] Related test cases are identified
- [ ] Reproducibility is documented

---

## Reviewer Notes

[Space for developer/reviewer notes during investigation]

---

**Original Reporter:** [Your name]  
**Report Date:** [YYYY-MM-DD]  
**Last Updated:** [YYYY-MM-DD]  

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-07 | Initial report |
| | | |

---

## Related Issues

- Issue #[number]: [Title]
- PR #[number]: [Title]

---

**For more information on Web4 CLI functional testing, see:**
- [Functional Testing Documentation](./WEB4_FUNCTIONAL_TESTING.md)
- [Test Suite Overview](../web4_functional.rs)
- [CLI User Guide](../../CLI_USER_GUIDE.md)
