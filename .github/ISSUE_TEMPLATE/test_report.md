---
name: "[TEST] Testing Findings and Results"
about: Report testing results, findings, or test case failures
title: "[TEST] "
labels: test
assignees: ''

---

## [TEST] Testing Report

**Related Test Issue:** [Link to testing issue #537 or specify which test plan]

**Test Phase:** [which phase were you testing?]
- [ ] Phase 1: Domain Registration
- [ ] Phase 2: Initial Deployment
- [ ] Phase 3: Persistence Across Restart
- [ ] Phase 4: Deployment Updates
- [ ] Phase 5: Version Rollback
- [ ] Phase 6: Domain Release & Deletion
- [ ] Phase 7: Edge Cases & Error Handling

## Test Results

**Status:** 
- [ ] ✅ Passed
- [ ] ⚠️ Partially Failed
- [ ] ❌ Failed

**Summary:** [Brief result summary]

## What Was Tested

```bash
# Commands executed:
zhtp-cli domain register --domain test1.zhtp
zhtp-cli deploy site ./dist --domain test1.zhtp --keystore ~/.zhtp/keystore
# etc.
```

## Expected vs Actual

**Expected Behavior:**
[What should happen]

**Actual Behavior:**
[What actually happened]

## Environment

- **Platform:** [macOS/Windows/Linux version]
- **Node:** [local/remote - specify IP if remote]
- **Node Version:** [output of `zhtp --version`]
- **CLI Version:** [output of `zhtp-cli --version`]
- **Date Tested:** [YYYY-MM-DD]
- **Tester Name:** [optional]

## Observations

- [What went well]
- [What was confusing]
- [Unexpected behaviors]
- [Performance notes]

## Attached Evidence

- [ ] Screenshots (if UI-related)
- [ ] Command output logs
- [ ] Error messages
- [ ] Network traces (if connectivity issue)

## Bug or Design Issue?

- [ ] Bug: Something is broken
  - If bug, create [BUG] issue with details
- [ ] Design: Behavior is unexpected but working
  - Describe what should change
- [ ] Feature Request: Missing capability
  - Create [FEATURE] issue with details

## Checklist

- [ ] Title includes `[TEST]` prefix
- [ ] Test phase specified
- [ ] Clear pass/fail status
- [ ] Environment documented
- [ ] Evidence included if needed
- [ ] No sensitive data (IPs, keys, etc.)
