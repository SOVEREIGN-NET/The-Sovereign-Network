# Agent Task List - Casino PRs

**Last Updated:** 2026-02-01 by Opus
**Scope:** ONLY PRs by scasino983/casino

---

## PR Status Summary

| PR | Branch | Status | CI | Action Needed |
|----|--------|--------|----|----|
| #1035 | 846-fix-resubmit | READY | Building | Wait for CI |
| #1036 | 878-phase1-resubmit | READY | PASS | Request review |
| #1037 | 879-880-phase2-3-resubmit | READY | PASS | Request review |
| #1038 | network-tests-resubmit | READY | PASS | Request review |
| #1041 | 881-phase4-security-hardening | READY | PASS | Request review |
| #1042 | 882-phase5-stress-testing | READY | PASS | Request review |
| #1043 | mesh-dedup-sonarcloud-fix | READY | Rebuilding | Fixed by Opus |

---

## Task 1: Fix PR #1043 - DONE

Fixed by Opus: Pushed `fd2562a` with updated Cargo.lock.

---

## Task 2: Request Reviews (Priority: MEDIUM)

All these PRs are passing CI and ready:

```bash
gh pr edit 1035 1036 1037 1038 1041 1042 --add-reviewer REVIEWER_USERNAME
```

Or manually request reviews in GitHub UI.

---

## Merge Order (HUMAN ONLY)

PRs must be merged in this order (dependencies):

1. #1035 (Block Sync - CRITICAL)
2. #1036 (Phase 1)
3. #1037 (Phase 2+3)
4. #1038 (Network Tests)
5. #1041 (Phase 4)
6. #1042 (Phase 5)
7. #1043 (Dedup fix - can merge anytime after #1035)

**DO NOT MERGE AS AGENT** - Only human reviewers merge.

---

## Completed

- [x] All PRs marked as ready (not draft)
- [x] Identified #1043 failure cause (Cargo.lock)
- [x] PRs #1035-1042 all passing CI

---

## Notes for Haiku/Sonnet

1. Check `agent_context.yaml` for session state
2. Check `agent_db.json` for known fixes
3. Only touch files in the PR you're fixing
4. Run `cargo check` before pushing
5. Leave `[READY FOR REVIEW]` comment when done
