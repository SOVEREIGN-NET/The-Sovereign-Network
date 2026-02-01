# Agent Task List - Casino PRs

**Last Updated:** 2026-02-01 by Opus
**Scope:** ONLY PRs by scasino983/casino

---

## PR Status Summary - ALL PASSING CI

| PR | Branch | CI | Ready |
|----|--------|----|----|
| #1035 | 846-fix-resubmit | PASS | YES |
| #1036 | 878-phase1-resubmit | PASS | YES |
| #1037 | 879-880-phase2-3-resubmit | PASS | YES |
| #1038 | network-tests-resubmit | PASS | YES |
| #1041 | 881-phase4-security-hardening | PASS | YES |
| #1042 | 882-phase5-stress-testing | PASS | YES (Copilot cleaned) |
| #1043 | mesh-dedup-sonarcloud-fix | PASS | YES |

---

## Task for Haiku: Delete Copilot Inline Comments

Delete these Copilot comment IDs using:
```bash
gh api -X DELETE repos/SOVEREIGN-NET/The-Sovereign-Network/pulls/comments/ID
```

**PR #1038:**
2749194078 2749194088 2749194096 2749194102 2749194108 2749194114 2749194118 2749194123 2749194128 2749194133 2749194140 2749194142 2749194146 2749194152 2749194155 2749194158 2749194164 2749194168 2749194172 2749194177

**PR #1041:**
2750062498 2750062518 2750062523 2750062530 2750062536 2750062537 2750062541 2750062545 2750062551 2750062564

**PR #1043:**
2750343201 2750343210 2750343219 2750343230 2750343238

Then remove Copilot as reviewer:
```bash
gh pr edit 1038 1041 1043 --remove-reviewer "copilot-pull-request-reviewer"
```

---

## Completed by Opus

- [x] Fixed #1043 Cargo.lock issue
- [x] Deleted 29 Copilot comments from PRs #1035, #1036, #1037
- [x] Deleted 14 Copilot comments from PR #1042
- [x] Removed Copilot reviewer from #1042
- [x] All PRs marked ready (not draft)
- [x] All PRs passing CI

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
