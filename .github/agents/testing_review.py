#!/usr/bin/env python3
"""
Testing review agent.

Rules:
- BLOCKER for critical PRs without relevant tests.
- MAJOR if only snapshots changed for logic changes.
- MINOR if coverage appears reduced (heuristic: more code added than tests).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

CODE_PATTERNS = [
    "**/*.py", "**/*.go", "**/*.rs", "**/*.ts", "**/*.tsx",
    "**/*.js", "**/*.jsx", "**/*.sol", "**/*.java", "**/*.kt",
    "**/*.swift", "**/*.cpp", "**/*.c", "**/*.h",
]

TEST_PATTERNS = [
    "**/tests/**", "**/test/**",
    "**/test_*.py", "**/*_test.go",
    "**/*.test.ts", "**/*.test.tsx", "**/*.test.js",
    "**/*.spec.ts", "**/*.spec.tsx", "**/*.spec.js",
    "**/*.t.sol",
]

SNAPSHOT_PATTERNS = [
    "**/__snapshots__/**", "**/*.snap",
]


def is_test_file(f: str) -> bool:
    return common.match_any(f, TEST_PATTERNS)


def is_snapshot(f: str) -> bool:
    return common.match_any(f, SNAPSHOT_PATTERNS)


def is_code_file(f: str) -> bool:
    return common.match_any(f, CODE_PATTERNS) and not is_test_file(f) and not is_snapshot(f)


def main() -> int:
    files = common.get_changed_files()
    policy = common.load_policy()
    result = common.AgentResult(
        agent="testing",
        status=common.Status.PASS,
        risk_level="low",
    )

    if not files:
        result.applicable = False
        result.summary = "No changes detected."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    risk = common.aggregate_risk_level(common.applicable_rules(files, policy))
    result.risk_level = risk

    code_files = [f for f in files if is_code_file(f)]
    test_files = [f for f in files if is_test_file(f)]
    snap_files = [f for f in files if is_snapshot(f)]

    if not code_files and not test_files and not snap_files:
        result.applicable = False
        result.summary = "No code or test files in this PR."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    needs_tests = common.requires_tests(files, policy) or risk in ("high", "critical")

    if needs_tests and not test_files:
        result.add(common.Finding(
            severity=common.Severity.BLOCKER,
            title=f"{risk.title()}-risk PR has no test changes",
            description=(
                f"This PR is classified `{risk}` but no test files were "
                "added or updated."
            ),
            recommendation=(
                "Add tests covering the changed behavior. For critical "
                "subsystems (chain, contracts, tokenomics, governance, "
                "identity), include invariant or property tests."
            ),
            file=code_files[0] if code_files else files[0],
        ))

    if snap_files and code_files and not test_files:
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Logic changes covered only by snapshot updates",
            description=(
                f"{len(code_files)} code file(s) changed alongside "
                f"{len(snap_files)} snapshot file(s), but no actual test "
                "code was added or updated. Snapshots auto-update without "
                "asserting intent."
            ),
            recommendation=(
                "Add explicit assertions describing what the new behavior "
                "should be, not just what it currently is."
            ),
            file=code_files[0],
        ))

    # Coverage-reduction heuristic: count added lines in code vs. test files.
    # Use git numstat — works without external coverage tooling.
    if code_files and test_files:
        try:
            base = common._resolve_base_ref()
            if base:
                rc, out, _ = common._run([
                    "git", "diff", "--numstat", f"{base}...HEAD",
                ])
                if rc == 0:
                    code_added = 0
                    test_added = 0
                    for line in out.splitlines():
                        parts = line.split("\t")
                        if len(parts) != 3:
                            continue
                        added_str, _, p = parts
                        if added_str == "-":
                            continue
                        try:
                            added = int(added_str)
                        except ValueError:
                            continue
                        if is_test_file(p):
                            test_added += added
                        elif is_code_file(p):
                            code_added += added
                    # Heuristic: if code grows by >100 lines and tests by <10% of that.
                    if code_added > 100 and test_added < max(10, code_added // 10):
                        result.add(common.Finding(
                            severity=common.Severity.MINOR,
                            title="Test growth lags behind code growth",
                            description=(
                                f"This PR adds ~{code_added} lines of code "
                                f"and only ~{test_added} lines of tests. "
                                "Coverage likely decreased."
                            ),
                            recommendation=(
                                "Add more tests for the new code paths. "
                                "Consider running coverage locally and "
                                "comparing to base."
                            ),
                        ))
        except Exception as e:  # noqa: BLE001
            print(f"[testing] numstat heuristic skipped: {e}", file=sys.stderr)

    if not result.findings:
        result.summary = (
            f"{len(code_files)} code + {len(test_files)} test file(s) "
            "changed; testing posture looks healthy."
        )
    else:
        result.summary = (
            f"{len(code_files)} code + {len(test_files)} test file(s) "
            f"changed; {len(result.findings)} concern(s) raised."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
