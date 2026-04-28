#!/usr/bin/env python3
"""
UX safety review agent.

Rules:
- MAJOR if wallet, seed-phrase, transfer, governance, or other irreversible
  action UX changed without warning copy or tests.
- MAJOR if a user can perform a destructive action without explicit
  confirmation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

UI_PATTERNS = [
    "frontend/**", "web/**", "mobile/**",
    "**/wallet/**", "**/components/**",
]

CRITICAL_UX_KEYWORDS = [
    r"\bwallet\b", r"\bseed[_ ]?phrase\b", r"\bmnemonic\b",
    r"\btransfer\b", r"\bsend\b", r"\bsign(?:[_ ]?Transaction)?\b",
    r"\bvote\b", r"\bdelegate\b", r"\bproposal\b",
    r"\bdelete\b", r"\bremove\b", r"\bdestroy\b",
    r"\brevoke\b", r"\bapprove\b", r"\bunlock\b",
    r"\bwithdraw\b", r"\bredeem\b",
]

CONFIRMATION_HINTS = [
    r"\bconfirm\b", r"\bconfirmation\b",
    r"\bareYouSure\b", r"\bare\s+you\s+sure\b",
    r"\bdouble[_ ]?check\b",
    r"\bdialog\b", r"\bmodal\b",
    r"\bcheckbox\b",
    r"\btype\s+(?:to|the)\s+confirm\b",
]

WARNING_HINTS = [
    r"\bwarning\b", r"\bcaution\b", r"\bdanger\b",
    r"\birreversible\b", r"\bcannot\s+be\s+undone\b",
    r"\bpermanent\b",
]

UI_FILE_EXTS = (".tsx", ".jsx", ".ts", ".js", ".vue", ".svelte", ".swift", ".kt")


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="ux_safety",
        status=common.Status.PASS,
        risk_level="medium",
    )

    relevant = common.filter_files(files, UI_PATTERNS)
    relevant = [f for f in relevant if f.endswith(UI_FILE_EXTS) or f.endswith(".swift")]
    if not relevant:
        result.applicable = False
        result.summary = "No UI/component files in this PR."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    crit_pat = re.compile("|".join(CRITICAL_UX_KEYWORDS), re.IGNORECASE)
    conf_pat = re.compile("|".join(CONFIRMATION_HINTS), re.IGNORECASE)
    warn_pat = re.compile("|".join(WARNING_HINTS), re.IGNORECASE)

    risky_files: list[str] = []
    files_without_confirm: list[str] = []
    files_without_warning: list[str] = []

    for f in relevant:
        text = common.read_file_safe(f) or ""
        if not text:
            continue
        if not crit_pat.search(text):
            continue
        risky_files.append(f)
        if not conf_pat.search(text):
            files_without_confirm.append(f)
        if not warn_pat.search(text):
            files_without_warning.append(f)

    if not risky_files:
        result.applicable = False
        result.summary = "No critical UX surfaces touched."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    has_tests = common.has_test_changes(files)
    if not has_tests:
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Critical UX surface changed without test changes",
            description=(
                f"{len(risky_files)} UI file(s) reference wallet, "
                "seed-phrase, transfer/send, sign, vote, delegate, "
                "withdraw, or delete actions. No UI tests were added or "
                "updated."
            ),
            recommendation=(
                "Add tests covering the irreversible-action flow: confirm "
                "modal renders, button is disabled until typed confirmation "
                "matches, and warning copy is visible."
            ),
            file=risky_files[0],
        ))

    if files_without_warning:
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Irreversible action UI lacks visible warning copy",
            description=(
                f"{len(files_without_warning)} file(s) implement a critical "
                "action but contain no warning / caution / irreversible / "
                "permanent / cannot-be-undone copy."
            ),
            recommendation=(
                "Add explicit warning text near the action button. For "
                "wallet/seed-phrase flows, include 'never share' guidance."
            ),
            file=files_without_warning[0],
        ))

    if files_without_confirm:
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="User can perform destructive action without confirmation",
            description=(
                f"{len(files_without_confirm)} file(s) implement a "
                "destructive or irreversible action without any confirm / "
                "modal / dialog / type-to-confirm pattern."
            ),
            recommendation=(
                "Wrap destructive actions in a confirmation modal. For "
                "high-stakes actions (large transfers, account deletion), "
                "require typing a phrase to confirm."
            ),
            file=files_without_confirm[0],
        ))

    if not result.findings:
        result.summary = (
            f"{len(risky_files)} UX-critical file(s) reviewed; warning copy "
            "and confirmations look intact."
        )
    else:
        result.summary = (
            f"{len(risky_files)} UX-critical file(s) reviewed; "
            f"{len(result.findings)} concern(s) raised."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
