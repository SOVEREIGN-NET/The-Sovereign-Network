#!/usr/bin/env python3
"""
Governance review agent.

Rules:
- BLOCKER if proposal execution, quorum, delegation, voting power, emergency
  powers, or admin permissions changed without governance tests.
- MAJOR if emergency powers lack a time limit or audit log.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

GOV_PATTERNS = [
    "governance/**", "dao/**",
    "**/Governor*.sol", "**/Governance*.sol",
    "**/Timelock*.sol", "**/Voting*.sol",
    "**/governance*.py", "**/governance*.ts", "**/governance*.go", "**/governance*.rs",
]

GOV_KEYWORDS = [
    r"\bquorum\b", r"\bdelegat(?:e|ion|ed)\b",
    r"\bvotingPower\b", r"\bvoting[_ ]power\b",
    r"\bproposal[_ ]?(?:execute|execution|threshold)?\b",
    r"\bexecute(?:Proposal|Transaction)?\b",
    r"\bemergency\b", r"\bpause\b", r"\bunpause\b", r"\bguardian\b",
    r"\bonlyOwner\b", r"\bonlyAdmin\b", r"\bDEFAULT_ADMIN_ROLE\b",
    r"\baccessControl\b", r"\bgrantRole\b", r"\brevokeRole\b",
]

EMERGENCY_KEYWORDS = [
    r"\bemergency\b", r"\bpanic\b",
    r"\bpause\b", r"\bunpause\b",
    r"\bguardian\b",
]

TIME_LIMIT_HINTS = [
    r"\bdeadline\b", r"\bexpir(?:y|es?|ation)\b",
    r"\btimelock\b", r"\bblock\.timestamp\s*[<+]",
    r"\bduration\b", r"\bMAX[_ ]?DURATION\b",
]

AUDIT_LOG_HINTS = [
    r"\bemit\s+\w*Emergency\w*",
    r"\bevent\s+\w*Emergency\w*",
    r"\bemit\s+\w*Pause\w*",
    r"\baudit[_ ]?log\b",
]


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="governance",
        status=common.Status.PASS,
        risk_level="medium",
    )

    relevant = common.filter_files(files, GOV_PATTERNS)
    # Also catch role/admin changes anywhere in solidity contracts.
    contract_files = common.filter_files(files, ["**/*.sol", "contracts/**", "smart-contracts/**"])

    gov_pat = re.compile("|".join(GOV_KEYWORDS), re.IGNORECASE)

    candidate_files = list(set(relevant + contract_files))
    gov_hit_files: list[str] = []
    for f in candidate_files:
        text = common.read_file_safe(f) or ""
        if gov_pat.search(text):
            gov_hit_files.append(f)

    if not gov_hit_files:
        result.applicable = False
        result.summary = "No governance-relevant code changes detected."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    result.risk_level = "critical"

    # Tests required
    if not common.has_test_changes(files):
        result.add(common.Finding(
            severity=common.Severity.BLOCKER,
            title="Governance/admin logic changed without tests",
            description=(
                f"{len(gov_hit_files)} file(s) reference quorum, delegation, "
                "voting power, proposal execution, emergency powers, or admin "
                "roles, but no tests were added or updated."
            ),
            recommendation=(
                "Add tests for: quorum thresholds, vote counting, delegation "
                "transitions, proposal lifecycle, role grants/revokes, and "
                "any timelock or emergency path."
            ),
            file=gov_hit_files[0],
        ))

    # Emergency powers without time limits or audit logs
    em_pat = re.compile("|".join(EMERGENCY_KEYWORDS), re.IGNORECASE)
    time_pat = re.compile("|".join(TIME_LIMIT_HINTS), re.IGNORECASE)
    audit_pat = re.compile("|".join(AUDIT_LOG_HINTS))

    for f in gov_hit_files:
        text = common.read_file_safe(f) or ""
        if not em_pat.search(text):
            continue
        has_time = bool(time_pat.search(text))
        has_audit = bool(audit_pat.search(text))
        if not has_time:
            result.add(common.Finding(
                severity=common.Severity.MAJOR,
                title="Emergency power without visible time limit",
                description=(
                    "This file references emergency / pause / guardian powers "
                    "but does not appear to bound them in time (no deadline, "
                    "expiration, timelock, or duration)."
                ),
                recommendation=(
                    "Add an explicit time limit (e.g. `MAX_PAUSE_DURATION`) "
                    "and document the rationale in the governance docs."
                ),
                file=f,
            ))
        if not has_audit:
            result.add(common.Finding(
                severity=common.Severity.MAJOR,
                title="Emergency power without visible audit-log emission",
                description=(
                    "Emergency or pause logic was modified but no event "
                    "emission or audit-log entry is visible in the file."
                ),
                recommendation=(
                    "Emit a dedicated event whenever emergency powers are "
                    "exercised, including the actor, reason, and timestamp."
                ),
                file=f,
            ))

    if not result.findings:
        result.summary = (
            f"{len(gov_hit_files)} governance file(s) changed; tests are "
            "present and emergency-power constraints look intact."
        )
    else:
        result.summary = (
            f"{len(gov_hit_files)} governance file(s) changed; "
            f"{len(result.findings)} concern(s) raised."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
