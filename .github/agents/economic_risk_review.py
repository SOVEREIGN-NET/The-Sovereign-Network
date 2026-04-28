#!/usr/bin/env python3
"""
Economic risk review agent.

Rules:
- BLOCKER if rewards, fees, curves, treasury, liquidity, or incentives changed
  without simulation or invariant tests.
- MAJOR if spam/Sybil/griefing cost is unclear (no rate-limit, deposit, or
  reputation gate visible in incentive-touching files).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

INCENTIVE_PATTERNS = [
    "tokenomics/**", "treasury/**",
    "**/reward*", "**/incentive*", "**/curve*",
    "**/liquidity*", "**/staking*",
    "contracts/**", "smart-contracts/**", "**/*.sol",
]

ECON_KEYWORDS = [
    r"\breward\b", r"\bincentive\b", r"\bemission\b",
    r"\bfee\b", r"\btreasur(?:y|er)\b",
    r"\bbond(?:ing)?[_ ]?curve\b", r"\bAMM\b",
    r"\bliquidity\b", r"\bstak(?:e|ing)\b",
    r"\bslash(?:ing)?\b",
]

SIM_TEST_PATTERNS = [
    "**/simulations/**", "**/sims/**",
    "**/*invariant*test*", "**/*invariant*spec*",
    "**/*property*test*", "**/*fuzz*test*",
    "**/test/**invariant*", "**/test/**fuzz*",
]

ANTI_ABUSE_HINTS = [
    r"\brate[_ ]?limit\b",
    r"\bcooldown\b",
    r"\bdeposit\b",
    r"\bstake(?:Required)?\b",
    r"\breputation\b",
    r"\bproof[_ ]?of[_ ]?work\b",
    r"\bcaptcha\b",
    r"\bnonce\b",
    r"\bminAmount\b",
    r"\brequire\([^)]*amount\s*>=",
]


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="economic_risk",
        status=common.Status.PASS,
        risk_level="medium",
    )

    relevant = common.filter_files(files, INCENTIVE_PATTERNS)
    if not relevant:
        result.applicable = False
        result.summary = "No incentive-relevant files in this PR."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    econ_pat = re.compile("|".join(ECON_KEYWORDS), re.IGNORECASE)
    abuse_pat = re.compile("|".join(ANTI_ABUSE_HINTS), re.IGNORECASE)

    econ_files: list[str] = []
    files_with_abuse_guard: set[str] = set()

    for f in relevant:
        text = common.read_file_safe(f) or ""
        if econ_pat.search(text):
            econ_files.append(f)
        if abuse_pat.search(text):
            files_with_abuse_guard.add(f)

    if not econ_files:
        result.applicable = False
        result.summary = "No incentive/economic keywords detected in relevant files."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    result.risk_level = "critical"

    has_sim_or_invariant = bool(common.filter_files(files, SIM_TEST_PATTERNS))
    if not has_sim_or_invariant:
        # Allow generic test changes to soften this to MAJOR rather than BLOCKER
        # — but the rule says BLOCKER. Keep it as BLOCKER per spec.
        result.add(common.Finding(
            severity=common.Severity.BLOCKER,
            title="Incentive logic changed without simulation or invariant tests",
            description=(
                f"{len(econ_files)} file(s) reference rewards, fees, curves, "
                "treasury, liquidity, staking, or slashing — but no "
                "simulation, invariant, property, or fuzz tests were added "
                "or updated."
            ),
            recommendation=(
                "Add tests under `tests/invariant/`, `tests/simulations/`, or "
                "`tests/fuzz/` covering: monotonicity of curves, conservation "
                "of value, fee accounting, and edge cases (zero, max, dust)."
            ),
            file=econ_files[0],
        ))

    # Spam/Sybil/griefing cost clarity
    files_without_guard = [f for f in econ_files if f not in files_with_abuse_guard]
    if files_without_guard:
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Spam/Sybil/griefing cost is unclear",
            description=(
                f"{len(files_without_guard)} incentive file(s) do not show "
                "any rate-limit, cooldown, deposit, stake, reputation, or "
                "minimum-amount guard. Cheap-action paths can be exploited."
            ),
            recommendation=(
                "Document the abuse model and add a guard appropriate to the "
                "context (per-actor cooldowns, minimum stake, deposit, or "
                "reputation gate). If the operation is intentionally free, "
                "say so in a comment and explain why the abuse cost is borne "
                "elsewhere."
            ),
            file=files_without_guard[0],
        ))

    if not result.findings:
        result.summary = (
            f"{len(econ_files)} incentive file(s) changed; simulation/"
            "invariant tests present and abuse guards visible."
        )
    else:
        result.summary = (
            f"{len(econ_files)} incentive file(s) changed; "
            f"{len(result.findings)} concern(s) raised."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
