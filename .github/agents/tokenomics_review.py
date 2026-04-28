#!/usr/bin/env python3
"""
Tokenomics review agent.

Rules:
- BLOCKER if supply/mint/burn/reserve/treasury/fee/vesting/reward logic
  changed without invariant tests.
- BLOCKER if a fixed supply can be bypassed (e.g. mint without supply cap).
- MAJOR if rounding or decimal-precision logic changed without tests.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

TOKENOMICS_PATTERNS = [
    "tokenomics/**", "treasury/**",
    "contracts/**", "smart-contracts/**", "**/*.sol",
    "**/token*.py", "**/token*.ts", "**/token*.go", "**/token*.rs",
    "**/reward*.py", "**/reward*.ts", "**/reward*.go", "**/reward*.rs",
    "**/vesting*.py", "**/vesting*.ts", "**/vesting*.go", "**/vesting*.rs",
    "**/treasury*.py", "**/treasury*.ts", "**/treasury*.go", "**/treasury*.rs",
]

# Keywords that indicate value-affecting logic
VALUE_KEYWORDS = [
    r"\bmint\b", r"\bburn\b", r"\btotalSupply\b",
    r"\bsupply\b", r"\bmaxSupply\b", r"\bMAX_SUPPLY\b",
    r"\breserve\b", r"\btreasury\b",
    r"\bfee\b", r"\btransferFee\b", r"\bfeeRate\b",
    r"\bvest(ing)?\b", r"\bcliff\b",
    r"\breward\b", r"\bemission\b", r"\binflation\b",
    r"\bbond(ing)?[_ ]?curve\b",
]

ROUNDING_KEYWORDS = [
    r"\bdecimals\b", r"\bDecimal\b",
    r"\bWAD\b", r"\bRAY\b", r"\b1e1[0-9]\b", r"\b1e[2-9]\b",
    r"\bround(?:ing|ed|Down|Up|HalfUp)?\b",
    r"\bmulDiv\b", r"\bfullMul\b",
]

# Patterns that suggest mint without a supply cap check.
UNCAPPED_MINT_RE = re.compile(
    r"function\s+\w*[Mm]int\w*\s*\([^)]*\)[^{]*\{(?:(?!\}).){0,500}",
    re.DOTALL,
)


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="tokenomics",
        status=common.Status.PASS,
        risk_level="medium",
    )

    relevant = common.filter_files(files, TOKENOMICS_PATTERNS)
    if not relevant:
        result.applicable = False
        result.summary = "No tokenomics-relevant files in this PR."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    value_pat = re.compile("|".join(VALUE_KEYWORDS), re.IGNORECASE)
    rounding_pat = re.compile("|".join(ROUNDING_KEYWORDS))

    value_hits: list[tuple[str, int]] = []
    rounding_hits: list[tuple[str, int]] = []
    uncapped_mint_files: list[str] = []

    for f in relevant:
        text = common.read_file_safe(f) or ""
        for m in value_pat.finditer(text):
            value_hits.append((f, text.count("\n", 0, m.start()) + 1))
            break
        for m in rounding_pat.finditer(text):
            rounding_hits.append((f, text.count("\n", 0, m.start()) + 1))
            break

        # Solidity-only check: mint function bodies that never reference a cap.
        if f.endswith(".sol"):
            for body_match in UNCAPPED_MINT_RE.finditer(text):
                body = body_match.group(0)
                # If the function body doesn't mention any cap-like guard,
                # flag it.
                cap_referenced = any(re.search(p, body, re.IGNORECASE) for p in [
                    r"\bMAX_SUPPLY\b", r"\bmaxSupply\b", r"\bcap\(\)",
                    r"\btotalSupply\(\)\s*[<+\-]", r"\bsupplyCap\b",
                    r"require\([^)]*supply",
                ])
                if not cap_referenced:
                    uncapped_mint_files.append(f)
                    break

    if not value_hits:
        result.summary = "Tokenomics-adjacent files changed but no value-affecting keywords detected."
        result.risk_level = "medium"
        common.emit_result(result, files)
        return common.exit_for_status(result)

    result.risk_level = "critical"

    has_tests = common.has_test_changes(files)
    if not has_tests:
        first_f, first_line = value_hits[0]
        result.add(common.Finding(
            severity=common.Severity.BLOCKER,
            title="Token value-affecting logic changed without invariant tests",
            description=(
                "Detected modifications referencing supply, mint, burn, reserve, "
                "treasury, fee, vesting, reward, emission, or bonding-curve "
                "logic — but no tests are touched in this PR."
            ),
            recommendation=(
                "Add invariant and property tests covering: total-supply "
                "conservation, mint/burn accounting, fee accumulation, "
                "vesting schedules, and reward distribution. For Solidity, "
                "Foundry's `invariant_*` tests are recommended."
            ),
            file=first_f,
            line=first_line,
        ))

    if uncapped_mint_files:
        result.add(common.Finding(
            severity=common.Severity.BLOCKER,
            title="Mint function appears to bypass supply cap",
            description=(
                f"Detected mint function(s) in {len(uncapped_mint_files)} "
                "Solidity file(s) whose bodies do not reference `MAX_SUPPLY`, "
                "`maxSupply`, `cap()`, `supplyCap`, or any guard against "
                "exceeding total supply."
            ),
            recommendation=(
                "Add an explicit `require(totalSupply() + amount <= MAX_SUPPLY)` "
                "guard, or document why this mint is unbounded (e.g. a vault "
                "wrapper). Cover with invariant tests."
            ),
            file=uncapped_mint_files[0],
        ))

    if rounding_hits and not has_tests:
        first_f, first_line = rounding_hits[0]
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Rounding/decimal-precision logic changed without tests",
            description=(
                "Code referencing decimals, WAD/RAY, rounding, or mulDiv was "
                "modified but no tests were updated."
            ),
            recommendation=(
                "Add unit tests that exercise edge cases: dust amounts, max "
                "values, and known overflow boundaries. Verify rounding "
                "direction is consistent with system invariants."
            ),
            file=first_f,
            line=first_line,
        ))

    if not result.findings:
        result.summary = (
            f"Tokenomics-relevant changes in {len(relevant)} file(s); "
            "tests are present and no obvious risks detected."
        )
    else:
        result.summary = (
            f"Tokenomics changes in {len(relevant)} file(s); "
            f"{len(result.findings)} concern(s) raised."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
