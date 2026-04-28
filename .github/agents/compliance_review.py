#!/usr/bin/env python3
"""
Compliance review agent.

Rules:
- BLOCKER if KYC/AML/tax/reporting/compensation-sensitive logic changed
  without a compliance note in this PR.
- MAJOR if token compensation, liquidity, stablecoin, fiat off-ramp, or
  securities-sensitive files changed without docs/compliance update.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

KYC_AML_KEYWORDS = [
    r"\bKYC\b", r"\bAML\b", r"\bCFT\b",
    r"\bsanctions?\b", r"\btravel[ _]rule\b",
    r"\btax(?:[ _]report(?:ing)?)?\b", r"\b1099\b",
    r"\bbeneficial[ _]owner\b",
    r"\bcompensation\b", r"\bpayroll\b",
    r"\bcustody\b", r"\bcustodian\b",
]

SECURITIES_KEYWORDS = [
    r"\bsecurit(?:y|ies)\b", r"\bSEC\b", r"\bMiCA\b",
    r"\binvestor[s]?\b", r"\baccredited\b",
    r"\bstablecoin\b", r"\bUSD[CT]\b",
    r"\bfiat\b", r"\boff[ _-]?ramp\b", r"\bon[ _-]?ramp\b",
    r"\bliquidity\b", r"\bdividend\b",
]

COMPLIANCE_DOCS_PATTERNS = [
    "docs/compliance/**",
    "**/COMPLIANCE*",
    "**/compliance.md",
    "**/legal/**",
    "**/regulatory/**",
]


def has_compliance_note(files: list[str]) -> bool:
    return bool(common.filter_files(files, COMPLIANCE_DOCS_PATTERNS))


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="compliance",
        status=common.Status.PASS,
        risk_level="low",
    )

    if not files:
        result.applicable = False
        result.summary = "No changes detected."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    kyc_pat = re.compile("|".join(KYC_AML_KEYWORDS), re.IGNORECASE)
    sec_pat = re.compile("|".join(SECURITIES_KEYWORDS), re.IGNORECASE)

    kyc_hits: list[tuple[str, int]] = []
    sec_hits: list[tuple[str, int]] = []

    code_files = [f for f in files if not common.match_any(f, [
        "**/*.md", "docs/**", "**/*.lock", "**/*.snap",
    ])]

    for f in code_files:
        text = common.read_file_safe(f) or ""
        if not text:
            continue
        for m in kyc_pat.finditer(text):
            kyc_hits.append((f, text.count("\n", 0, m.start()) + 1))
            break
        for m in sec_pat.finditer(text):
            sec_hits.append((f, text.count("\n", 0, m.start()) + 1))
            break

    if not kyc_hits and not sec_hits:
        result.applicable = False
        result.summary = "No compliance-sensitive keywords detected."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    has_note = has_compliance_note(files)

    if kyc_hits:
        result.risk_level = "critical"
        if not has_note:
            first_f, first_line = kyc_hits[0]
            result.add(common.Finding(
                severity=common.Severity.BLOCKER,
                title="KYC/AML/tax/compensation-sensitive change without compliance note",
                description=(
                    f"Detected references to KYC, AML, sanctions, travel-rule, "
                    f"tax/1099, payroll, or custody in {len(kyc_hits)} file(s), "
                    "but this PR does not add or update any document under "
                    "`docs/compliance/`, a `COMPLIANCE.md`, or a `legal/` path."
                ),
                recommendation=(
                    "Add a compliance note under `docs/compliance/` (or update "
                    "an existing one) describing what changed, why, and the "
                    "regulatory context. Tag `@SOVEREIGN-NET/compliance` for "
                    "review."
                ),
                file=first_f,
                line=first_line,
            ))

    if sec_hits:
        if result.risk_level != "critical":
            result.risk_level = "high"
        if not has_note:
            first_f, first_line = sec_hits[0]
            result.add(common.Finding(
                severity=common.Severity.MAJOR,
                title="Securities/stablecoin/fiat-ramp change without docs update",
                description=(
                    "Detected references to securities, stablecoins, fiat "
                    "on/off-ramps, liquidity, dividends, or accredited-investor "
                    "concepts. These often carry regulatory implications."
                ),
                recommendation=(
                    "Update `docs/compliance/` with the regulatory rationale, "
                    "and confirm with `@SOVEREIGN-NET/compliance` whether the "
                    "change requires legal sign-off."
                ),
                file=first_f,
                line=first_line,
            ))

    if not result.findings:
        result.summary = (
            "Compliance-sensitive keywords detected; a compliance note is "
            "present in this PR."
        )
    else:
        result.summary = (
            f"Compliance-sensitive references found; {len(result.findings)} "
            "concern(s) raised."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
