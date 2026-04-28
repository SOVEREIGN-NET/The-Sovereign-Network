#!/usr/bin/env python3
"""
Privacy / ZK-DID review agent.

Rules:
- BLOCKER if raw biometric, private identity, seed phrase, or sensitive PII
  appears to be logged or stored.
- MAJOR if identity-linking behavior changed without a privacy note.
- MAJOR if zk-proof verification code changed without tests.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

PRIVACY_PATTERNS = [
    "identity/**", "zk/**",
    "**/zkdid/**", "**/*zk*proof*", "**/*zkproof*",
    "**/did/**", "**/credential*",
]

# Sensitive identifiers that should never appear in logs / persistent stores.
SENSITIVE_TERMS = [
    "seed_phrase", "seedPhrase", "seed phrase",
    "mnemonic",
    "private_key", "privateKey", "priv_key", "privKey",
    "biometric", "fingerprint_template", "face_template", "iris_template",
    "passport_number", "passportNumber",
    "ssn", "social_security",
    "national_id", "nationalId", "tax_id", "taxId",
    "DNIe", "eIDAS",
    "dateOfBirth", "date_of_birth",
]

LOG_OR_STORE_RE = re.compile(
    r"\b(?:log(?:ger)?\.(?:debug|info|warn|error|trace)|console\.(?:log|info|warn|error|debug)|"
    r"println!|fmt\.(?:Print|Println|Printf)|System\.out\.print|"
    r"db\.(?:save|insert|set|put)|redis\.(?:set|hset)|kv\.put|"
    r"localStorage\.setItem|AsyncStorage\.setItem|UserDefaults)",
    re.IGNORECASE,
)

ZK_VERIFY_RE = re.compile(
    r"\b(?:verifyProof|verify_proof|Groth16Verify|PlonkVerify|"
    r"snark[Vv]erify|verifier\.(?:verify|check))\b"
)

LINKING_KEYWORDS = [
    r"\blink(?:ed|ing)?[_ ]?identit(?:y|ies)\b",
    r"\bcorrelat(?:e|ion|ed)\b",
    r"\bdeanonymi(?:s|z)e\b",
    r"\bglobal[_ ]?identifier\b",
    r"\bcross[_ ]?reference\b",
]

PRIVACY_DOC_PATTERNS = [
    "docs/privacy/**",
    "**/PRIVACY*",
    "**/privacy.md",
    "docs/**/privacy*.md",
]


def has_privacy_note(files: list[str]) -> bool:
    return bool(common.filter_files(files, PRIVACY_DOC_PATTERNS))


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="privacy_zkdid",
        status=common.Status.PASS,
        risk_level="medium",
    )

    relevant = common.filter_files(files, PRIVACY_PATTERNS)
    if not relevant and not files:
        result.applicable = False
        result.summary = "No changes detected."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    # We also scan general code for sensitive PII appearing in logs/stores —
    # not only identity/ paths.
    text_files = [f for f in files if common.match_any(f, [
        "**/*.py", "**/*.js", "**/*.ts", "**/*.tsx", "**/*.jsx",
        "**/*.go", "**/*.rs", "**/*.swift", "**/*.kt", "**/*.java",
        "**/*.sol",
    ])]

    sensitive_lower = [s.lower() for s in SENSITIVE_TERMS]

    pii_findings: list[tuple[str, int, str, str]] = []
    for f in text_files:
        text = common.read_file_safe(f) or ""
        if not text:
            continue
        lower_text = text.lower()
        # Quick reject: only do per-line scan if any sensitive term is present.
        if not any(term in lower_text for term in sensitive_lower):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            ll = line.lower()
            for term in sensitive_lower:
                if term in ll and LOG_OR_STORE_RE.search(line):
                    pii_findings.append((f, i, term, line.strip()[:160]))
                    break

    for f, line_no, term, snippet in pii_findings:
        result.add(common.Finding(
            severity=common.Severity.BLOCKER,
            title=f"Sensitive identifier `{term}` in a logging or persistence call",
            description=(
                "A sensitive identifier appears on the same line as a log "
                "or storage call. This is a high-risk pattern for leaking "
                "PII, biometrics, or key material.\n\n"
                f"```\n{snippet}\n```"
            ),
            recommendation=(
                "Never log or store raw sensitive identifiers. Hash, redact, "
                "or replace with an opaque reference. If transient handling "
                "is genuinely required, document it in `docs/privacy/`."
            ),
            file=f,
            line=line_no,
        ))

    # ZK proof verification touched without tests
    zk_files = []
    for f in relevant:
        text = common.read_file_safe(f) or ""
        if ZK_VERIFY_RE.search(text):
            zk_files.append(f)
    if zk_files and not common.has_test_changes(files):
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="ZK proof verification code changed without test changes",
            description=(
                f"{len(zk_files)} file(s) reference proof verification "
                "(verifyProof / Groth16Verify / PlonkVerify / verifier.verify) "
                "but no tests were updated."
            ),
            recommendation=(
                "Add tests covering valid proofs, invalid proofs, malformed "
                "inputs, and known edge cases. Verifier code must not regress."
            ),
            file=zk_files[0],
        ))

    # Identity-linking behavior changed without privacy note
    linking_pat = re.compile("|".join(LINKING_KEYWORDS), re.IGNORECASE)
    linking_hits: list[str] = []
    for f in relevant:
        text = common.read_file_safe(f) or ""
        if linking_pat.search(text):
            linking_hits.append(f)
    if linking_hits and not has_privacy_note(files):
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Identity-linking behavior changed without a privacy note",
            description=(
                f"References to identity linking, correlation, or "
                f"deanonymization detected in {len(linking_hits)} file(s), "
                "with no privacy doc updated in this PR."
            ),
            recommendation=(
                "Add or update `docs/privacy/` describing what gets linked, "
                "under what authority, and how the user is informed."
            ),
            file=linking_hits[0],
        ))

    if relevant:
        result.risk_level = "critical"

    if not result.findings:
        if relevant:
            result.summary = (
                f"{len(relevant)} privacy/ZK file(s) changed; no obvious "
                "privacy regressions detected."
            )
        else:
            result.applicable = False
            result.summary = "No privacy-relevant code paths changed."
    else:
        result.summary = (
            f"{len(result.findings)} privacy/ZK concern(s) raised."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
