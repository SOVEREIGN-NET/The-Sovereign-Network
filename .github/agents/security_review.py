#!/usr/bin/env python3
"""
Security review agent.

Rules:
- BLOCKER on committed secrets/private keys/tokens.
- BLOCKER on unsafe eval/exec/deserialization patterns.
- BLOCKER on workflow using `pull_request_target`.
- MAJOR on broad GitHub Actions permissions like `contents: write` unless
  justification is present in a comment in the same file.
- MAJOR on disabled TLS / certificate verification.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

# --------------------------------------------------------------------------- #
# Pattern catalogs
# --------------------------------------------------------------------------- #

# High-confidence secret patterns. These are intentionally conservative; the
# goal is to surface obvious mistakes, not run a full secret-scanner.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key id",          re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS secret access key",      re.compile(r"(?i)aws(.{0,20})?(secret|sk)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9/+=]{40}[\"']")),
    ("GitHub token (ghp_/gho_/...)", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token",                re.compile(r"\bxox[abp]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key",             re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe live key",            re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("PEM private key block",      re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("BIP-39 mnemonic header",     re.compile(r"(?im)^\s*(mnemonic|seed[_ ]?phrase)\s*[:=]\s*['\"]([a-z]+\s+){11,23}[a-z]+['\"]")),
    ("Hex private key (32 bytes)", re.compile(r"(?i)(?:private[_ ]?key|priv[_ ]?key)\s*[:=]\s*[\"']?(0x)?[a-f0-9]{64}[\"']?")),
    ("JWT-shaped token",           re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("Generic API key assignment", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{24,}[\"']")),
]

# Files we never scan for secrets to avoid endless false positives.
SECRET_SKIP_PATTERNS = [
    "**/*.lock",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/Cargo.lock",
    "**/poetry.lock",
    "**/go.sum",
    "**/*.min.js",
    "**/*.snap",
    "**/dist/**",
    "**/build/**",
    "**/node_modules/**",
    "**/vendor/**",
    "**/test*/fixtures/**",
    "**/fixtures/**",
    "**/__snapshots__/**",
    "**/*.test.*",
    "**/*.spec.*",
    "docs/**",
    "**/*.md",
]

# Source-code patterns we treat as text candidates for secret + dangerous-pattern scanning.
TEXT_CODE_PATTERNS = [
    "**/*.py", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx",
    "**/*.go", "**/*.rs", "**/*.sol", "**/*.java", "**/*.kt",
    "**/*.swift", "**/*.rb", "**/*.cs", "**/*.cpp", "**/*.c", "**/*.h",
    "**/*.yaml", "**/*.yml", "**/*.json", "**/*.toml", "**/*.env*",
    "**/*.sh", "**/*.bash", "**/*.zsh", "**/*.cfg", "**/*.ini",
    "**/.env*", "**/Dockerfile*", "**/Makefile*",
]

# Dangerous code patterns
DANGEROUS_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "Python eval()/exec() on dynamic input",
        re.compile(r"\b(?:eval|exec)\s*\([^)]*(?:input|request|argv|environ|stdin)"),
        "BLOCKER",
        "Eval/exec on user-controlled input enables arbitrary code execution.",
    ),
    (
        "Python pickle.load on untrusted input",
        re.compile(r"\bpickle\.(?:load|loads)\s*\("),
        "BLOCKER",
        "`pickle` is unsafe for deserializing data from untrusted sources.",
    ),
    (
        "PyYAML unsafe load",
        re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*[A-Za-z_]*Safe)"),
        "BLOCKER",
        "`yaml.load` without `SafeLoader` allows arbitrary object construction.",
    ),
    (
        "Java/Python ObjectInputStream / Marshal.load",
        re.compile(r"\b(?:ObjectInputStream|Marshal\.load|jsonpickle\.decode)\b"),
        "BLOCKER",
        "Native deserialization of untrusted data is a known RCE vector.",
    ),
    (
        "JavaScript eval()",
        re.compile(r"(?<!\w)eval\s*\("),
        "MAJOR",
        "Avoid `eval()` in JS/TS; it complicates auditing and enables injection.",
    ),
    (
        "child_process exec with template literal",
        re.compile(r"\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*`[^`]*\$\{"),
        "MAJOR",
        "Shell-style exec with interpolated strings is a command-injection risk.",
    ),
    (
        "Disabled TLS verification (Python requests)",
        re.compile(r"verify\s*=\s*False"),
        "MAJOR",
        "TLS verification disabled — disables MITM protection.",
    ),
    (
        "Disabled TLS verification (curl/wget)",
        re.compile(r"\bcurl\b[^|;\n]*\s(-k|--insecure)\b|\bwget\b[^|;\n]*\s--no-check-certificate\b"),
        "MAJOR",
        "TLS verification disabled in shell command.",
    ),
    (
        "Disabled TLS verification (Node/Go)",
        re.compile(r"rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true"),
        "MAJOR",
        "TLS verification disabled in client config.",
    ),
    (
        "MD5/SHA1 used for security",
        re.compile(r"\b(?:hashlib\.md5|hashlib\.sha1|crypto\.createHash\(['\"]md5['\"]\)|crypto\.createHash\(['\"]sha1['\"]\))"),
        "MINOR",
        "MD5/SHA-1 are broken for security uses; verify this is non-security context.",
    ),
]

# Workflow-specific checks
WORKFLOW_PATTERNS = ["**/.github/workflows/*.yml", "**/.github/workflows/*.yaml",
                    ".github/workflows/*.yml", ".github/workflows/*.yaml"]


def is_skipped(path: str) -> bool:
    return common.match_any(path, SECRET_SKIP_PATTERNS)


def scan_secrets(path: str, text: str) -> list[common.Finding]:
    findings: list[common.Finding] = []
    for label, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append(common.Finding(
                severity=common.Severity.BLOCKER,
                title=f"Possible committed secret: {label}",
                description=(
                    f"A pattern matching `{label}` was found in this file. "
                    "Even if it is a placeholder, committing real secrets must "
                    "be assumed when patterns match these formats."
                ),
                recommendation=(
                    "Remove the value, rotate the credential, and load it from "
                    "a secret manager or `${{ secrets.* }}` in CI. Add the file "
                    "or pattern to `.gitignore` if appropriate."
                ),
                file=path,
                line=line_no,
            ))
    return findings


def scan_dangerous(path: str, text: str) -> list[common.Finding]:
    findings: list[common.Finding] = []
    for title, pat, sev_str, why in DANGEROUS_PATTERNS:
        for m in pat.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append(common.Finding(
                severity=common.Severity(sev_str),
                title=title,
                description=why,
                recommendation=(
                    "Review this call site. If unavoidable, document the "
                    "justification inline and ensure inputs are validated."
                ),
                file=path,
                line=line_no,
            ))
    return findings


def scan_workflow(path: str, text: str) -> list[common.Finding]:
    findings: list[common.Finding] = []

    # pull_request_target is a hard rule per project policy.
    if re.search(r"^\s*pull_request_target\s*:", text, re.MULTILINE):
        findings.append(common.Finding(
            severity=common.Severity.BLOCKER,
            title="Workflow uses `pull_request_target`",
            description=(
                "`pull_request_target` runs in the context of the base repo "
                "with read/write secrets and the base ref's workflow file. "
                "Combined with checkout of PR head, it is a well-known "
                "exploit path. Project policy forbids it."
            ),
            recommendation=(
                "Use `pull_request` (and `merge_group` for required-check "
                "compatibility) instead. If you need post-merge actions, run "
                "them on `push` to the protected branch."
            ),
            file=path,
        ))

    # Broad permissions check
    perm_block = re.search(r"^permissions\s*:\s*\n((?:\s+\S.*\n)+)",
                           text, re.MULTILINE)
    broad_perms = ("contents: write", "packages: write", "id-token: write",
                   "actions: write", "deployments: write", "pull-requests: write")
    if "permissions: write-all" in text:
        findings.append(common.Finding(
            severity=common.Severity.MAJOR,
            title="Workflow grants `permissions: write-all`",
            description="This grants every scope, vastly expanding blast radius if a step is compromised.",
            recommendation="Replace with a minimal, explicit `permissions:` block (read-only by default).",
            file=path,
        ))
    elif perm_block:
        block = perm_block.group(1)
        for bp in broad_perms:
            if bp in block:
                # Allow if a comment justifying it is on the same line or the line above.
                m = re.search(rf"^.*{re.escape(bp)}.*$", block, re.MULTILINE)
                snippet = m.group(0) if m else ""
                if "#" in snippet and "justif" in snippet.lower():
                    continue
                findings.append(common.Finding(
                    severity=common.Severity.MAJOR,
                    title=f"Broad workflow permission: `{bp}`",
                    description=(
                        f"`{bp}` expands the GITHUB_TOKEN's authority. With no "
                        "inline justification comment, this should be tightened."
                    ),
                    recommendation=(
                        f"Remove `{bp}` if not needed, or add a comment on the "
                        "same line starting with `# justification:` explaining why."
                    ),
                    file=path,
                ))

    # No permissions block at all on a non-trivial workflow
    if not perm_block and "permissions:" not in text:
        findings.append(common.Finding(
            severity=common.Severity.MINOR,
            title="Workflow has no `permissions:` block",
            description="Without an explicit block, GITHUB_TOKEN inherits the repo-default permissions.",
            recommendation="Add an explicit `permissions:` block scoped to read-only by default.",
            file=path,
        ))

    return findings


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="security",
        status=common.Status.PASS,
        risk_level="medium",
    )

    if not files:
        result.applicable = False
        result.summary = "No changes detected."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    scanned = 0
    for f in files:
        if is_skipped(f):
            continue
        text = common.read_file_safe(f)
        if text is None:
            continue
        scanned += 1

        if common.match_any(f, TEXT_CODE_PATTERNS) or "/.env" in f or f.endswith(".env"):
            for finding in scan_secrets(f, text):
                result.add(finding)
            for finding in scan_dangerous(f, text):
                result.add(finding)

        if common.match_any(f, WORKFLOW_PATTERNS) or f.startswith(".github/workflows/"):
            for finding in scan_workflow(f, text):
                result.add(finding)

    if any(common.match_any(f, [
        "contracts/**", "smart-contracts/**", "**/*.sol",
        "identity/**", "zk/**", "tokenomics/**", "treasury/**",
        "governance/**", "infra/prod/**", "migrations/**",
    ]) for f in files):
        result.risk_level = "critical"

    if not result.findings:
        result.summary = f"Scanned {scanned} file(s); no security issues detected."
    else:
        result.summary = (
            f"Scanned {scanned} file(s); found {len(result.findings)} issue(s)."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
