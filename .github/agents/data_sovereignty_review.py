#!/usr/bin/env python3
"""
Data sovereignty review agent.

Rules:
- BLOCKER if database/network config exposes internal DBs publicly.
- MAJOR if migration lacks rollback or data-retention note.
- MAJOR if sensitive data is stored without an encryption mention.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

CONFIG_PATTERNS = [
    "infra/**", "**/k8s/**", "**/kubernetes/**",
    "**/terraform/**", "**/helm/**",
    "**/docker-compose*.yml", "**/Dockerfile*",
    "**/*.tf", "**/*.tfvars",
]

PUBLIC_EXPOSURE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "Service exposes 0.0.0.0",
        re.compile(r"\b0\.0\.0\.0\b"),
    ),
    (
        "Kubernetes Service of type LoadBalancer with DB image",
        re.compile(r"type:\s*LoadBalancer", re.IGNORECASE),
    ),
    (
        "Security group / ingress 0.0.0.0/0",
        re.compile(r"0\.0\.0\.0/0"),
    ),
    (
        "Publicly accessible DB",
        re.compile(r"publicly_accessible\s*=\s*true", re.IGNORECASE),
    ),
]

DB_HINTS = re.compile(
    r"\b(?:postgres|mysql|mariadb|mongodb|redis|elasticsearch|"
    r"cassandra|clickhouse|cockroachdb|neo4j|influxdb)\b",
    re.IGNORECASE,
)

MIGRATION_PATTERNS = [
    "migrations/**", "**/migrations/**", "**/*.migration.sql",
]

ROLLBACK_HINTS = ["down(", "DOWN", "rollback", "BEGIN;", "DROP TABLE IF EXISTS"]
RETENTION_HINTS = ["retention", "ttl", "expires_at", "retain", "purge", "GDPR"]

SENSITIVE_FIELD_PATTERNS = [
    r"\bemail\b", r"\bphone\b", r"\baddress\b",
    r"\bdate_of_birth\b", r"\bdob\b",
    r"\bpassword\b", r"\bpassword_hash\b",
    r"\btoken\b", r"\bseed\b", r"\bmnemonic\b",
    r"\bnational_id\b", r"\btax_id\b", r"\bpassport\b",
    r"\bbiometric\b",
]
ENCRYPTION_HINTS = re.compile(
    r"\b(?:encrypt(?:ed|ion)?|aes|kms|envelope[_ ]?encrypt|"
    r"vault|hsm|argon2|bcrypt|scrypt|pbkdf2)\b",
    re.IGNORECASE,
)


def is_public_exposure(path: str, text: str) -> list[tuple[str, int]]:
    hits: list[tuple[str, int]] = []
    if not DB_HINTS.search(text):
        # Only flag if the same file references a database; otherwise we'd
        # flag every public web ingress.
        return hits
    for label, pat in PUBLIC_EXPOSURE_PATTERNS:
        m = pat.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            hits.append((label, line))
    return hits


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="data_sovereignty",
        status=common.Status.PASS,
        risk_level="medium",
    )

    config_files = common.filter_files(files, CONFIG_PATTERNS)
    migration_files = common.filter_files(files, MIGRATION_PATTERNS)
    code_files = [f for f in files if common.match_any(f, [
        "**/*.py", "**/*.go", "**/*.ts", "**/*.tsx", "**/*.js",
        "**/*.rs", "**/*.java", "**/*.kt",
    ])]

    if not config_files and not migration_files and not code_files:
        result.applicable = False
        result.summary = "No infra/migration/code files in this PR."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    # 1) Public DB exposure
    for f in config_files:
        text = common.read_file_safe(f) or ""
        if not text:
            continue
        for label, line in is_public_exposure(f, text):
            result.add(common.Finding(
                severity=common.Severity.BLOCKER,
                title=f"Internal database may be publicly exposed: {label}",
                description=(
                    "This config file references a database service AND a "
                    "public-network exposure pattern (0.0.0.0, 0.0.0.0/0, "
                    "publicly_accessible, or LoadBalancer)."
                ),
                recommendation=(
                    "Bind databases to private networks only. Use ClusterIP, "
                    "private subnets, or VPC-internal endpoints. Front "
                    "user-facing services with an explicit, audited proxy."
                ),
                file=f,
                line=line,
            ))

    # 2) Migration rollback / retention
    for f in migration_files:
        text = common.read_file_safe(f) or ""
        has_rollback = any(h in text for h in ROLLBACK_HINTS)
        has_retention = any(h.lower() in text.lower() for h in RETENTION_HINTS)
        if not has_rollback:
            result.add(common.Finding(
                severity=common.Severity.MAJOR,
                title="Migration lacks visible rollback / down step",
                description=(
                    "This migration does not contain a `down(`, `DOWN`, "
                    "`rollback`, or equivalent reverse step."
                ),
                recommendation=(
                    "Add a reverse migration that restores the prior schema "
                    "state, or document why the change is irreversible."
                ),
                file=f,
            ))
        if not has_retention and re.search(r"CREATE\s+TABLE", text, re.IGNORECASE):
            result.add(common.Finding(
                severity=common.Severity.MAJOR,
                title="New table without data-retention note",
                description=(
                    "A new table is created but no retention/TTL/expiry "
                    "field or note is visible in the migration."
                ),
                recommendation=(
                    "Document the retention policy for this table (or add "
                    "an `expires_at` / TTL column where appropriate). "
                    "Reference your data-retention policy in `docs/`."
                ),
                file=f,
            ))

    # 3) Sensitive fields stored without encryption mention
    sens_pat = re.compile("|".join(SENSITIVE_FIELD_PATTERNS), re.IGNORECASE)
    suspect_files: list[str] = []
    for f in migration_files + code_files:
        text = common.read_file_safe(f) or ""
        if not text:
            continue
        # Only inspect files that look like persistence or schema definitions.
        looks_like_persistence = (
            "schema" in f.lower()
            or "model" in f.lower()
            or f.endswith((".sql", ".prisma", ".graphql"))
            or re.search(r"\bCREATE\s+TABLE\b", text, re.IGNORECASE)
            or re.search(r"\bclass\s+\w+\(.*Model.*\)", text)
        )
        if not looks_like_persistence:
            continue
        if sens_pat.search(text) and not ENCRYPTION_HINTS.search(text):
            suspect_files.append(f)
    for f in suspect_files[:5]:  # cap noise
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Sensitive field persisted without visible encryption",
            description=(
                "This file appears to define schema/models containing "
                "sensitive fields (email, phone, address, password, token, "
                "etc.) but does not reference encryption (AES, KMS, Vault, "
                "argon2/bcrypt/scrypt/pbkdf2)."
            ),
            recommendation=(
                "Encrypt sensitive columns at rest (envelope encryption with "
                "KMS), hash secrets with Argon2id/bcrypt, and document the "
                "approach in `docs/security/`."
            ),
            file=f,
        ))

    if not result.findings:
        result.summary = (
            f"Inspected {len(config_files)} config + {len(migration_files)} "
            "migration file(s); no data-sovereignty issues detected."
        )
    else:
        result.summary = f"{len(result.findings)} data-sovereignty concern(s) raised."

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
