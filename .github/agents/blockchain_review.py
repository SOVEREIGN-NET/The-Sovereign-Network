#!/usr/bin/env python3
"""
Blockchain review agent.

Rules:
- BLOCKER if chain/contract/token state files changed without tests.
- BLOCKER if nonce/replay/finality/state-transition logic changed without
  explicit tests.
- MAJOR if testnet/mainnet separation is unclear.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

CHAIN_PATTERNS = [
    "contracts/**", "smart-contracts/**",
    "**/*.sol", "**/*.cairo", "**/*.vy",
    "chain/**", "blockchain/**", "consensus/**", "node/**",
]

STATE_TRANSITION_KEYWORDS = [
    r"\bnonce\b", r"\breplay\b", r"\bfinality\b",
    r"\bstate[_ ]?transition\b", r"\bblockHeader\b",
    r"\bvalidate(Block|Tx|Header)\b", r"\bapplyBlock\b",
    r"\bcommit(State|Block)\b", r"\bfork[_ ]?choice\b",
    r"\bconsensus\b",
]

NETWORK_HINTS = [r"\bmainnet\b", r"\btestnet\b", r"\bdevnet\b", r"\bchainId\b", r"\bCHAIN_ID\b"]
HARDCODED_NETWORK_RE = re.compile(
    r"\b(?:chainId|CHAIN_ID)\s*[=:]\s*[0-9]+\b|\b(?:rpcUrl|RPC_URL)\s*[=:]\s*['\"]https?://[^'\"]+['\"]"
)


def main() -> int:
    files = common.get_changed_files()
    result = common.AgentResult(
        agent="blockchain",
        status=common.Status.PASS,
        risk_level="medium",
    )

    chain_files = common.filter_files(files, CHAIN_PATTERNS)
    if not chain_files:
        result.applicable = False
        result.summary = "No chain/contract files in this PR."
        common.emit_result(result, files)
        return common.exit_for_status(result)

    result.risk_level = "critical"

    has_tests = common.has_test_changes(files)
    if not has_tests:
        result.add(common.Finding(
            severity=common.Severity.BLOCKER,
            title="Chain/contract code changed without test changes",
            description=(
                f"{len(chain_files)} chain or contract file(s) were modified, "
                "but no tests were added or updated in this PR."
            ),
            recommendation=(
                "Add unit and/or integration tests covering the modified "
                "behavior. For Solidity, add Foundry/Hardhat tests; for chain "
                "logic, add deterministic state-transition tests."
            ),
            file=chain_files[0],
        ))

    # Look for state-transition / nonce / finality changes specifically.
    state_pat = re.compile("|".join(STATE_TRANSITION_KEYWORDS), re.IGNORECASE)
    state_hits: list[tuple[str, int]] = []
    for f in chain_files:
        text = common.read_file_safe(f) or ""
        for m in state_pat.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            state_hits.append((f, line))
            break  # one per file is enough to flag

    if state_hits and not has_tests:
        first_f, first_line = state_hits[0]
        result.add(common.Finding(
            severity=common.Severity.BLOCKER,
            title="State-transition/nonce/finality code touched without tests",
            description=(
                f"Detected references to state-transition, nonce, replay, or "
                f"finality logic in {len(state_hits)} file(s) without "
                "corresponding tests."
            ),
            recommendation=(
                "Add explicit tests for nonce ordering, replay protection, "
                "and finality invariants. These paths must not regress."
            ),
            file=first_f,
            line=first_line,
        ))

    # Hardcoded network endpoints / chain IDs without network separation
    network_separated = False
    for f in chain_files + common.filter_files(files, ["**/config/**", "**/networks/**"]):
        text = common.read_file_safe(f) or ""
        hint_count = sum(1 for kw in NETWORK_HINTS if re.search(kw, text, re.IGNORECASE))
        if hint_count >= 2:
            network_separated = True
            break

    has_hardcoded = False
    hardcoded_file: str | None = None
    hardcoded_line: int | None = None
    for f in chain_files:
        text = common.read_file_safe(f) or ""
        m = HARDCODED_NETWORK_RE.search(text)
        if m:
            has_hardcoded = True
            hardcoded_file = f
            hardcoded_line = text.count("\n", 0, m.start()) + 1
            break

    if has_hardcoded and not network_separated:
        result.add(common.Finding(
            severity=common.Severity.MAJOR,
            title="Hardcoded network endpoint or chain ID without explicit env separation",
            description=(
                "Found a hardcoded RPC URL or chain ID, but no clear "
                "mainnet/testnet/devnet separation in config files of this PR."
            ),
            recommendation=(
                "Move endpoints/chain IDs into a config layer that distinguishes "
                "mainnet vs. testnet vs. devnet, and reference them by env."
            ),
            file=hardcoded_file or chain_files[0],
            line=hardcoded_line,
        ))

    if not result.findings:
        result.summary = (
            f"{len(chain_files)} chain/contract file(s) changed; tests are "
            "present and no obvious blockchain risks detected."
        )
    else:
        result.summary = (
            f"{len(chain_files)} chain/contract file(s) changed; "
            f"{len(result.findings)} concern(s) raised."
        )

    common.emit_result(result, files)
    return common.exit_for_status(result)


if __name__ == "__main__":
    sys.exit(main())
