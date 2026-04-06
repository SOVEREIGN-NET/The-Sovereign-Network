#!/usr/bin/env python3
"""
Testnet reset helper: removes g4 from node configs on g1/g2/g3.
Run this on each node, or run remotely via SSH.

Usage:
  python3 reset-testnet-drop-g4.py /opt/zhtp/config.toml
"""

import sys
import re

G4_IDENTITY = "did:zhtp:15c2a03fb839312c581f041ecb738c9871b290d7bc66c0ceb787e9eeeecf2395"
G4_IP = "77.42.77.183:9334"

def remove_g4(path: str) -> None:
    with open(path, "r") as f:
        lines = f.readlines()

    out = []
    skip = False
    i = 0
    while i < len(lines):
        line = lines[i]

        # Detect start of g4 bootstrap_validator block
        if line.strip() == "[[network.bootstrap_validators]]":
            # Look ahead to check if next identity line is g4
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith("[["):
                if G4_IDENTITY in lines[j]:
                    skip = True
                    break
                j += 1
            if skip:
                # Skip forward until next [[...]] block or end of file
                i += 1
                while i < len(lines):
                    if lines[i].strip().startswith("[["):
                        break
                    i += 1
                skip = False
                continue

        # Remove g4 from bootstrap_peers list
        if "bootstrap_peers" in line and G4_IP in line:
            # Remove the g4 entry from the list
            line = re.sub(r',?\s*"77\.42\.77\.183:9334"', '', line)
            line = re.sub(r'"77\.42\.77\.183:9334",?\s*', '', line)
            # Clean up any trailing comma before ]
            line = re.sub(r',\s*\]', ']', line)

        out.append(line)
        i += 1

    with open(path, "w") as f:
        f.writelines(out)

    print(f"Updated {path}: removed g4 ({G4_IP})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 reset-testnet-drop-g4.py <config.toml>")
        sys.exit(1)
    remove_g4(sys.argv[1])
