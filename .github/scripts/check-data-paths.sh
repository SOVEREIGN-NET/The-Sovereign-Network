#!/usr/bin/env bash
#
# Forbid CWD-relative data paths in Rust source.
#
# Every persisted-file path must be anchored at `zhtp::node_data_dir()`
# (via `zhtp::node_data_path`) or a configured absolute path. Raw
# `"./data/..."` or `PathBuf::from("./data/...")` literals only work
# by accident of process CWD and break silently otherwise — see the
# POUW budget save regression that produced this guard.
#
# Exclusions: tests (any */tests/** or *_tests.rs path), build output,
# docs, and plans.

set -euo pipefail

# Catch every common CWD-relative form:
#   "./data/..."                            (raw literal)
#   PathBuf::from("./data/...")             (PathBuf ctor)
#   Path::new("./data/...")                 (borrowed Path)
#   std::path::Path::new("./data/...")      (fully-qualified)
#   PathBuf::from_str("./data/...")         (Result-returning ctor)
# The character class `[A-Za-z_:]*` matches optional path prefixes
# (`std::path::`) on Path/PathBuf so qualified forms also trip the guard
# (CR #2660).
hits=$(grep -RInE '"\./data/|(PathBuf|Path)::(from|from_str|new)\("\./data/|[A-Za-z_:]+::Path::new\("\./data/' \
    zhtp/src lib-network/src lib-blockchain/src lib-consensus/src \
  | grep -vE '/tests?/|_tests\.rs|/target/|/docs/|/plans/' \
  || true)

if [ -n "$hits" ]; then
  echo "::error::Forbidden CWD-relative data path literal found."
  echo "Use \`zhtp::node_data_path(\"data/...\")\` instead."
  echo ""
  echo "$hits"
  exit 1
fi

echo "ok — no CWD-relative data path literals in source."
