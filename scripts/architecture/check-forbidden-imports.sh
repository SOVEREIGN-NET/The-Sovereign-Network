#!/bin/bash

# Forbidden Imports Checker
# Checks for specific forbidden imports in lib-types and core crates

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "🔍 Checking for forbidden imports..."

STRICT_LIB="lib-types"
CORE_LIBS=("lib-types" "lib-crypto" "lib-proofs")

# Forbidden imports in lib-types
FORBIDDEN_LIB_TYPES_IMPORTS=(
    "use std::fs"
    "use std::net"
    "use std::io"
    "use std::process"
    "use std::env"
    "use tokio::"
    "use reqwest::"
    "use sqlx::"
    "use hyper::"
    "use axum::"
    "use tracing::"
    "use log::"
    "use serde_json"
    "use async_trait"
    "use chrono"
    "use uuid"
    "use rand::"
)

# Forbidden network/IO imports for core libs
FORBIDDEN_CORE_NETWORK_IMPORTS=(
    "use std::net"
    "use reqwest::"
    "use hyper::"
    "use quinn::"
    "use tokio::net"
)

ERRORS_FOUND=0

if [ -d "$STRICT_LIB" ]; then
    echo "📦 Checking $STRICT_LIB..."
    for forbidden in "${FORBIDDEN_LIB_TYPES_IMPORTS[@]}"; do
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                echo "❌ ERROR: Forbidden import found in $STRICT_LIB:"
                echo "   File: $line"
                ERRORS_FOUND=$((ERRORS_FOUND + 1))
            fi
        done < <(grep -rn "$forbidden" "$STRICT_LIB/src" 2>/dev/null || true)
    done
fi

# Check core libs for direct network calls
for crate in "${CORE_LIBS[@]}"; do
    if [ -d "$crate" ]; then
        echo "📦 Checking $crate for network imports..."
        for forbidden in "${FORBIDDEN_CORE_NETWORK_IMPORTS[@]}"; do
            while IFS= read -r line; do
                if [ -n "$line" ]; then
                    echo "❌ ERROR: Network import found in core crate $crate:"
                    echo "   File: $line"
                    ERRORS_FOUND=$((ERRORS_FOUND + 1))
                fi
            done < <(grep -rn "$forbidden" "$crate/src" 2>/dev/null || true)
        done
    fi
done

# Direct filesystem access in lib-types (strict)
if [ -d "$STRICT_LIB" ]; then
    echo "💾 Checking for direct I/O in $STRICT_LIB..."
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            echo "❌ ERROR: Direct file system access found in $STRICT_LIB:"
            echo "   File: $line"
            ERRORS_FOUND=$((ERRORS_FOUND + 1))
        fi
    done < <(grep -rn "File::open\|File::create\|std::fs::" "$STRICT_LIB/src" 2>/dev/null || true)
fi

if [ $ERRORS_FOUND -eq 0 ]; then
    echo "🎉 No forbidden imports found!"
    exit 0
else
    echo "💥 Found $ERRORS_FOUND forbidden import violations!"
    exit 1
fi
