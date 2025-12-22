#!/bin/bash

# Forbidden Imports Checker
# Checks for specific forbidden imports in lib-types and core crates

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "🔍 Checking for forbidden imports..."

workspace_libs() {
    awk '
        BEGIN { in_members = 0 }
        /^members[[:space:]]*=[[:space:]]*\\[/ { in_members = 1; next }
        in_members && /\\]/ { in_members = 0 }
        in_members {
            gsub(/"/, "", $0)
            gsub(/,/, "", $0)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
            if ($0 ~ /^lib-/) print $0
        }
    ' Cargo.toml
}

ALL_LIBS=($(workspace_libs))
STRICT_LIB="lib-types"
PURE_LIBS=("lib-crypto" "lib-proofs" "lib-identity")
IO_ALLOWED_LIBS=("lib-blockchain" "lib-consensus" "lib-dht" "lib-dns" "lib-economy" "lib-network" "lib-protocols" "lib-storage")

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

# Forbidden network/IO imports for strict/pure libs
FORBIDDEN_CORE_NETWORK_IMPORTS=(
    "use std::net"
    "use reqwest::"
    "use hyper::"
    "use quinn::"
    "use tokio::net"
)

FORBIDDEN_IO_ALLOWED_IMPORTS=(
    "use std::env"
    "use std::process"
    "use actix_web::"
    "use axum::"
    "use diesel::"
    "use hyper::"
    "use mongodb::"
    "use mysql::"
    "use postgres::"
    "use redis::"
    "use reqwest::"
    "use rocket::"
    "use rusqlite::"
    "use sea_orm::"
    "use sqlx::"
    "use surrealdb::"
    "use tokio_postgres::"
    "use warp::"
)

ERRORS_FOUND=0

coverage_check() {
    local lib="$1"
    for entry in "$STRICT_LIB" "${PURE_LIBS[@]}" "${IO_ALLOWED_LIBS[@]}"; do
        if [ "$lib" = "$entry" ]; then
            return 0
        fi
    done
    return 1
}

for lib in "${ALL_LIBS[@]}"; do
    if ! coverage_check "$lib"; then
        echo "❌ ERROR: $lib is not assigned to a policy tier"
        ERRORS_FOUND=$((ERRORS_FOUND + 1))
    fi
done

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

# Check strict/pure libs for direct network calls
for crate in "$STRICT_LIB" "${PURE_LIBS[@]}"; do
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

# Check IO-allowed libs for broad forbidden imports
for crate in "${IO_ALLOWED_LIBS[@]}"; do
    if [ -d "$crate" ]; then
        echo "📦 Checking $crate for IO-allowed forbidden imports..."
        for forbidden in "${FORBIDDEN_IO_ALLOWED_IMPORTS[@]}"; do
            while IFS= read -r line; do
                if [ -n "$line" ]; then
                    echo "❌ ERROR: Forbidden import found in IO-allowed crate $crate:"
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
