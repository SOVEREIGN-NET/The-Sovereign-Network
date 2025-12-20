#!/bin/bash

# Core Purity Validation Script
# Enforces strict rules for foundational crates (especially lib-types)

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "🔍 Validating core crate purity..."

CORE_LIBS=("lib-types" "lib-crypto" "lib-proofs")
STRICT_LIBS=("lib-types")

# Forbidden imports for core libs (networking/IO/runtime coupling)
FORBIDDEN_CORE_IMPORTS=(
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
    "use quinn::"
    "use rustls::"
    "use socket2::"
    "use mdns_sd::"
    "use serialport::"
    "use rocksdb::"
)

ERRORS_FOUND=0

check_lib_types_policy() {
    local crate_dir="lib-types"
    local cargo_toml="$crate_dir/Cargo.toml"

    if [ ! -f "$cargo_toml" ]; then
        echo "❌ ERROR: lib-types Cargo.toml not found"
        ERRORS_FOUND=$((ERRORS_FOUND + 1))
        return
    fi

    # Enforce no features for lib-types
    if grep -q "^\[features\]" "$cargo_toml"; then
        echo "❌ ERROR: lib-types must not define feature flags"
        ERRORS_FOUND=$((ERRORS_FOUND + 1))
    fi

    # Enforce dependency whitelist for lib-types
    local allowed_deps=("serde" "blake3" "hex")
    local found_deps
    found_deps=$(awk '
        BEGIN { in_deps = 0 }
        /^\[dependencies\]/ { in_deps = 1; next }
        /^\[/ { in_deps = 0 }
        in_deps && $0 !~ /^[[:space:]]*#/ && $0 ~ /=/ {
            line = $0
            sub(/#.*/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            split(line, parts, "=")
            name = parts[1]
            gsub(/[[:space:]]+$/, "", name)
            print name
        }
    ' "$cargo_toml")

    for dep in $found_deps; do
        local allowed=false
        for allowed_dep in "${allowed_deps[@]}"; do
            if [ "$dep" = "$allowed_dep" ]; then
                allowed=true
                break
            fi
        done
        if [ "$allowed" = false ]; then
            echo "❌ ERROR: lib-types depends on disallowed crate: $dep"
            ERRORS_FOUND=$((ERRORS_FOUND + 1))
        fi
    done

    # Enforce no internal crate dependencies
    if grep -q "path[[:space:]]*=[[:space:]]*\"../" "$cargo_toml"; then
        echo "❌ ERROR: lib-types must not depend on internal crates"
        ERRORS_FOUND=$((ERRORS_FOUND + 1))
    fi

    # Enforce no async or tokio in lib-types source
    if grep -r "async fn" "$crate_dir/src" 2>/dev/null; then
        echo "❌ ERROR: lib-types must not contain async functions"
        ERRORS_FOUND=$((ERRORS_FOUND + 1))
    fi
    if grep -r "tokio" "$crate_dir/src" 2>/dev/null; then
        echo "❌ ERROR: lib-types must not reference tokio"
        ERRORS_FOUND=$((ERRORS_FOUND + 1))
    fi
}

for crate in "${CORE_LIBS[@]}"; do
    local_path="$crate"
    if [ ! -d "$local_path" ]; then
        echo "⚠️  Crate $crate not found, skipping..."
        continue
    fi

    echo "📦 Checking crate: $crate"

    # Enforce strict lib-types policy
    if [ "$crate" = "lib-types" ]; then
        check_lib_types_policy
    fi

    # Check for forbidden imports in core libs
    for forbidden in "${FORBIDDEN_CORE_IMPORTS[@]}"; do
        if grep -r "$forbidden" "$local_path/src" 2>/dev/null | grep -v "^Binary"; then
            echo "❌ ERROR: Core crate $crate imports forbidden library: $forbidden"
            ERRORS_FOUND=$((ERRORS_FOUND + 1))
        fi
    done

    echo "✅ Crate $crate passed core purity checks"
done

if [ $ERRORS_FOUND -eq 0 ]; then
    echo "🎉 All core crates passed purity validation!"
    exit 0
else
    echo "💥 Found $ERRORS_FOUND core purity violations!"
    exit 1
fi
