#!/bin/bash

# Dependency Validation Script
# Validates that dependency rules are followed for core crates

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "🔍 Validating dependency rules..."

CORE_LIBS=("lib-types" "lib-crypto" "lib-proofs")

# Forbidden dependencies for core crates (runtime/network/storage coupling)
FORBIDDEN_CORE_DEPS=(
    "tokio"
    "reqwest"
    "sqlx"
    "hyper"
    "axum"
    "quinn"
    "rustls"
    "serialport"
    "mdns-sd"
    "socket2"
    "governor"
    "rocksdb"
    "lib-network"
    "lib-storage"
    "lib-dht"
    "lib-dns"
)

ERRORS_FOUND=0

get_dependencies() {
    local cargo_toml="$1"
    awk '
        BEGIN { in_deps = 0 }
        /^\[dependencies\]/ { in_deps = 1; next }
        /^\[target\..*\.dependencies\]/ { in_deps = 1; next }
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
    ' "$cargo_toml"
}

for crate in "${CORE_LIBS[@]}"; do
    cargo_toml="$crate/Cargo.toml"

    if [ ! -f "$cargo_toml" ]; then
        echo "⚠️  Crate $crate not found, skipping..."
        continue
    fi

    echo "📦 Checking dependencies for crate: $crate"

    deps=$(get_dependencies "$cargo_toml")

    for forbidden_dep in "${FORBIDDEN_CORE_DEPS[@]}"; do
        if echo "$deps" | grep -q "^${forbidden_dep}$"; then
            echo "❌ ERROR: Core crate $crate depends on forbidden library: $forbidden_dep"
            ERRORS_FOUND=$((ERRORS_FOUND + 1))
        fi
    done

    # lib-types must only depend on a strict allowlist
    if [ "$crate" = "lib-types" ]; then
        allowed_deps=("serde" "blake3" "hex")
        for dep in $deps; do
            allowed=false
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
    fi

    echo "✅ Crate $crate dependencies are valid"
done

# Check for circular dependencies using cargo tree
if command -v cargo >/dev/null 2>&1; then
    echo "🔄 Checking for circular dependencies..."
    if cargo tree --invert --workspace 2>&1 | grep -q "cycle detected"; then
        echo "❌ ERROR: Circular dependencies detected"
        ERRORS_FOUND=$((ERRORS_FOUND + 1))
    else
        echo "✅ No circular dependencies found"
    fi
fi

if [ $ERRORS_FOUND -eq 0 ]; then
    echo "🎉 All dependency rules are valid!"
    exit 0
else
    echo "💥 Found $ERRORS_FOUND dependency violations!"
    exit 1
fi
