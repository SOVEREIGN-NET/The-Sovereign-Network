#!/bin/bash
# Check for TRUE duplicate type definitions across DIFFERENT crates

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Checking for cross-crate duplicate types..."

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Collect all types
for crate in lib-*/src; do
    [[ "$crate" == "lib-types/src" ]] && continue
    crate_name=$(echo "$crate" | sed 's|/src||')
    
    for file in "$crate"/*.rs; do
        [[ -f "$file" ]] || continue
        
        grep -n "^pub struct" "$file" | while read -r line; do
            linenum=$(echo "$line" | cut -d: -f1)
            struct_name=$(echo "$line" | sed 's/.*pub struct \([A-Za-z0-9_]*\).*/\1/')
            [[ -z "$struct_name" ]] && continue
            
            fields=$(sed -n "${linenum},/^}/p" "$file" | \
                grep -E "^\s+pub" | \
                sed 's/.*pub \([a-zA-Z0-9_]*\):.*/\1/' | \
                tr '\n' ' ' | \
                sed 's/ $//')
            
            echo "$crate_name:$struct_name:$fields"
        done
    done
done > "$TEMP_DIR/types.txt"

# Find duplicates - use unique crate list per (name, fields)
awk -F: '{
    key = $2 SUBSEP $3
    crates[key] = crates[key] ? crates[key] SUBSEP $1 : $1
}
END {
    for (key in crates) {
        n = split(crates[key], arr, SUBSEP)
        # Get unique crate names
        delete seen
        unique = ""
        for (i = 1; i <= n; i++) {
            if (!seen[arr[i]]) {
                seen[arr[i]] = 1
                unique = unique ? unique SUBSEP arr[i] : arr[i]
            }
        }
        count = 0
        for (c in seen) count++
        if (count > 1) {
            split(key, parts, SUBSEP)
            print parts[1] SUBSEP unique
        }
    }
}' "$TEMP_DIR/types.txt" > "$TEMP_DIR/dups.txt"

if [[ -s "$TEMP_DIR/dups.txt" ]]; then
    echo ""
    echo -e "${RED}ERROR: Found cross-crate duplicate types:${NC}"
    while IFS=SUBSEP read -r name crates; do
        echo -e "${YELLOW}Type: $name${NC}"
        echo "$crates" | tr SUBSEP '\n' | sed 's/^/  - /'
        echo ""
    done < "$TEMP_DIR/dups.txt"
    exit 1
fi

echo -e "${GREEN}No cross-crate duplicate types found.${NC}"
exit 0
