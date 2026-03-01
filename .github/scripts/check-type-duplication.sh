#!/bin/bash
# Check for TRUE duplicate type definitions across DIFFERENT crates

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Checking for cross-crate duplicate types..."

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Collect all types - output as "type_name crate_name field1 field2 ..."
for crate in lib-*/src; do
    [[ "$crate" == "lib-types/src" ]] && continue
    crate_name=$(echo "$crate" | sed 's|/src||')
    
    # Recursively find all .rs files in the crate (fix for comment #4)
    find "$crate" -name "*.rs" -print0 | while IFS= read -r -d '' file; do
        [[ -f "$file" ]] || continue
        
        grep -n "^pub struct" "$file" | while read -r line; do
            linenum=$(echo "$line" | cut -d: -f1)
            struct_name=$(echo "$line" | sed 's/.*pub struct \([A-Za-z0-9_]*\).*/\1/')
            [[ -z "$struct_name" ]] && continue
            
            # Extract struct body using balanced brace matching (fix for comment #1)
            fields=$(awk -v start="$linenum" '
                NR >= start {
                    # Count opening and closing braces
                    for (i = 1; i <= NF; i++) {
                        # Remove non-brace characters, then count
                        val = $i
                        gsub(/[^{}]/, "", val)
                        for (j = 1; j <= length(val); j++) {
                            c = substr(val, j, 1)
                            if (c == "{") depth++
                            if (c == "}") depth--
                        }
                    }
                    # Collect lines within the struct
                    if (NR == start || in_struct) {
                        in_struct = 1
                        print
                        if (depth == 0 && NR > start) exit
                    }
                }
            ' "$file" | \
                grep -E "^\s+pub" | \
                sed 's/.*pub \([a-zA-Z0-9_]*\):.*/\1/' | \
                tr '\n' ' ' | \
                sed 's/ $//')
            
            echo "$struct_name $crate_name $fields"
        done
    done
done > "$TEMP_DIR/types.txt"

# Find duplicates: group by type_name and check if in multiple crates
# Using exact string comparison instead of regex (fix for comment #2)
awk '
{
    type = $1
    crate = $2
    fields = ""
    for (i = 3; i <= NF; i++) {
        fields = fields (fields ? " " : "") $i
    }
    
    key = type SUBSEP fields
    
    if (!(key in crate_list)) {
        crate_list[key] = crate
    } else {
        # Deduplicate using exact string comparison on comma-separated crate names
        found = 0
        n = split(crate_list[key], crates_arr, ",")
        for (i = 1; i <= n; i++) {
            if (crates_arr[i] == crate) {
                found = 1
                break
            }
        }
        if (!found) {
            crate_list[key] = crate_list[key] "," crate
        }
    }
}
END {
    for (key in crate_list) {
        n = split(crate_list[key], crates, ",")
        if (n > 1) {
            split(key, parts, SUBSEP)
            type_name = parts[1]
            printf "%s:%s\n", type_name, crate_list[key]
        }
    }
}
' "$TEMP_DIR/types.txt" > "$TEMP_DIR/dups.txt"

if [[ -s "$TEMP_DIR/dups.txt" ]]; then
    echo ""
    echo -e "${YELLOW}WARNING: Found cross-crate duplicate types (informational only):${NC}"
    while IFS=: read -r name crates; do
        echo -e "${YELLOW}Type: $name${NC}"
        echo "$crates" | tr ',' '\n' | sed 's/^/  - /'
        echo ""
    done < "$TEMP_DIR/dups.txt"
    # Informational check - always exit 0 (fix for comment #5)
    exit 0
fi

echo -e "${GREEN}No cross-crate duplicate types found.${NC}"
exit 0
