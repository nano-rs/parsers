#!/usr/bin/env bash
# Validate VRL syntax for changed parser.yaml files.
# Exits non-zero if any parser has VRL compilation errors.
# Warnings are reported but do not block.

set -euo pipefail

CHANGED_FILE="${1:?Usage: validate-vrl.sh <file-with-changed-paths>}"
FAIL=0
WARN=0
PASS=0

# Minimal test events — just enough structure for VRL to compile + run against.
#   log:        a wrapped raw log line (the common `parser_vrl` shape)
#   enrichment: a pushed nano_enrich record (the `normalize_vrl` shape, NAN-1149)
# The enrichment event carries a non-empty external_id so identity-style
# normalizers don't `abort` on the missing-key guard during the run check.
TEST_EVENT='{"message": "{\"timestamp\":\"2025-01-01T00:00:00Z\",\"severity\":\"INFO\"}"}'
ENRICH_TEST_EVENT='{"external_id":"S-1-5-21-100-500","username":"jdoe","upn":"jdoe@corp.example","email":"jdoe@corp.example","display_name":"Jane Doe","version":1717000000000,"account_status":"active","groups":["domain admins"]}'

while IFS= read -r parser_file; do
    [ -z "$parser_file" ] && continue
    [ ! -f "$parser_file" ] && continue

    parser_name=$(yq '.name' "$parser_file")
    echo "─────────────────────────────────────────"
    echo "Validating: $parser_name ($parser_file)"
    echo "─────────────────────────────────────────"

    # NAN-1149: an enrichment parser (kind: enrichment, or any file carrying a
    # normalize_vrl) keeps its VRL in `normalize_vrl` and is fed a pushed-record
    # test event instead of a wrapped log line.
    kind=$(yq '.kind // "parser"' "$parser_file")
    normalize_vrl=$(yq '.normalize_vrl' "$parser_file")
    is_enrichment=0
    if [ "$kind" = "enrichment" ] || { [ -n "$normalize_vrl" ] && [ "$normalize_vrl" != "null" ]; }; then
        is_enrichment=1
    fi

    if [ "$is_enrichment" -eq 1 ]; then
        vrl_program="$normalize_vrl"
        event_json="$ENRICH_TEST_EVENT"
        if [ -z "$vrl_program" ] || [ "$vrl_program" = "null" ]; then
            echo "  ERROR: enrichment parser has no normalize_vrl field"
            FAIL=$((FAIL + 1))
            continue
        fi
    else
        vrl_program=$(yq '.parser_vrl' "$parser_file")
        event_json="$TEST_EVENT"
        if [ -z "$vrl_program" ] || [ "$vrl_program" = "null" ]; then
            echo "  ERROR: No parser_vrl field found"
            FAIL=$((FAIL + 1))
            continue
        fi
    fi

    # Write VRL to temp file (vector vrl reads from file)
    vrl_file=$(mktemp /tmp/vrl_XXXXXX.vrl)
    echo "$vrl_program" > "$vrl_file"

    # Write test event to temp file
    event_file=$(mktemp /tmp/event_XXXXXX.json)
    echo "$event_json" > "$event_file"

    # Run Vector VRL validation
    # --print-object outputs the transformed event
    # Exit code 0 = valid, non-zero = compilation error
    output=""
    if output=$(vector vrl --input "$event_file" --program "$vrl_file" --print-object 2>&1); then
        # Check for warnings in output
        if echo "$output" | grep -qi "warning"; then
            echo "  WARN: VRL compiled with warnings"
            echo "$output" | grep -i "warning" | head -5 | sed 's/^/    /'
            WARN=$((WARN + 1))
        else
            echo "  OK: VRL compiled successfully"
        fi
        PASS=$((PASS + 1))
    else
        echo "  FAIL: VRL compilation error"
        echo "$output" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi

    rm -f "$vrl_file" "$event_file"
done < "$CHANGED_FILE"

echo ""
echo "═══════════════════════════════════════"
echo "Results: $PASS passed, $WARN warnings, $FAIL failed"
echo "═══════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    echo "Blocking merge — fix VRL errors above."
    exit 1
fi

echo "All parsers valid. Clear to merge."
exit 0
