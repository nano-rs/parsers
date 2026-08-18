#!/usr/bin/env bash
# Validate the OCSF parser tree (parsers-ocsf/).
#
# Companion to validate-vrl.sh, not a replacement. validate-vrl.sh proves a
# parser COMPILES and does not abort; this proves the record it emits is a
# legal, queryable OCSF event for the OCSF version the parser declares.
#
# Two gates per sample:
#   Gate 1  VRL — `vector vrl` compiles AND RUNS the program on the sample.
#                 A program that compiles but aborts on real input drops every
#                 event it touches; that is a hard failure here.
#   Gate 2  OCSF — the EMITTED event is checked against nano's OCSF contract
#                 (when the validator binary is available) plus the tree-wide
#                 consistency rules below, which always run.
#
# Tree-wide consistency rules (scripts/ocsf_event_checks.py):
#   - metadata.version equals the parser's own `ocsf_version` key
#   - type_uid == class_uid * 100 + activity_id
#   - the parser never writes `.udm.*` or `source_type`
#   - class_uid is a real, NON-DEPRECATED class in that OCSF version
#     (1.9 deprecated 3001 Account Change and 3005 User Access Management in
#      favour of 3007 User Management / 3006 Group Management)
#   - every OCSF path written is promoted (queryable) or under `unmapped.*`;
#     anything else is reported as silently unqueryable
#
# Samples live BESIDE the parser:  parsers-ocsf/<source>/samples/*.json
# Each file is a raw log line, or a {"message": "<raw line>"} wrapper. Cover
# every branch — one sample per event type the source emits. A parser with no
# samples is reported as UNVALIDATED rather than failing the run, so a tree that
# is still being filled in stays checkable.
#
# Usage:
#   scripts/validate-ocsf.sh                          # whole parsers-ocsf/ tree
#   scripts/validate-ocsf.sh <file-with-parser-paths> # like validate-vrl.sh
#   scripts/validate-ocsf.sh parsers-ocsf/apache/parser.yaml [...]
#
# The OCSF contract binary is a nano build artifact and is not vendored here.
# Point OCSF_VALIDATOR at it (or put `ocsf_event_validate` on PATH) to run
# gate 2's schema half; without it that half reports SKIPPED and every static
# rule above still runs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKS="$REPO_ROOT/scripts/ocsf_event_checks.py"

FAIL=0
PASS=0
UNVALIDATED=0
UNVALIDATED_NAMES=""
UNQUERYABLE=0

# ---- work out which parsers to check -------------------------------------
PARSERS=()
if [ "$#" -eq 0 ]; then
    while IFS= read -r line; do PARSERS+=("$line"); done < <(
        find "$REPO_ROOT/parsers-ocsf" -name parser.yaml | sort
    )
elif [ "$#" -eq 1 ] && [ -f "$1" ] && [ "$(basename "$1")" != "parser.yaml" ]; then
    # A file listing parser paths, one per line — same contract as validate-vrl.sh
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        [ ! -f "$line" ] && continue
        case "$line" in parsers-ocsf/*|*/parsers-ocsf/*) PARSERS+=("$line") ;; esac
    done < "$1"
else
    PARSERS=("$@")
fi

if [ "${#PARSERS[@]}" -eq 0 ]; then
    echo "No parsers-ocsf/ parsers to validate."
    exit 0
fi

if [ -n "${OCSF_VALIDATOR:-}" ] || command -v ocsf_event_validate >/dev/null 2>&1; then
    echo "OCSF contract validator: available (gate 2 schema check ENABLED)"
else
    echo "OCSF contract validator: not found — set OCSF_VALIDATOR to enable the"
    echo "schema half of gate 2. Static consistency rules still run."
fi
echo ""

for parser_file in "${PARSERS[@]}"; do
    [ -f "$parser_file" ] || continue
    parser_dir="$(dirname "$parser_file")"
    parser_name=$(yq '.name' "$parser_file")
    ocsf_version=$(yq '.ocsf_version // "unset"' "$parser_file")

    echo "─────────────────────────────────────────"
    echo "Validating: $parser_name ($parser_file)  ocsf_version=$ocsf_version"
    echo "─────────────────────────────────────────"

    parser_failed=0

    # ---- static source rules (run even with zero samples) ----
    if ! python3 "$CHECKS" source --parser "$parser_file"; then
        parser_failed=1
    fi

    vrl_program=$(yq '.parser_vrl' "$parser_file")
    if [ -z "$vrl_program" ] || [ "$vrl_program" = "null" ]; then
        echo "    FAIL source: no parser_vrl field"
        FAIL=$((FAIL + 1))
        continue
    fi
    vrl_file=$(mktemp /tmp/ocsf_vrl_XXXXXXXXXX.vrl)
    printf '%s\n' "$vrl_program" > "$vrl_file"

    # ---- samples ----
    # Two conventions exist in this tree and BOTH are real coverage:
    #   sidecar : parsers-ocsf/<source>/samples/*.json
    #   inline  : a `samples:` block in parser.yaml (what validate-vrl.sh reads)
    # Reading only the sidecar form left 50 of 64 parsers OCSF-unvalidated while
    # they were in fact sample-covered — the gate reported a coverage gap that
    # did not exist, and missed schema errors in the parsers it skipped.
    samples=()
    if [ -d "$parser_dir/samples" ]; then
        while IFS= read -r s; do samples+=("$s"); done < <(
            find "$parser_dir/samples" -name '*.json' | sort
        )
    fi
    inline_dir=""
    if [ "${#samples[@]}" -eq 0 ]; then
        inline_dir=$(mktemp -d "${TMPDIR:-/tmp}/nano_inline.XXXXXX")
        if python3 "$CHECKS" extract-inline "$parser_file" "$inline_dir" 2>/dev/null; then
            while IFS= read -r s; do samples+=("$s"); done < <(
                find "$inline_dir" -name '*.json' | sort
            )
        fi
    fi

    if [ "${#samples[@]}" -eq 0 ]; then
        echo "    UNVALIDATED: no samples — add parsers-ocsf/$(basename "$parser_dir")/samples/*.json or a samples: block"
        UNVALIDATED=$((UNVALIDATED + 1))
        UNVALIDATED_NAMES="${UNVALIDATED_NAMES}${parser_name} "
        rm -f "$vrl_file"; [ -n "$inline_dir" ] && rm -rf "$inline_dir"
        if [ "$parser_failed" -eq 1 ]; then FAIL=$((FAIL + 1)); fi
        continue
    fi

    for sample in "${samples[@]}"; do
        label="$(basename "$sample")"
        event_file=$(mktemp /tmp/ocsf_event_XXXXXXXXXX.json)
        python3 "$CHECKS" wrap "$sample" > "$event_file"

        out_file=$(mktemp /tmp/ocsf_out_XXXXXXXXXX.json)
        # `vector vrl` exits 0 even when the program aborts at runtime, so the
        # exit code is not the signal — an aborted run emits no object at all.
        if ! vector vrl --input "$event_file" --program "$vrl_file" 2>/dev/null \
             | grep -v "INFO vector" | tail -1 > "$out_file"; then
            :
        fi
        if [ ! -s "$out_file" ] || ! head -c1 "$out_file" | grep -q '{'; then
            echo "      FAIL $label: [VRL] program aborted or emitted no object — the parser would DROP this event"
            vector vrl --input "$event_file" --program "$vrl_file" 2>&1 \
                | grep -v "INFO vector" | grep -v '^\s*$' | head -3 | sed 's/^/             /'
            parser_failed=1
        else
            check_out=$(python3 "$CHECKS" check --parser "$parser_file" --event "$out_file" --label "$label" || true)
            echo "$check_out"
            if echo "$check_out" | grep -q "FAIL "; then parser_failed=1; fi
            if echo "$check_out" | grep -q "WARN .*NOT promoted"; then
                UNQUERYABLE=$((UNQUERYABLE + 1))
            fi
        fi
        rm -f "$event_file" "$out_file"
    done

    if [ "$parser_failed" -eq 1 ]; then
        FAIL=$((FAIL + 1))
        echo "    RESULT: FAIL (${#samples[@]} sample(s))"
    else
        PASS=$((PASS + 1))
        echo "    RESULT: PASS (${#samples[@]} sample(s))"
    fi
    rm -f "$vrl_file"; [ -n "$inline_dir" ] && rm -rf "$inline_dir"
done

echo ""
echo "═══════════════════════════════════════"
echo "Results: $PASS passed, $FAIL failed, $UNVALIDATED unvalidated (no samples)"
echo "Samples writing non-promoted OCSF paths: $UNQUERYABLE"
echo "═══════════════════════════════════════"

# A parser with no samples is not "fine" — it is unproven. Name them so the gap
# stays visible rather than reading as coverage.
if [ "$UNVALIDATED" -gt 0 ]; then
    echo ""
    echo "$UNVALIDATED parser(s) have no samples/ and were only source-checked:"
    echo "  $UNVALIDATED_NAMES" | fold -s -w 76 | sed 's/^/  /'
    echo "  These are NOT verified to emit a valid OCSF event."
fi

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "Blocking merge — fix the OCSF errors above."
    exit 1
fi

echo ""
echo "All OCSF parsers valid. Clear to merge."
exit 0
