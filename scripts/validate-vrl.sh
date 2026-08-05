#!/usr/bin/env bash
# Validate VRL syntax for changed parser.yaml files.
# Exits non-zero if any parser has VRL compilation errors.
# Warnings are reported but do not block.

set -euo pipefail

CHANGED_FILE="${1:?Usage: validate-vrl.sh <file-with-changed-paths>}"
FAIL=0
WARN=0
PASS=0
SAMPLED=0
UNSAMPLED=0
UNSAMPLED_NAMES=""

# `vector vrl --print-object` emits timestamps as VRL literals (t'2026-01-01T…'),
# which is not valid JSON. Rewrite them to plain strings so the result can be
# fed to jq. Used to tell "ran to completion" from "aborted": a program that
# finishes emits a JSON object, one that aborts emits "aborted" or a bare error.
normalize_vector_output() {
    printf '%s' "$1" | grep -v "INFO vector" | perl -pe "s/t'([^']*)'/\"\$1\"/g"
}

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

    # NAN-1329: nano's app-side parser validator does a *raw* character count of
    # (), {} and [] across the whole VRL — strings, regex literals and comments
    # included — and refuses to deploy on any imbalance, before the VRL ever
    # reaches the compiler. `vector vrl` below is more lenient: it correctly
    # ignores a bracket inside a regex char class like `[^(]` / `[^)]`. So a
    # parser can compile cleanly here yet fail to deploy on a real tenant. Mirror
    # the app's raw count so that gap is caught at PR time, not on the user's box.
    read -r op cp ob cb os cs <<EOF
$(printf '%s' "$vrl_program" | awk '
        { for (i = 1; i <= length($0); i++) { c = substr($0, i, 1)
            if (c == "(") op++; else if (c == ")") cp++
            else if (c == "{") ob++; else if (c == "}") cb++
            else if (c == "[") os++; else if (c == "]") cs++ } }
        END { printf "%d %d %d %d %d %d", op, cp, ob, cb, os, cs }')
EOF
    imbalance=""
    [ "$op" != "$cp" ] && imbalance="${imbalance}    parentheses: $op opening, $cp closing\n"
    [ "$ob" != "$cb" ] && imbalance="${imbalance}    braces: $ob opening, $cb closing\n"
    [ "$os" != "$cs" ] && imbalance="${imbalance}    square brackets: $os opening, $cs closing\n"
    if [ -n "$imbalance" ]; then
        echo "  FAIL: unbalanced brackets — nano's parser validator rejects this on deploy"
        printf "%b" "$imbalance"
        echo "    A bracket inside a regex char class (e.g. [^(] or [^)]) trips the raw count."
        echo "    Escape it as hex so no literal bracket appears in the source:"
        echo "      [^\\]]  ->  [^\\x5D]      [^}]  ->  [^\\x7D]"
        echo "      [^)]   ->  [^\\x29]      [^(]  ->  [^\\x28]"
        echo "    Do NOT substitute '.+?' — it looks equivalent but is not: '.' excludes"
        echo "    newlines in Rust regex while a negated class matches them, so a capture"
        echo "    that can span a line silently stops matching. The hex form is exact."
        FAIL=$((FAIL + 1))
        continue
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
    compiled=0
    if output=$(vector vrl --input "$event_file" --program "$vrl_file" --print-object 2>&1); then
        compiled=1
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

    # NAN-2327: everything above proves only that the program COMPILES.
    # `vector vrl` exits 0 even when the program aborts at runtime — it prints
    # the error and returns success — so the exit-code check above cannot see a
    # parser that drops every event it touches. Two such defects shipped to main
    # behind a green run (FRO-677: a float array index in the PRI decode, and
    # string! on a non-participating optional regex group).
    #
    # The reliable signal is whether `--print-object` emitted a JSON object. A
    # parser that handles a bad line writes its complaint INTO the event (e.g.
    # .metadata.parse_error) and still emits an object; one that aborts emits
    # "aborted" or a bare error line instead. So: parseable as JSON = ran to
    # completion, not parseable = aborted.
    if [ "$compiled" -eq 1 ] && [ "$is_enrichment" -eq 0 ]; then
        if ! normalize_vector_output "$output" | jq -e . >/dev/null 2>&1; then
            echo "  NOTE: aborts on the generic stub event (no JSON emitted)"
            echo "        Not blocking — the stub is not a meaningful input for"
            echo "        most parsers. Add samples: to assert real behaviour."
        fi
    fi

    # ---------------------------------------------------------------------
    # Sample-based runtime validation (NAN-2327)
    #
    # An optional `samples:` block carries representative RAW lines for this
    # parser. Unlike the stub above these are inputs the parser is expected to
    # handle, so aborting on one is a hard failure, and declared `expect:`
    # fields must match. This is the check that would have caught FRO-677.
    #
    #   samples:
    #     - raw: '<30>Aug  5 12:00:00 host1 testd: probe'
    #       expect:
    #         udm.severity: low
    #         udm.src_host: host1
    # ---------------------------------------------------------------------
    sample_count=$(yq '.samples // [] | length' "$parser_file")
    if [ "$compiled" -eq 1 ] && [ "${sample_count:-0}" -gt 0 ]; then
        SAMPLED=$((SAMPLED + 1))
        sample_failed=0
        idx=0
        while [ "$idx" -lt "$sample_count" ]; do
            raw=$(yq ".samples[$idx].raw" "$parser_file")
            sample_event=$(mktemp /tmp/sample_XXXXXX.json)
            jq -nc --arg m "$raw" '{message: $m}' > "$sample_event"

            s_out=$(vector vrl --input "$sample_event" --program "$vrl_file" --print-object 2>&1)
            s_json=$(normalize_vector_output "$s_out")

            if ! printf '%s' "$s_json" | jq -e . >/dev/null 2>&1; then
                echo "  FAIL: sample[$idx] aborted at runtime — the parser would DROP this event"
                echo "    input:  $raw"
                echo "$s_out" | grep -v "INFO vector" | head -3 | sed 's/^/    output: /'
                sample_failed=1
            else
                # Assert declared expectations, if any
                exp_keys=$(yq -o=json ".samples[$idx].expect // {}" "$parser_file" | jq -r 'keys[]?')
                for key in $exp_keys; do
                    want=$(yq ".samples[$idx].expect.\"$key\"" "$parser_file")
                    got=$(printf '%s' "$s_json" | jq -r --arg p "$key" 'getpath($p | split(".")) // "<missing>"')
                    if [ "$got" != "$want" ]; then
                        echo "  FAIL: sample[$idx] expected $key = '$want' but got '$got'"
                        echo "    input: $raw"
                        sample_failed=1
                    fi
                done
            fi
            rm -f "$sample_event"
            idx=$((idx + 1))
        done

        if [ "$sample_failed" -eq 1 ]; then
            FAIL=$((FAIL + 1))
            PASS=$((PASS - 1))
        else
            echo "  OK: $sample_count sample(s) parsed and matched expectations"
        fi
    elif [ "$is_enrichment" -eq 0 ]; then
        UNSAMPLED=$((UNSAMPLED + 1))
        UNSAMPLED_NAMES="${UNSAMPLED_NAMES}${parser_name} "
    fi

    rm -f "$vrl_file" "$event_file"
done < "$CHANGED_FILE"

echo ""
echo "═══════════════════════════════════════"
echo "Results: $PASS passed, $WARN warnings, $FAIL failed"
echo "Runtime samples: $SAMPLED parser(s) exercised against real input"
echo "═══════════════════════════════════════"

# NAN-2327: a compile-only pass is a weak signal. Name the parsers that carry no
# samples so the gap stays visible rather than reading as full coverage.
if [ "$UNSAMPLED" -gt 0 ]; then
    echo ""
    echo "$UNSAMPLED parser(s) have no samples: block and were only compile-checked:"
    echo "  $UNSAMPLED_NAMES" | fold -s -w 76 | sed 's/^/  /'
    echo "  These are NOT verified to parse anything. Add samples: to cover them."
fi

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "Blocking merge — fix VRL errors above."
    exit 1
fi

echo ""
echo "All parsers valid. Clear to merge."
exit 0
