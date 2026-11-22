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

# One private scratch directory per run, removed on any exit; the per-parser
# files live inside it under fixed names. A plain `mktemp -d` template works on
# GNU and BSD (macOS) mktemp alike, and concurrent runs never share a file.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/validate_vrl.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Telling "ran to completion" from "aborted"
#
# `vector vrl` exits 0 when a program aborts at runtime: it prints the error
# message (or just "aborted") and returns success. Only a COMPILE error gives a
# non-zero exit. So the exit code separates "compiles" from "does not", and
# something else has to separate "finished" from "aborted".
#
# This script used to decide that by scraping `--print-object` output: rewrite
# the t'…' timestamp literals into JSON strings with a regex, then ask jq
# whether the result parsed. The regex matched ANY `t'…'`, so a sample value
# such as `'root'@host` or `'commit'` was rewritten too, the JSON broke, and a
# parser that had run fine was reported as aborted.
#
# Now the program itself reports completion. Each run appends one final
# expression to the parser:
#
#     "<marker>:" + encode_base64(encode_json(.))
#
# and runs WITHOUT --print-object, so vector prints that expression's value.
# The final expression is reached only if nothing before it aborted, so:
#   - the marker line present  -> the program completed; the payload is the
#                                 event as real JSON (encode_json renders
#                                 timestamps as strings and escapes control
#                                 characters), base64 so no event content can
#                                 alter or imitate the line
#   - the marker line absent   -> the program aborted; vector printed the error
# The marker carries a per-run random nonce, so a sample or an abort message
# can never forge it. Event content is never pattern-matched.
#
# Limitation: a program that leaves via `return` skips the appended
# expression and is reported as aborted. No parser in this repo uses `return`;
# if one ever does, this check needs a different completion signal.
# ---------------------------------------------------------------------------
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
DONE_MARKER="__nano_vrl_completed__:${NONCE}:"

# write_probe_program <vrl source> <out file>
write_probe_program() {
    printf '%s\n"%s" + encode_base64(encode_json(.))\n' "$1" "$DONE_MARKER" > "$2"
}

# run_probe <event file> <probe program file>
# Sets PROBE_RC (vector's exit status: non-zero = compile error), PROBE_OUT
# (vector's full output, for messages) and PROBE_JSON (the emitted event as
# JSON, empty if the program aborted). Returns 0 only if the program completed.
run_probe() {
    PROBE_RC=0
    PROBE_OUT=$(vector vrl --input "$1" --program "$2" 2>&1) || PROBE_RC=$?
    PROBE_JSON=""
    [ "$PROBE_RC" -eq 0 ] || return 1
    local line
    # The marker line is a VRL string literal of base64 chars, so it is also
    # a valid JSON string: let jq strip the marker and decode it.
    line=$(printf '%s\n' "$PROBE_OUT" | grep -F "\"${DONE_MARKER}" | tail -1) || true
    [ -n "$line" ] || return 1
    PROBE_JSON=$(printf '%s' "$line" | jq -r --arg m "$DONE_MARKER" 'ltrimstr($m) | @base64d') || return 1
    [ -n "$PROBE_JSON" ]
}

# Output for humans: vector's lines minus its INFO log banner.
vector_messages() {
    printf '%s\n' "$1" | grep -v "INFO vector" || true
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

    # vector vrl reads the program and the event from files.
    src_file="$WORK/source.vrl"
    printf '%s\n' "$vrl_program" > "$src_file"
    event_file="$WORK/event.json"
    printf '%s\n' "$event_json" > "$event_file"
    # The probe program is the parser plus the completion marker (see
    # run_probe), used for every runtime check below. Compiling is judged on
    # the parser ALONE: an incomplete last line such as `.x =` would otherwise
    # take the appended marker as its right-hand side and compile.
    vrl_file="$WORK/program.vrl"
    write_probe_program "$vrl_program" "$vrl_file"

    # Run Vector VRL validation
    # Exit code 0 = valid, non-zero = compilation error
    output=""
    compiled=0
    if output=$(vector vrl --input "$event_file" --program "$src_file" --print-object 2>&1); then
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
    # The signal is the completion marker (run_probe). A parser that handles a
    # bad line writes its complaint INTO the event (e.g. .metadata.parse_error)
    # and still completes; one that aborts never reaches the marker.
    if [ "$compiled" -eq 1 ] && [ "$is_enrichment" -eq 0 ]; then
        if ! run_probe "$event_file" "$vrl_file"; then
            echo "  NOTE: aborts on the generic stub event (no event emitted)"
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
            sample_event="$WORK/sample.json"
            jq -nc --arg m "$raw" '{message: $m}' > "$sample_event"

            if ! run_probe "$sample_event" "$vrl_file"; then
                echo "  FAIL: sample[$idx] aborted at runtime — the parser would DROP this event"
                echo "    input:  $raw"
                vector_messages "$PROBE_OUT" | head -3 | sed 's/^/    output: /'
                sample_failed=1
            else
                s_json="$PROBE_JSON"
                # Assert declared expectations, if any
                exp_keys=$(yq -o=json ".samples[$idx].expect // {}" "$parser_file" | jq -r 'keys[]?')
                for key in $exp_keys; do
                    want=$(yq ".samples[$idx].expect.\"$key\"" "$parser_file")
                    # `// "<missing>"` was wrong for two values. jq's alternative
                    # operator treats BOTH null and `false` as empty, so any
                    # expectation of a boolean false reported "<missing>" -- which
                    # reads as "the parser never emitted the field" when the parser
                    # emitted it correctly. That made a false assertion impossible
                    # to write anywhere in this repo, and the failure message sent
                    # you looking in the wrong place. `0` was always fine: jq counts
                    # it truthy. Absent and null still collapse to "<missing>",
                    # which is the behaviour every existing sample relies on.
                    # Numeric path components index ARRAYS. `split(".")` gives
                    # strings, and jq refuses to index an array with "0", so any
                    # expectation reaching into evidences[], osint[] or
                    # observables[] died with "Cannot index array with string"
                    # -- which is a jq error, not a parser failure, and the
                    # sample simply could not be written. OCSF puts a great deal
                    # in arrays; asserting into them is not exotic.
                    got=$(printf '%s' "$s_json" | jq -r --arg p "$key" '
                        ($p | split(".") | map(if test("^[0-9]+$") then tonumber else . end)) as $path
                        | getpath($path) as $v | if $v == null then "<missing>"
                          # encode_json writes a whole-valued float as 1.0;
                          # VRL prints it as 1. Compare the VRL form, which is
                          # what every existing expectation was written against.
                          elif ($v | type) == "number" and $v == ($v | floor)
                               and $v > -9007199254740992 and $v < 9007199254740992 then $v + 0
                          else $v end')
                    if [ "$got" != "$want" ]; then
                        echo "  FAIL: sample[$idx] expected $key = '$want' but got '$got'"
                        echo "    input: $raw"
                        sample_failed=1
                    fi
                done
            fi
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
