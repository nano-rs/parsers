#!/usr/bin/env bash
# NAN-5388: every parser must load in nano's shipped Vector within the budget.
#
# An install's deploy waits 45 s for Vector to acknowledge a config reload, and
# a reload recompiles every deployed parser. nano-rs/parsers#67 made Microsoft
# Sysmon slow enough to compile that deploying it outlived that window on
# installs, and every deploy rolled back. validate-vrl.sh and validate-ocsf.sh
# could not see it: they only check that a program compiles, not how long it
# takes, and they run upstream Vector rather than nano's build.
#
# This loads each parser's program as a remap in the pinned nano Vector image
# (scripts/compile-budget.lock) with `vector validate --no-environment`, on ONE
# CPU (the content publisher's measurement host is a single vCPU), and fails
# any parser over BUDGET_SECS. The content publisher runs the same check before
# it signs a parsers bundle; a parser that fails here would be refused there.
#
# Usage:
#   scripts/check-compile-budget.sh                          # whole repository
#   scripts/check-compile-budget.sh <file-with-parser-paths> # like validate-vrl.sh
#
# Needs docker and yq.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
. "$REPO_ROOT/scripts/compile-budget.lock"
: "${BUDGET_SECS:?}" "${BUDGET_VERSION:?}" "${VECTOR_IMAGE:?}" "${REFERENCE_BASELINE_MS:?}" "${RUNNER_FACTOR_CAP:?}"
BUDGET_MS=$((BUDGET_SECS * 1000))
BUDGET_RUNS="${BUDGET_RUNS:-3}"
# Tests only: a smaller budget (a real overrun) and a synthetic slow runner
# (every measured time multiplied).
BUDGET_MS="${BUDGET_TEST_BUDGET_MS:-$BUDGET_MS}"
SLOWDOWN="${BUDGET_TEST_SLOWDOWN:-1}"
# A parser still loading at twice the budget is stopped; it has failed already.
KILL_SECS=$((BUDGET_SECS * 2))

PARSERS=()
if [ "$#" -eq 0 ]; then
    while IFS= read -r p; do PARSERS+=("$p"); done < <(
        cd "$REPO_ROOT" && find parsers-ocsf enrichments -name parser.yaml | sort
    )
else
    while IFS= read -r p; do
        [ -n "$p" ] && [ -f "$REPO_ROOT/$p" ] && PARSERS+=("$p")
    done < "$1"
fi
if [ "${#PARSERS[@]}" -eq 0 ]; then
    echo "No parsers to check."
    exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/compile_budget.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/vrl"

# One program file per parser: normalize_vrl for an enrichment parser,
# parser_vrl otherwise (the same choice validate-vrl.sh makes).
: > "$WORK/list"
for p in "${PARSERS[@]}"; do
    f="$REPO_ROOT/$p"
    kind=$(yq '.kind // "parser"' "$f")
    program=$(yq '.normalize_vrl // ""' "$f")
    if [ "$kind" != "enrichment" ] && { [ -z "$program" ] || [ "$program" = "null" ]; }; then
        program=$(yq '.parser_vrl // ""' "$f")
    fi
    if [ -z "$program" ] || [ "$program" = "null" ]; then
        echo "FAIL $p: no parser_vrl / normalize_vrl"
        exit 1
    fi
    id=$(printf '%s' "$p" | tr '/' '_')
    printf '%s\n' "$program" > "$WORK/vrl/$id.vrl"
    printf '%s %s\n' "$id" "$p" >> "$WORK/list"
done

# Runs inside the Vector image: one `vector validate` per parser, timed.
cat > "$WORK/measure.sh" <<'INNER'
set -u
kill_secs="$1"
while read -r id path; do
    cat > "/tmp/$id.toml" <<TOML
[sources.in]
type = "stdin"

[transforms.parse]
type = "remap"
inputs = ["in"]
file = "/w/vrl/$id.vrl"

[sinks.out]
type = "blackhole"
inputs = ["parse"]
TOML
    start=$(date +%s%N)
    if timeout -s KILL "$kill_secs" vector validate --no-environment "/tmp/$id.toml" > "/w/$id.log" 2>&1; then
        status=ok
    else
        rc=$?
        if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then status=killed; else status=failed; fi
    fi
    end=$(date +%s%N)
    echo "$path $(( (end - start) / 1000000 )) $status"
done < "$2"
INNER

# The runner reference: a frozen program whose load time on a normal runner is
# REFERENCE_BASELINE_MS. It is timed before, between and after the parsers.
printf '%s\n' "$(cat "$REPO_ROOT/scripts/compile-budget-reference.vrl")" > "$WORK/vrl/__reference__.vrl"
echo "__reference__ scripts/compile-budget-reference.vrl" > "$WORK/ref_list"

measure() {  # <list file> <out file>
    cp "$1" "$WORK/run_list"
    docker run --rm --cpus=1 --network=none -v "$WORK:/w" --entrypoint sh "$VECTOR_IMAGE" /w/measure.sh "$KILL_SECS" /w/run_list > "$2"
}
ref_ms() {  # <out file>: the reference's time, or refuse
    read -r _ ms status < "$1"
    if [ "$status" != ok ]; then
        echo "The reference program did not load ($status): the measurement is broken." >&2
        exit 1
    fi
    echo "$ms"
}

echo "Vector: $VECTOR_IMAGE"
echo "Budget: ${BUDGET_SECS}s per parser (budget v$BUDGET_VERSION), 1 CPU; median of up to ${BUDGET_RUNS} runs; runner factor cap ${RUNNER_FACTOR_CAP}"
echo ""
measure "$WORK/ref_list" "$WORK/ref1"
measure "$WORK/list" "$WORK/run1"
measured=$(wc -l < "$WORK/run1")
if [ "$measured" -ne "${#PARSERS[@]}" ]; then
    echo "Measured $measured of ${#PARSERS[@]} parsers: the measurement run broke."
    exit 1
fi
measure "$WORK/ref_list" "$WORK/ref2"
# A parser past half the budget on its first run (or refused, or killed) is
# run again, so its verdict is a median; one well under the budget cannot be a
# regression a slower runner hides (a slow runner only adds time).
RESULTS=("$WORK/run1")
: > "$WORK/near"
while read -r path ms status; do
    if [ "$status" != ok ] || [ "$ms" -gt $((BUDGET_MS / 2)) ]; then
        awk -v p="$path" '$2 == p' "$WORK/list" >> "$WORK/near"
    fi
done < "$WORK/run1"
if [ -s "$WORK/near" ]; then
    for i in $(seq 2 "$BUDGET_RUNS"); do
        measure "$WORK/near" "$WORK/run$i"
        RESULTS+=("$WORK/run$i")
    done
fi
measure "$WORK/ref_list" "$WORK/ref3"

python3 "$REPO_ROOT/scripts/compile_budget_verdict.py" --budget-ms "$BUDGET_MS" \
    --baseline-ms "$REFERENCE_BASELINE_MS" --cap "$RUNNER_FACTOR_CAP" --slowdown "$SLOWDOWN" \
    --ref "$(ref_ms "$WORK/ref1"),$(ref_ms "$WORK/ref2"),$(ref_ms "$WORK/ref3")" \
    ${GITHUB_STEP_SUMMARY:+--summary "$GITHUB_STEP_SUMMARY"} "${RESULTS[@]}" | tee "$WORK/verdict"
status=${PIPESTATUS[0]}
# A refused program: show why.
while read -r path _ st; do
    if [ "$st" = failed ]; then
        id=$(printf '%s' "$path" | tr '/' '_')
        echo "  $path:"; grep -v "^\s*$" "$WORK/$id.log" | tail -5 | sed 's/^/    /'
    fi
done < "$WORK/run1"
if [ "$status" -ne 0 ]; then
    echo "An install reloads every deployed parser within a 45 s acknowledgement"
    echo "window; the content publisher will not sign a revision containing these."
    exit 1
fi
