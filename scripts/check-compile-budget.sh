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
: "${BUDGET_SECS:?}" "${BUDGET_VERSION:?}" "${VECTOR_IMAGE:?}"
BUDGET_MS=$((BUDGET_SECS * 1000))
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
done < /w/list
INNER

echo "Vector: $VECTOR_IMAGE"
echo "Budget: ${BUDGET_SECS}s per parser (budget v$BUDGET_VERSION), 1 CPU"
echo ""
docker run --rm --cpus=1 --network=none -v "$WORK:/w" --entrypoint sh "$VECTOR_IMAGE" /w/measure.sh "$KILL_SECS" \
    | sort -k2 -n -r > "$WORK/results"

FAIL=0
printf '%-60s %10s  %s\n' "parser" "load (ms)" "result"
while read -r path ms status; do
    id=$(printf '%s' "$path" | tr '/' '_')
    verdict=OK
    if [ "$status" = killed ]; then
        verdict="FAIL: still loading after ${KILL_SECS}s (budget ${BUDGET_SECS}s)"
        FAIL=$((FAIL + 1))
    elif [ "$status" = failed ]; then
        verdict="FAIL: Vector refused the program"
        FAIL=$((FAIL + 1))
    elif [ "$ms" -gt "$BUDGET_MS" ]; then
        verdict="FAIL: over budget (${ms} ms > ${BUDGET_MS} ms)"
        FAIL=$((FAIL + 1))
    fi
    printf '%-60s %10s  %s\n' "$path" "$ms" "$verdict"
    if [ "$status" = failed ]; then
        grep -v "^\s*$" "$WORK/$id.log" | tail -5 | sed 's/^/    /'
    fi
done < "$WORK/results"

measured=$(wc -l < "$WORK/results")
if [ "$measured" -ne "${#PARSERS[@]}" ]; then
    echo ""
    echo "Measured $measured of ${#PARSERS[@]} parsers: the measurement run broke."
    exit 1
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### Parser load budget (${BUDGET_SECS}s, nano Vector, 1 CPU)"
        echo ""
        echo "| parser | load (ms) |"
        echo "|---|---:|"
        head -10 "$WORK/results" | while read -r path ms _; do echo "| \`$path\` | $ms |"; done
    } >> "$GITHUB_STEP_SUMMARY"
fi

echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "$FAIL parser(s) over the load budget or refused by Vector."
    echo "An install reloads every deployed parser within a 45 s acknowledgement"
    echo "window; the content publisher will not sign a revision containing these."
    exit 1
fi
echo "All ${#PARSERS[@]} parsers load within ${BUDGET_SECS}s."
