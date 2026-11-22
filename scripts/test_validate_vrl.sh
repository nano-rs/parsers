#!/usr/bin/env bash
# Regression tests for scripts/validate-vrl.sh's runtime-abort detection.
#
# validate-vrl.sh once decided "aborted" by regex-rewriting `vector vrl
# --print-object` output into JSON. The rewrite matched any `t'…'`, so a sample
# value such as `'root'@host` or `'commit'` corrupted the JSON and a parser that
# ran fine was reported as having aborted. These cases pin the fix: event
# content never decides the verdict; only whether the program completed does.
#
# Needs vector, yq and jq on PATH (the same tools validate-vrl.sh needs).
# Usage: scripts/test_validate_vrl.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATE="$REPO_ROOT/scripts/validate-vrl.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/test_validate_vrl.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0

# run_case <name> <want: pass|fail> <grep pattern the output must contain>
# Reads the parser.yaml body from stdin.
run_case() {
    local name="$1" want="$2" pattern="$3" rc=0 out
    mkdir -p "$WORK/$name"
    cat > "$WORK/$name/parser.yaml"
    printf '%s\n' "$WORK/$name/parser.yaml" > "$WORK/$name/list.txt"
    out=$(bash "$VALIDATE" "$WORK/$name/list.txt" 2>&1) || rc=$?
    local ok=1
    if [ "$want" = "pass" ] && [ "$rc" -ne 0 ]; then ok=0; fi
    if [ "$want" = "fail" ] && [ "$rc" -eq 0 ]; then ok=0; fi
    if ! printf '%s\n' "$out" | grep -qE -- "$pattern"; then ok=0; fi
    if [ "$ok" -eq 1 ]; then
        echo "ok   $name"
    else
        echo "FAIL $name (exit $rc, wanted $want, pattern: $pattern)"
        printf '%s\n' "$out" | sed 's/^/     | /'
        FAILURES=$((FAILURES + 1))
    fi
}

# Quote-wrapped words ending in t (`'root'`, `'commit'`, `'host't'`) in the raw
# line, copied into the event, alongside a real timestamp and a tab. This was
# reported as "aborted at runtime" before the fix.
run_case quoted_t_words pass "OK: 2 sample\(s\) parsed and matched expectations" <<'YAML'
name: test_quoted_t_words
parser_vrl: |
  .raw = string!(.message)
  .user = parse_regex(.raw, r'for (?P<u>\S+) from') ?? {}
  .time = t'2026-01-01T00:00:00Z'
  .count = 1.0
  .flag = false
samples:
  - raw: "Accepted password for 'root'@10.0.0.1 from 10.0.0.1 port 22 ssh2"
    expect:
      raw: "Accepted password for 'root'@10.0.0.1 from 10.0.0.1 port 22 ssh2"
      user.u: "'root'@10.0.0.1"
      time: "2026-01-01T00:00:00Z"
      count: 1
      flag: false
  - raw: "git: 'commit' is a git command. See 'git --help'. ok't'	tab"
    expect:
      raw: "git: 'commit' is a git command. See 'git --help'. ok't'	tab"
YAML

# A real runtime abort is still caught and fails the run.
run_case real_abort fail "FAIL: sample\[0\] aborted at runtime" <<'YAML'
name: test_real_abort
parser_vrl: |
  .n = to_int!(.message)
samples:
  - raw: "user 'root'@host is not a number"
YAML

# An explicit `abort` whose message looks like a completed event is still an
# abort: completion is signalled only by the program reaching its end.
run_case abort_message_imitates_event fail "FAIL: sample\[0\] aborted at runtime" <<'YAML'
name: test_abort_imitates_event
parser_vrl: |
  if contains(string!(.message), "x") { abort "{\"message\": \"looks like JSON\"}" }
  .ok = true
samples:
  - raw: "x 'commit'"
YAML

# Expectation mismatches are still reported against the decoded event.
run_case expectation_mismatch fail "expected user = 'admin' but got ''root''" <<'YAML'
name: test_expectation_mismatch
parser_vrl: |
  .user = "'root'"
samples:
  - raw: "anything"
    expect:
      user: admin
YAML

# A compile error is still a compile error.
run_case compile_error fail "FAIL: VRL compilation error" <<'YAML'
name: test_compile_error
parser_vrl: |
  .x =
YAML

echo ""
if [ "$FAILURES" -gt 0 ]; then
    echo "$FAILURES validate-vrl.sh regression case(s) failed."
    exit 1
fi
echo "All validate-vrl.sh regression cases passed."
