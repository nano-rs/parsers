#!/usr/bin/env bash
# Fetch nano's input-contract classifier (`parser_input_contract`) pinned in
# scripts/input-contract.lock, verify its sha256, and print the path. Exits 3
# (and prints nothing) while the lock has no published build.
#
# Usage: NANO_INPUT_CONTRACT="$(scripts/fetch-input-contract.sh <dest-dir>)"
# An auth token for a non-public URL is read from OCSF_VALIDATOR_TOKEN (the same
# read-only token as the OCSF validator; never echoed).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$REPO_ROOT/scripts/input-contract.lock"
DEST="${1:?usage: fetch-input-contract.sh <dest-dir>}"
url=$(sed -n 's/^url=//p' "$LOCK")
want=$(sed -n 's/^sha256=//p' "$LOCK")
if [ -z "$url" ] || [ "$url" = "UNSET" ] || [ -z "$want" ] || [ "$want" = "UNSET" ]; then
    echo "input-contract.lock has no published build pinned yet" >&2
    exit 3
fi
mkdir -p "$DEST"
out="$DEST/parser_input_contract"
if [ -n "${OCSF_VALIDATOR_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: Bearer ${OCSF_VALIDATOR_TOKEN}" -H "Accept: application/octet-stream" -o "$out" "$url"
else
    curl -fsSL -H "Accept: application/octet-stream" -o "$out" "$url"
fi
got=$( { sha256sum "$out" 2>/dev/null || shasum -a 256 "$out"; } | cut -d" " -f1)
if [ "$got" != "$want" ]; then
    echo "parser_input_contract sha256 mismatch: got $got, want $want" >&2
    rm -f "$out"
    exit 1
fi
chmod +x "$out"
echo "$out"
