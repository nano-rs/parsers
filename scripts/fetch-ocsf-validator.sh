#!/usr/bin/env bash
# Fetch nano's OCSF contract validator (`ocsf_event_validate`) pinned in
# scripts/ocsf-validator.lock, verify its sha256, and print the path.
#
# The binary is a nano build artifact (nanosiem-core `--bin ocsf_event_validate`,
# the same `validate_ocsf_event` the lake writer enforces at admission). The lock
# names the exact nanosiem commit it was built from, its download URL and sha256.
#
# Usage: OCSF_VALIDATOR="$(scripts/fetch-ocsf-validator.sh <dest-dir>)"
# An auth token for a non-public URL is read from OCSF_VALIDATOR_TOKEN (never echoed).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$REPO_ROOT/scripts/ocsf-validator.lock"
DEST="${1:?usage: fetch-ocsf-validator.sh <dest-dir>}"
url=$(sed -n 's/^url=//p' "$LOCK")
want=$(sed -n 's/^sha256=//p' "$LOCK")
if [ -z "$url" ] || [ -z "$want" ] || [ "$url" = "UNSET" ]; then
    echo "ocsf-validator.lock has no url/sha256 pinned" >&2
    exit 1
fi
mkdir -p "$DEST"
out="$DEST/ocsf_event_validate"
if [ -n "${OCSF_VALIDATOR_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: Bearer ${OCSF_VALIDATOR_TOKEN}" -H "Accept: application/octet-stream" -o "$out" "$url"
elif [[ "$url" == https://api.github.com/repos/nano-rs/nanosiem/* ]]; then
    echo "OCSF_VALIDATOR_TOKEN is not set: the pinned validator is a private nano-rs/nanosiem" >&2
    echo "release asset. Set it to a read-only token for that repo (CI: repo secret)." >&2
    exit 1
else
    curl -fsSL -o "$out" "$url"
fi
got=$(sha256sum "$out" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then
    echo "ocsf_event_validate sha256 mismatch: got $got, want $want" >&2
    rm -f "$out"
    exit 1
fi
chmod +x "$out"
echo "$out"
