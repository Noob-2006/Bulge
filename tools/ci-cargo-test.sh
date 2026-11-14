#!/usr/bin/env bash
# CI: run `cargo test <args>` and, when it fails, turn each failure into a GitHub annotation
# (the panic site plus the two message lines after it, and cargo's own `error:` lines), so a
# failed run can be diagnosed from the check's annotations without signing in to read the log.
#   tools/ci-cargo-test.sh --workspace --locked
set -uo pipefail
log="${RUNNER_TEMP:-/tmp}/cargo-test-$$.log"
st=0
cargo test "$@" 2>&1 | tee "$log" || st=$?
if [ "$st" -ne 0 ]; then
  awk '/panicked at/ {n=3; msg=""} n>0 {msg = msg (msg=="" ? "" : "%0A") $0; n--; if (n==0) print "::error title=cargo test::" msg}' "$log" | head -40
  grep -E '^error(\[|:)' "$log" | head -10 | sed 's/^/::error title=cargo::/'
fi
rm -f "$log"
exit "$st"
