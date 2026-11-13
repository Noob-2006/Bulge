#!/usr/bin/env bash
# Run a command and, if it fails, publish the tail of its output as error annotations.
# Annotations are public on the run page (logs need a signed-in account), so a failure can be
# diagnosed from the API without access to the logs.
#
#   bash "$GITHUB_WORKSPACE/.github/scripts/annotate.sh" <command> [args…]
set -uo pipefail
log="$(mktemp)"
"$@" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
if [ "$rc" -ne 0 ]; then
	title="$(basename "$1") failed (exit $rc), last lines"
	# Workflow-command escaping: % → %25, CR dropped, LF → %0A; 40 lines per annotation.
	tail -n 160 "$log" | sed $'s/\x1b\\[[0-9;]*[A-Za-z]//g' | awk -v t="$title" '
		{ gsub(/%/, "%25"); gsub(/\r/, ""); buf = buf $0 "%0A"; n++
		  if (n == 40) { printf "::error title=%s::%s\n", t, buf; buf = ""; n = 0 } }
		END { if (buf != "") printf "::error title=%s::%s\n", t, buf }'
fi
rm -f "$log"
exit "$rc"
