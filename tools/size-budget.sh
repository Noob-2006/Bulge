#!/bin/bash
# Size budget check for the seagent release binaries (audit row D6).
#
# Reads tools/size-budget.tsv, builds each listed configuration, compares the stripped
# binary against its budget and fails if any build is over. The numbers behind the
# budgets, and what each build contains, are explained in docs/BUILD.md.
#
#   tools/size-budget.sh                 # build + measure + check (a few minutes)
#   tools/size-budget.sh --only slim     # check one configuration
#   tools/size-budget.sh --no-build      # re-check what the last run left in the cache dir
#   tools/size-budget.sh --json          # machine-readable result
#   tools/size-budget.sh --tolerance=N   # allow N % over a budget (LTO layout drifts ~0.3 %
#                                        # between runs on the same tree)
#
# Builds go to ${SEAGENT_SIZE_TARGET_DIR:-$XDG_CACHE_HOME/seagent-size-budget/target} (default
# ~/.cache/seagent-size-budget/target), NOT to ./target: this script replaces the binary of
# each configuration in turn, and target/release/seagent is the one the tests and e2e use.
#
# Exit codes: 0 all within budget, 1 over budget or missing, 2 usage/environment error.
set -u

cd "$(dirname "$0")/.." || exit 2

budget_file=tools/size-budget.tsv
json=0
build=1
tolerance=0
only=""
while [ $# -gt 0 ]; do
  arg=$1
  shift
  case "$arg" in
    --no-build) build=0 ;;
    --json) json=1 ;;
    --tolerance) tolerance=${1:?--tolerance needs a value}; shift ;;
    --tolerance=*) tolerance=${arg#--tolerance=} ;;
    --only) only=${1:?--only needs a build name}; shift ;;
    --only=*) only=${arg#--only=} ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "size-budget: unknown argument $arg" >&2; exit 2 ;;
  esac
done
[ -f "$budget_file" ] || { echo "size-budget: $budget_file missing" >&2; exit 2; }

export CARGO_TARGET_DIR=${SEAGENT_SIZE_TARGET_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/seagent-size-budget/target}
export CARGO_INCREMENTAL=0
mkdir -p "$CARGO_TARGET_DIR" 2>/dev/null || { echo "size-budget: cannot create $CARGO_TARGET_DIR" >&2; exit 2; }

fail=0
rows=()
while IFS=$'\t' read -r name profile features budget last command; do
  case "$name" in ''|'#'*) continue ;; esac
  if [ -n "$only" ]; then
    case ",$only," in
      *",$name,"*) ;;
      *) continue ;;
    esac
  fi
  args=()
  if [ "$profile" = release ]; then args+=(--release); else args+=(--profile "$profile"); fi
  case "$features" in
    default) : ;;
    none) args+=(--no-default-features) ;;
    *) args+=(--no-default-features --features "$features") ;;
  esac
  if [ "$build" = 1 ]; then
    if ! cargo build -p seagent "${args[@]}" >/dev/null 2>&1; then
      rows+=("$name|$budget|0|build failed")
      fail=1
      continue
    fi
  fi
  bin="$CARGO_TARGET_DIR/$profile/seagent"
  if [ ! -f "$bin" ]; then
    rows+=("$name|$budget|0|missing $bin (run without --no-build)")
    fail=1
    continue
  fi
  size=$(stat -c %s "$bin")
  limit=$(( budget + budget * tolerance / 100 ))
  verdict=ok
  if [ "$size" -gt "$limit" ]; then
    verdict="OVER by $(( size - budget )) bytes"
    fail=1
  fi
  rows+=("$name|$budget|$size|$verdict")
done < "$budget_file"

if [ "$json" = 1 ]; then
  printf '{"ok": %s, "target_dir": "%s", "builds": [' \
    "$([ "$fail" = 0 ] && echo true || echo false)" "$CARGO_TARGET_DIR"
  first=1
  for row in "${rows[@]}"; do
    IFS='|' read -r name budget size verdict <<<"$row"
    [ "$first" = 1 ] || printf ', '
    first=0
    printf '{"name":"%s","budget":%s,"bytes":%s,"verdict":"%s"}' "$name" "$budget" "$size" "$verdict"
  done
  printf ']}\n'
else
  printf '%-14s %12s %12s %7s  %s\n' build budget bytes used verdict
  for row in "${rows[@]}"; do
    IFS='|' read -r name budget size verdict <<<"$row"
    used=-
    if [ "$size" != 0 ] && [ "$budget" != 0 ]; then
      used=$(awk -v s="$size" -v b="$budget" 'BEGIN { printf "%.1f%%", s * 100 / b }')
    fi
    printf '%-14s %12s %12s %7s  %s\n' "$name" "$budget" "$size" "$used" "$verdict"
  done
fi

if [ "$fail" != 0 ]; then
  echo "size-budget: FAILED — see docs/BUILD.md for what each build contains" >&2
  exit 1
fi
[ "$json" = 1 ] || echo "size-budget: all builds within budget"
exit 0
