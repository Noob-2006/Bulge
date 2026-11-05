#!/usr/bin/env bash
# Reproducible-build check: does the same source tree produce the same bytes from two paths?
#
# Why this matters: a release binary that cannot be rebuilt from the tag is a binary nobody can
# audit. The check is deliberately end-to-end and dumb — copy the tree, build it twice from
# *different absolute paths* with *different target directories*, hash the artifacts, compare.
#
# The two usual sources of "not reproducible" are (a) the build directory embedded in debug info
# and panic locations and (b) wall-clock/ordering effects. (a) is removed with
# `--remap-path-prefix=<copy>=/build/ark`, which is exactly what a distributor would do; whatever
# still differs afterwards is (b) and is a real bug (hash-map iteration order, parallel codegen
# inputs, build scripts reading the clock). SOURCE_DATE_EPOCH is pinned for the same reason.
#
# Cost: --quick (default) builds the `ark` binary twice in the dev profile — roughly one to two
# minutes on a machine with warm crate sources. --full (or ARK_REPRO_FULL=1) builds the whole
# workspace and compares every `.rlib` as well, which takes several minutes. This is why
# `crates/ark/tests/supply_chain.rs` only checks that this script parses, never runs it.
#
# Usage: repro-check.sh [--quick|--full] [--keep] [--root DIR]
set -euo pipefail

# Byte order everywhere: two runs must agree on sorting, not on the reviewer's locale.
export LC_ALL=C

PROG=$(basename "$0")
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
MODE=quick
KEEP=0

# `ARK_REPRO_FULL=1` is the knob the checklist uses; an explicit flag always wins over it.
if [ "${ARK_REPRO_FULL:-0}" = "1" ]; then
    MODE=full
fi

usage() {
    cat <<EOF
Usage: $PROG [--quick|--full] [--keep] [--root DIR]

Build the same tree twice from two different absolute paths and compare the artifacts.

  --quick   compare only the \`ark\` binary, dev profile (default; ~1-2 minutes)
  --full    compare the binary and every workspace .rlib (several minutes)
  --keep    keep the scratch tree under \$TMPDIR for inspection
  --root    workspace root (default: two levels above this script)
  --help    show this help

Environment:
  ARK_REPRO_FULL=1   same as --full
  SOURCE_DATE_EPOCH  fixed at 1700000000 for both builds

Exit status: 0 = all artifacts identical, 1 = at least one DIFF, 2 = usage error.
Never writes to \$HOME or to the shared target/ directory.
EOF
}

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --quick) MODE=quick; shift ;;
        --full) MODE=full; shift ;;
        --keep) KEEP=1; shift ;;
        --root) [ $# -ge 2 ] || die "--root needs a value"; ROOT=$(cd -- "$2" && pwd); shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -f "$ROOT/Cargo.toml" ] || die "$ROOT does not look like the workspace root (no Cargo.toml)"
command -v cargo >/dev/null 2>&1 || die "cargo not found in PATH"
command -v tar >/dev/null 2>&1 || die "tar not found in PATH"
if command -v sha256sum >/dev/null 2>&1; then
    SHA256=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
    SHA256=(shasum -a 256)
else
    die "neither sha256sum nor shasum found in PATH"
fi

export SOURCE_DATE_EPOCH=1700000000
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true

SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/ark-repro-XXXXXX")
cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        printf '%s: scratch tree kept at %s\n' "$PROG" "$SCRATCH" >&2
    else
        rm -rf "$SCRATCH"
    fi
}
trap cleanup EXIT

# Two deliberately different path *lengths*: a build that embeds its own directory shows up as a
# difference even when nothing else changes.
A=$SCRATCH/a
B=$SCRATCH/copy-with-a-longer-path

copy_tree() {
    local dest=$1
    mkdir -p "$dest"
    # `target/` is the shared build cache (never to be read by a repro check), `data/` is local
    # state and `.git/` is not source.
    tar -C "$ROOT" --exclude=./target --exclude=./data --exclude=./.git -cf - . | tar -C "$dest" -xf -
}

printf '%s: copying %s twice (excluding target/, data/, .git/)\n' "$PROG" "$ROOT"
copy_tree "$A"
copy_tree "$B"

if [ "$MODE" = full ]; then
    BUILD_ARGS=(--workspace)
    printf '%s: full mode — building the whole workspace twice; this takes minutes\n' "$PROG"
else
    BUILD_ARGS=(-p ark --bin ark)
    printf '%s: quick mode — building only the `ark` binary (use --full for the rlib set)\n' "$PROG"
fi

build() {
    local dir=$1 target=$2 log=$3
    printf '%s: building %s -> %s\n' "$PROG" "$dir" "$target"
    if ! ( cd "$dir" && CARGO_TARGET_DIR="$target" \
            RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$dir=/build/ark" \
            cargo build --offline --locked "${BUILD_ARGS[@]}" ) >"$log" 2>&1; then
        tail -n 40 "$log" >&2
        die "build failed in $dir (full log: $log)"
    fi
}

hash_file() { "${SHA256[@]}" "$1" | cut -d' ' -f1; }

# `name<TAB>sha256`, one line per artifact, sorted so the two lists can be compared directly.
collect() {
    local target=$1 out=$2
    : > "$out"
    [ -f "$target/debug/ark" ] || die "no binary at $target/debug/ark"
    printf 'bin/ark\t%s\n' "$(hash_file "$target/debug/ark")" >> "$out"
    if [ "$MODE" = full ]; then
        local rlib
        for rlib in "$target"/debug/deps/*.rlib; do
            [ -e "$rlib" ] || continue
            # `libfoo-1a2b3c4d5e6f7890.rlib` -> `lib/foo`: the hash suffix is what we compare,
            # the crate name is the key.
            printf 'lib/%s\t%s\n' \
                "$(basename "$rlib" .rlib | sed -E 's/^lib//; s/-[0-9a-f]{16}$//')" \
                "$(hash_file "$rlib")" >> "$out"
        done
    fi
    sort -o "$out" "$out"
}

build "$A" "$SCRATCH/target-a" "$SCRATCH/build-a.log"
build "$B" "$SCRATCH/target-b" "$SCRATCH/build-b.log"

collect "$SCRATCH/target-a" "$SCRATCH/a.sha"
collect "$SCRATCH/target-b" "$SCRATCH/b.sha"

printf '\n  %-58s %s\n' "artifact" "result"
printf '  %-58s %s\n' "--------" "------"
DIFFS=0
COUNT=0
while IFS= read -r key; do
    COUNT=$((COUNT + 1))
    ha=$(awk -F'\t' -v k="$key" '$1 == k { print $2 }' "$SCRATCH/a.sha")
    hb=$(awk -F'\t' -v k="$key" '$1 == k { print $2 }' "$SCRATCH/b.sha")
    if [ -n "$ha" ] && [ "$ha" = "$hb" ]; then
        printf '  %-58s PASS\n' "$key"
    else
        DIFFS=$((DIFFS + 1))
        printf '  %-58s DIFF  a=%.12s b=%.12s\n' "$key" "${ha:-absent}" "${hb:-absent}"
    fi
done < <(cut -f1 "$SCRATCH/a.sha" "$SCRATCH/b.sha" | sort -u)

printf '\n  build A: %s\n  build B: %s\n' "$A" "$B"
if [ "$DIFFS" -ne 0 ]; then
    printf '%s: %d of %d artifact(s) differ — this build is NOT reproducible\n' "$PROG" "$DIFFS" "$COUNT"
    # Most first-time DIFFs in this workspace are not codegen at all: a crate that calls
    # `env!("CARGO_MANIFEST_DIR")` bakes its own absolute build path into the binary, which no
    # compiler flag can remap and which differs by construction between the two copies.
    if grep -rqs --include=*.rs 'CARGO_MANIFEST_DIR' "$ROOT/crates"; then
        printf '%s: hint — crates in this tree embed `env!("CARGO_MANIFEST_DIR")`; a DIFF limited to\n' "$PROG"
        printf '  that string is a path-embedding bug (make the path relative). Find them with:\n'
        printf "    grep -rn --include=*.rs 'CARGO_MANIFEST_DIR' crates | grep -v tests/\n"
    fi
    [ "$KEEP" -eq 1 ] || printf '%s: re-run with --keep to inspect the two trees\n' "$PROG"
    exit 1
fi
printf '%s: OK — %d artifact(s) identical across two build paths\n' "$PROG" "$COUNT"
