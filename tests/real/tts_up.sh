#!/usr/bin/env bash
# Real local Piper (piper1-gpl) for seagent's `[media.tts.piper]` path — E5.
#
# Installs a pinned `piper-tts` into a venv and one voice under $TMPDIR, verifies the
# binary really runs, and prints the env vars `crates/seagent-media/tests/real_tts.rs` needs:
#
#   export TMPDIR=/some/scratch/dir          # required: nothing is written outside it
#   eval "$(tests/real/tts_up.sh)"           # ~150 MB of downloads on the first run
#   cargo test -p seagent-media --test real_tts
#
# Idempotent: a second call reuses the venv/voice and only re-verifies them (~2 s).
# No root, no `pip --user`, no writes to $HOME (uv's cache and the venv both live under
# $TMPDIR), and /tmp is refused because seagent's own temp dir must stay inside $TMPDIR.
#
# Downloads (piper-tts 1.8.0 ships only wheels, no linux tarball):
#   piper-tts 32.6 MiB + onnxruntime 22.7 MiB + numpy 16.0 MiB + 4 small deps
#   en_US-lessac-medium.onnx 63,201,294 B + .onnx.json 4,885 B
set -euo pipefail

VERSION="${PIPER_TTS_VERSION:-1.8.0}"
VOICE="${PIPER_VOICE:-en_US-lessac-medium}"

if [ -z "${TMPDIR:-}" ]; then
  echo "tts_up: TMPDIR must be set (nothing is installed outside it)" >&2
  exit 2
fi
case "$TMPDIR" in
  /tmp|/tmp/*) echo "tts_up: refusing TMPDIR=$TMPDIR — point it at a scratch dir, not /tmp" >&2; exit 2 ;;
esac
mkdir -p "$TMPDIR"
ROOT="$(cd "$TMPDIR" && pwd)"
VENV="$ROOT/piper-tts"
VOICES="$ROOT/voices"
PIPER="$VENV/bin/piper"
MODEL="$VOICES/$VOICE.onnx"
export PYTHONNOUSERSITE=1

say() { echo "tts_up: $*" >&2; }

# Already installed by an earlier run (or handed in by the caller): reuse it.
if [ -n "${SEAGENT_REAL_PIPER:-}" ] && [ -x "${SEAGENT_REAL_PIPER}" ] && [ -n "${SEAGENT_REAL_PIPER_VOICE:-}" ] && [ -f "${SEAGENT_REAL_PIPER_VOICE}" ]; then
  PIPER="$SEAGENT_REAL_PIPER"
  MODEL="$SEAGENT_REAL_PIPER_VOICE"
  say "reusing SEAGENT_REAL_PIPER=$PIPER"
elif [ -x "$PIPER" ] && [ -f "$MODEL" ] && [ -f "$MODEL.json" ]; then
  say "piper-tts $VERSION and $VOICE already present in $ROOT"
else
  # 1. The engine. piper1-gpl v1.8.0 publishes wheels + an sdist only (no
  #    piper_linux_x86_64.tar.gz like the old rhasspy/piper 2023.11 releases), so the
  #    CLI is `python -m piper` inside a venv.
  if [ ! -x "$PIPER" ]; then
    if command -v uv >/dev/null 2>&1; then
      say "creating $VENV (uv)"
      UV_CACHE_DIR="$ROOT/uv-cache" UV_PYTHON_INSTALL_DIR="$ROOT/uv-python" \
        uv venv --python "${PIPER_PYTHON:-3.12}" "$VENV" >&2
      UV_CACHE_DIR="$ROOT/uv-cache" UV_PYTHON_INSTALL_DIR="$ROOT/uv-python" \
        uv pip install --python "$VENV/bin/python" "piper-tts==$VERSION" >&2
    else
      say "creating $VENV (python3 -m venv + pip)"
      "${PIPER_PYTHON:-python3}" -m venv "$VENV" >&2
      "$VENV/bin/python" -m pip install --no-cache-dir --disable-pip-version-check "piper-tts==$VERSION" >&2
    fi
  fi
  # 2. One voice: seagent's own downloader (`python -m piper.download_voices`), which is the
  #    same path `[media.tts.piper] voice = "<name>"` uses.
  if [ ! -f "$MODEL" ] || [ ! -f "$MODEL.json" ]; then
    say "downloading voice $VOICE"
    "$VENV/bin/python" -m piper.download_voices "$VOICE" --download-dir "$VOICES" >&2
  fi
fi

# 3. Verify the binary really runs, then synthesize one short sentence with the voice.
if ! "$PIPER" --help >/dev/null 2>&1; then
  echo "tts_up: $PIPER --help failed — piper is not usable" >&2
  exit 1
fi
SMOKE="$ROOT/smoke"
rm -rf "$SMOKE" && mkdir -p "$SMOKE"
printf 'Piper is speaking on this machine.' | "$PIPER" --model "$MODEL" --output_file "$SMOKE/out.wav" >/dev/null 2>&1 || {
  echo "tts_up: piper could not synthesize with $MODEL" >&2
  exit 1
}
"$VENV/bin/python" - "$SMOKE/out.wav" <<'PY' >&2
import sys, wave
w = wave.open(sys.argv[1])
assert w.getnframes() > 0, "empty wav"
print(f"tts_up: smoke wav {w.getnframes() / w.getframerate():.2f}s @ {w.getframerate()} Hz, {w.getnchannels()} ch, {w.getsampwidth() * 8}-bit")
PY
rm -rf "$SMOKE"

# 4. What the test needs. `piper --help` above is the "binary runs" check; SEAGENT_HOME is
#    left to the test, which forces its own throwaway one.
echo "export SEAGENT_REAL_PIPER=$(printf '%q' "$PIPER")"
echo "export SEAGENT_REAL_PIPER_VOICE=$(printf '%q' "$MODEL")"
say "done (piper-tts $VERSION, voice $VOICE)"
