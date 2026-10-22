#!/usr/bin/env bash
# Score bulge's organization mode on self-contained TheAgentCompany tasks.
#
# TheAgentCompany (arXiv 2412.14161) ships one Docker image per task: a baked
# input, an instruction, and an ENCRYPTED evaluator that scores checkpoints
# (partial credit). Its official runner drives an agent *inside* a container;
# bulge instead runs each task in its own libkrun microVM, so we use only the
# task images' inputs + evaluators and run bulge natively.
#
# Scope: tasks whose evaluator reads only /workspace and whose input is a file
# (not a service). bulge deliberately blocks host/LAN addresses, so the many
# TheAgentCompany tasks that require browsing host-run services (GitLab,
# ownCloud, RocketChat, Plane) are out of scope here by design, not by accident.
#
# usage: BULGE_API_KEY=... scripts/tac-eval.sh [task ...]
#   env: BULGE_MODEL (default deepseek-flash), BULGE_BASE_URL, TAC_REGISTRY
#        (default ghcr.io/theagentcompany), WORK (default a tmp dir).
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
BULGE=${BULGE:-$REPO/target/debug/bulge}
MODEL=${BULGE_MODEL:-deepseek-flash}
REG=${TAC_REGISTRY:-ghcr.io/theagentcompany}
KEY='theagentcompany is all you need'   # TheAgentCompany's hardcoded evaluator key
WORK=${WORK:-$(mktemp -d)}
TASKS=("$@")
[ ${#TASKS[@]} -eq 0 ] && TASKS=(ds-sql-exercise hr-check-attendance-one-day hr-check-attendance-multiple-days hr-check-attendance-multiple-days-department)

score_line() { python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(d['final_score']['result'],d['final_score']['total'])" "$1" 2>/dev/null; }

total_got=0; total_max=0
printf '%-44s %7s  %s\n' task score result
for t in "${TASKS[@]}"; do
  img="$REG/$t-image:1.0.0"
  L="$WORK/$t"; rm -rf "$L"; mkdir -p "$L/ws" "$L/jobs" "$L/scored"
  cp -a "$HOME/.bulge/harness" "$L/harness" 2>/dev/null || mkdir -p "$L/harness"
  podman pull -q "$img" >/dev/null 2>&1 || { echo "$t  (image unavailable)"; continue; }
  cid=$(podman create "$img")
  # Inputs: any db/csv under /data or /utils, plus the instruction.
  for src in /data /utils; do
    for f in $(podman run --rm --entrypoint sh "$img" -c "ls $src 2>/dev/null | grep -iE '\.(db|csv|xlsx|json|txt)$'" 2>/dev/null); do
      [ "$f" = rates_info.txt ] && continue   # answer key; never hand it to the agent
      podman cp "$cid:$src/$f" "$L/ws/$f" 2>/dev/null && cp "$L/ws/$f" "$L/scored/$f" 2>/dev/null
    done
  done
  podman cp "$cid:/instruction/task.md" "$L/task.md" 2>/dev/null
  podman rm "$cid" >/dev/null
  inputs=$(cd "$L/ws" && ls | paste -sd, -)
  goal="You run a data team. The input file(s) ($inputs) are already in /workspace; do NOT use owncloud or any web service — the files are local. $(cat "$L/task.md"). Delegate to your team; a worker may pip install needed libraries (network is available). Put every deliverable in /workspace."
  timeout 1800 "$BULGE" run --model "$MODEL" ${BULGE_BASE_URL:+--base-url "$BULGE_BASE_URL"} --network \
    --writeback "$L/scored" --store "$L/jobs" --harness "$L/harness" --workspace "$L/ws" \
    --max-steps 30 --max-secs 1700 --max-model-tokens 2000000 --goal "$goal" >"$L/out" 2>"$L/err"
  podman run --rm --network none -v "$L/scored:/workspace:ro" -v "$L:/out" \
    -e DECRYPTION_KEY="$KEY" --entrypoint sh "$img" \
    -c "cd /utils && DECRYPTION_KEY='$KEY' python_default /utils/eval.py --trajectory_path /dev/null --result_path /out/result.json >/dev/null 2>&1; cat /out/result.json" >/dev/null 2>&1
  read -r got max < <(score_line "$L/result.json"); got=${got:-0}; max=${max:-0}
  printf '%-44s %3s/%-3s  %s\n' "$t" "$got" "$max" "$([ "$got" = "$max" ] && [ "$max" != 0 ] && echo PASS || echo partial)"
  total_got=$((total_got+got)); total_max=$((total_max+max))
done
echo "-----"
printf 'TOTAL %d/%d checkpoints\n' "$total_got" "$total_max"
echo "work dir: $WORK"
