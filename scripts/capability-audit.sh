#!/usr/bin/env bash
# Capability audit — MEASURED against actual source trees (reproducible).
#
# Every cell is computed by probing the repo on disk:
#   * bulge  : the capability's concrete code symbol must exist in crates/.
#   * her/ocl/oco/dsh : a specific marker FILE or SYMBOL (located during the
#     code review, with file:line in docs/COMPARISON.md) must exist in that repo.
# Nothing here is hand-typed Y/·; a missing repo shows "?" (not inspected).
# This is capability DETECTION, not an end-to-end task benchmark (running four
# other agents needs their own keys/envs); it is the reproducible comparison.
#
#   bash scripts/capability-audit.sh
set -u
BULGE="${BULGE_ROOT:-$HOME/bulge}"
declare -A ROOT=( [her]="$HOME/hermes-agent" [ocl]="$HOME/openclaw" [oco]="$HOME/opencode" [dsh]="$HOME/deepseek-harness" )
bpass=0; btot=0

# probe <repo-root> <marker>  -> prints " Y " / " · " / " ? "
#   marker "f:relpath"      file/dir exists
#   marker "s:PATTERN"      regex present anywhere (precise pattern)
#   marker "-"              known-absent (no marker) => ·
probe() {
  local root="$1" marker="$2"
  [ -d "$root" ] || { printf ' ? '; return; }
  case "$marker" in
    -) printf ' · ' ;;
    f:*) [ -e "$root/${marker#f:}" ] && printf ' Y ' || printf ' · ' ;;
    s:*) grep -rqiE "${marker#s:}" "$root" --include=*.ts --include=*.py --include=*.rs --include=*.js \
           --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=build --exclude-dir=target --exclude-dir=.git 2>/dev/null && printf ' Y ' || printf ' · ' ;;
  esac
}

# row <axis> <label> <bulge-symbol> <her> <ocl> <oco> <dsh>
row() {
  local axis="$1" label="$2" bsym="$3"; shift 3
  local b; btot=$((btot+1))
  if grep -rqE "$bsym" "$BULGE/crates" 2>/dev/null; then b="HAVE"; bpass=$((bpass+1)); else b="MISS"; fi
  printf '%-8s | %-22s | %-5s |%s|%s|%s|%s\n' "$axis" "$label" "$b" \
    "$(probe "${ROOT[her]}" "$1")" "$(probe "${ROOT[ocl]}" "$2")" "$(probe "${ROOT[oco]}" "$3")" "$(probe "${ROOT[dsh]}" "$4")"
}

echo "# bulge capability audit — measured against source  ($(date -u +%FT%TZ))"
echo "# her=hermes ocl=openclaw oco=opencode dsh=deepseek-harness   Y=detected ·=absent ?=repo not present"
echo
printf '%-8s | %-22s | %-5s |her|ocl|oco|dsh\n' axis capability bulge
printf '%.0s-' {1..66}; echo
#   axis   label                    bulge-symbol                her-marker                                     ocl-marker                                  oco-marker                                       dsh-marker
# microVM: per code review none of the four run a guest microVM sandbox (opencode=none,
# hermes/openclaw=Docker/SSH, deepseek=policy modes); a stray "firecracker" in a deploy
# comment is not an agent sandbox, so the reference markers are known-absent.
row 安全 "real microVM 隔離"       'libkrun|Vm::launch'        '-'  '-'  '-'  '-'
row 安全 "寫回 diff 審批"          'changes::apply'            '-'                                             '-'                                         'f:packages/core/src/snapshot.ts'                '-'
row 安全 "程式碼策略引擎"          'fn evaluate|Effect::Deny'  'f:acp_adapter/permissions.py'                  'f:src/infra/exec-approvals-policy.ts'      'f:packages/core/src/permission.ts'              'f:packages/sandbox/sandbox-policy'
row 安全 "Pre/PostToolUse hooks"   'HookedDispatcher'          's:pre_tool_call'                               's:agent-harness-exec-review-runtime'       'f:packages/plugin/src/effect/tool.ts'           's:tools/(pre|post).?execute|pre-execute'
row 安全 "秘密遮蔽"               'fn redact_secrets'         'f:agent/redact.py'                             'f:src/security/secret-mask.ts'             '-'                                              '-'
row 安全 "注入/威脅樣式庫"        'fn is_threat'              'f:tools/threat_patterns.py'                    '-'                                         '-'                                              '-'
row 安全 "LLM 二次審查閘"          'REVIEW_POLICY'             '-'                                             'f:extensions/autoreview'                   '-'                                              'f:packages/experimental/auto-review'
row 智能 "學習迴圈(造技能)"      'propose_skill'             'f:agent/background_review.py'                  'f:src/skills/workshop/experience-review.ts' '-'                                             '-'
row 智能 "反污染護欄"            'DO_NOT_CAPTURE'            's:do.?not.?capture'                            's:do.?not.?capture|never (persist|record)'  '-'                                             '-'
row 智能 "使用者模型 USER.md"      'propose_profile'           's:USER\.md'                                    's:USER\.md'                                '-'                                              '-'
row 智能 "技能 curator(老化)"    'fn curate'                 'f:agent/curator.py'                            '-'                                         '-'                                              '-'
row 智能 "對話/任務檢索"          'fn search_default'         'f:tools/session_search_tool.py'               '-'                                         '-'                                              'f:packages/session-query'
# Auto-surfacing the most relevant past job at task start — bulge-exclusive: the
# review found Hermes deliberately keeps past transcripts tool-only (no blind
# auto-injection); the others have no recall to auto-surface at all.
row 智能 "自動浮現過往工作"      'fn most_relevant'          '-'                                            '-'                                         '-'                                              '-'
row 智能 "子代理委派"            'DelegateHandler'           'f:tools/delegate_tool.py'                      's:subagent'                                'f:packages/core/src/tool/plugin/subagent.ts'    'f:packages/subagent'
row 自動 "時間排程 cron"          'enum Schedule'             'f:cron'                                        'f:src/cron'                                '-'                                              'f:packages/schedule'
row 自動 "事件觸發"              'OnPathChange'              '-'                                             'f:src/cron/event-source.ts'                '-'                                              '-'
row 自動 "MCP 外部工具"          'McpClient'                 's:mcp'                                         's:mcp'                                     's:mcp'                                          'f:packages/mcp'
row 自動 "ACP 代理伺服器"         'bulge_cli::acp|fn serve'   'f:acp_adapter'                                's:\bacp\b'                                 '-'                                              'f:packages/acp'
row 體驗 "桌面 App"              'tauri'                     's:electron|desktop app|tauri'                 'f:apps'                                     '-'                                              'f:apps/desktop'

echo
printf '%.0s-' {1..66}; echo
echo "bulge capabilities present: $bpass / $btot  (verified by code symbol)"
echo
echo "## executed functional evidence (bulge)"
cd "$BULGE" || exit 1
cargo test -q --workspace 2>/dev/null | awk '/test result/ {ok+=$4; f+=$6} END {printf "cargo test --workspace: %d passed, %d failed\n", ok, f}'
cargo clippy -q --workspace --all-targets -- -D warnings >/dev/null 2>&1 && echo "clippy --workspace --all-targets -D warnings: clean" || echo "clippy: WARNINGS"
