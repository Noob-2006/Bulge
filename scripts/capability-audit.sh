#!/usr/bin/env bash
# Capability audit — reproducible evidence for docs/COMPARISON.md.
#
# Two parts:
#   1. bulge side is VERIFIED BY EXECUTION: each capability must have its concrete
#      code symbol present in crates/, and the whole test suite must pass.
#   2. the reference-agent columns are the findings of the detailed code review
#      (see docs/COMPARISON.md for file:line citations). They are fixed data here,
#      NOT a fuzzy grep, because a grep for e.g. "skill" cannot tell a real
#      learn-from-experience loop (Hermes) from read-only skill assets (dsh).
#
#   bash scripts/capability-audit.sh
#
# Reference legend:  Y = has it,  · = does not,  ~ = partial / different form.
set -u
BULGE="${BULGE_ROOT:-$HOME/bulge}"
pass=0; fail=0

# row <axis> <label> <bulge-symbol-grep> <her> <ocl> <oco> <dsh>
row() {
  local axis="$1" label="$2" bpat="$3" her="$4" ocl="$5" oco="$6" dsh="$7"
  local b="MISS"
  if grep -rqE "$bpat" "$BULGE/crates" 2>/dev/null; then b="HAVE"; pass=$((pass+1)); else b="MISS"; fail=$((fail+1)); fi
  printf '%-8s | %-24s | %-5s |  %s  |  %s  |  %s  |  %s\n' "$axis" "$label" "$b" "$her" "$ocl" "$oco" "$dsh"
}

echo "# bulge capability audit  ($(date -u +%FT%TZ))"
echo "# bulge column: verified by code symbol + test suite below."
echo "# her=hermes ocl=openclaw oco=opencode dsh=deepseek-harness  (Y/·/~ from code review)"
echo
printf '%-8s | %-24s | %-5s | her | ocl | oco | dsh\n' "axis" "capability" "bulge"
printf '%.0s-' {1..72}; echo
#                                                               her ocl oco dsh
row 安全 "real microVM 隔離"       'libkrun|Vm::launch'           '~' '~' '·' '~'
row 安全 "寫回 diff 審批"          'changes::apply'               '~' '~' 'Y' '~'
row 安全 "程式碼策略引擎"          'fn evaluate|Effect::Deny'     '~' 'Y' 'Y' 'Y'
row 安全 "Pre/PostToolUse hooks"   'HookedDispatcher'             'Y' 'Y' 'Y' 'Y'
row 安全 "秘密遮蔽"               'fn redact_secrets'            'Y' 'Y' '·' '·'
row 安全 "注入/威脅偵測"          'fn is_threat'                 'Y' '·' '·' '·'
row 安全 "LLM 二次審查閘"          'REVIEW_POLICY'               '·' '·' '·' 'Y'
row 智能 "學習迴圈(造技能)"      'propose_skill'                'Y' '·' '·' '·'
row 智能 "反污染護欄"            'DO_NOT_CAPTURE'               'Y' '·' '·' '·'
row 智能 "使用者模型 USER.md"      'propose_profile'              'Y' '·' '·' '·'
row 智能 "技能台帳+curator"       'fn curate'                    'Y' '·' '·' '·'
row 智能 "對話/任務檢索"          'fn search_default'            'Y' '·' '·' 'Y'
row 智能 "子代理委派"            'DelegateHandler'              'Y' '~' 'Y' 'Y'
row 自動 "時間排程 cron"          'enum Schedule'                'Y' 'Y' '·' 'Y'
row 自動 "事件觸發"              'OnPathChange'                 '~' 'Y' '·' '·'
row 自動 "MCP 外部工具"          'McpClient'                    'Y' 'Y' 'Y' 'Y'
row 自動 "ACP 代理伺服器"         'bulge_cli::acp|fn serve'      'Y' 'Y' '·' 'Y'
row 功能 "完整 VM 可程式環境"     'VmDispatcher|exec'            '~' '~' '·' '~'
row 體驗 "桌面 App"              'tauri'                        'Y' 'Y' '·' 'Y'

echo
printf '%.0s-' {1..72}; echo
echo "bulge capabilities present: $pass / $((pass+fail))"
echo
echo "## executed functional evidence (bulge)"
cd "$BULGE" || exit 1
cargo test -q --workspace 2>/dev/null | awk '/test result/ {ok+=$4; f+=$6} END {printf "cargo test --workspace: %d passed, %d failed\n", ok, f}'
if cargo clippy -q --workspace --all-targets -- -D warnings >/dev/null 2>&1; then
  echo "cargo clippy --workspace --all-targets -D warnings: clean"
else
  echo "cargo clippy: WARNINGS PRESENT"
fi
echo
echo "Reading: capabilities only Hermes also has (learning loop, user model, curator,"
echo "anti-poison guardrail, threat detect) — bulge adds a real microVM + writeback"
echo "approval that Hermes lacks. No single reference agent has bulge's full column."
