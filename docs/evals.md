# ark 評測與蒸餾（`ark evals`、`ark distill`）

本文件說明 ark 的評測 runner 與職業準則蒸餾工具。**本輪所有自動測試只用假模型（`fake/*`）**；真模型的跑法列在「真跑指令」一節，等決定預算後再執行。

## 1. 一個 runner

```text
題目（原生 JSONL／SWE-bench／Terminal-Bench／GAIA／OSWorld／角色情境題）
  × 受測對象（ark × 各模型；外部 agent 以指令形式）
  × 重跑次數
  → 每次嘗試：答案、工作目錄、token、成本、耗時
  → 評分：exact／contains／regex／command／file／judge 模型
  → results.jsonl ＋ report.json ＋ report.md
```

- `ark evals list|run`：原本的 hermetic 執行期探針，不變。
- 計分評測都在同一個指令下：`ark evals bench|roles|fetch|import|report|compare|collect|swe-score|suites|agents`。
- 程式：`crates/ark/src/ops/evalkit/`（`run.rs` 嘗試迴圈、`grade.rs` 評分、`bench.rs` 標準評測介接、`external.rs` 外部 agent、`roles.rs` 角色情境、`report.rs` 報表、`fake.rs` 假模型）。`ark batch swe` 的 mini-SWE 迴圈（`miniswe.rs`）就是 runner 的 `mini` harness。

### 題目格式（原生）

每行一個 JSON：

```json
{"id": "smoke-fix", "kind": "agent", "prompt": "…",
 "files": {"add.sh": "…"}, "setup": ["git init -q …"], "image": null,
 "checks": [{"type": "command", "cmd": "sh test.sh"},
            {"type": "judge", "points": [{"text": "…", "keywords": ["…"], "weight": 1}], "pass_at": 0.6}],
 "reference": "給 judge 的參考資料", "fake": {"commands": ["…"], "answer": "…"}, "meta": {}}
```

- `kind`：`chat`（單次呼叫，無工具）、`agent`（完整 ark kernel 或 mini harness，在新的工作目錄）、`desktop`（OSWorld）。
- 分數＝各 check 的平均；全部 check 通過才算 pass。judge 依 rubric 點加權計分。
- `fake` 只給 `fake/oracle` 用，真模型忽略。

### Harness

| 任務 | harness |
|---|---|
| chat | 直接呼叫模型（system＝任務 system＋受測對象的準則） |
| agent，無 image | `ark`：完整 kernel＋內建工具，每次嘗試新 session，session 存在 run 自己的 home |
| agent，有 image（或 `--harness mini`） | mini-SWE 迴圈，在容器 `ark-test-eval-<task>-<rand>` 內；評分在容器拆除前做；drop guard 保證移除 |
| desktop | Bot Desktop 容器 `ark-test-eval-osworld-*` |

所有子程序都在自己的 process group，逾時或 panic 時整組 kill。

### 模型與成本

- 受測模型：`--model provider/model`（可重複，或 `--models a,b`）。只有指定真模型時才載入使用者的 provider 設定。
- `fake/oracle`：照題目的 `fake` 腳本呼叫 shell 工具再作答；system 帶角色準則時會複述準則（讓「有／無準則」與消融可觀察）。`fake/blank`：一律答不知道。`fake/judge`：以 rubric keywords 離線評分。
- 成本：`--price MODEL=IN,OUT`（每百萬 token 美元）＞ 設定檔 `[prices]` ＞ models.dev 價格表（離線時不查）。
- judge：`--judge provider/model`，judge 的 token 與成本分開統計。

### 報表

`report.md`／`report.json`：每個受測對象的 done、pass rate、平均分、pass@k、pass^k、重跑一致性、token、成本、judge 成本、pending／error／unsupported；依 suite、依題目的矩陣。`ark evals compare A B` 並排比較兩次 run。`--resume` 只補跑未完成的嘗試。

## 2. 外部 agent 並排（pro-008）

```sh
ark evals bench --suite builtin:smoke --model fake/oracle --agents claude-code,codex=o4-mini,opencode --judge fake/judge --out runs/x
# 檢查 runs/x/external/commands.sh 後自己執行，然後：
ark evals collect runs/x
```

- ark 不內建這些工具，只產生指令（`share/evals/agents.toml`，`{prompt}`／`{model}`／`{workdir}` 逐參數替換，不經 shell）並收集輸出（json／jsonl／text；讀出 token 與自報成本）。
- `--exec-external` 才由 ark 直接啟動（逾時、process group）。這些工具會直接改工作目錄，不可信任的題目請在容器或 VM 內跑。

## 3. 標準評測介接

題集一律讀**本機路徑**；下載一次之後離線可用。

| 評測 | 下載 | suite 寫法 | 計分 |
|---|---|---|---|
| SWE-bench Lite／Verified | `ark evals fetch swe-lite --to DIR`（HF datasets-server 分頁） | `swe-lite:DIR[#ids=a,b]`；`--swe-images` 用官方 per-instance 映像，`--repos DIR` 用本機 mirror | 擷取 patch → `swe/predictions-<subject>.jsonl` → 官方 harness（`swe/commands.sh`）→ `ark evals swe-score DIR --report <json>` 匯入 resolved |
| Terminal-Bench | `ark evals fetch tbench --to DIR`（git clone） | `tbench:DIR[#category=system-administration&tag=…]` | 每題 build 自己的映像，於容器內跑 `run-tests.sh`；多容器 compose 題標為 unsupported |
| GAIA | `ark evals fetch gaia --to DIR`（需 HF_TOKEN、先接受條款） | `gaia:DIR[#level=1&split=validation]` | validation：官方 quasi-exact match；test：寫 `gaia/submission-<subject>.jsonl` 供排行榜 |
| OSWorld | `ark evals fetch osworld --to DIR`（git clone） | `osworld:DIR[#domain=os&index=test_small.json]`；`--desktop-image`、`--cache-dir`、`--container-env` | 在 Bot Desktop 容器內：`ark screen start` → 設定步驟 → agent → 評估；目前計算 `exact_match`、`check_include_exclude`（指令輸出或檔案），其他評估函式明確標為 unsupported，不猜 |

`ARK_OFFLINE=1` 或 `--dry-run` 時 `fetch` 只印出指令。Bot Desktop 映像：`podman build -t localhost/ark-bot-desktop:latest -f share/evals/osworld/Containerfile .`。

## 4. 內建題庫

- `builtin:smoke`（3 題）：QA（GAIA 式比對）、修 bug 的 agent 題、SWE 式 git 題（產生 patch）。
- `builtin:devops-incidents`（5 題，pro-018）：磁碟滿、憑證過期、OOMKilled、DNS 設定錯、DB 連線池耗盡；假 log／假告警，contains＋judge＋檔案檢查。Terminal-Bench 的 DevOps 子集用 `tbench:DIR#category=system-administration`。
- `builtin:roles`（25 題，pro-047）：devops、swdev、secops、data、itsupport 各 5 題繁中情境題，每題有 judge rubric 與參考說明。

## 5. 角色情境評測與逐條消融（pro-047／048）

```sh
ark evals roles --preset all --model fake/oracle --judge fake/judge --ablate --out runs/roles
```

- 同一批題目跑兩次：**有準則**（L0 核心＋組裝後的 L1/L2 角色段，與 `ark role use` 相同）與**無準則**（中性 system）。`--mode with|without|both`。
- `--provenance DIR`：把第一次蒸餾的 provenance（規則 ← 方法與出處）加進 judge 的參考資料。
- `--ablate`：每次拿掉一條準則重跑；分數下降不超過 `--threshold`（預設 0）的規則標為 `delete-candidate`。結果在 `roles.json` 與報表的 Ablation 表。
- 不修改角色載入器，只讀 `ark_kernel::roles`。

## 6. `ark distill`（pro-059／060）

```sh
ark distill run --isco 2512 --model M --judge J --questions share/evals/roles/swdev.jsonl --seed-file SEED --out DIR
```

| 階段 | 產出 |
|---|---|
| research | agent（含 web 工具）依 ISCO 職業找 1–3 位典範人物與方法，每項方法至少一個 URL 出處；沒出處的方法直接丟棄並記錄 → `research.json` |
| abstract | 方法以 `m1…`、人物以 `E1…` 交給模型（人名不進這個提示）→ `pack/<slug>/SKILL.md`（不含人名的準則）＋`provenance.json`（內部用，不隨包發佈） |
| check | 無人名（全名與長度 ≥4 的姓名片段）、無連結與引文、每條規則都追溯到有出處的方法、L2 ≤400 token；再把候選包放進角色樹副本 `tree/` 跑 `share/roles/check.py`（格式、extends/isco、預算、雜湊人名表） |
| eval | 候選準則有／無對照（可加 `--ablate`），報表在 `eval/` |
| sign | 檢查通過才簽：`ark role sign` 簽 `tree/`，再以該公鑰 `ark role verify --key` |

每個階段也可單獨執行（`research`、`abstract`、`check`、`eval`、`sign`）。regulated 狀態、保留行為與 Scope 段落沿用同 ISCO 的既有包，蒸餾不會放寬界線。

## 7. 團隊蒸餾（pro-067）

```sh
ark distill team --input DIR --authorization auth.toml --model ollama/qwen3 --slug team-oncall --isco 2522 --out DIR
```

沒有授權聲明就拒絕執行。授權聲明（TOML）：

```toml
basis = "consent"          # consent（本人同意）或 employer（公司授權，需 authority）
granted_by = "…"
authority = "…"
granted_at = "2026-10-01"
purpose = "整理團隊值班與事故處理的共同做法"   # 特定目的（個資法 §5、§19/§20）
notice_given = true        # 已告知（§8/§9）
sensitive_data = false     # 含 §6 特種個資則拒絕
retention_days = 90        # 1–365（最小化）
cross_border = false       # 模型不在本機時必須為 true（§21，已告知）
[[subjects]]
name = "王小明"
consent = true
aliases = ["小明"]
```

- 檢查依據 `docs/compliance-tw.md`（第 2 節個資法、清單 #3、#5、#6）。
- 遮罩沿用 `ark_security::pii`（email、電話、卡號、身分證、IP）＋名單內的人名／別名換成「成員A…」，檔名也遮。只在遮罩後的副本（0600）上工作；遮罩後仍出現人名就中止。
- 模型回覆含真名就拒收；出處是 `file:masked/<檔>#L<行>`。
- 執行記入稽核事件流（`distill.team`）。`ark distill purge --out DIR` 依保存期限刪除遮罩後資料與名單。

## 8. 真跑指令（待決定預算）

以下會呼叫付費模型或下載大型資料，本輪未執行。成本可先用 `--limit` 小量試跑估算。

```sh
# 0. 準備
ark evals fetch swe-lite --to ~/datasets/swe-lite
ark evals fetch tbench   --to ~/datasets/terminal-bench
ark evals fetch gaia     --to ~/datasets/gaia          # 需要 HF_TOKEN
ark evals fetch osworld  --to ~/datasets/osworld
podman build -t localhost/ark-bot-desktop:latest -f share/evals/osworld/Containerfile .

# 1. 自建題庫＋模型矩陣＋judge（便宜，先跑）
ark evals bench --suite builtin:smoke --suite builtin:devops-incidents \
  --model anthropic/claude-sonnet-4-5 --model openai/gpt-5 --judge anthropic/claude-opus-4-1 --repeat 3 --out runs/custom

# 2. 角色情境：有／無準則，再做消融
ark evals roles --preset all --model anthropic/claude-sonnet-4-5 --judge anthropic/claude-opus-4-1 --repeat 3 --out runs/roles
ark evals roles --preset devops --model anthropic/claude-sonnet-4-5 --judge anthropic/claude-opus-4-1 --ablate --out runs/roles-ablate

# 3. SWE-bench Lite（patch → 官方 harness）
ark evals bench --suite swe-lite:~/datasets/swe-lite --swe-images --harness mini --model anthropic/claude-sonnet-4-5 --limit 20 --out runs/swe
sh runs/swe/swe/commands.sh          # pip install swebench；需 Docker/Podman

# 4. Terminal-Bench（DevOps 子集）
ark evals bench --suite 'tbench:~/datasets/terminal-bench#category=system-administration' --model anthropic/claude-sonnet-4-5 --out runs/tbench

# 5. GAIA validation level 1
ark evals bench --suite 'gaia:~/datasets/gaia#level=1' --model anthropic/claude-sonnet-4-5 --out runs/gaia

# 6. OSWorld（容器內的 ark 需要金鑰：--container-env FILE）
ark evals bench --suite 'osworld:~/datasets/osworld#domain=os&index=test_small.json' --model anthropic/claude-sonnet-4-5 --container-env ~/.config/ark/eval.env --out runs/osworld

# 7. 與其他 agent 並排
ark evals bench --suite builtin:devops-incidents --model anthropic/claude-sonnet-4-5 --agents claude-code,codex,opencode --judge anthropic/claude-opus-4-1 --out runs/side
sh runs/side/external/commands.sh && ark evals collect runs/side

# 8. 蒸餾一個職業
ark distill run --isco 2522 --model anthropic/claude-sonnet-4-5 --judge anthropic/claude-opus-4-1 \
  --questions share/evals/roles/devops.jsonl --seed-file ~/keys/roles-seed.b64 --out runs/distill-2522
```

模型名稱請換成你設定好的 `provider/model`。
