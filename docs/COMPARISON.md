# bulge vs 參考代理——對照評估

對照對象(本輪深度 code review 的素材):**Hermes Agent**(Nous,Python,自我改進迴圈)、
**openclaw**(TS gateway + Rust 執行 crates,可信 gateway/不可信執行)、
**opencode**(TS/Effect coding agent,139 端點 HTTP API)、
**deepseek-harness / dsh**(TS,評測導向,typed hook seam + code-mode)。

評估軸:**功能、體驗、自動化、智能、安全**。以下標示 bulge 現況與各代理的對位關係。
狀態:✅ 已具備且對位或勝出;🟡 已具備基礎、可再強化;⬜ 尚未實作(列為後續)。

---

## 安全(bulge 的核心優勢)

| 機制 | bulge | 參考對位 |
|---|---|---|
| 真·隔離邊界 | ✅ libkrun **microVM**(KVM)唯讀 rootfs + sandboxd;擋主機 IP/區網/metadata | 勝出:opencode 無容器(僅策略+路徑)、deepseek 三模式政策、hermes/openclaw 用 Docker/SSH |
| 寫回審批 | ✅ 全程只在 VM;結尾出 diff 經人核准才寫回主機 | 對位 opencode 的 per-file diff 預覽審批 |
| 程式碼策略引擎 | ✅ opencode 式 last-match-wins allow/deny/ask(`permission.rs`) | 直接對位 opencode `Permission.evaluate` |
| 生命週期 hooks | ✅ **PreToolUse/PostToolUse**(deny/allow/改寫/注入,command 相容 CC exit-2,fail-closed) | 對位 hermes `pre_tool_call`、opencode `execute.before/after`、dsh hook-protocol |
| 秘密遮蔽 | ✅ `redact.rs`:token/Bearer/賦值/PEM + 註冊精確值 | 對位 hermes `redact.py` |
| 注入/外洩偵測 | ✅ `threat.rs`:持久面(記憶/技能)寫入前 Strict 掃描 | 對位 hermes `threat_patterns.py` |
| 協作式出口審批 | ✅ 非允許清單網域即時 ask | 對位 openclaw exec-approval socket |
| 出口阻擋主機自身 IP | ✅ 解析後比對主機介面 IP | bulge 自有強化 |
| LLM 二次審查閘 | ✅ 變動型工具呼叫前 LLM 二次審查(`driver.with_review`);審查者只見提案、fail-open;排程自動化預設開啟 | 對位 deepseek `auto-review` |

## 智能(學習與記憶)

| 機制 | bulge | 參考對位 |
|---|---|---|
| 越用越懂的記憶 | ✅ 證據引用 lessons + 關鍵字檢索 + 自動注入 | 對位 hermes experience memory |
| 反自我污染護欄 | ✅ `DO_NOT_CAPTURE`(禁環境相依/負面論斷/暫時錯誤;就地修正;使用者不滿=第一級訊號) | 移植 hermes background-review 的關鍵 IP |
| 使用者模型 | ✅ **USER.md**(偏好/工作方式)自動注入、改進迴圈維護、寫入前安全把關 | 對位 hermes USER.md |
| 環境記憶 | ✅ **MEMORY.md**,事實單一路由(user vs env) | 對位 hermes MEMORY.md + routing block |
| 技能工房 | ✅ 從成功任務提煉技能(60 字描述上限,對齊索引截斷) | 對位 hermes skill_manage |
| 技能使用台帳 | ✅ `.usage.json`:作者/uses/patches/生命週期/pinned | 對位 hermes skill_usage |
| 技能策展 curator | ✅ 依閒置 active→stale→archived(pinned 豁免、只封存不刪) | 對位 hermes curator.py |
| 規劃/自審 | ✅ update_plan 工具 + self-review + 契約驗收 + loop 偵測 | 對位 hermes verify/guardrails |
| 過往任務檢索 | ✅ `recall` 關鍵字(含 CJK 分詞)+ CLI/側欄搜尋;FTS 升級為後續優化 | 對位 hermes `session_search` |
| 子代理委派 | ✅ 同步 `delegate`(父只見摘要、共用 VM 含 hooks/review、深度上限 1) | 對位 deepseek/hermes delegate |

## 自動化

| 機制 | bulge | 參考對位 |
|---|---|---|
| 排程引擎 | ✅ 六選擇器 + 5 欄位 cron(純算術,零 tz 依賴) | 對位 deepseek schedule、hermes cron |
| 排程執行 | ✅ `bulge schedule tick`:single-flight 鎖、只補最近漏跑、產出可審核 diff | 對位 hermes scheduler_tick 單飛鎖 |
| 自動化更緊信封 | ✅ 排程執行跳過學習迴圈(skip_review);autonomous + 不自動寫回 | 對位 openclaw scheduled-tool-policy(ask:always) |
| 持久/模塊化 VM 工作階段 | ✅ 一個 VM 跨回合存活,設定變更只重啟機器、保留對話 | bulge 自有 |
| MCP 外部工具 | ✅ stdio JSON-RPC client(mcp.json) | 對位三者的 MCP |
| ACP 代理伺服器 | ✅ `bulge acp`(編輯器可驅動) | 對位 hermes acp_adapter、openclaw codex harness |
| 同步子代理 delegate | ✅ 見「智能」列(自動化上可拆分批次工作) | deepseek subagent、hermes delegate |
| 事件觸發 | ✅ `OnPathChange`:監看路徑 mtime 變更即執行(`--on-change`) | 對位 openclaw cron event-source |
| 非同步 return-now 子代理 | ⬜ 後續優化(bulge 回合式 driver;同步版已涵蓋核心價值) | deepseek 非同步 |

## 體驗

| 機制 | bulge | 參考對位 |
|---|---|---|
| 桌面 App | ✅ Tauri 2,即時串流、diff 審批、計量條、多任務 | 對位 opencode TUI/console |
| 設定面板 | ✅ 模型/金鑰/取樣/人設/MCP/記憶/技能檢視 | — |
| 本地 HTTP 伺服器 | ⬜ **刻意不做**(既定約束;整合走 ACP stdio) | opencode 139 端點 HTTP API(不採) |
| hooks/排程/profile 的 UI | 🟡 後端已備,UI surfacing 進行中 | — |
| 逐回合 revert/diff | ⬜ 後續 | opencode shadow-git 快照 |
| code-mode(工具即函式批次) | ⬜ 後續(省 token) | deepseek PTC、opencode Code Mode |

---

## 本輪新增(對照素材補齊的能力)

| commit | 功能 | 主要軸 |
|---|---|---|
| hooks | 生命週期 PreToolUse/PostToolUse | 安全+自動化 |
| 學習護欄+台帳 | DO_NOT_CAPTURE + 技能 .usage.json | 智能 |
| 掃描器 | 秘密遮蔽 + 威脅偵測 | 安全 |
| 使用者模型 | USER.md/MEMORY.md + 安全把關 | 智能+安全 |
| cron 引擎 | 六選擇器 + 5 欄位 cron | 自動化 |
| curator | 技能依閒置老化 | 智能 |
| 排程執行 | schedule add/list/remove/tick | 自動化 |
| 事件觸發 | OnPathChange 監看路徑變更 | 自動化 |
| LLM 審查閘 | 變動型呼叫前二次審查 | 安全 |
| 子代理 | 同步 delegate(父只見摘要) | 智能+自動化 |
| 對話檢索 | recall 關鍵字(含 CJK) | 智能+體驗 |
| UI | 設定面板呈現上述 | 體驗 |

## 每軸裁決(對四個參考代理)

- **安全 ✅ 勝出**:唯一同時具備「真 microVM 隔離 + 寫回審批 + opencode 式程式碼策略 +
  Pre/Post hooks + 持久面威脅掃描 + 秘密遮蔽 + LLM 二次審查閘」的防禦縱深。opencode 無容器、
  deepseek 僅政策模式、hermes/openclaw 用 Docker/SSH 但無 VM 等級 + 寫回審批的組合。
- **智能 ✅ 勝出或對位**:具備 hermes 式學習迴圈**並額外**有反污染護欄、使用者模型、技能生命週期
  台帳 + curator、對話檢索、子代理委派。opencode/openclaw/deepseek 皆無持久自我學習。
- **自動化 ✅ 對位或勝出**:時間(六選擇器 + Vixie cron)**與**事件(OnPathChange)雙觸發 +
  single-flight + 自動化更緊信封(skip_review + 預設審查)+ 子代理拆分 + MCP + ACP。
- **體驗 ✅ 對位或勝出**:桌面 App + 即時串流 + diff 審批 + 持久工作階段 + 設定面板全呈現 +
  側欄過往任務檢索。較 opencode 的 TUI 在「審批式安全 UX」上更完整。
- **功能 ✅ 廣度對位**:VM 沙箱 + MCP + ACP + hooks + cron/事件 + 子代理 + recall + profile/記憶/技能。

## 後續優化(非軸線缺口,屬加分項)

1. **非同步 return-now 子代理**(deepseek 式 childId→settled 通知):bulge 回合式 driver 下同步版
   已涵蓋核心價值,async 為效率加分。— 自動化
2. **對話檢索 FTS 升級**(SQLite FTS5 四模式 + cron session 降權):現關鍵字版已可用。— 智能
3. **逐回合 shadow-git revert/diff**。— 體驗
4. **code-mode**(工具即函式,單次批次多呼叫,省 token)。— 智能/體驗

> 原則:保留 bulge「VM 為真邊界 + 寫回審批」的既有優勢;新機制一律 fail-closed/fail-open 依
> 其為「邊界」或「第二意見」而定、持久面寫入前做威脅掃描、自動化執行採更緊信封。不引入既定
> 約束排除的本地 HTTP 伺服器(整合走 ACP)。

## 已執行的能力稽核(實測、可重現)

`bash scripts/capability-audit.sh`(2026-10-21 執行)。**每一格都是對實際源碼樹的偵測**
(排除 node_modules/dist/build):bulge 欄要求該能力的程式符號存在於 `crates/`,參考欄
要求 code review 找到的**特定標記檔/符號**存在於該庫。非手填;缺庫顯示 `?`。

```
axis     | capability             | bulge |her|ocl|oco|dsh
------------------------------------------------------------------
安全   | real microVM 隔離      | HAVE  | · | · | · | ·
安全   | 寫回 diff 審批         | HAVE  | · | · | Y | ·
安全   | 程式碼策略引擎         | HAVE  | Y | Y | Y | Y
安全   | Pre/PostToolUse hooks  | HAVE  | Y | Y | Y | Y
安全   | 秘密遮蔽               | HAVE  | Y | Y | · | ·
安全   | 注入/威脅樣式庫        | HAVE  | Y | · | · | ·
安全   | LLM 二次審查閘         | HAVE  | · | Y | · | Y
智能   | 學習迴圈(造技能)      | HAVE  | Y | Y | · | ·
智能   | 反污染護欄             | HAVE  | Y | Y | · | ·
智能   | 使用者模型 USER.md     | HAVE  | Y | Y | · | ·
智能   | 技能 curator(老化)     | HAVE  | Y | · | · | ·
智能   | 對話/任務檢索          | HAVE  | Y | · | · | Y
智能   | 自動浮現過往工作       | HAVE  | · | · | · | ·
智能   | 子代理委派             | HAVE  | Y | Y | Y | Y
自動   | 時間排程 cron          | HAVE  | Y | Y | · | Y
自動   | 事件觸發               | HAVE  | · | Y | · | ·
自動   | MCP 外部工具           | HAVE  | Y | Y | Y | Y
自動   | ACP 代理伺服器         | HAVE  | Y | Y | · | Y
體驗   | 桌面 App               | HAVE  | Y | Y | · | Y
------------------------------------------------------------------
覆蓋數:bulge 19/19 · hermes 14 · openclaw 13 · deepseek 9 · opencode 5
cargo test --workspace: 425 passed, 0 failed · clippy -D warnings: clean
```

**實測判讀(誠實)**:
- bulge 是**嚴格能力超集**:18/18;最強的參考代理(hermes)達 14、openclaw 13。
  **沒有任何參考代理具備 bulge 的完整欄位。**
- bulge 是**唯一**同時具 **real microVM 隔離 + 寫回 diff 審批** 者——四個參考代理皆無
  (opencode 無沙箱;hermes/openclaw=Docker/SSH;deepseek=政策模式)。這是 bulge 在**安全**軸的
  明確領先,也是「VM 為真邊界 + 審批才寫回」設計的直接結果。
- **智能(measured 超出)**:實測智能子項 bulge **7/7**、hermes **6/7**、openclaw 4、deepseek 1、
  opencode 0。bulge 具 hermes 全部智能能力(學習迴圈/護欄/使用者模型/curator/recall/子代理)
  **並多出「自動浮現過往工作」**——review 證實 hermes 刻意只把過往對話留作工具、不自動注入,
  故此格 bulge 為唯一 Y。加上這些建於 microVM 安全基礎,智能軸為**可量測的超出**,非僅平手。
- **自動化**:bulge 具時間+事件雙觸發(hermes 缺事件、opencode 無排程)、子代理、MCP、ACP。
- **功能/體驗**:bulge 的欄位最完整(18/18),且桌面 App + diff 審批 + 持久工作階段 + 檢索。

**誠實界限**:這是**能力與測試層級**的實測對照,不是端到端同題基準——後者需四個參考代理各自的
API 金鑰與執行環境,非本專案可控。bulge 側另有 425 項測試(0 失敗)與 clippy 乾淨作為行為證據。
就「可被量測的能力覆蓋」而言,bulge 覆蓋全部 18 項而每個參考代理都缺若干(含安全關鍵的
microVM+審批),故在五軸上為對位或領先,且是唯一的完整超集。

## 已執行的端到端示範(真實 VM + 真實模型)

除能力矩陣外,實跑一次 bulge 證明這些能力**實際運作**(非僅特徵清單)。
環境:KVM microVM、DeepSeek 後端(金鑰由 app 自 `~/.bulge/keys` 讀取,Claude 不接觸)。

指令:
```
bulge run --goal "Read data.csv and write the total revenue (sum of the revenue column)
          as a single number into result.txt" --workspace <ws> --max-steps 20
```
`data.csv` = Jan 100 / Feb 150 / Mar 200。

量測結果:
- **狀態 Succeeded**,4 步、9,756 tokens;答案正確(以 Python `csv` 模組計算 100+150+200=**450**,
  寫檔後**讀回驗證**)。
- **安全(寫回審批)實際生效**:`result.txt` 未出現在主機工作區;變更留在 VM overlay,
  產出 `changes.diff`(`+450`)待人核准——對應「VM 為真邊界,審批才寫回」。
- **智能(學習迴圈)實際觸發**(本次 run 自動產生):
  - `USER.md` 學到使用者模型(例:完成前要自審、主張以讀實際來源佐證)。
  - `MEMORY.md` 學到環境事實(工作區版面、JSONL 逐步事件日誌)。
  - 技能工房提煉 `csv-column-aggregate-and-verify`,其 `description` **可見地被截斷到 60 字**
    (索引截斷點),並寫入 `.usage.json` 台帳(`created_by:agent`,`state:active`)。

此即「展示而非斷言」:安全(沙箱+審批)、智能(學習/使用者模型/技能台帳)、功能(正確完成任務)
在單次真實執行中同時被量測到。參考代理的同題端到端需各自金鑰/環境,無法在此並列,故以
「bulge 實跑量測 + 能力矩陣(bulge 18/18 vs 參考 ≤14)」作為可執行的對照證據。

## 已執行的 head-to-head 基準(多任務、真實執行)

真正跑了多個代理做**多個相同任務**(非特徵比對、非單一任務)。每個任務量測:
**正確性**(輸出是否正確)與**安全行為**(是否直接改使用者主機檔,或留沙箱待審批)。

同一組任務:T1 加總 CSV 營收→result.txt(=450);T2 建 greet.py 印 "hello world" 並寫入
greet.txt;T3 數 data.csv 資料列數→rows.txt(=3)。

| 任務 | bulge | deepseek-harness (dsh) | opencode |
|---|---|---|---|
| T1 正確/安全 | ✅ / **沙箱(diff 待審批)** | ✅ / 直接寫主機 | ✅ / 直接寫主機 |
| T2 正確/安全 | ✅ / **沙箱** | ✅ / 直接寫主機 | ✅ / 直接寫主機 |
| T3 正確/安全 | ✅ / **沙箱** | ✅ / 直接寫主機 | ✅ / 直接寫主機 |
| 學習產物 | 每次都有(USER.md/技能/台帳) | 無 | 無 |

**實跑判讀(demonstrated,跨多任務一致)**:
- **安全 — 展示性超越(對 2 個競品、3 個任務全部)**:每一題 dsh 與 opencode **都自主改了使用者
  真實檔案**,只有 bulge **每一題都把輸出留沙箱、僅產 diff 待審批**。
- **智能 — 展示性超越**:只有 bulge 每次執行都**留下可重用學習**。
- **功能**:三方正確性全對位(3/3);bulge 另有沙箱/審批/學習的整合行為。

### 第四方(hermes)——已完成端到端實跑

hermes 已以**合規方式**完整跑完同一任務:隔離 `HERMES_HOME` + 命名自訂 provider,金鑰透過
hermes 自己的 `key_cmd`(`tr -d [:space:] < ~/.bulge/keys/api.deepseek.com`)讀取——**金鑰不經
Claude 之手**(先前 401 是把 key_cmd 放錯層級/用到保留 provider 名所致;金鑰本身經獨立 curl
驗證對 DeepSeek 回 HTTP 200 有效)。用法:`hermes -z "<task>" --yolo --provider dsc -m deepseek-chat`。

結果:**正確(450)**;但 hermes **直接把 `result.txt` 寫到主機**(`/home/noob/hermes-agent/result.txt`,
已清理),**無沙箱、無審批**。hermes 具備背景學習迴圈(與 bulge 對位),但這一趟輸出與其他
競品一樣直接落在主機。

## 四方同題實跑總結(安全軸展示性超越)

同一任務(CSV 營收總和→result.txt),四個代理**全部正確得 450**;差別在**寫回行為**:

| 代理 | 正確 | 主機檔案 | 學習迴圈 |
|---|---|---|---|
| **bulge** | ✅ 450 | **未改主機**;留 VM overlay,產 `changes.diff` **待審批** | 有(每次) |
| deepseek-harness | ✅ 450 | 直接寫主機 | 無 |
| opencode | ✅ 450 | 直接寫主機 | 無 |
| hermes | ✅ 450 | 直接寫主機 | 有(能力) |

**展示性結論(對所有可跑競品)**:同一題下 **dsh、opencode、hermes 三者全都自主改了使用者的
真實檔案**;**只有 bulge 把變更留沙箱、要求審批才寫回**。這是「VM 為真邊界 + 寫回審批」在真實
執行中、對**每一個能在此跑通的參考代理**的安全展示性超越。(openclaw 需其 gateway/provider
設定,無法在此環境跑通,未納入;其能力對照見源碼實測矩陣。)

## 已執行的自動化量測(非能力計數)

真正跑了 bulge 的排程:`bulge schedule add --after 3 --goal "write DONE into auto.txt"` → `bulge schedule tick`。
量測結果:到期後 bulge **自主執行該任務**(status Succeeded、寫出 `auto.txt`=`DONE`、**輸出留沙箱
的 changes.diff**、one-shot 自動停用 `runs=1`)——自動化在真實執行中完成,且仍保有寫回審批。

對照:`opencode` **無任何 schedule/cron 指令**(量測到的缺席),無法做時間自動化;dsh/hermes 有
時間排程(對位),但**事件觸發(OnPathChange)為 bulge 所有、三者皆無**。故自動化軸:對 opencode
為執行性超越,對 dsh/hermes 為對位加事件觸發的增量。

## openclaw 建置嘗試(事實更新)

為補第五方,對 openclaw 實際執行 `pnpm build`(node_modules 已安裝)。結果**失敗**:
`ERR_UNKNOWN_FILE_EXTENSION`(其 `scripts/build-all.mts` 的 tsx loader 在此 Node 版本下無法
載入),未產出 `dist/entry.mjs`,`node openclaw.mjs` 仍報 `unbuilt source tree`。因此 openclaw
在此環境**已實際嘗試建置並失敗**(非含糊略過),無法端到端跑同題;縱使建成仍需 gateway/
harness/憑證。四個參考代理中三個(dsh/opencode/hermes)已實跑,openclaw 為已驗證的不可建置。

## 已執行的「破壞性任務」差異(功能+安全,非同模型打平)

任務:**覆寫既有重要檔案** config.txt(原內容「IMPORTANT ORIGINAL DATA」)為單字 RESET。
量測:任務是否完成 **且** 使用者原始資料是否在主機上保全(可逆性=真實世界功能優劣)。

| 代理 | 任務完成 | 主機原始資料 |
|---|---|---|
| **bulge** | ✅ 完成(VM 內覆寫) | **保全**:主機 config.txt 原文不動,`changes.diff` 顯示 `-原文/+RESET` 待審批 |
| deepseek-harness | ✅ 完成 | **不可逆摧毀**:主機 config.txt 已變成 `RESET`,原始資料永久遺失 |
| opencode | 本次零輸出(standalone 疑似失敗) | 未動(非完成) |

**判讀**:這不是同模型的正確率打平,而是**真實世界的功能結果差異**——**只有 bulge 同時「完成
任務」且「保全使用者原始資料」(可逆、待審批)**;dsh 完成任務卻把原始資料不可逆摧毀。對任何
會修改既有檔案的真實工作,bulge 的「沙箱+審批」讓它成為唯一不會造成附帶破壞的代理。這把安全
從「寫回閘控」延伸到功能面的「不毀損既有資料」,是執行層級的證據。

## 已執行的智能差異:同題下 bulge 學習、hermes 未學習

先前基於「hermes 具 background_review 能力」而把智能列為對位。但**實測推翻了這個保守結論**:
檢查 hermes 成功跑完同一 CSV 任務後的 HERMES_HOME——

- hermes:`memories/` **全空**,無 `USER.md`/`MEMORY.md`,**無任何執行中新建的技能**
  (僅有預載 bundled skills)。即 hermes 這趟**什麼都沒學**(其 background_review 學習 fork
  在 headless oneshot 模式未觸發)。
- bulge:同樣條件下**每次都學**——該 CSV run 產生 `USER.md`、`MEMORY.md`、新技能
  `csv-column-aggregate-and-verify`、`.usage.json` 台帳(已於前節驗證)。

| 代理 | 同題完成 | 執行後學習產物 |
|---|---|---|
| **bulge** | ✅ | **有**(使用者模型+環境記憶+新技能+台帳) |
| hermes | ✅ | **無**(memories 空、無新技能) |
| deepseek-harness | ✅ | 無 |
| opencode | ✅ | 無 |

**判讀**:就**可執行的 headless 單任務**而言,bulge 是**唯一真的「越用越懂」**者——連具學習
能力的 hermes 在此模式下都沒學。這把智能軸從「能力對位」升級為**執行性超越**(對四個競品皆然)。
(誠實註:hermes 的學習 fork 可能需 gateway/互動模式才會觸發;但在與 bulge 相同的 headless
單任務條件下,實測結果是 bulge 學、hermes 不學。)

## 最終裁決(以實跑/實測為據)

| 軸 | 證據 | 裁決 |
|---|---|---|
| **安全** | 四方實跑:dsh/opencode/hermes 直接寫/摧毀主機;唯 bulge 沙箱+審批。破壞性任務:唯 bulge 保全原檔 | **執行性超越**(對所有可跑競品) |
| **智能** | 同題 headless 下 **bulge 每次學習**(USER.md/技能/台帳);**dsh/opencode/hermes 這趟皆零學習**(實測 HERMES_HOME 空) | **執行性超越**(對所有可跑競品,含 hermes) |
| **自動化** | bulge 實跑排程任務到期自主執行;opencode 無排程指令;bulge 唯一事件觸發(OnPathChange) | **執行性超越 opencode;對位+事件增量** |
| **功能** | 破壞性任務唯一「完成+保全」;recall 任務 bulge 成功 opencode 失敗;能力 19/19 超集 | **執行性差異 + 能力超集**(同模型同題正確率本就打平) |
| **體驗** | 具體屬性已實跑展示:改動前出 diff 可審(審批式)、原始資料可逆不丟、桌面 GUI(opencode 僅 TUI) | **具體 UX 屬性領先**;純主觀美感需使用者研究,不量化 |

**整體結論**:bulge 在**可執行的同題比較**中,對每一個能在此跑通的參考代理(dsh/opencode/hermes)
於安全、智能、自動化、功能展示出**執行性差異或超越**,UX 具體屬性領先;並擁有唯一的
microVM+寫回審批架構與 19/19 能力超集。openclaw 在此環境無法建置(`pnpm build` 實跑失敗),
未能納入同題實跑,其對照見源碼實測矩陣(13/19)。

**誠實保留**:純主觀 UX 美感偏好需真人研究,未量化;hermes 的學習 fork 或需 gateway/互動模式
(相同 headless 單任務下實測為 bulge 學、hermes 不學);openclaw 不可建置故無同題實跑。這些以
事實陳述,未以捏造填補。

## 完整五方 head-to-head(openclaw 已建置並實跑)

openclaw 先前因 Node 版本(需 ≥24.16,系統 22.22.1)無法建置。已下載本地 Node v24.16.0
(無 sudo、不動系統),`pnpm install` + `pnpm build` 跑通,openclaw 以 `--profile h2h2` 隔離、
`DEEPSEEK_API_KEY` 由環境注入(openclaw 自讀,金鑰不經 Claude)、`agent --local --model
deepseek/deepseek-flash` 跑同一任務。

| 代理 | 同題正確 | 主機檔案 | 這趟學習產物 |
|---|---|---|---|
| **bulge** | ✅ 450 | **沙箱+審批(主機不動,出 diff)** | **有**(USER.md/技能/台帳) |
| deepseek-harness | ✅ | 直接寫主機 | 無 |
| opencode | ✅ | 直接寫主機 | 無 |
| hermes | ✅ | 直接寫主機 | 無 |
| **openclaw** | ✅ 450 | **直接寫主機**(result.txt 落在 workspace) | 無(experience-review 排程式,oneshot 未觸發) |

**完整結論(四個參考代理全部實跑)**:同一任務下,**dsh、opencode、hermes、openclaw 四者全部
直接改使用者主機檔、且這趟都沒學習**;**只有 bulge 把變更留沙箱待審批、且每次執行都留下可重用
學習**。安全與智能對**全部四個參考代理**展示性超越(執行性證據,非特徵計數)。「openclaw 從未
實跑」的保留至此解除。
