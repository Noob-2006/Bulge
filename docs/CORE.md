# Bulge 核心設計（目標：Bessemer L4）— 草案 2026-10-20

L4 = 整份工作從頭到尾自主完成。bulge 的做法：**VM 內部完全自主；跨越邊界的動作（寫回主機、高風險外連）由規則閘門判斷，必要時才問人**。

## 0. 自主模式（每個工作可選）
| 模式 | 人要做的事 | 對應等級 |
|---|---|---|
| 協作 | 核准計畫 + 每次寫回主機的 diff | L2 |
| 自主（**預設**） | 只在結尾核准最終 diff；中途只有高風險閘門會打斷 | L3–L4 |
| 全自動 | 規則判定低風險的 diff 直接套用（工作區有快照可回復）；高風險仍要人 | L4 |

寫回快照（已實作，`bulge-vm::writeback`）：**每一次**寫回（全自動、人工核准、`--writeback`）都先把會碰到的路徑原狀（內容、權限、symlink 目標、被刪目錄的整棵樹、將新建的父目錄）存到 `<job>/writebacks/<id>/` 並落盤，之後才套用；manifest 即稽核紀錄（路徑、前後狀態、是否無人審批、略過原因、回復時間與衝突）。一鍵回復：`bulge rollback <job> [<id>]` 或 App「寫回紀錄」。寫回後又被改過的路徑視為衝突、不覆蓋（`--force`／「仍要覆蓋」才覆蓋），所以回復舊寫回不會蓋掉之後的修改。全自動依 `risk::gate` 套用 Low／Medium，附帶產物與 High 留給人。

## 1. 工作模型（Job）
- `Job { goal, deliverables[], acceptance[], autonomy, budget, workspace }`。
- 開工第一步：模型把需求整理成**交付物契約**（要產出哪些檔案、格式、驗收條件），寫進 job 狀態；之後的驗證都對照它。
- 狀態全部在主機端：只追加的事件日誌（JSONL，參考 DSH session-persistence）+ SQLite 索引（參考 opencode session 表）。
- **恢復**：每一步一次模型呼叫、從持久歷史續跑（opencode）；寫前先記執行宣告（write-ahead claim）；完成標記帶 harness 指紋（Harness² runmark）。bulge 或 VM 崩潰後，從日誌重建並重開 VM（工作區 overlay 的未套用改動先匯出到主機端暫存）。

## 2. 代理迴圈
```
規劃 → [執行步驟 → 工具結果 → 守衛檢查]* → 完成閘門 → 交付（diff 審批 / 套用）
```
- **規劃**：todo 清單（DSH todo_write）＋ 交付物契約；每完成一項更新。偏離偵測：工具動作的目標不在計畫範圍內 → 提醒，持續偏離 → 暫停。
- **預算（硬上限）**：步數 / token / 牆鐘 / 金額。到 80% 進入收尾模式：停用探索類工具、要求先把已有成果交付（opencode max-steps）。到 100% 強制停止並交付現況。
- **迴圈偵測**：openclaw 六種偵測器（重複、參數微調、乒乓、無進展輪詢、未知工具、全域斷路器），結果雜湊去除易變欄位；同錯 3 次停。觸發時依 Harness² 錯誤分類注入「一個有界替代方案 + 停止條件」，再犯則暫停。
- **完成閘門（自我驗證）**：模型宣告完成時，先跑**機械檢查**（交付物存在、能被解析、指定的測試/指令通過，全在 VM 裡跑），再跑**自我審查**（Harness² 六準則）。不通過就退回迴圈，最多 N 次，之後誠實回報未完成項目。
- **context 與省 token**：REFERENCES §3 全套（快取穩定前綴、修剪、壓縮、spill、延遲載入工具）。

## 3. 自動風險判斷（規則式）
- VM 內的動作預設低風險（VM 是邊界）。
- 需要判斷的是**跨邊界**的動作：
  - 寫回主機：依 diff 內容分級（只改文字檔 / 新增 vs 刪除大量檔案 / 改可執行檔、設定檔、隱藏檔）。
    附帶產物（直譯器快取、建置輸出）：依工作區自己的 `.gitignore`、`.git/info/exclude` 與使用者的 `~/.bulge/review_ignore`（gitignore 語法，缺檔用內建預設）判定，git 的優先順序；規則讀主機端執行前的版本（guest 改 `.gitignore` 無效）。符合者仍列出並標明命中的規則，只是預設不勾選、`--writeback` 不寫回。
  - 網路：**DNS 閘門**（新）——guest 的 DNS 已經只能打到 bulge 的轉送位址，改成由 bulge 自己解析並記錄網域：常見套件來源與工作相關網域放行；第一次出現的網域在自主模式下**放行並記錄**（使用者決定，2026-10-20），協作模式可設為詢問；連線只能打到 DNS 回答過的 IP（擋掉直接用 IP 外洩）。這同時緩解「資料外洩到公網」漏洞。
  - 金鑰、使用者資料：永不進 VM。
- LLM 審查只當第二意見（DSH auto-review 的分類）。

## 4. Harness 樹（bulge 自己的可演化部分）
- `~/.bulge/harness/`：system prompt、guardrails、工具說明、記憶（USER.md / MEMORY.md）、skills、hooks。資料模型照 Harness² `Tree` + SurfaceSpec + 驗證器（常駐字數預算、skill 必須有觸發語）。
- 有版本、可 diff；任何修改都走同一套 diff 審批。

## 5. 越用越懂
1. **記憶**（openclaw）：壓縮前 flush、閒置整合（回傳 add/merge/supersede 操作）、不可信來源不能成為記憶。
   儲存（已實作，`bulge-harness::store`）：`~/.bulge/harness/memory/memory.db`（SQLite，WAL）存教訓與 USER／ENV 兩個 profile；教訓以 FTS5＋BM25 取用（cue 權重 2、內文 1，乘信心值），中文以 bigram 索引；每次取用記 `uses`／`last_used_at`。首次開啟時一次匯入舊的 markdown 記憶（檔案保留不再讀取）。
2. **skills**（openclaw skill_workshop）：自動建立 / 修補，改前存版本，30 天未用封存。
3. **harness 改進器**（Harness² 便宜版）：閒置時或工作失敗 / 結果分歧時，讀執行紀錄，提出**引用證據**的 harness 修改 → 驗證器 → （可選）在 VM 裡重播同類任務試跑 → 使用者核准 → 寫入教訓庫（cue / lesson / evidence / confidence，含污染標記、使用次數、衰減）。

## 6. 評估
- bulge headless 模式（同一核心、無 UI、JSONL 事件流）+ Harness² BenchmarkAdapter → 用 JobBench（評審可接 DeepSeek）量測；加一組 bulge 自己的通用任務集（含失敗注入）。
- 方法照 Harness²：盲評、評分失敗＝排除、答案不進 context、固定種子。
- 「到達 L4」的判準：自主模式下，在評估集上的完成率與人工協作模式相當，且零次越界。

## 7. 實作階段
| 階段 | 內容 | 轉寫標記（dsh） |
|---|---|---|
| C1 | 事件日誌 + job 狀態 + 恢復 | DSH session-persistence-jsonl、opencode session 表 |
| C2 | 迴圈本體：步進、工具分派（接 bulge-vm）、預算、收尾模式 | DSH agent-loop、opencode max-steps |
| C3 | 守衛：迴圈偵測、權限規則、風險分級、DNS 閘門 | openclaw tool-loop-detection、opencode permission |
| C4 | context：修剪、壓縮、spill、快取穩定 | DSH compaction、openclaw session-pruning、opencode compaction |
| C5 | 完成閘門 + 規劃 / 偏離偵測 | Harness² 準則（prompt）、DSH goal / todo |
| C6 | harness 樹 + 記憶 + skills + 改進器 | Harness² tree / library、openclaw memory / skill-workshop |
| C7 | headless CLI + Harness² adapter + 評估 | Harness² spec / substrate |

每階段結束都有真實任務驗收（在 VM 裡跑），不以單元測試代替。
