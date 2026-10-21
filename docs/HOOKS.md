# Lifecycle hooks（生命週期鉤子）

讓使用者在**每次工具呼叫前後**插入自己的邏輯,是 bulge 在「安全 + 自動化」上對齊並超越參考代理(Hermes / opencode / deepseek-harness)的機制。

- `PreToolUse`:在工具執行**前**。可**封鎖**(deny)或**改寫參數**(rewrite)。
- `PostToolUse`:在工具執行**後**。可把額外內容**注入**回模型(附在工具結果後)。

鉤子宣告於 `~/.bulge/hooks.json`,沿用 Claude Code / Hermes 的格式,既有知識可直接轉移。檔案不存在 = 無鉤子(純通過)。

## 設定格式

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "exec",
        "hooks": [
          { "type": "deny", "reason": "git push 一律人工執行", "when": "git push*" }
        ]
      },
      {
        "matcher": "write|edit",
        "hooks": [
          { "type": "command", "command": "~/.bulge/hooks/scan.sh", "timeout_ms": 8000 }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "exec",
        "hooks": [ { "type": "command", "command": "~/.bulge/hooks/note.sh" } ]
      }
    ]
  }
}
```

頂層也接受省略 `hooks` 外層的裸形式:`{ "PreToolUse": [...], "PostToolUse": [...] }`。

### matcher
工具名比對:`*` 或留空 = 全部;否則以 `|` 分隔的精確工具名清單(如 `"write|edit|exec"`)。內建工具:`read` `write` `edit` `glob` `grep` `exec`,以及 MCP 工具 `mcp__<伺服器>__<工具>`。

### action(`type`)
| type | 事件 | 作用 |
|---|---|---|
| `deny` | Pre | 封鎖此呼叫;`reason` 回給模型;`when`(glob,比對主要資源:檔案路徑或 exec 指令)省略為「永遠」。 |
| `allow` | Pre | 短路放行,停止評估後續 action——可在廣泛 `deny` 前開例外。`when` 同上。 |
| `command` | Pre/Post | 執行**主機**指令(見下)。 |

`deny`/`allow` 為純程式判斷,不執行任何主機程式——這是最安全地強制「沙箱本會放行」之策略的方式。

## command 鉤子協定

`command` 以 `sh -c` 在**主機上(沙箱之外)**執行,等同使用者自行安裝的程式(與 MCP 伺服器同級的信任假設:bulge 只因使用者把它寫進自己的 `hooks.json` 才會執行)。

- **stdin**:工具呼叫的 JSON,`{"event","tool","arguments",[ "result" ]}`(`result` 僅 Post)。
- **stdout(JSON,全部欄位選填)**:
  ```json
  { "action": "allow|deny|continue", "reason": "...", "context": "附加給模型的文字", "arguments": { "改寫後的參數": "..." } }
  ```
  - `action: "deny"`(Pre)→ 封鎖,`reason` 回模型。
  - `arguments`(Pre)→ 取代該呼叫的參數。
  - `context` → 附在工具結果後,送回模型。
- **結束碼**:非 JSON stdout 時,`exit 0` 且有輸出 → 當作 `context` 注入;**`exit != 0`(Pre)→ 封鎖**,stderr 為原因(相容 Claude Code 的 exit 2 慣例)。
- **逾時**:預設 10 秒(`timeout_ms` 可調);逾時或被取消 → 封鎖。

## 安全與併發
- 任一有鉤子的工具一律視為**併發屏障**(保序,因 command 鉤子可能有副作用);無鉤子工具沿用內層 dispatcher 的併發判斷。
- `deny`/`allow`/逾時/取消皆**fail-closed**(出錯即封鎖),符合 bulge 的謹慎預設。
