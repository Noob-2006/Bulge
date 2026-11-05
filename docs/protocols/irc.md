# IRC（RFC 1459／2812 + IRCv3）對照表

SE Agent 實作：`crates/seagent-channel/src/irc.rs`（1638 行）。上游：OpenClaw `extensions/irc/src/{client,channel}.ts`、Hermes `plugins/platforms/irc/adapter.py`（622 行）；opencode 無 IRC。

| 面向 | 官方規格 | OpenClaw | Hermes | SE Agent |
|---|---|---|---|---|
| 傳輸 | TCP 明文 6667 / TLS 6697；一行 ≤512 bytes（含 CRLF） | TLS／明文，`client.ts` 自寫 socket | asyncio 自寫（`adapter.py:181`） | `seagent_net::stream::Stream`（TCP/TLS），`MAX_LINE = 512`（`irc.rs:35`） |
| 註冊 | `CAP LS 302` → `CAP REQ` → `CAP END`，`PASS`/`NICK`/`USER`，等 `001` | 有 | `PASS/NICK/USER` + 等 001、暱稱衝突重試（`adapter.py:487`） | 同（`irc.rs:694-705`），並解析 `RPL_ISUPPORT`（005） |
| 能力協商 | `server-time`、`message-tags`、`echo-message`、`account-tag`、`sasl` | 部分 | 部分 | `irc.rs:791` 逐一要求；`echo-message` 才會有伺服器 msgid，`message-tags` 才有 `+draft/reply` 回覆 |
| SASL | `AUTHENTICATE PLAIN` | — | — | 有（`sasl = (authcid, password)`）；伺服器沒提供 PLAIN 直接 `Auth` 錯誤（`irc.rs:786`） |
| NickServ | `PRIVMSG NickServ :IDENTIFY`、`GHOST`、`REGISTER` | 有 | 有 | 有（`irc.rs:845-862`），暱稱被佔用先 GHOST 再 NICK |
| 長度 | 整行 512 bytes；實務訊息上限約 400–450 | 分段 | 分段 | `MAX_LINE` 扣掉 `:nick!user@host PRIVMSG target :` 後分段（`irc.rs:1024-1040`），預設 `max_chars = 350` |
| 訊息 | `PRIVMSG <target> :text`；`NOTICE` | 有 | 有 | 有；`silent` 走 NOTICE（`irc.rs:1032`），CTCP ACTION 轉 `* nick text`（`irc.rs:941`） |
| 格式化 | 無標準（mIRC 控制碼） | 剝除 | 剝除 | `strip_formatting` 剝除控制碼，Markdown 一律轉純文字 |
| 速率限制 | 無規範；實務 2 msg/s、burst 4 | 有節流 | 有 | token bucket `flood_burst = 4` / `flood_interval = 400ms`（`irc.rs:482`） |
| 重連 | 指數退避 | 有 | 有 | `reconnect_base 1s → max 30s`，連線存活 ≥ `STABLE` 才重置（`irc.rs:659`） |
| 斷線偵測 | `PING`/`PONG` | 有 | 有 | 半個 `LIVENESS` 沒收到任何資料就送 `PING :seagent`，整個 `LIVENESS` 靜默就重連（`irc.rs:721`） |
| 錯誤碼 | 401/403/404 無此暱稱/頻道、432 暱稱無效、464 密碼錯、KICK | 部分 | 部分 | 401/403/404 → `NotFound`（不再重試）；432 → `Fatal`；464/465 → `Auth`；KICK 記在 `gone`（`irc.rs:875-889`） |

## SE Agent 的選擇與差異

1. **自寫 IRCv3 能力協商**：三家上游都只做最小集；SE Agent 依 `message-tags` / `echo-message` 動態改變 `caps()`（`reply` 只有 `message-tags` 時才為真，`irc.rs:987`）。
2. **`NICKLEN` 沒有遵守**：真實 ngircd 27 回報 `NICKLEN=9`，SE Agent 的暱稱退路（`{base}_` / `{base}_N`）只截到 24 字元（`irc.rs:870`），超過的伺服器會自己截斷或拒絕。目前不會壞，但也不完全符合 005。
3. **行長估算多算一個空格**：`format!(":{nick}!@ ").len()`（`irc.rs:1035`）比實際 prefix 長 1 byte，屬保守估計，不影響正確性。
4. 沒有 `MONITOR`/`WHOX`；成員名單靠 `353`/`366`。

## 實測（本輪真的跑起來的）

ngircd 27（官方 Ubuntu 套件解到 TMPDIR 執行，`tests/real/run.sh`）＋自寫的對端 IRC client：

- `crates/seagent-channel/tests/real_irc.rs`
  - `registers_and_joins_on_real_ircd`：`CAP LS 302` 註冊、`001`、JOIN `#seagent`、自己出現在 `353` 名單。
  - `receives_channel_message_from_real_ircd`：對端 `PRIVMSG #seagent` → `Inbound{chat:"#seagent", sender:"alice", chat_type:Group}`，`message_id` 由伺服器 msgid 或本地 id 補上。
  - `sends_to_real_ircd`：`send()` → 對端真的收到 `:seagentsend!… PRIVMSG #seagent :seagent says hi`。
  - `receives_direct_message_from_real_ircd`：`PRIVMSG seagentsdm` → `chat_type:Direct`。
- 未涵蓋：TLS、SASL、NickServ（測試 ircd 沒有 services）、`+draft/reply`（ngircd 不提供 `message-tags`）。
