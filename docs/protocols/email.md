# 電子郵件（SMTP + IMAP + MIME）對照表

ark 實作：`crates/ark-channel/src/email.rs`（3219 行）＋`charset.rs`（WHATWG 編碼）。上游：Hermes `plugins/platforms/email/adapter.py`（1055 行）；**OpenClaw 沒有 email 通道**（`extensions/` 無對應目錄）；opencode 無。

| 面向 | 官方規格 | OpenClaw | Hermes | ark |
|---|---|---|---|---|
| 收信 | IMAP4rev1（RFC 3501）+ IDLE（RFC 2177） | 無 | `imaplib`（`adapter.py:121`） | 自寫 IMAP client：`LOGIN` → `SELECT` → `UID SEARCH UNSEEN UID n:*`，有 IDLE 就 IDLE，否則每 `poll_interval_secs` 輪詢（`email.rs:883`） |
| 連線安全 | 993 implicit TLS / 143 STARTTLS | — | 有 | `imap_security` = `tls`（預設）/`starttls`/`plain`；`plain` 只給本機測試用 |
| 寄信 | SMTP（RFC 5321）：`EHLO`、`AUTH PLAIN`/`LOGIN`、`MAIL`/`RCPT`/`DATA` 點號轉義 | — | `smtplib` | 自寫（`email.rs:1151`）；465 implicit TLS、587 STARTTLS、plain |
| 唯一的 ID 指令 | RFC 2971 `ID`（163/126 的 SELECT 需要） | — | 有 | 伺服器提供才送 `ID ("name" "ark")`（模組註解） |
| 信箱名稱 | RFC 3501 modified UTF-7 | — | 有 | `imap_utf7_encode/decode`（`email.rs:339`），`收件匣` → `&ZTZO9lMj-` |
| 標頭解析 | RFC 5322；RFC 2047 編碼字（相鄰字要先串接再解碼）；RFC 2231 參數 | — | 有 | 有（`decode_words`、`parse_headers`、`params`） |
| MIME | multipart 樹、base64、quoted-printable、8-bit | — | 有 | 有（`parse_mail`、`b64_decode_lenient`、`qp_decode`） |
| 字元集 | IANA charset；WHATWG 別名 | — | Python codecs | 自寫 `charset.rs`（Big5/HKSCS、GBK/gb18030、Shift_JIS、EUC-JP、ISO-2022-JP、EUC-KR、單一位元組、UTF-16） |
| 寄件者驗證 | RFC 8601 `Authentication-Results`（DMARC/SPF/DKIM） | — | 只信最上面一個 AR 標頭，authserv-id 必須相符（`adapter.py:73-81`） | 同（`verify_sender_authentication`，`email.rs:2166`）；`require_authenticated_sender` 預設 true |
| 自動信過濾 | — | — | 有 | `is_automated`（13 種 noreply 樣式 + `Auto-Submitted: auto-*` + 退信），`email.rs:2001` |
| 引用剝除 | — | — | 有 | `strip_quoted`（`>` 引用、`On … wrote:`、簽名分隔線），`email.rs:1889` |
| 討論串 | `Message-ID` / `In-Reply-To` / `References` | — | 有 | 有；`thread` = 根 `Message-ID`，回覆帶 `In-Reply-To`/`References` 與 `Re:` |
| 位移量 | `UIDVALIDITY` + UID | — | 有 | 持久化游標，**下一次 poll 才提交**（at-least-once）；`\Seen` 一起提交（`email.rs:1092`） |
| 批次與大小 | — | — | 有限制 | 每次最多 50 封（`BATCH`）、標頭先抓（`BODY.PEEK[HEADER]`，64 KiB 上限）再決定是否下載本體；附件上限 25 MiB、訊息 40 MiB |
| 長度 | 無硬上限（郵件可很長） | — | 50000 字元 | `MAX_MESSAGE = 50_000`（`email.rs:38`） |

## ark 的選擇與差異

1. **完全自寫**（沒有 imaplib/smtplib/lettre）：好處是 TLS、UTF-7、charset、AR 驗證都在同一處；風險是邊界情況要自己維護——`charset.rs` 是本輪看到最大的一塊自寫解碼器。
2. **預設 `require_authenticated_sender = true`**：自架伺服器（沒有 AR 標頭）會被當成不可信而丟棄，必須明設 `false` 或 `authserv_id`——和 Hermes 一致，但對自架使用者是陷阱（本輪測試就是這樣踩到）。
3. **`skip_existing = true`**：第一次啟動會跳過信箱裡已有的郵件。團隊信箱第一次接上時「舊信不回」是刻意的，但很容易被誤認為壞掉（本輪測試也踩到）。
4. 標題會以 `[Subject: …]` 形式帶進文字（Hermes 相同），因此 `Inbound.text` 不是純內文。

## 實測（本輪真的跑起來的）

GreenMail standalone（podman，SMTP 3025 / IMAP 3143 / REST 8080，`tests/real/run.sh`）：

- `crates/ark-channel/tests/real_email.rs`
  - `receives_delivered_mail_over_real_imap`：用真 SMTP 交信 → IMAP 收到 → `sender`/`chat` = 寄件者位址、`message_id` = `Message-ID`、引用段被剝除、`[Subject: …]` 前置。
  - `sends_through_real_smtp`：`send()` 走真 SMTP，回傳的 id 是 `Message-ID`，並用 GreenMail REST API 確認伺服器真的存下這封信（`reply body from ark`）。
- 未涵蓋：TLS/STARTTLS、IDLE、附件、非 ASCII 標頭（單元測試覆蓋）、真實 Gmail/Outlook 的 AR 標頭。
