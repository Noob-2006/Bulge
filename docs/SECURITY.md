# SE Agent 安全實作說明（操作者版）

這份文件說明「現在程式碼實際怎麼做」，以及每一道防線**到哪裡為止**。設計理由與威脅模型在 `docs/risk-assessment.md`；本文件只講可驗證的行為、設定與指令。

- 上一輪（第 5 輪）的全貌：`audit/GAPS-next.md` 的 A 段。
- 所有指令都可以用 `SEAGENT_HOME=<暫存目錄>` 隔離測試。

---

## 1. 金鑰庫：靜態加密與解鎖來源（A4）

### 1.1 問題

第 5 輪之前，金鑰放在 `config/secrets.toml`（權限 0600 的**明文**）。任何人拿到那個檔案的一份副本——備份、profile 匯出、權限設錯的複本、被偷的筆電——就拿到全部金鑰。0600 只擋「同一台機器上的其他使用者」，不擋「檔案離開這台機器」。

### 1.2 現在的做法

| 層 | 實作 | 檔案 |
|---|---|---|
| AEAD | ChaCha20-Poly1305（`ring`），每次寫入新的 96-bit nonce | `crates/seagent-security/src/secretbox.rs` |
| 密碼 KDF | PBKDF2-HMAC-SHA256，預設 600,000 次，下限 100,000 次（低於下限直接拒絕） | 同上 |
| 儲存 | `config/secrets.enc`（0600，原子寫入）。標頭 `backend`/`kdf`/`iterations`/`salt` 全部當作 **AEAD 附加認證資料（AAD）**，所以把 `iterations` 改成 1 或換 salt 都會讓 tag 驗證失敗，而不是靜默降級 | `crates/seagent-kernel/src/secretstore.rs` |
| 對外介面 | `seagent_kernel::vault::Vault`（`names`/`set`/`remove`/`substitute`/`redact`/`leaks`），行為與第 5 輪相同 | `crates/seagent-kernel/src/vault.rs` |

解鎖來源（**新** store 依序探測；既有 store 一律用檔案標頭記錄的來源）。探測順序是 `keyring` → `tpm`（**只有 root 服務**）→ `passphrase` → `env` → `plaintext`。

| backend | 金鑰在哪 | 需求 |
|---|---|---|
| `keyring` | 登入 keyring（Secret Service），透過 `secret-tool` | `libsecret-tools`；金鑰解鎖需要已解鎖的 keyring |
| `tpm` | 隨機資料金鑰以 `systemd-creds --with-key=tpm2` 封存在 `config/secrets.key`（0600） | `systemd-creds` + TPM（`/dev/tpmrm0`）。**不自動選用**（見下） |
| `passphrase` | 不存在任何檔案；每次開啟用 PBKDF2 從密語導出 | `SEAGENT_VAULT_PASSPHRASE_FILE`（0600 檔，優先）或 `SEAGENT_VAULT_PASSPHRASE` |
| `env` | `SEAGENT_VAULT_KEY`（32 bytes hex 或 base64）；適合 systemd `LoadCredential` | 由啟動環境提供 |
| `plaintext` | 沒有來源時的**明確降級**：沿用 0600 明文 `secrets.toml` | 無 |

選擇與強制：

```bash
seagent secrets backend            # 目前用哪個 backend、檔案在哪、有哪些注意事項
seagent secrets status             # 已解鎖時的同一份資訊（含 secret 數量）
seagent secrets migrate            # 把明文 secrets.toml 併入 secrets.enc 並銷毀明文
SEAGENT_VAULT_BACKEND=tpm seagent secrets migrate
SEAGENT_VAULT_REQUIRE_ENCRYPTION=1 # 沒有金鑰來源時直接失敗，不降級
```

**為什麼 TPM 不自動選用**：對非 root 使用者，每一次 `systemd-creds encrypt/decrypt` 都會經 polkit 要授權——vault 每開一次就跳一次密碼框，這正是第 0 段禁止的「核准洪水」。所以自動探測只在 `geteuid()==0`（systemd 服務）時選 TPM；其他使用者要用 `SEAGENT_VAULT_BACKEND=tpm seagent secrets migrate` 明確選擇，或在 unit 裡用 root 服務。測試一律用 `Options.creds_tool` / `Options.keyring_tool` 指向 TMPDIR 裡的替身腳本，不會呼叫真正的 `systemd-creds`、`secret-tool` 或任何會跳視窗的工具。

**遷移是一次性且可驗證的**：讀明文 → 寫密文 → **讀回並逐項比對** → 才用 0 覆寫明文再刪除。讀回不一致就保留明文並報錯（`crates/seagent-kernel/src/secretstore.rs` 的 `verify_readback`）。`seagent secrets set` 之後 `secrets.toml` 不再存在，備份／profile 匯出清單也同步改成 `secrets.enc` + `secrets.key`。

### 1.3 VM 與 broker 永遠拿不到明文

- 明文只存在 daemon 的記憶體（`Arc<Vault>`）；VM 內沒有任何設定檔或 socket。
- 工具在 VM 裡看到的是 `{{secret:NAME}}`；替換（`Vault::substitute`）發生在 daemon 這一側，用於**出口請求**（egress proxy 注入 header／broker 代送）。
- 出口掃描會攔下任何含明文值的請求（`Vault::leaks`）；日誌與工具輸出用 `Vault::redact` 換回佔位符。
- 既有測試：`egress_injects_secrets_and_refuses_them_on_the_way_out`、`injected_secret_reaches_upstream_only`（`crates/seagent-security/tests/`）。

### 1.4 到哪裡為止

- **不擋**執行中的 root：daemon 必須持有解密後的金鑰。
- **不擋**記憶體 dump／core dump。
- `tpm` backend 綁「這台機器 + TPM」，不綁使用者；同一台機器上能讀 `secrets.key` 的使用者仍需 TPM 才能解封，但 root 可以透過 TPM 解封。
- `keyring` backend 的安全性等於登入 keyring 的安全性。
- `SEAGENT_VAULT_PASSPHRASE`（環境變數）對同使用者其他程序可見（`/proc/<pid>/environ`），優先用 `SEAGENT_VAULT_PASSPHRASE_FILE`。
- 金鑰輪替沒有自動化：換 backend 或換密語時，用 `seagent secrets backend` 確認，然後重新 `set` 每個值（或先 `migrate` 再人工確認）。

---

## 2. 外掛／技能來源驗證（A13）

| 保證 | 實作 | 測試（節選） |
|---|---|---|
| **簽章**：套件 manifest 以 Ed25519 簽章，金鑰由 trust store 決定 | `seagent_security::signing`（`PublicKey`、`verify`、`manifest_digest`、`TrustStore`）、`seagent_skills::hub::verify`、`seagent_plugin::verify::verify_manifest` | `signed_bundle_verifies_and_records_the_signer`、`signed_manifest_verifies_and_tampering_is_refused` |
| **完整性**：內容 digest 以排序後的 `路徑\0<sha256>\n` 計算；安裝後在 `check`/`update` 重新計算，磁碟被改過就回報 `integrity_failure` | `hub::verify::{content_digest, verify_installed}` | `installed_dir_drift_is_an_integrity_failure` |
| **版本鎖定**：lock 檔記錄 `version` + `content_hash` + `key_id`；hub 端跳到別的版本會拒絕，除非 `--force` | `hub::verify::{pin, enforce_pin}` | `pinned_version_refuses_a_hub_side_jump_without_force` |
| **能力變更要重新確認（防 rug pull）**：更新後能力變多 → 需要同意，非互動時直接拒絕並列出新增能力 | `plugin_guard::{summarize, widened}`，`seagent_plugin::verify::capability_diff` | `capability_widening_on_update_needs_consent` |

預設 `[policy] require_signature = false`（**不破壞既有安裝**）；要強制簽章，在 trust store TOML 設 `require_signature = true`，未簽章或簽章無效的套件會被拒絕並指出缺少哪個 key id。

---

## 3. SSRF 判定合一（A14）

只有一份位址分類表：`seagent_security::url_safety`（`is_blocked_ip`、`is_always_blocked_ip`、`BLOCKED_HOSTNAMES`、`check_host`、`check_resolved`）。

| 呼叫端 | 用法 |
|---|---|
| web 工具 / egress gate / `seagent security check-url` | 直接使用 |
| 瀏覽器 | `seagent-browser::policy` delegate（第 5 輪） |
| 圖片／影音抓取 | `seagent-media::vision` delegate（第 5 輪），本輪加上**連線時**再判定 |
| 模型供應商 | `seagent-model::net::is_metadata_host` delegate（本輪） |
| Teams 同意上傳 | `seagent-channel::msteams::consent_addresses_ok` delegate（本輪） |

另外，媒體抓取 provider 給的結果網址時：每個轉址跳點都重新判定，且**實際 dial 的位址**也再判定一次（`seagent-media::http::PinnedResolver`），所以「檢查時解析到公開位址、連線時解析到內網」的 DNS rebinding 走不通。信任清單是 `host:port` 精確比對：信任 `127.0.0.1:8080` 不會順便信任 `127.0.0.1:22`。

---

## 4. 供應鏈與發佈（A18）

| 項目 | 位置 | 說明 |
|---|---|---|
| SBOM | `packaging/release/sbom.py` | SPDX 2.3 JSON，`Cargo.lock` 為結構來源、`cargo metadata` 補授權；輸出可重現（排序、`SOURCE_DATE_EPOCH`、內容雜湊當 namespace）；`--check` 驗證既有 SBOM |
| 發佈簽章 | `packaging/release/{gen-key,sign,verify-release}.sh` | Ed25519（openssl），detached 簽章蓋在 `SHA256SUMS` 上；`verify-release.sh` 同時檢查每個檔案的雜湊、有無未列出的檔案、SBOM 是否為合法 SPDX |
| 可重現建置 | `packaging/release/repro-check.sh` | 兩個不同路徑、各自 `CARGO_TARGET_DIR`、固定 `SOURCE_DATE_EPOCH`，逐檔比對雜湊 |
| 依賴更新審查 | `packaging/release/DEPENDENCY-REVIEW.md` | 新依賴要什麼理由、`cargo deny`、授權、feature、build script/proc-macro 審查、OSV 分級處理 |
| 發佈流程 | `packaging/release/README.md` | 從版本號到 `SHA256SUMS.sig` 的完整步驟 |

**已知限制**：目前 `repro-check.sh --quick` 會回報 `bin/seagent` DIFF，原因是若干模組在編譯期用 `env!("CARGO_MANIFEST_DIR")` 把建置路徑寫進二進位（`seagent-kernel/selfrepo.rs`、`seagent-browser`、`seagent-skills`、`seagent-vm`、`seagent-plugin`）。腳本會印出找出它們的指令；在那些呼叫點改掉之前，「可重現建置」是**檢查機制已就位、目標尚未達成**。

---

## 5. 本輪一併修掉的小洞（A15）

| 問題 | 修正 |
|---|---|
| 媒體抓取 provider 端點的轉址／DNS rebinding | 每次跳點 + 連線時各判定一次（`PinnedResolver`） |
| `docs/pdf.rs` 暫存目錄 0755 | 建立時就是 0700 |
| `ui.terminal.open` 可用任意絕對路徑執行 | 只接受 PATH 上的允許清單短名，解析成絕對路徑後 exec（不經 shell），拒絕 group/world 可寫的目標 |
| `seagent uninstall --purge` 無防呆 | 拒絕 `/`、`$HOME`、`/home`、`/root`、`/usr…`、`/etc`、`/var`、少於 3 層的路徑、指向它們的 symlink |
| `/prompt` 草稿 0644 | 以 `O_NOFOLLOW` + `0600` 建立，編輯器結束後刪除 |
| 測試碰到真實 `$HOME` | 改注入路徑／`TempDir`，`test_hygiene_allow.txt` 只能變短 |
| kanban paused 不顯示 | `/workboard dispatch` 先印 `paused: …`，JSON 也有 `paused` |

## 6. 第 9 輪：safety 組補的破口

| 項目 | 做法 | 入口 |
|---|---|---|
| 發檔來源（srv-012） | channel 動作讀主機檔案前，路徑（解析 symlink、`..`）必須落在 session 工作區或 artifact 目錄（＋`SEAGENT_SEND_ROOTS`），且不是金鑰類檔案（`.ssh`、`.gnupg`、`.aws`、`id_*`、`secrets.*`…）；`message` 工具先檢查一次，Discord／Slack／Feishu／Yuanbao 的讀檔函式再檢查一次。這是獨立於出口核准的第二層 | `message` 工具、`seagent message` |
| 預設隔離（srv-015／016） | 沒有 microVM 時，所有 session（含 owner）都進 bwrap／Landlock，主機家目錄與金鑰不掛入；連 namespace 沙箱都沒有才在主機執行並印 `NOT ISOLATED` | `seagent sandbox explain`、`seagent doctor` |
| 聊天回覆過濾（srv-019、H11） | 頻道回覆與串流預覽移除 `<memory-context>`／`<recalled-context>`，並遮罩金鑰樣式字串 | 所有 channel |
| 遠端第 3 級核准（srv-017／018） | 見 MANUAL §4.5：owner 限定、二次確認、無 Allow Always、記錄核准者、逾時通知 | 聊天按鈕、`/approve` |
| MCP 工具釘選（gen2-505） | 首次載入時對每個工具的名稱／說明／schema／annotations 取 SHA-256（`<data>/mcp-pins.json`）；之後有變動或新增的工具一律不給模型，直到 `seagent mcp pins diff` 檢視、`seagent mcp pins accept` 重新核准 | `seagent mcp pins` |
| 提示與內建技能完整性（gen2-508） | `crates/seagent-skills/bundled-skills.sha256`（編進二進位）記錄基礎系統提示與每個內建技能的 SHA-256；磁碟上被改過或不在清單內的內建技能不載入、不同步；測試強制清單與原始碼一致 | `seagent doctor` |
| 執行期秘密掃描（H11 執行期那一半） | 工具輸出在進入上下文／session log 前遮罩金鑰樣式字串（並留一筆 Notice）；`git commit` 的暫存變更含 vault 值或金鑰樣式時先問人。`[security] mask_output_secrets = false` 可關。CI 端的掃描由 release 組處理 | 自動 |

---

## 7. 回報安全問題

如果是金鑰外洩：先 `seagent secrets set NAME` 換掉該金鑰，再 `seagent secrets backend` 確認加密狀態。程式缺陷請附上 `seagent doctor`、`seagent security audit` 的輸出與重現步驟；不要在 issue 裡貼任何 `{{secret:…}}` 的實際值。

---

## 8. 網路與遠端連線：周界防護（無伺服器，但不只靠一個 token）

SE Agent 沒有雲端中繼：App Server 直接面對本機、區域網路，必要時面對 tunnel 或公網。原本的防線是 LAN 模式（自簽 P-256 憑證＋指紋釘選、mDNS 不帶 token、setup code／需核准的 8 碼配對、可撤銷的 `sed1_` 裝置 token、其餘 token 驗證）。這一節是在那之上加的周界層，以及**刻意不加**的東西。程式：`crates/seagent-app/src/netguard.rs`（周界）、`device_auth.rs`（裝置金鑰）、`devices.rs`（裝置紀錄）、`a2a.rs`（重送）。

### 8.1 威脅模型

| 威脅 | 攻擊者能做什麼（加這層之前） | 現在的防線 | 剩下的風險 |
|---|---|---|---|
| **同一個 LAN 的攻擊者** | 掃 8640 埠、猜 8 碼配對碼、猜 token、嗅探 | TLS＋指紋釘選（原有）；`/pair/client` 每址限速（原有）＋**全網失敗預算**（10 分鐘 60 次錯碼即暫停所有 8 碼配對並通知 owner）；**失敗鎖定**；`allow_sources` 子網白名單 | 可以讓 8 碼配對暫停（DoS）；QR／setup code 仍可用 |
| **被入侵的已配對裝置** | 用它的 token 做它 scope 內的事 | 每台裝置**獨立 scope**（`read` 只能看／`write` 完整操作／`approve` 也能核准，可隨時改，access token 立即生效）；高風險動作仍走原本的核准流程（`write` 裝置不能答覆 gate）；撤銷 1 秒內斷線；**登出所有裝置**；清單顯示最後位址與時間 | 在 scope 內、撤銷前的行為擋不住 |
| **token 被偷**（備份、`hosts.json`、手機儲存、XSS 讀 localStorage） | 永久冒用這台裝置 | **裝置金鑰綁定**：配對時送 P-256 公鑰（私鑰在平台金鑰庫，見 8.2）；console token 之後**不能當 bearer**，只能在 `POST /pair/refresh` 配合**這把私鑰的新簽章**換短效 access token（`sea1_`，預設 60 分鐘，只在記憶體） | 偷到 access token：最多用到過期或撤銷；只在退回檔案的平台（見 8.2），同時拿到 App 資料夾才等於偷到裝置 |
| **瀏覽器 CSRF／DNS rebinding** | 惡意網頁把自己的網域重新解析到 127.0.0.1 或 LAN IP，同源地呼叫 API | 瀏覽器請求（有 Origin／`Sec-Fetch-*`／WebSocket）的 `Host` 必須是這台的名字：IP 字面值、`localhost`、本機名稱／`.local`、私有字尾（`.lan`、`.home.arpa`、`.internal`…）、`allowed_hosts`、`public_url`、`allow_origins`；cookie 工作階段的狀態變更需要允許的 Origin 或 `Sec-Fetch-Site: same-origin` | 不送 `Sec-Fetch-*` 的舊瀏覽器做同源 GET 時不檢查 Host——但 GET 都需要 token，攻擊頁拿不到 |
| **惡意網頁攻擊 localhost** | 跨站 POST、開 WebSocket、Chrome PNA 預檢 | 跨站 Origin 一律拒絕（原有）；POST 只收 JSON（原有）；**CORS 只回應列在 `allow_origins` 的來源**，從不送 `*`＋credentials、從不送 `Access-Control-Allow-Private-Network`；安全標頭 | 本機惡意程式本來就不在這層的範圍 |
| **暴力破解** | 無限猜 token、密碼、配對碼 | 單一位址 10 分鐘內 10 次失敗（錯 token、錯配對碼、錯簽章、錯密碼、錯 A2A token）→ 鎖 1 分鐘，24 小時內每再犯一次加倍，上限 1 小時；鎖定寫稽核並通知 owner | tunnel 後的所有來源共用一個桶（見 8.3） |
| **重送** | 重放擷取到的請求 | refresh 簽章含主機 id＋時間戳（±5 分鐘）＋一次性 nonce；A2A `messageId` 15 分鐘內重複就回原本的 task、不再跑一輪；node 協定原本就是每條連線一個 `connect.challenge` nonce；配對碼／bootstrap token 一次性且會過期（原有） | ACP 走 stdio（本機子程序），沒有網路重送面 |
| **經 tunnel／公網 IP 暴露** | cloudflared、Tailscale Funnel、ngrok、SSH 轉送把公網流量變成「來自 127.0.0.1」 | loopback 連線帶 `X-Forwarded-For`、`Forwarded`、`CF-Connecting-IP`、`Tailscale-User-Login`、`cf-ray`… 而沒設 `behind_proxy`，就**不算本機**：依回報的位址判斷，公網或無位址 → 主控台路由 403，直到 `behind_proxy = true` 或 `allow_public = true`；LAN 模式下經 tunnel 的私有位址只收裝置憑證；公開暴露開啟時啟動畫面大聲警告、寫 `exposure.public` 稽核、主控台顯示紅字 | 你自己設的 `behind_proxy` 之後就信任那個代理的 `X-Forwarded-For`（ent-120 的規則不變） |

### 8.2 措施、設定與入口

```toml
[app.exposure]
allow_sources = ["192.168.1.0/24", "fd00::/8"]   # 選用：本機以外只收這些來源（webhook／A2A 不受影響）
allowed_hosts = ["seagent.corp.example", "*.vpn.example"]  # 瀏覽器可用的額外主機名稱
require_device_key = false   # true：還沒綁金鑰的舊裝置一律拒絕（預設讓它們繼續用、下次啟動自動綁定）
device_access_ttl_secs = 3600   # access token 壽命（2–86400 秒）；用戶端在約 80 % 時自動續期
```

| 措施 | 行為 | 入口 |
|---|---|---|
| 裝置金鑰 | 配對 body 的 `device.publicKey`（65 bytes 未壓縮 P-256，base64url）與 `keyStore`。App：`apps/desktop/devkey`（`seagent-devkey`，Windows／macOS／Linux／Android／iOS 同一份），見下表；瀏覽器：`ui/web/devauth.js`（WebCrypto，私鑰 non-extractable，存在 IndexedDB，`keyStore = webcrypto`）。`seagent doctor`／`seagent security audit` 的 `lan.device_keys` 列出每種金鑰庫的裝置數，有 `file` 或未綁定時是 warn | `GET /pair/info`（主機 id＋時鐘，公開）、`POST /pair/refresh` |
| 自動續期 | 簽章訊息 `seagent-device-refresh|v1|<hostId>|<deviceId>|<ts>|<nonce>`；App 在 `host_open` 與主控台呼叫 `console_access_token` 時換新，瀏覽器在連線前與斷線重連時換新；daemon 重啟後每台裝置靜默重換一次 | 不需要使用者動作 |
| 遷移 | 舊版配對的裝置（沒有金鑰）照常可用；新版 App／瀏覽器下次啟動時用舊 token＋新公鑰呼叫 refresh，主機綁定一次（`device.bind` 稽核），之後舊 token 不再能當 bearer。主機太舊（沒有 `/pair/info`）時用舊 token，行為與以前相同。舊版 App 連新主機：App 內的 WebView 不會自己綁金鑰（金鑰屬於 App 的 Rust 端），所以照舊用 console token，App 更新後第一次開啟才綁定 | 自動 |
| 失敗鎖定 | 見 8.1；`429`＋`Retry-After`；本機（loopback、沒有轉送標頭）永不鎖定 | `auth.lockout` 稽核、`security.alert` 通知 |
| 網路範圍 | LAN 模式只收私有網段（原有）；`allow_sources`；公網來源需要 `allow_public` 或 `behind_proxy` | `net.refused` 稽核（每個位址每種原因 10 分鐘一筆，避免掃描器灌爆）、`seagent_http_perimeter_refused_total` |
| Host／rebinding、CSRF、CORS、標頭 | 見 8.1。所有回應補上 `X-Content-Type-Options: nosniff`、`X-Frame-Options: SAMEORIGIN`（外掛面板與即時畫面是我們自己的頁面嵌入）、`Referrer-Policy: no-referrer`、`Cross-Origin-Resource-Policy: same-origin`；API 回應加 `default-src 'none'; frame-ancestors 'self'`；UI 保留自己的 CSP（`frame-ancestors 'none'`）；HSTS 只在公開＋原生 TLS 時送 | 自動 |
| 裝置權限與工作階段 | `seagent devices scope ID read|write|approve`、`seagent devices revoke ID`、`seagent devices revoke --all --yes`（登出所有裝置）；`seagent devices list` 顯示是否綁金鑰、最後時間與位址 | ARP `devices.scope`、`devices.revoke_all`；主控台「裝置 → 連線裝置與安全」（`ui/web/devsec.js`） |
| 通知 owner | 新裝置配對、位址被鎖定、全網錯碼過多：daemon log 的 `SECURITY:` 行、稽核 `security.alert`、以及 `[alerts] targets` 的每個頻道／webhook（同一事件只送一次） | `governance::alert_as` |
| 公開暴露警告 | `allow_public = true` 啟動時印出一整排 `!` 的 WARNING 並寫 `exposure.public`；經 `behind_proxy` 第一次看到公網來源時也印一次；`lan.status` 帶 `publicExposure`／`warning`，主控台紅字顯示 | 自動 |

稽核：`auth.failed`、`auth.lockout`、`auth.login`、`device.pair`（含 `keyBound`）、`device.bind`、`device.refresh`（只記拒絕）、`device.scope`、`device.revoke`、`device.revoke_all`、`net.refused`、`exposure.public`、`security.alert`。這些是安全紀錄，持久保存；成功的 refresh 與過期 access token 的 401 不寫（每台裝置每小時都會發生，屬於例行）。

App 端的金鑰庫（`seagent-devkey`；第一次選定後記在 `<app data>/device-key.json`，之後永遠開同一個，不會默默換成別的——換金鑰主機會拒絕）：

| 平台 | 第一選擇 | 其次 | 最後才用 |
|---|---|---|---|
| Windows | CNG：**Microsoft Platform Crypto Provider**（TPM 內產生與使用） | **Microsoft Software Key Storage Provider**，export policy 0（不可匯出） | 檔案 |
| macOS／iOS | **Secure Enclave**（Keychain 項目） | 軟體 **Keychain** 金鑰 | 檔案 |
| Android | **Android Keystore**（有 StrongBox 就用，否則 TEE），經 mobile plugin（`DeviceKeystore.kt`） | — | 檔案 |
| Linux | **TPM**：用 `systemd-creds --with-key=tpm2` 封存，與 vault 的 TPM backend 同一條路；只在 root 時自動選（一般使用者每次解封都會跳 polkit） | — | 檔案（0600 PKCS#8） |

`SEAGENT_DEVICE_KEY_STORE=<kind>` 強制指定。前一版留下的 `device-key.p8` 繼續使用（主機可能已綁定它）。

**續期保證（永遠自動、不需使用者動作，直到撤銷）**：

| 用戶端／連線 | 怎麼續 | 證據 |
|---|---|---|
| 網頁主控台（瀏覽器） | `devauth.js` 在 access token 壽命約 80 % 時續期；失敗以 2→60 秒退避一直重試；連線被拒（過期、主機重啟）時 `forget()` 後重連並先續期；裝置憑證連不上時安靜重試（只有主機回「已撤銷」才要求重新配對） | `webui_devices.rs`（真瀏覽器，3 秒 TTL，至少 3 次續期，WebSocket 不斷） |
| App（桌面／手機） | `host_open` 與主控台的 `console_access_token` 由 Rust 端簽章換新（暫時性失敗重試 3 次）；頁面內同上 | `devkey.rs` `transient_failures_are_retried_and_final_ones_are_not` |
| 開著的 WebSocket（主控台、即時畫面、ARP 訂閱） | 不需要續：主機只在撤銷或停用時關閉；scope 變更在 1 秒內直接套用到已開的連線（不重連） | `device_credentials_renew_silently_over_many_expiry_cycles`、`webui_devices.rs` |
| 主機重啟（記憶體中的 access token 消失） | 下一次 refresh 立即成功；重啟前簽的 refresh 會被拒（見下），用戶端重試時用新的主機時鐘重簽 | `device_credentials_renew_silently_over_many_expiry_cycles`、`a_refresh_signed_before_a_restart_is_refused_after_it` |
| 筆電睡了好幾天 | console token 不會過期；醒來後 WebSocket 重連、先 refresh；時間戳用主機時鐘（`/pair/info`），睡眠造成的時鐘差不影響 | 同上 |
| node（`/node`）、電腦對電腦叢集、CLI | 不使用 access token：node 是 Ed25519 挑戰＋node token；叢集節點用未綁定的裝置 token（`seagent lan connect`）；CLI 走本機 socket | — |
| 頻道、webhook、A2A、排程 | 完全不經過這套機制 | — |

注意：`require_device_key = true` 會拒絕未綁定的裝置——包括 `seagent lan connect` 建立的叢集節點（它們沒有裝置金鑰），所以預設關閉。

**重啟之後**：鎖定會保存（`<data>/security/lockouts.json`，只在鎖定開始時寫一次、最多 256 筆、0600），所以重啟不會清掉暴力破解的處罰；refresh 的 nonce 不落地，而是要求簽章時間不早於這次 daemon 啟動的時間（用戶端用主機時鐘簽），重啟前截到的 refresh 一律無效——不需要每次 refresh 都寫磁碟。

**新網路通知**：每台裝置記住它用過的網段（IPv4 `/24`、IPv6 `/64`，最多 16 個）。配對時的網段安靜記下；之後從沒見過的網段出現時，經同一條通知路徑（daemon log、`security.alert` 稽核、`[alerts] targets`）告訴 owner，**不阻擋**。


### 8.3 為了自主性刻意不做的事

原則（`docs/risk-assessment.md` 第 0 段）：防護不能多到 agent 不能自己做事、或使用者天天被打斷。依 risk-assessment §3.1 的兩個審查問題：

1. **典型的夜間任務多停幾次？** 0 次。排程、goal、頻道機器人在 daemon 內跑，不經 App Server；經 tunnel 進來的頻道 webhook、A2A、外掛路由不套用來源／Host／白名單規則，webhook 也不受鎖定影響；已配對裝置的續期是自動的。唯一會「停」的是被鎖定的位址（10 次失敗之後；A2A 也算，因為 peer token 只能靠猜）與沒有宣告的 tunnel 上的主控台。
2. **有沒有不需要詢問的替代做法？** 這一層本來就不詢問：拒絕、鎖定、續期都沒有提示；需要人的只有原本就有的配對核准（8 碼）。

逐項：

| 沒做的事 | 為什麼 |
|---|---|
| 本機 owner 的額外驗證（二次確認、PIN、每次簽章） | loopback 上沒有轉送標頭的請求就是這台機器；它仍需要 app token，但不會被鎖定、不會被要求裝置金鑰、不會多一個提示 |
| 已配對裝置的日常提示 | 續期全自動；scope 變更、撤銷都在主機端做，裝置端不必再確認 |
| 對 webhook、外掛路由、A2A 套用 Host／來源／白名單規則 | 頻道 webhook 經 tunnel 從公網進來是正常的，它們有自己的簽章；A2A 有每個 peer 的 token。若套用，頻道自動化與 agent-to-agent 就要人介入 |
| 每個請求都做持有證明（DPoP 式簽章） | WebSocket 長連線、瀏覽器、手機 WebView 都要改協定，成本高；短效 access token＋refresh 簽章已經讓「只偷到 bearer」失效。開著的 WebSocket 在 access token 過期後**繼續有效**，直到撤銷（撤銷 1 秒內斷） |
| 預設要求裝置金鑰（`require_device_key`） | 會讓舊版 App 與不支援 WebCrypto 的瀏覽器立刻無法連線；預設讓它們繼續用、下次啟動自動綁定 |
| 對 tunnel 後的每個真實 IP 分開鎖定（沒設 `behind_proxy` 時） | 那時轉送標頭不可信：照它分桶，攻擊者換一個標頭值就繞過，或冒充別人的 IP 讓別人被鎖。所以整條 tunnel 一個桶；webhook 路由不受鎖定影響 |
| LAN 自簽憑證上的 HSTS | 對 `.local` 名稱，HSTS 會把「可以點過去」的憑證警告變成死路，手機就配不起來 |
| 嚴格的 Host 白名單（只收 IP） | 家用路由器的名字（`studio.lan`、`box.home.arpa`）無法出現在公網 DNS，rebinding 用不到；所以私有字尾與單一標籤名稱放行，其他名稱用 `allowed_hosts` 加 |
| mTLS 用戶端憑證當成 LAN 預設 | 原有 `client_auth` 仍可用；預設改成要求它，手機瀏覽器就沒辦法用了。裝置金鑰提供同等的「持有證明」而不需要安裝憑證 |

### 8.4 測試

| 措施 | 測試 |
|---|---|
| 暴力破解鎖定、加倍、本機不鎖 | `server::tests::brute_force_locks_an_address_out_with_backoff` |
| DNS rebinding Host 被拒、合法名稱與非瀏覽器放行 | `server::tests::a_rebinding_host_header_is_refused` |
| 偷到 token 沒有裝置金鑰被拒、refresh 不能重送 | `server::tests::a_stolen_device_token_without_the_device_key_is_refused`、`device_auth::tests::refresh_needs_the_key_a_fresh_timestamp_and_an_unused_nonce` |
| 舊裝置繼續可用並自動遷移、`require_device_key` | `server::tests::existing_paired_devices_keep_working_and_migrate`、`device_auth::tests::a_legacy_device_binds_its_first_key_and_only_that_one` |
| 公網來源（tunnel）被拒、webhook 不受影響 | `server::tests::a_public_source_is_refused_unless_exposure_is_on` |
| 來源白名單 | `server::tests::the_source_allowlist_limits_network_peers` |
| cookie CSRF、CORS（無 private-network 授權）、安全標頭 | `server::tests::cookie_csrf_cors_and_security_headers` |
| 金鑰綁定裝置、access token 過期、scope 即時生效、登出所有裝置 | `devices::tests::key_bound_devices_need_a_signature_and_access_tokens_expire` |
| 全網錯碼預算 | `devices::tests::distributed_code_guessing_pauses_code_pairing` |
| A2A `messageId` 重送 | `a2a::tests::a_replayed_message_id_maps_to_its_task_per_peer` |
| P-256 簽章 | `seagent_net::crypto::tests::p256_device_signatures_verify_and_tampering_fails` |
| App 端金鑰（所有平台同一份） | `apps/desktop/src-tauri/src/devkey.rs` `the_key_is_made_once_kept_and_signs_what_the_host_verifies` |

### 8.5 到哪裡為止

- 平台金鑰庫不可用時（沒有 TPM 又不是 root 的 Linux、沒有 Keychain 存取權的未簽章 macOS 建置、沒有橋接的 Android）退回 0600 檔案，那時能讀 App 資料夾的程式同時拿得到 token 和金鑰；`lan.device_keys` 會標出這種裝置。Linux TPM 模式下金鑰在 App 執行期間仍在記憶體中（與 vault 相同）。Android 與 Apple 的實作只做了型別檢查與單元測試，沒有在實機上跑過。
- 瀏覽器的私鑰 non-extractable，但同源的 XSS 仍可**當場使用**它（拿不走）。
- access token 是 bearer：在它過期前（預設 60 分鐘）被偷走仍可用；開著的 WebSocket 只在撤銷時才斷。
- access token 在記憶體：daemon 重啟讓每台裝置重新 refresh 一次（自動）。鎖定會保存；失敗次數（未達上限的）不保存。
- 全網錯碼預算可以被 LAN 上的攻擊者用來暫停 8 碼配對（QR／setup code 不受影響）。
- `behind_proxy = true` 之後信任該代理的轉送標頭；代理本身設錯（例如附加而不是覆寫 `X-Forwarded-For` 又把自己列為可信）時，來源判斷就跟著錯。
- 沒有 GeoIP；新網段只通知不阻擋，同一個 /24 內換位址不會通知。
- 獨立的即時畫面頁 `/view/?token=…`（不是主控台內的即時畫面）用網址裡固定的 token 輪詢；給它裝置的 access token 時，過期後要從主控台重開。主控台內的即時畫面走 WebSocket，不受影響。
