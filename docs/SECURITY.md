# ark 安全實作說明（操作者版）

這份文件說明「現在程式碼實際怎麼做」，以及每一道防線**到哪裡為止**。設計理由與威脅模型在 `docs/risk-assessment.md`；本文件只講可驗證的行為、設定與指令。

- 上一輪（第 5 輪）的全貌：`audit/GAPS-next.md` 的 A 段。
- 所有指令都可以用 `ARK_HOME=<暫存目錄>` 隔離測試。

---

## 1. 金鑰庫：靜態加密與解鎖來源（A4）

### 1.1 問題

第 5 輪之前，金鑰放在 `config/secrets.toml`（權限 0600 的**明文**）。任何人拿到那個檔案的一份副本——備份、profile 匯出、權限設錯的複本、被偷的筆電——就拿到全部金鑰。0600 只擋「同一台機器上的其他使用者」，不擋「檔案離開這台機器」。

### 1.2 現在的做法

| 層 | 實作 | 檔案 |
|---|---|---|
| AEAD | ChaCha20-Poly1305（`ring`），每次寫入新的 96-bit nonce | `crates/ark-security/src/secretbox.rs` |
| 密碼 KDF | PBKDF2-HMAC-SHA256，預設 600,000 次，下限 100,000 次（低於下限直接拒絕） | 同上 |
| 儲存 | `config/secrets.enc`（0600，原子寫入）。標頭 `backend`/`kdf`/`iterations`/`salt` 全部當作 **AEAD 附加認證資料（AAD）**，所以把 `iterations` 改成 1 或換 salt 都會讓 tag 驗證失敗，而不是靜默降級 | `crates/ark-kernel/src/secretstore.rs` |
| 對外介面 | `ark_kernel::vault::Vault`（`names`/`set`/`remove`/`substitute`/`redact`/`leaks`），行為與第 5 輪相同 | `crates/ark-kernel/src/vault.rs` |

解鎖來源（**新** store 依序探測；既有 store 一律用檔案標頭記錄的來源）。探測順序是 `keyring` → `tpm`（**只有 root 服務**）→ `passphrase` → `env` → `plaintext`。

| backend | 金鑰在哪 | 需求 |
|---|---|---|
| `keyring` | 登入 keyring（Secret Service），透過 `secret-tool` | `libsecret-tools`；金鑰解鎖需要已解鎖的 keyring |
| `tpm` | 隨機資料金鑰以 `systemd-creds --with-key=tpm2` 封存在 `config/secrets.key`（0600） | `systemd-creds` + TPM（`/dev/tpmrm0`）。**不自動選用**（見下） |
| `passphrase` | 不存在任何檔案；每次開啟用 PBKDF2 從密語導出 | `ARK_VAULT_PASSPHRASE_FILE`（0600 檔，優先）或 `ARK_VAULT_PASSPHRASE` |
| `env` | `ARK_VAULT_KEY`（32 bytes hex 或 base64）；適合 systemd `LoadCredential` | 由啟動環境提供 |
| `plaintext` | 沒有來源時的**明確降級**：沿用 0600 明文 `secrets.toml` | 無 |

選擇與強制：

```bash
ark secrets backend            # 目前用哪個 backend、檔案在哪、有哪些注意事項
ark secrets status             # 已解鎖時的同一份資訊（含 secret 數量）
ark secrets migrate            # 把明文 secrets.toml 併入 secrets.enc 並銷毀明文
ARK_VAULT_BACKEND=tpm ark secrets migrate
ARK_VAULT_REQUIRE_ENCRYPTION=1 # 沒有金鑰來源時直接失敗，不降級
```

**為什麼 TPM 不自動選用**：對非 root 使用者，每一次 `systemd-creds encrypt/decrypt` 都會經 polkit 要授權——vault 每開一次就跳一次密碼框，這正是第 0 段禁止的「核准洪水」。所以自動探測只在 `geteuid()==0`（systemd 服務）時選 TPM；其他使用者要用 `ARK_VAULT_BACKEND=tpm ark secrets migrate` 明確選擇，或在 unit 裡用 root 服務。測試一律用 `Options.creds_tool` / `Options.keyring_tool` 指向 TMPDIR 裡的替身腳本，不會呼叫真正的 `systemd-creds`、`secret-tool` 或任何會跳視窗的工具。

**遷移是一次性且可驗證的**：讀明文 → 寫密文 → **讀回並逐項比對** → 才用 0 覆寫明文再刪除。讀回不一致就保留明文並報錯（`crates/ark-kernel/src/secretstore.rs` 的 `verify_readback`）。`ark secrets set` 之後 `secrets.toml` 不再存在，備份／profile 匯出清單也同步改成 `secrets.enc` + `secrets.key`。

### 1.3 VM 與 broker 永遠拿不到明文

- 明文只存在 daemon 的記憶體（`Arc<Vault>`）；VM 內沒有任何設定檔或 socket。
- 工具在 VM 裡看到的是 `{{secret:NAME}}`；替換（`Vault::substitute`）發生在 daemon 這一側，用於**出口請求**（egress proxy 注入 header／broker 代送）。
- 出口掃描會攔下任何含明文值的請求（`Vault::leaks`）；日誌與工具輸出用 `Vault::redact` 換回佔位符。
- 既有測試：`egress_injects_secrets_and_refuses_them_on_the_way_out`、`injected_secret_reaches_upstream_only`（`crates/ark-security/tests/`）。

### 1.4 到哪裡為止

- **不擋**執行中的 root：daemon 必須持有解密後的金鑰。
- **不擋**記憶體 dump／core dump。
- `tpm` backend 綁「這台機器 + TPM」，不綁使用者；同一台機器上能讀 `secrets.key` 的使用者仍需 TPM 才能解封，但 root 可以透過 TPM 解封。
- `keyring` backend 的安全性等於登入 keyring 的安全性。
- `ARK_VAULT_PASSPHRASE`（環境變數）對同使用者其他程序可見（`/proc/<pid>/environ`），優先用 `ARK_VAULT_PASSPHRASE_FILE`。
- 金鑰輪替沒有自動化：換 backend 或換密語時，用 `ark secrets backend` 確認，然後重新 `set` 每個值（或先 `migrate` 再人工確認）。

---

## 2. 外掛／技能來源驗證（A13）

| 保證 | 實作 | 測試（節選） |
|---|---|---|
| **簽章**：套件 manifest 以 Ed25519 簽章，金鑰由 trust store 決定 | `ark_security::signing`（`PublicKey`、`verify`、`manifest_digest`、`TrustStore`）、`ark_skills::hub::verify`、`ark_plugin::verify::verify_manifest` | `signed_bundle_verifies_and_records_the_signer`、`signed_manifest_verifies_and_tampering_is_refused` |
| **完整性**：內容 digest 以排序後的 `路徑\0<sha256>\n` 計算；安裝後在 `check`/`update` 重新計算，磁碟被改過就回報 `integrity_failure` | `hub::verify::{content_digest, verify_installed}` | `installed_dir_drift_is_an_integrity_failure` |
| **版本鎖定**：lock 檔記錄 `version` + `content_hash` + `key_id`；hub 端跳到別的版本會拒絕，除非 `--force` | `hub::verify::{pin, enforce_pin}` | `pinned_version_refuses_a_hub_side_jump_without_force` |
| **能力變更要重新確認（防 rug pull）**：更新後能力變多 → 需要同意，非互動時直接拒絕並列出新增能力 | `plugin_guard::{summarize, widened}`，`ark_plugin::verify::capability_diff` | `capability_widening_on_update_needs_consent` |

預設 `[policy] require_signature = false`（**不破壞既有安裝**）；要強制簽章，在 trust store TOML 設 `require_signature = true`，未簽章或簽章無效的套件會被拒絕並指出缺少哪個 key id。

---

## 3. SSRF 判定合一（A14）

只有一份位址分類表：`ark_security::url_safety`（`is_blocked_ip`、`is_always_blocked_ip`、`BLOCKED_HOSTNAMES`、`check_host`、`check_resolved`）。

| 呼叫端 | 用法 |
|---|---|
| web 工具 / egress gate / `ark security check-url` | 直接使用 |
| 瀏覽器 | `ark-browser::policy` delegate（第 5 輪） |
| 圖片／影音抓取 | `ark-media::vision` delegate（第 5 輪），本輪加上**連線時**再判定 |
| 模型供應商 | `ark-model::net::is_metadata_host` delegate（本輪） |
| Teams 同意上傳 | `ark-channel::msteams::consent_addresses_ok` delegate（本輪） |

另外，媒體抓取 provider 給的結果網址時：每個轉址跳點都重新判定，且**實際 dial 的位址**也再判定一次（`ark-media::http::PinnedResolver`），所以「檢查時解析到公開位址、連線時解析到內網」的 DNS rebinding 走不通。信任清單是 `host:port` 精確比對：信任 `127.0.0.1:8080` 不會順便信任 `127.0.0.1:22`。

---

## 4. 供應鏈與發佈（A18）

| 項目 | 位置 | 說明 |
|---|---|---|
| SBOM | `packaging/release/sbom.py` | SPDX 2.3 JSON，`Cargo.lock` 為結構來源、`cargo metadata` 補授權；輸出可重現（排序、`SOURCE_DATE_EPOCH`、內容雜湊當 namespace）；`--check` 驗證既有 SBOM |
| 發佈簽章 | `packaging/release/{gen-key,sign,verify-release}.sh` | Ed25519（openssl），detached 簽章蓋在 `SHA256SUMS` 上；`verify-release.sh` 同時檢查每個檔案的雜湊、有無未列出的檔案、SBOM 是否為合法 SPDX |
| 可重現建置 | `packaging/release/repro-check.sh` | 兩個不同路徑、各自 `CARGO_TARGET_DIR`、固定 `SOURCE_DATE_EPOCH`，逐檔比對雜湊 |
| 依賴更新審查 | `packaging/release/DEPENDENCY-REVIEW.md` | 新依賴要什麼理由、`cargo deny`、授權、feature、build script/proc-macro 審查、OSV 分級處理 |
| 發佈流程 | `packaging/release/README.md` | 從版本號到 `SHA256SUMS.sig` 的完整步驟 |

**已知限制**：目前 `repro-check.sh --quick` 會回報 `bin/ark` DIFF，原因是若干模組在編譯期用 `env!("CARGO_MANIFEST_DIR")` 把建置路徑寫進二進位（`ark-kernel/selfrepo.rs`、`ark-browser`、`ark-skills`、`ark-vm`、`ark-plugin`）。腳本會印出找出它們的指令；在那些呼叫點改掉之前，「可重現建置」是**檢查機制已就位、目標尚未達成**。

---

## 5. 本輪一併修掉的小洞（A15）

| 問題 | 修正 |
|---|---|
| 媒體抓取 provider 端點的轉址／DNS rebinding | 每次跳點 + 連線時各判定一次（`PinnedResolver`） |
| `docs/pdf.rs` 暫存目錄 0755 | 建立時就是 0700 |
| `ui.terminal.open` 可用任意絕對路徑執行 | 只接受 PATH 上的允許清單短名，解析成絕對路徑後 exec（不經 shell），拒絕 group/world 可寫的目標 |
| `ark uninstall --purge` 無防呆 | 拒絕 `/`、`$HOME`、`/home`、`/root`、`/usr…`、`/etc`、`/var`、少於 3 層的路徑、指向它們的 symlink |
| `/prompt` 草稿 0644 | 以 `O_NOFOLLOW` + `0600` 建立，編輯器結束後刪除 |
| 測試碰到真實 `$HOME` | 改注入路徑／`TempDir`，`test_hygiene_allow.txt` 只能變短 |
| kanban paused 不顯示 | `/workboard dispatch` 先印 `paused: …`，JSON 也有 `paused` |

## 6. 第 9 輪：safety 組補的破口

| 項目 | 做法 | 入口 |
|---|---|---|
| 發檔來源（srv-012） | channel 動作讀主機檔案前，路徑（解析 symlink、`..`）必須落在 session 工作區或 artifact 目錄（＋`ARK_SEND_ROOTS`），且不是金鑰類檔案（`.ssh`、`.gnupg`、`.aws`、`id_*`、`secrets.*`…）；`message` 工具先檢查一次，Discord／Slack／Feishu／Yuanbao 的讀檔函式再檢查一次。這是獨立於出口核准的第二層 | `message` 工具、`ark message` |
| 預設隔離（srv-015／016） | 沒有 microVM 時，所有 session（含 owner）都進 bwrap／Landlock，主機家目錄與金鑰不掛入；連 namespace 沙箱都沒有才在主機執行並印 `NOT ISOLATED` | `ark sandbox explain`、`ark doctor` |
| 聊天回覆過濾（srv-019、H11） | 頻道回覆與串流預覽移除 `<memory-context>`／`<recalled-context>`，並遮罩金鑰樣式字串 | 所有 channel |
| 遠端第 3 級核准（srv-017／018） | 見 MANUAL §4.5：owner 限定、二次確認、無 Allow Always、記錄核准者、逾時通知 | 聊天按鈕、`/approve` |
| MCP 工具釘選（gen2-505） | 首次載入時對每個工具的名稱／說明／schema／annotations 取 SHA-256（`<data>/mcp-pins.json`）；之後有變動或新增的工具一律不給模型，直到 `ark mcp pins diff` 檢視、`ark mcp pins accept` 重新核准 | `ark mcp pins` |
| 提示與內建技能完整性（gen2-508） | `crates/ark-skills/bundled-skills.sha256`（編進二進位）記錄基礎系統提示與每個內建技能的 SHA-256；磁碟上被改過或不在清單內的內建技能不載入、不同步；測試強制清單與原始碼一致 | `ark doctor` |
| 執行期秘密掃描（H11 執行期那一半） | 工具輸出在進入上下文／session log 前遮罩金鑰樣式字串（並留一筆 Notice）；`git commit` 的暫存變更含 vault 值或金鑰樣式時先問人。`[security] mask_output_secrets = false` 可關。CI 端的掃描由 release 組處理 | 自動 |

---

## 7. 回報安全問題

如果是金鑰外洩：先 `ark secrets set NAME` 換掉該金鑰，再 `ark secrets backend` 確認加密狀態。程式缺陷請附上 `ark doctor`、`ark security audit` 的輸出與重現步驟；不要在 issue 裡貼任何 `{{secret:…}}` 的實際值。
