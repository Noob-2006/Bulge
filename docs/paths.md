# 路徑與目錄配置

SE Agent 自己的檔案（設定、資料、快取、日誌、執行期、共用資料）只從一個地方決定：`seagent_core::layout`（`crates/seagent-core/src/layout.rs`），核心的 `Paths`（`seagent_kernel::config::Paths`）建立在它上面。其他程式碼不得自己寫出這些路徑，`crates/seagent/tests/path_lint.rs` 會擋下。

`seagent config path`（或 `seagent config path --json`）印出目前實際使用的配置與判定原因。

## 模式判定（依序，先符合者勝）

| 順序 | 條件 | 模式 |
|---|---|---|
| 1 | 設了 `SEAGENT_HOME` | **portable**：全部放在 `$SEAGENT_HOME` 底下（測試、`seagent -p 名稱` 設定檔、可攜安裝、容器 `/data`）|
| 2 | `SEAGENT_MODE=system` 或 `SEAGENT_MODE=user` | 明確指定（套件的系統服務單元設 `SEAGENT_MODE=system`）|
| 3 | 以非 root 帳號執行，且該帳號 passwd 家目錄是 `/var/lib/seagent` | **system**（因此 `sudo -u seagent seagent …` 自動對到系統服務）|
| 4 | 其他 | **user**（XDG）|

任一目錄都可個別覆寫（只接受絕對路徑）：`SEAGENT_CONFIG_DIR`、`SEAGENT_DATA_DIR`、`SEAGENT_CACHE_DIR`、`SEAGENT_LOG_DIR`、`SEAGENT_RUNTIME_DIR`。共用資料另有 `SEAGENT_SHARE_DIR`（見 `seagent_core::share`）。

## 配置表

| | user（XDG）| system（FHS，ent-008）| portable（`SEAGENT_HOME`）|
|---|---|---|---|
| 設定＋金鑰 | `$XDG_CONFIG_HOME/seagent` | `/etc/seagent`（root:seagent 1770）| `$SEAGENT_HOME/config` |
| 組織政策 | `/etc/seagent/managed.toml`、`managed.d/` | 同左 | 同左 |
| 資料 | `$XDG_DATA_HOME/seagent` | `/var/lib/seagent` | `$SEAGENT_HOME/data` |
| 快取 | `$XDG_CACHE_HOME/seagent` | `/var/cache/seagent` | `$SEAGENT_HOME/cache` |
| 日誌 | `<資料>/logs`（`seagentd.log` 在資料目錄）| `/var/log/seagent`（含 `seagentd.log`）| `<資料>/logs` |
| 執行期（socket）| `$XDG_RUNTIME_DIR/seagent`，否則 `<資料>/run` | `/run/seagent` | `$SEAGENT_HOME/run` |
| 預設工作目錄 | `<資料>/workspace` | `/var/lib/seagent/workspace` | `<資料>/workspace` |
| 程式 | `~/.local/bin/seagent` | `/usr/bin/seagent`（套件）或 `/usr/local/bin/seagent` | — |
| 共用資料 | `~/.local/lib/seagent/share` | `/usr/share/seagent` 或 `/usr/local/share/seagent` | `SEAGENT_SHARE_DIR` |

`/etc/seagent` 的權限是 root:seagent、1770（sticky）：服務帳號可以建立與改寫自己的 `config.toml`、`secrets.*`，但不能取代 root 擁有的政策檔；政策載入器也拒絕非 root 擁有的政策檔。系統單元以 `ReadWritePaths=-/etc/seagent` 在 `ProtectSystem=full` 下開放這一個目錄。

socket 路徑上限 107 位元組：執行期目錄過深時改用 `$XDG_RUNTIME_DIR/seagent-<雜湊>` 或 `/tmp/seagent-<uid>/seagent-<雜湊>`（0700，拒絕別人建立的目錄）。

## 向下相容（ent-008 之前的系統安裝）

舊的系統服務以 `SEAGENT_HOME=/var/lib/seagent` 執行（設定在 `/var/lib/seagent/config`，資料在 `/var/lib/seagent/data`）。

- 仍然設 `SEAGENT_HOME` 的舊單元照舊運作（portable 模式），不搬任何東西。
- 新單元（`SEAGENT_MODE=system`）在 `/etc/seagent/config.toml` 不存在、而 `/var/lib/seagent/config/config.toml` 存在時，繼續讀舊設定目錄；`/var/lib/seagent/data` 存在時一律用它當資料目錄（資料永不搬移）。`seagent config path` 會以 `note` 標出正在使用的舊位置。
- 套件 postinstall 會把舊設定**複製**（不是搬移）到 `/etc/seagent` 一次；之後就以 `/etc/seagent` 為準，舊檔保留。

## 改了什麼

| 分類 | 數量 | 處理 |
|---|---|---|
| (b) SE Agent 自己的配置，散落各處自行計算 | 約 25 處 | 改由 `seagent_core::layout`／`Paths` 提供：`Paths::from_env`、系統服務常數（`ops/service.rs`）、`seagent-media` 的模型／語音快取、`seagent-browser` 資料目錄與訊息、會議用 Chrome 設定檔、`exec/sandbox.rs` 的 SE Agent 目錄、`ops/profile.rs`、`debugdump` 的 `/etc/seagent/no-debug-upload`、`managed::SYSTEM_DIR`、`seagent_core::share` 與 `seagent-vm` 的共用資料清單、`cluster keygen` 提示、`seagentd.log`／`logs`／`commands.log` 的位置、wizard 與 setup 的預設工作目錄 |
| (b) 系統服務配置（ent-008）| — | `/etc/seagent` 設定、`/var/lib/seagent` 資料、`/var/cache/seagent`、`/var/log/seagent`、`/run/seagent`；systemd 單元加上 `SEAGENT_MODE=system`、`CacheDirectory`、`LogsDirectory`、`RuntimeDirectory`、`ReadWritePaths=-/etc/seagent`（systemd < 231 改寫成 `ReadWriteDirectories`）；tmpfiles、nfpm、postinstall、NixOS 模組、Ansible、cloud-init 一併更新 |
| (c) 工具預設位置 | 瀏覽器 24、其他十餘處 | 瀏覽器改成先查 `$PATH`，固定安裝位置只當備援（仍可用 `browser.executable`、`SEAGENT_BROWSER_EXECUTABLE` 指定）；新增 `seagent_core::layout::which` |
| 遠端主機上的暫存路徑 | 1 | iMessage 的遠端 Mac `/tmp/seagent-imessage-*`：路徑在對方機器上，保留 |

## 刻意保留

| 類別 | 例子 | 為什麼 |
|---|---|---|
| (a) 作業系統介面 | `/proc`、`/sys`、`/dev/null`、`/dev/tty`、`/etc/os-release`、`/etc/hostname`、`/usr/bin/env`、`/bin/sh`、`/usr/share/zoneinfo`、`/tmp/.X11-unix` | 由核心或標準定義，不可設定；lint 的 `OS_INTERFACE` 清單 |
| 容器／VM／沙箱「內部」的路徑 | `/home/seagent`、`/root/workspace`、`/run/seagent/broker.sock`（VM guest）、bwrap 內的 `/tmp`、容器 tmpfs | 是 SE Agent 自己建出來的映像內配置，不是主機路徑 |
| 敏感路徑拒絕清單 | `gate.rs` 的系統目錄、`risk.rs` 的備份與資料庫目錄、`sandbox.rs` 不掛載的家目錄子路徑、`threat.rs`／`skills_guard.rs` 偵測樣式 | 安全規則本身就是「這些路徑」 |
| 工具備援位置 | 瀏覽器安裝位置、`/usr/local/bin/brv`、Homebrew／Nix 前綴、`update.rs` 判斷套件管理員安裝 | 先查 `$PATH`／設定值，找不到才看常見位置 |
| socket 長度備援 | `/tmp/seagent-<uid>` | 只在執行期目錄超過 sun_path 上限時；拒絕不屬於自己的目錄 |

完整的已審查清單在 `crates/seagent/tests/path_lint_allow.txt`（檔案＋字面值，不含行號）。新增的絕對路徑若不在清單中，`cargo test -p seagent --test path_lint` 會失敗；確實需要固定時加進清單：`SEAGENT_BLESS=1 cargo test -p seagent --test path_lint`。

## 部署檔

| 檔案 | 狀態 |
|---|---|
| `Dockerfile*`、Helm | 容器內 `SEAGENT_HOME=/data`（portable 模式），刻意不變 |
| `packaging/systemd/*`、`nix/nixos.nix` | 由 `ops/service.rs` 產生／檢查；系統模式 FHS 配置 |
| `packaging/nfpm` | `/etc/seagent` 改為 root:seagent 1770；postinstall 建目錄、搬舊設定、提示一次性設定連結 |
| `deploy/ansible`、`deploy/cloud-init` | `SEAGENT_MODE=system`；Ansible 以 `seagent_config_dir: /etc/seagent` 判斷是否已設定 |
| 連接埠 | `127.0.0.1:8640` 是預設值（`[app] listen`、`install.sh --port`、`seagent setup bootstrap --listen`）|
