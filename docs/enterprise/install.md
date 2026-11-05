# 安裝與發佈物驗證

所有路徑都得到同一份靜態二進位 `seagent` 與同一份共用資料（`seagent_core::share` 在執行期尋找）。目錄配置（使用者 XDG／系統 FHS／`SEAGENT_HOME`）與判定規則見 [../paths.md](../paths.md)；`seagent config path` 印出實際使用的位置。

## 0. 一個指令

```sh
curl --proto '=https' --tlsv1.2 -fsSL <發佈位置>/install.sh | sudo sh -s -- --system
```

| 步驟 | 做什麼 |
|---|---|
| 1 平台 | 讀 `/etc/os-release` 與 CPU；選模式（`--user`／`--system`，有 TTY 時會問，預設個人安裝）|
| 2 取得與驗證 | 下載靜態 musl tarball 與 `SHA256SUMS`；設了 `SEAGENT_RELEASE_PUBKEY` 時驗 Ed25519 簽章；有 `gh` 時驗來源證明。離線包或 `SEAGENT_RELEASE_BASE=file://…` 不連網 |
| 3 安裝 | 系統：`/usr/local/bin/seagent`＋`/usr/local/share/seagent`（或 `--package` 的 deb/rpm），建立 `seagent` 帳號與 `/etc/seagent`（root:seagent 1770）、`/var/lib/seagent`、`/var/cache/seagent`、`/var/log/seagent`、`/run/seagent` |
| 4 設定 | `seagent setup bootstrap`：開啟本機網頁主控台（`127.0.0.1:8640` 或 `--port`），在保管庫產生 `APP_TOKEN`；不碰模型設定 |
| 5 服務 | systemd：`seagentd.service`（系統）或使用者單元；沒有 systemd（容器）時以服務帳號在背景執行 `seagent daemon` |
| 6 健康檢查 | 等 `GET /health` |
| 7 設定連結 | `seagent setup link`：一次性、30 分鐘有效的設定權杖（只存雜湊，0600），網址放在 `#fragment`，不進伺服器日誌與 Referer |

重跑即升級（設定不變、服務重啟）；`--uninstall` 停止並移除程式，保留 `/etc/seagent` 與 `/var/lib/seagent`；`--uninstall --purge` 另外刪除設定、金鑰、資料、快取、日誌與 `seagent` 帳號（`/etc/seagent/managed*` 政策保留）。

遠端主機：`ssh -L 8640:127.0.0.1:8640 <主機>` 後在本機瀏覽器開連結。主控台預設只綁 loopback；對外開放要走 `[app.exposure]` 全套防線。

### 網頁設定精靈（`/setup`）

`POST /setup/rpc`（JSON-RPC 2.0，標頭 `x-seagent-setup-token`；管理者權杖也可走 `/arp`）：

| 方法 | 參數 | 結果 |
|---|---|---|
| `setup.status` | – | `{locked, token_valid, mode, paths, configured, providers[], security_modes[], auth_modes[], channels[], workspace, service, expires_ms}`；權杖無效時只回 `{locked, token_valid: false, reason}` |
| `setup.test_provider` | `{provider, api_key?, base_url?}` | `{ok, count, models[]}` 或 `{ok: false, error}`（不回顯金鑰）|
| `setup.apply` | `{provider, model, api_key?, base_url?, security?: strict｜balanced｜relaxed, workspace?, auth?: {mode: token｜oidc, issuer?, client_id?, client_secret?}, channel?: {kind: telegram｜discord, token, owner?}, autostart?}` | `{ok, config, lines[], console_url, restart}` |

`setup.apply` 成功即消耗權杖並鎖定精靈（`<資料>/setup/done.json`）；`seagent setup`（終端機）與 `seagent setup --non-interactive` 完成時也會鎖定。重新開啟：`seagent setup link --reopen`。金鑰、OIDC client secret、bot token 只進保管庫，設定檔只有 `{{secret:…}}` 參照。套用後 daemon 以新設定重啟（systemd 下以結束碼 75 讓 `Restart=on-failure` 拉起；背景模式自行重啟）。

## 1. 套件

套件名稱是 **`seagent`**，二進位也叫 `seagent`。本產品改名前叫 `ark`、套件叫 `ark-agent`；`seagent` 宣告 `Replaces`／`Provides`／`Conflicts: ark-agent`，直接升級即可取代舊套件，設定與資料由安裝後腳本搬到新位置（見下方「從 ark 升級」）。

| 路徑 | 內容 |
|---|---|
| `/usr/bin/seagent` | 靜態二進位 |
| `/usr/share/seagent/` | 技能、角色、plugin 目錄、VM／sandbox-browser 建置來源、`managed-by-package`（`seagent update` 因此不會自我更新）|
| `/etc/seagent/`（root:seagent 1770）、`/etc/seagent/managed.d/` | 系統服務的 `config.toml`、金鑰（服務帳號擁有）＋組織政策（root 擁有）。套件只擁有目錄與 `managed.toml.example` |
| `/usr/lib/systemd/system/seagentd.service` | 系統服務（`render_unit` 產生，`SEAGENT_MODE=system`；systemd < 245 時 postinstall 以 `seagent service print --system` 重新產生，219 也可）|
| `/usr/lib/sysusers.d/seagent.conf`、`/usr/lib/tmpfiles.d/seagent.conf` | 專用帳號 `seagent`；`/etc/seagent`、`/var/lib/seagent`、`/var/cache/seagent`、`/var/log/seagent`、`/run/seagent` |
| `/var/lib/seagent`、`/var/cache/seagent`、`/var/log/seagent` | 資料、快取、日誌。**不屬於套件**：移除套件不會刪資料與帳號 |

安裝**不會**啟動服務。啟動（或改用第 0 節的一個指令）：

```sh
sudo -u seagent seagent setup bootstrap          # 開啟本機網頁主控台
sudo systemctl enable --now seagentd
sudo -u seagent seagent setup link               # 一次性設定精靈連結
# 或無人值守：
sudo -u seagent env SEAGENT_SETUP_API_KEY=… seagent setup --non-interactive --no-service --provider anthropic --model claude-sonnet-4-5
seagent doctor
```

`sudo -u seagent seagent …` 會自動使用系統配置（服務帳號的家目錄是 `/var/lib/seagent`）；其他帳號可設 `SEAGENT_MODE=system`。從 ent-008 之前的版本升級時，postinstall 把 `/var/lib/seagent/config` 複製到 `/etc/seagent`，資料留在 `/var/lib/seagent/data` 照常讀取。

`seagent setup` 無人值守旗標與環境變數見 `crates/seagent/src/setup_server.rs`：`--provider`、`--model`、`--base-url`、`--channel`、`--owner`、`--no-service`、`--verify`；金鑰只從環境讀（`SEAGENT_SETUP_API_KEY` 或供應商自己的變數），直接進 vault，不經 argv。

建置（維護者）：

```sh
packaging/nfpm/build-packages.sh --bin <靜態 seagent> --arch amd64 --out dist   # 需要 podman|docker 或 nfpm
```

為什麼用 nfpm：同一份 `nfpm.yaml` 同時產生 deb 與 rpm，不需要 rpmbuild／dpkg 在建置機上，也不需要 cargo 外掛（`cargo-deb`／`cargo-generate-rpm` 會自己用 glibc 重編，而我們要發的是已驗證的靜態 musl 二進位）。

## 2. 簽章的套件庫

```sh
# apt（純 python3 + dpkg-deb + gpg）
packaging/repo/make-apt-repo.py --debs dist --out repo/apt --key-id <KEYID>
# yum/dnf（createrepo_c + rpmsign；沒有就自動用 rockylinux:9 容器）
packaging/repo/make-yum-repo.sh --rpms dist --out repo/rpm --key-id <KEYID> --base-url https://packages.example.com/seagent/rpm
# 端到端驗證：臨時金鑰、debian:12 與 rockylinux:9 實際安裝，並確認外來簽章被拒
packaging/repo/test-repos.sh dist
```

客戶端（apt）：

```sh
install -m 0644 seagent-archive-keyring.gpg /etc/apt/keyrings/
echo 'deb [signed-by=/etc/apt/keyrings/seagent-archive-keyring.gpg] https://packages.example.com/seagent/apt stable main' > /etc/apt/sources.list.d/seagent.list
apt-get update && apt-get install seagent
```

客戶端（dnf／yum）：取 `seagent.repo` 放入 `/etc/yum.repos.d/`，內容已設 `gpgcheck=1`、`repo_gpgcheck=1`。每個 rpm 有簽章，`repomd.xml.asc` 簽中繼資料。

簽章金鑰請放在 HSM／離線機，不要放在 CI；release workflow 以 secret `SEAGENT_REPO_GPG_KEY`（無密語的金鑰）做示範，沒設就不產生套件庫並顯示警告。

## 3. 離線包（air-gapped）

連網區：

```sh
packaging/offline/make-offline-bundle.sh --dist <已驗證的發佈目錄> --arch x86_64 \
   [--vm-image <seagent sandbox vm image build 的輸出>] [--key release-key.pem] --out seagent-offline-0.1.0-x86_64.tar.gz
```

隔離區：

```sh
tar xzf seagent-offline-0.1.0-x86_64.tar.gz && cd seagent-offline
./install-offline.sh --key /path/to/release-key.pub.pem          # tarball 安裝到 /usr/local（root）或 ~/.local
./install-offline.sh --key … --package                          # 改用 rpm/dpkg 裝套件
sudo sh install.sh --system                                      # 或：一個指令（用 release/ 內的檔案，不連網），含服務與設定連結
```

腳本先驗 `BUNDLE.sha256`（及其簽章），再執行 `verify-release.sh release/`（簽章 → 雜湊 → 無額外檔 → SBOM），最後才安裝；全程不連網。

## 4. 容器映像

| 檔案 | 基底 | 用途 |
|---|---|---|
| `Dockerfile` | debian trixie-slim ＋ tini ＋ git | 預設；agent 可在容器內執行 shell／git |
| `Dockerfile.ubi` | UBI 9 minimal | OpenShift／RHEL 環境（支援任意 uid、group 0）|
| `Dockerfile.distroless` | distroless static nonroot | 最小攻擊面；**沒有 shell**，適合遠端執行後端或純通道／API 場景 |

三者都是多階段建置、非 root、`HEALTHCHECK seagent health`，並通過 `seagent docker check`。CI（`.github/workflows/images.yml`）以原生 amd64／arm64 runner 建置、BuildKit SBOM＋provenance、以 cosign keyless 對 manifest digest 簽章：

```sh
cosign verify ghcr.io/<owner>/seagent:<tag> \
  --certificate-identity-regexp 'https://github.com/<owner>/seagent/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## 5. 組態管理

| 工具 | 位置 | 說明 |
|---|---|---|
| Ansible | `deploy/ansible/roles/seagent` | `seagent_install_method: repo｜package｜tarball`；`seagent_managed_policy` 寫入 `/etc/seagent/managed.toml`；無人值守 `seagent setup`；金鑰只在該 task 的環境變數（`no_log`）|
| cloud-init | `deploy/cloud-init/seagent.yaml` | 首次開機裝套件、寫政策、跑 `seagent setup`、啟動服務 |
| Terraform | `deploy/terraform/aws-ec2` | AL2023 單機，無公網 IP、無入站規則、IMDSv2、金鑰存 Secrets Manager、SSM 進入 |
| Helm | `deploy/helm/seagent` | 單副本 StatefulSet，`restricted` PSS、NetworkPolicy、政策 ConfigMap |

## 6. 驗證你拿到的東西

```sh
# 發佈目錄
packaging/release/verify-release.sh <dir> --key <帶外取得的 release-key.pub.pem>
# 套件
rpm -K seagent-*.rpm          # 需先 rpm --import RPM-GPG-KEY-seagent
dpkg-deb -I seagent_*.deb
# GitHub 來源證明
gh attestation verify seagent-*.tar.gz -R <owner>/seagent
```

## 7. 解除安裝

`apt remove seagent`／`dnf remove seagent`：停止並停用服務，移除程式。`/etc/seagent`、`/var/lib/seagent` 與 `seagent` 帳號保留（稽核與工作階段是證據）；要清除請先確認法律保全（`seagent retention hold list`），再 `sudo sh install.sh --uninstall --system --purge`（或自行 `rm -rf /var/lib/seagent /var/cache/seagent /var/log/seagent /etc/seagent/config.toml /etc/seagent/secrets.* && userdel seagent`）。用 `install.sh` 安裝的 tarball 版本：`sudo sh /usr/local/share/seagent/install.sh --uninstall --system`。
