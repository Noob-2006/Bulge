# 安裝 SE Agent

SE Agent（System Engineering Agent，指令 `seagent`）是單一個靜態連結的 Linux 執行檔，加上一包技能、角色與範本資料。本文件說明每一種安裝方式，以及在各種機器上裝不起來時要看什麼。

> 只想最快裝起來：跳到 [§2 一個指令安裝](#2-一個指令安裝)。裝不起來：跳到 [§9 疑難排解](#9-疑難排解)，每一列都是「看到什麼 → 為什麼 → 怎麼做」。
> 常見問題（帳號、費用、資料放哪、隱私）另見 [faq.md](faq.md)。

---

## 1. 先確認這台機器能不能裝

| 項目 | 需求 | 怎麼查 |
|---|---|---|
| 作業系統 | Linux（任何發行版；核心 4.x 以上） | `uname -sr` |
| CPU | x86_64 或 aarch64（arm64） | `uname -m` |
| C 函式庫 | 不需要：發行的執行檔是 musl 靜態連結，glibc 版本新舊、Alpine 都能跑 | — |
| 記憶體 | 執行本身約 50–150 MB；開桌面 VM 另加 2 GB（可設定） | `free -m` |
| 磁碟 | 程式 + 資料約 150 MB；桌面 VM 映像約 2.7 GB；microVM 映像另計 | `df -h ~` |
| 網路 | 安裝時需要連到 GitHub Releases（或你的鏡像）；之後只連你設定的模型供應商 | — |
| systemd | 有最好（開機自動啟動）；沒有也能裝，改用背景程序或 OpenRC | `ps -p 1 -o comm=` |

**選配**（缺了只是對應功能不能用，裝得起來）：

| 選配 | 用途 | 安裝 |
|---|---|---|
| `git` | 程式碼相關工具、worktree | `apt install git` / `dnf install git` / `pacman -S git` / `apk add git` |
| QEMU + `/dev/kvm` | 桌面 VM、工具隔離 microVM | `apt install qemu-system-x86 qemu-utils`；使用者加入 `kvm` 群組 |
| Chromium / Chrome | 瀏覽器工具 | 系統套件，或安裝時加 `--with-browser`（固定版本、驗證過雜湊） |
| `secret-tool`（libsecret） | 把保管庫金鑰放進系統鑰匙圈 | `apt install libsecret-tools` |
| docker / podman | 容器沙箱、sandbox-browser | 依發行版 |

macOS、Windows：沒有原生版本。Windows 請用 WSL2（見 §9）；macOS 可以用 Linux VM 或容器。

---

## 2. 一個指令安裝

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/se-agent/System-Engineering-Agent/releases/latest/download/install.sh | sh
```

- 不需要 sudo。程式放在 `~/.local/bin/seagent`，設定在 `~/.config/seagent`，資料在 `~/.local/share/seagent`。
- 會：下載對應 CPU 的版本 → 對照 `SHA256SUMS` 驗證 → 安裝 → 用 systemd 使用者服務啟動（沒有就改背景程序）→ 印出（桌面環境下自動開啟）一次性設定精靈連結。
- 精靈連結 30 分鐘內有效、只能用一次。過期了：`seagent setup link`。

### 當成系統服務安裝（伺服器、多人共用）

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/se-agent/System-Engineering-Agent/releases/latest/download/install.sh | sudo sh -s -- --system
```

建立專用帳號 `seagent`，設定在 `/etc/seagent`、狀態在 `/var/lib/seagent`、日誌在 `/var/log/seagent`，服務名稱 `seagentd`。

### 安裝程式選項

| 選項 | 作用 |
|---|---|
| `--user`（預設）／`--system` | 個人安裝／系統服務 |
| `--port N` | 網頁主控台埠號（只綁 127.0.0.1，預設 8640） |
| `--version vX.Y.Z` | 指定版本（預設最新） |
| `--no-start` | 只安裝，不設定、不啟動 |
| `--no-systemd` | 不用 systemd，改用背景程序 |
| `--no-browser` | 不自動開瀏覽器 |
| `--with-browser` | 一併安裝固定版本的 Chrome for Testing（驗證 sha256） |
| `--local-binary PATH` | 安裝你手上的執行檔（不下載） |
| `--package FILE` | 系統安裝改用 .deb/.rpm |
| `--from-source` | 用 cargo 從原始碼編譯 |
| `--uninstall [--purge]` | 解除安裝（預設保留設定與資料；`--purge` 一併清除） |
| `-y` | 不詢問，全用預設 |

環境變數：`SEAGENT_RELEASE_BASE`（鏡像目錄或 `file://`）、`SEAGENT_RELEASE_PUBKEY`（驗證 `SHA256SUMS.sig` 的公鑰）、`SEAGENT_INSTALL_DIR`（個人安裝的執行檔目錄）、`SEAGENT_REPO`。

重跑同一個指令就是升級。

---

## 3. 用發行版的套件管理員安裝

所有套件內容相同：`/usr/bin/seagent`、`/usr/share/seagent`、`/etc/seagent`、systemd 單元（Alpine 另附 OpenRC 腳本）。套件**不會**自動啟動服務——一個能連網的代理，必須等管理者設定後才開。安裝後照畫面上的 1-2-3 做即可。

### Debian / Ubuntu（.deb）

```bash
sudo apt install ./seagent_<版本>-1_amd64.deb
```

或加套件庫（發行版本附 `seagent-apt-repo.tar.gz`，簽章金鑰隨附）：見 [enterprise/install.md](enterprise/install.md)。

### Fedora / RHEL / Rocky / Alma / Amazon Linux / openSUSE（.rpm）

```bash
sudo dnf install ./seagent-<版本>-1.x86_64.rpm      # 或 yum localinstall／zypper install
```

### Arch Linux / Manjaro / EndeavourOS（pacman）

```bash
sudo pacman -U seagent-<版本>-1-x86_64.pkg.tar.zst
```

AUR：`seagent-bin`（上架後 `yay -S seagent-bin` 或 `paru -S seagent-bin`）。PKGBUILD 由 `packaging/arch/mkpkgbuild.sh` 從發行版本的 `SHA256SUMS` 產生，也可以自己產生後 `makepkg -si`。

### Alpine（apk，OpenRC）

```bash
sudo apk add --allow-untrusted ./seagent_<版本>-r1_x86_64.apk
sudo rc-update add seagentd default && sudo rc-service seagentd start
```

### 三步完成系統服務設定（所有套件相同）

```bash
sudo -u seagent seagent setup bootstrap     # 開啟本機網頁主控台（127.0.0.1:8640）
sudo systemctl enable --now seagentd        # Alpine：rc-service seagentd start
sudo -u seagent seagent setup link          # 一次性設定精靈連結
```

不想開瀏覽器：`sudo -u seagent seagent setup --non-interactive --provider <供應商> --model <模型>`（金鑰用環境變數 `SEAGENT_SETUP_API_KEY` 給，不放在指令列）。

---

## 4. 其他安裝方式

### npm

```bash
npm install -g @se-agent/seagent
seagent setup
```

npm 套件只是包裝：安裝時下載同一個發行執行檔並驗證 `SHA256SUMS`。離線：`SEAGENT_NPM_TARBALL=/path/seagent-x86_64-unknown-linux-musl.tar.gz npm install -g @se-agent/seagent`；鏡像：`SEAGENT_NPM_BASE_URL`。系統服務、稽核、多人環境請用發行版套件。

### Nix / NixOS

```bash
nix profile install github:se-agent/System-Engineering-Agent       # 單純裝指令
```

NixOS 系統服務：

```nix
{
  inputs.seagent.url = "github:se-agent/System-Engineering-Agent";
  # …
  imports = [ inputs.seagent.nixosModules.default ];
  services.seagent.enable = true;
}
```

Home Manager：`inputs.seagent.homeManagerModules.default`。

### 壓縮檔（任何 Linux，含 Alpine、容器）

```bash
curl -fsSLO https://github.com/se-agent/System-Engineering-Agent/releases/latest/download/seagent-x86_64-unknown-linux-musl.tar.gz
curl -fsSLO https://github.com/se-agent/System-Engineering-Agent/releases/latest/download/SHA256SUMS
grep ' seagent-x86_64-unknown-linux-musl.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf seagent-x86_64-unknown-linux-musl.tar.gz -C ~/.local     # 或 sudo tar … -C /usr/local
```

壓縮檔是一個 prefix：`bin/seagent` 與 `share/seagent/`，解到哪裡都能用（程式從自己的位置找到 `../share/seagent`）。

### 離線／隔離網路

發行版本附 `seagent-offline-<版本>-<arch>.tar.gz`（含執行檔、deb/rpm、技能資料，可選 Chrome for Testing）。在連得到網路的機器下載後帶進去：

```bash
tar -xzf seagent-offline-<版本>-amd64.tar.gz && cd seagent-offline-*
sudo ./install.sh --system        # 或 ./install-offline.sh
```

不會連任何網路。

### 容器

```bash
export SEAGENT_APP_TOKEN=$(openssl rand -hex 24)
docker compose -f packaging/docker/compose.yml up -d
```

另有 `Dockerfile.distroless`、`Dockerfile.ubi`、Helm chart（`deploy/helm/seagent`）、Ansible role（`deploy/ansible/roles/seagent`）、cloud-init（`deploy/cloud-init/seagent.yaml`）、Terraform 範例（`deploy/terraform`）。

### 從原始碼

```bash
git clone https://github.com/se-agent/System-Engineering-Agent && cd seagent
cargo build --release -p seagent                # Rust 1.80 以上
./packaging/install.sh --local-binary target/release/seagent
```

精簡建置、交叉編譯、靜態 musl：見 [BUILD.md](BUILD.md)。

---

## 5. 驗證你下載的檔案

1. **雜湊**：每個發行檔都列在 `SHA256SUMS`；安裝程式一定會比對。
2. **簽章**（建議）：`SHA256SUMS.sig` 是 Ed25519 簽章。取得發行公鑰後：

   ```bash
   SEAGENT_RELEASE_PUBKEY=release-key.pub.pem sh install.sh      # 簽章不符就中止
   packaging/release/verify-release.sh                            # 手動驗證
   ```

3. **建置來源**：有 GitHub CLI 時，安裝程式會順便跑 `gh attestation verify`。
4. **套件**：`rpm -K seagent-*.rpm`、`dpkg-deb -I seagent_*.deb`。

---

## 6. 裝好之後

| 想做什麼 | 指令 |
|---|---|
| 看安裝狀態、哪裡有問題 | `seagent doctor`、`seagent status` |
| 看檔案放在哪、為什麼 | `seagent config path` |
| 打開網頁主控台 | `seagent app open`（印出含 token 的網址） |
| 終端機設定精靈 | `seagent setup` |
| 換模型／金鑰 | `seagent model`、`seagent secrets set <名稱>`（從標準輸入讀，貼上後 Enter、Ctrl+D） |
| 看日誌 | `seagent logs`；系統服務：`journalctl -u seagentd` |
| 背景服務 | `seagent daemon start|stop|status` |
| 升級 | 重跑安裝指令；或 `seagent update`；套件安裝則用套件管理員 |

目錄的完整說明見 [paths.md](paths.md)。

---

## 7. 解除安裝

| 安裝方式 | 指令 | 資料 |
|---|---|---|
| 一個指令安裝 | `sh install.sh --uninstall`（加 `--purge` 一併刪除） | 預設保留 |
| deb | `sudo apt remove seagent` | 保留 `/etc/seagent`、`/var/lib/seagent`、帳號 |
| rpm | `sudo dnf remove seagent` | 同上 |
| pacman | `sudo pacman -R seagent`（AUR：`seagent-bin`） | 同上 |
| apk | `sudo apk del seagent` | 同上 |
| npm | `npm uninstall -g @se-agent/seagent` | 個人資料保留在 `~/.local/share/seagent` |

保留資料是刻意的：工作階段與稽核紀錄是證據。要完全清除：`rm -rf ~/.config/seagent ~/.local/share/seagent ~/.cache/seagent`（個人），或照套件移除時印出的指令（系統）。

---

## 8. 從舊名稱 ark 升級

這個專案以前叫 `ark`。升級時：

- **環境變數**：舊的 `ARK_*`（例如 `ARK_HOME`）仍然有效，等同 `SEAGENT_*`；兩者都設時以新的為準。
- **個人目錄**：第一次執行 `seagent` 時，`~/.config/ark`、`~/.local/share/ark`、`~/.cache/ark` 會自動搬成 `seagent`（新目錄已存在就不搬），並在畫面上說明。
- **專案目錄**：專案裡的 `.ark/` 在還沒有 `.seagent/` 前照樣讀取；要改名就直接 `mv .ark .seagent`。
- **系統安裝**：`seagent` 套件取代 `ark-agent`（`Replaces`），安裝後腳本把 `/etc/ark` 複製到 `/etc/seagent`、把 `/var/lib/ark` 搬到 `/var/lib/seagent`，並停用舊的 `arkd.service`。之後執行 `systemctl enable --now seagentd`。舊帳號 `ark` 保留，確認無用後可 `userdel ark`。
- **保管庫金鑰**：存在系統鑰匙圈或 TPM 的金鑰會以舊名稱找到並自動轉存新名稱。
- **桌面 VM 映像**：需重建（`seagent vm desktop build` 後 `seagent vm desktop reset <名稱>`）。
- **主控台**：瀏覽器存的登入 token 名稱改了，會再要求一次 token（`seagent app token` 會顯示）。

---

## 9. 疑難排解

先跑 `seagent doctor`，它會逐項列出找到的問題。下表是安裝階段最常見的情況。

### 9.1 下載與驗證

| 看到 | 原因 | 處理 |
|---|---|---|
| `needs curl or wget` | 精簡映像沒有下載工具 | `apk add curl`／`apt install curl`，或改用壓縮檔／離線包 |
| `download failed` | 連不到 GitHub、公司代理、DNS | 設 `https_proxy`；或在別台下載後用 `SEAGENT_RELEASE_BASE=file:///path` |
| `checksum mismatch` | 下載不完整、被代理改寫、鏡像不同步 | 重新下載；確認鏡像與 `SHA256SUMS` 同一版本；**不要**略過驗證 |
| `signature of SHA256SUMS does not verify` | 公鑰不對或檔案被竄改 | 確認公鑰來源；停止安裝並回報 |
| `prebuilt binaries are Linux-only` | 在 macOS／BSD 上執行 | 用 Linux VM、WSL2 或容器 |
| `unsupported CPU` | 32 位元或其他架構 | 只提供 x86_64、aarch64；其他架構用 `--from-source` |
| 公司 TLS 檢查（自簽 CA） | 代理換掉了憑證 | 把公司 CA 加進系統信任庫（`update-ca-certificates`／`update-ca-trust`） |

### 9.2 權限與帳號

| 看到 | 原因 | 處理 |
|---|---|---|
| `a system install needs root` | `--system` 沒加 sudo | `curl … | sudo sh -s -- --system` |
| `running as root: this is a user install for root` | 用 root 跑個人安裝 | 要系統服務請加 `--system` |
| `cannot create the seagent account` | 映像沒有 `useradd`／`adduser` | 安裝 `shadow-utils`（RHEL 系）／`passwd`，或先手動建帳號 |
| `add … to PATH` | `~/.local/bin` 不在 PATH | 照提示把 `export PATH=…` 加進 `~/.bashrc` 或 `~/.profile`，重新登入 |
| `/tmp` 是 noexec | 硬化過的主機 | `TMPDIR=$HOME/.cache/tmp sh install.sh` |

### 9.3 服務起不來

| 看到 | 原因 | 處理 |
|---|---|---|
| `systemd user unit failed; falling back to a background daemon` | SSH 登入沒有 user session（`XDG_RUNTIME_DIR` 空的） | 可以接受；要開機自動啟動：`sudo loginctl enable-linger $USER` 後重跑安裝 |
| 登出後服務停了 | 沒開 linger | `sudo loginctl enable-linger $USER` |
| `systemctl restart seagentd failed` | 設定錯誤、埠被占用 | `journalctl -u seagentd -n 50`；`sudo -u seagent seagent config validate` |
| `the console did not come up in 30s` | 啟動慢、埠衝突、防火牆 | `seagent doctor`；`ss -ltnp | grep 8640`；換埠：`--port 18640` |
| 容器裡沒有 systemd | PID 1 不是 systemd | `--no-systemd`，或直接 `seagent daemon run` 當前景程序 |
| SELinux 拒絕（`avc: denied`） | 強制模式下的檔案標籤 | `sudo restorecon -Rv /usr/bin/seagent /var/lib/seagent /etc/seagent` |
| systemd 很舊（CentOS 7） | 單元檔指令不認得 | 套件安裝後會自動改寫單元檔；手動：`seagent service print --system` |

### 9.4 網頁主控台

| 看到 | 原因 | 處理 |
|---|---|---|
| 在別台電腦開不到 | 主控台只綁 127.0.0.1（刻意的） | SSH 轉送：`ssh -L 8640:127.0.0.1:8640 主機`；要對外開放見 [enterprise/install.md](enterprise/install.md) 的反向代理與 TLS |
| 要求輸入 token | 新瀏覽器、token 換過、改名後 | `seagent app token`，或 `seagent app open` 直接帶 token 開 |
| 設定精靈連結失效 | 超過 30 分鐘或已使用 | `seagent setup link` |
| 左上角顯示連線中斷 | daemon 停了或重啟中 | `seagent daemon status`；它會自動重連 |

### 9.5 模型與金鑰

| 看到 | 原因 | 處理 |
|---|---|---|
| `Auth: … the key contains a control character` | 貼金鑰時終端機夾帶了控制碼 | `seagent secrets set <供應商>_API_KEY`，貼上後 Enter、Ctrl+D |
| `401`／`403` | 金鑰錯、過期、沒額度 | `seagent providers check`；到供應商後台確認 |
| `model not found` | 模型名稱打錯或供應商沒有 | `seagent models list <供應商>`；`seagent model` 互動選擇 |
| 一直重試 `Network` | 連不到供應商、代理 | 設 `https_proxy`；`seagent providers check <供應商>/<模型>` 測試連線 |

### 9.6 選配功能

| 看到 | 原因 | 處理 |
|---|---|---|
| 桌面 VM 很慢、提示 TCG | 沒有 `/dev/kvm` 權限 | `sudo usermod -aG kvm $USER` 後重新登入；雲端 VM 需開巢狀虛擬化 |
| `qemu-system-x86_64 not found` | 沒裝 QEMU | `apt install qemu-system-x86 qemu-utils` |
| 瀏覽器工具找不到瀏覽器 | 沒裝 Chromium | 重跑安裝加 `--with-browser`，或 `seagent browser install` |
| Chrome 沙箱失敗（Ubuntu 24.04） | AppArmor 限制非特權 user namespace | 已自動加 `--no-sandbox`（`no_sandbox = "auto"`）；或用桌面 VM 的瀏覽器 |
| 鑰匙圈不可用 | 沒有 `secret-tool` 或桌面登入鑰匙圈 | `apt install libsecret-tools`；伺服器改用 TPM 或密碼檔（`seagent secrets backend`） |

### 9.7 特殊環境

| 環境 | 注意 |
|---|---|
| WSL2 | 用 Ubuntu 發行版照一般方式安裝；需在 `/etc/wsl.conf` 開 `systemd=true` 才有服務；桌面 VM 需巢狀虛擬化 |
| Docker／LXC 容器 | `--no-systemd`；microVM／桌面 VM 需要把 `/dev/kvm` 傳進容器 |
| Raspberry Pi 等 arm64 | 64 位元系統可用；32 位元 Raspberry Pi OS 不支援 |
| 唯讀根目錄（Fedora Silverblue、Flatcar） | 用個人安裝（`~/.local`）或容器 |
| NixOS | 用 flake／模組，不要跑安裝腳本 |
| 多人共用主機 | 用系統服務；個人安裝之間互不相通；loopback 埠（桌面 VM 的瀏覽器除錯埠）同主機使用者看得到，見 [desktop-vm.md](desktop-vm.md) |

### 9.8 還是不行

收集以下資訊再回報（**不要**附上金鑰或 `secrets.toml`）：

```bash
seagent --version
seagent doctor
seagent config path
uname -a; cat /etc/os-release
journalctl -u seagentd -n 100 --no-pager      # 系統服務
seagent logs -n 100                           # 個人安裝
```

`seagent doctor` 與日誌已遮蔽祕密，但送出前仍請自行看過一遍。
