# 安裝與發佈物驗證

所有路徑都得到同一份靜態二進位 `ark` 與同一個 `/usr/share/ark`（`ark_core::share` 在執行期尋找）。

## 1. 套件

套件名稱是 **`ark-agent`**（二進位仍叫 `ark`）。Debian、Ubuntu、Fedora、openSUSE 的官方套件庫已有一個 KDE 壓縮工具叫 `ark`（同樣安裝 `/usr/bin/ark`）；用相同名字會讓 apt 因 epoch 較高而悄悄裝到 KDE 那個。`ark-agent` 宣告 `Conflicts: ark`，不會互相覆蓋。

| 路徑 | 內容 |
|---|---|
| `/usr/bin/ark` | 靜態二進位 |
| `/usr/share/ark/` | 技能、角色、plugin 目錄、VM／sandbox-browser 建置來源、`managed-by-package`（`ark update` 因此不會自我更新）|
| `/etc/ark/`、`/etc/ark/managed.d/` | 組織政策目錄（套件只擁有目錄與 `managed.toml.example`，不擁有政策檔）|
| `/usr/lib/systemd/system/arkd.service` | 系統服務（`render_unit` 產生；systemd < 245 時 postinstall 以 `ark service print --system` 重新產生，219 也可）|
| `/usr/lib/sysusers.d/ark.conf`、`/usr/lib/tmpfiles.d/ark.conf` | 專用帳號 `ark`、`/var/lib/ark`（0750）|
| `/var/lib/ark` | 狀態（`ARK_HOME`）。**不屬於套件**：移除套件不會刪資料與帳號 |

安裝**不會**啟動服務。啟動前先設定：

```sh
sudo -u ark env ARK_HOME=/var/lib/ark ARK_SETUP_API_KEY=… \
  ark setup --non-interactive --no-service --provider anthropic --model claude-sonnet-4-5
sudo systemctl enable --now arkd
ark doctor
```

`ark setup` 無人值守旗標與環境變數見 `crates/ark/src/setup_server.rs`：`--provider`、`--model`、`--base-url`、`--channel`、`--owner`、`--no-service`、`--verify`；金鑰只從環境讀（`ARK_SETUP_API_KEY` 或供應商自己的變數），直接進 vault，不經 argv。

建置（維護者）：

```sh
packaging/nfpm/build-packages.sh --bin <靜態 ark> --arch amd64 --out dist   # 需要 podman|docker 或 nfpm
```

為什麼用 nfpm：同一份 `nfpm.yaml` 同時產生 deb 與 rpm，不需要 rpmbuild／dpkg 在建置機上，也不需要 cargo 外掛（`cargo-deb`／`cargo-generate-rpm` 會自己用 glibc 重編，而我們要發的是已驗證的靜態 musl 二進位）。

## 2. 簽章的套件庫

```sh
# apt（純 python3 + dpkg-deb + gpg）
packaging/repo/make-apt-repo.py --debs dist --out repo/apt --key-id <KEYID>
# yum/dnf（createrepo_c + rpmsign；沒有就自動用 rockylinux:9 容器）
packaging/repo/make-yum-repo.sh --rpms dist --out repo/rpm --key-id <KEYID> --base-url https://packages.example.com/ark/rpm
# 端到端驗證：臨時金鑰、debian:12 與 rockylinux:9 實際安裝，並確認外來簽章被拒
packaging/repo/test-repos.sh dist
```

客戶端（apt）：

```sh
install -m 0644 ark-archive-keyring.gpg /etc/apt/keyrings/
echo 'deb [signed-by=/etc/apt/keyrings/ark-archive-keyring.gpg] https://packages.example.com/ark/apt stable main' > /etc/apt/sources.list.d/ark.list
apt-get update && apt-get install ark-agent
```

客戶端（dnf／yum）：取 `ark.repo` 放入 `/etc/yum.repos.d/`，內容已設 `gpgcheck=1`、`repo_gpgcheck=1`。每個 rpm 有簽章，`repomd.xml.asc` 簽中繼資料。

簽章金鑰請放在 HSM／離線機，不要放在 CI；release workflow 以 secret `ARK_REPO_GPG_KEY`（無密語的金鑰）做示範，沒設就不產生套件庫並顯示警告。

## 3. 離線包（air-gapped）

連網區：

```sh
packaging/offline/make-offline-bundle.sh --dist <已驗證的發佈目錄> --arch x86_64 \
   [--vm-image <ark sandbox vm image build 的輸出>] [--key release-key.pem] --out ark-offline-0.1.0-x86_64.tar.gz
```

隔離區：

```sh
tar xzf ark-offline-0.1.0-x86_64.tar.gz && cd ark-offline
./install-offline.sh --key /path/to/release-key.pub.pem          # tarball 安裝到 /usr/local（root）或 ~/.local
./install-offline.sh --key … --package                          # 改用 rpm/dpkg 裝套件
```

腳本先驗 `BUNDLE.sha256`（及其簽章），再執行 `verify-release.sh release/`（簽章 → 雜湊 → 無額外檔 → SBOM），最後才安裝；全程不連網。

## 4. 容器映像

| 檔案 | 基底 | 用途 |
|---|---|---|
| `Dockerfile` | debian trixie-slim ＋ tini ＋ git | 預設；agent 可在容器內執行 shell／git |
| `Dockerfile.ubi` | UBI 9 minimal | OpenShift／RHEL 環境（支援任意 uid、group 0）|
| `Dockerfile.distroless` | distroless static nonroot | 最小攻擊面；**沒有 shell**，適合遠端執行後端或純通道／API 場景 |

三者都是多階段建置、非 root、`HEALTHCHECK ark health`，並通過 `ark docker check`。CI（`.github/workflows/images.yml`）以原生 amd64／arm64 runner 建置、BuildKit SBOM＋provenance、以 cosign keyless 對 manifest digest 簽章：

```sh
cosign verify ghcr.io/<owner>/ark:<tag> \
  --certificate-identity-regexp 'https://github.com/<owner>/ark/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## 5. 組態管理

| 工具 | 位置 | 說明 |
|---|---|---|
| Ansible | `deploy/ansible/roles/ark` | `ark_install_method: repo｜package｜tarball`；`ark_managed_policy` 寫入 `/etc/ark/managed.toml`；無人值守 `ark setup`；金鑰只在該 task 的環境變數（`no_log`）|
| cloud-init | `deploy/cloud-init/ark.yaml` | 首次開機裝套件、寫政策、跑 `ark setup`、啟動服務 |
| Terraform | `deploy/terraform/aws-ec2` | AL2023 單機，無公網 IP、無入站規則、IMDSv2、金鑰存 Secrets Manager、SSM 進入 |
| Helm | `deploy/helm/ark` | 單副本 StatefulSet，`restricted` PSS、NetworkPolicy、政策 ConfigMap |

## 6. 驗證你拿到的東西

```sh
# 發佈目錄
packaging/release/verify-release.sh <dir> --key <帶外取得的 release-key.pub.pem>
# 套件
rpm -K ark-agent-*.rpm          # 需先 rpm --import RPM-GPG-KEY-ark
dpkg-deb -I ark-agent_*.deb
# GitHub 來源證明
gh attestation verify ark-*.tar.gz -R <owner>/ark
```

## 7. 解除安裝

`apt remove ark-agent`／`dnf remove ark-agent`：停止並停用服務，移除程式。`/var/lib/ark` 與 `ark` 帳號保留（稽核與工作階段是證據）；要清除請自行 `rm -rf /var/lib/ark && userdel ark`，並先確認法律保全（`ark retention hold list`）。
