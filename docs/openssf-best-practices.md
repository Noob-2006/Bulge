# OpenSSF Best Practices（passing 等級）自評對照

[OpenSSF Best Practices Badge](https://www.bestpractices.dev/) 是開源專案最常見的免費「基本合格」證明：在網站上逐條自評，填上證據連結，全部通過即取得 passing 徽章。本表把每一類要求對到本專案的證據，並標出還要做的事。

狀態：✅ 已具備　⏳ 檔案已備妥，等 repo 公開後生效　👤 需要維護者本人操作

## 基本資料

| 要求 | 狀態 | 證據 |
|---|---|---|
| 說明專案做什麼、怎麼取得、怎麼回饋 | ✅ | [README.md](../README.md)、[docs/install.md](install.md)、[docs/faq.md](faq.md) |
| 如何貢獻 | ✅ | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| 自由軟體授權，放在標準位置 | ✅ | [LICENSE](../LICENSE)（MIT）、[LICENSES/](../LICENSES)、[REUSE.toml](../REUSE.toml) |
| 基本文件與外部介面文件 | ✅ | [docs/MANUAL.md](MANUAL.md)、[docs/arp.md](arp.md)、`seagent help` |
| 網站使用 HTTPS | ⏳ | GitHub 頁面與發行下載皆為 HTTPS |
| 有可搜尋的討論管道 | 👤 | 開啟 GitHub Discussions |
| 以英文接受回報與討論 | ✅ | SECURITY.md、CONTRIBUTING.md 為英文，issue 中英皆可 |
| 專案仍在維護 | ⏳ | 公開後以 commit 與 issue 回應紀錄為證 |

## 變更管理

| 要求 | 狀態 | 證據 |
|---|---|---|
| 公開的版本控制、可追溯每次變更 | ⏳ | git 歷史；推上 GitHub 後公開 |
| 每次發行有唯一版本號、採語意化版本 | ✅ | `Cargo.toml` workspace version、`seagent --version` |
| 發行說明，列出已修正的公開漏洞 | ✅ | [CHANGELOG.md](../CHANGELOG.md)（含 **Security** 標記） |

## 回報

| 要求 | 狀態 | 證據 |
|---|---|---|
| 回報 bug 的流程與公開的 issue 追蹤 | ⏳ | GitHub Issues；回報方式見 CONTRIBUTING.md |
| 私下回報漏洞的流程 | ⏳ 👤 | [SECURITY.md](../SECURITY.md)；需在 repo 設定開啟 private vulnerability reporting |
| 14 天內回應漏洞回報 | ✅ | SECURITY.md 承諾 7 天內確認、14 天內初判 |

## 品質

| 要求 | 狀態 | 證據 |
|---|---|---|
| 可用標準工具建置 | ✅ | `cargo build`；[docs/BUILD.md](BUILD.md) |
| 自動化測試，新功能需附測試 | ✅ | `cargo test --workspace`（約 3,700 個）、`tests/e2e/run.py`（38 個）、發行版安裝矩陣；CONTRIBUTING.md 要求新行為附測試 |
| CI 自動跑測試 | ⏳ | [.github/workflows/ci.yml](../.github/workflows/ci.yml) |
| 開啟編譯器警告並嚴格處理 | ✅ | `cargo clippy --workspace --all-targets -- -D warnings`，CI 中失敗即擋 |

## 安全

| 要求 | 狀態 | 證據 |
|---|---|---|
| 至少一位主要開發者懂安全設計 | ✅ | [docs/SECURITY.md](SECURITY.md)、[docs/risk-assessment.md](risk-assessment.md) |
| 使用標準、公開審查過的密碼學，不自創演算法 | ✅ | `ring`（ChaCha20-Poly1305、HMAC-SHA256、PBKDF2）、`rustls`、Ed25519；不用 MD5／SHA-1 做安全用途 |
| 密碼儲存使用加鹽的迭代雜湊 | ✅ | 保管庫 PBKDF2 預設 600,000 次、下限 100,000 次 |
| 金鑰長度足夠、安全亂數 | ✅ | 256-bit 金鑰；系統亂數源 |
| 發行物防竄改（HTTPS＋雜湊＋簽章） | ✅ | `SHA256SUMS`、`SHA256SUMS.sig`、建置來源證明、容器映像 cosign 簽章 |
| repo 中沒有外洩的憑證 | ✅ | CI 的秘密掃描；測試用的拋棄式金鑰列入允許清單 |
| 已知公開漏洞 60 天內修正 | ✅ | `cargo-deny` 檢查相依套件公告；Dependabot 每週更新 |

## 分析

| 要求 | 狀態 | 證據 |
|---|---|---|
| 發行前跑靜態分析 | ⏳ | clippy；[CodeQL](../.github/workflows/codeql.yml)（Rust、JS/TS、Python、Actions） |
| 動態分析（建議） | ✅ | Rust 為記憶體安全語言；端對端測試與真實伺服器錄製向量的重放測試 |
| 供應鏈評分（加分） | ⏳ | [OpenSSF Scorecard](../.github/workflows/scorecard.yml) |

## 取得徽章的步驟（👤）

1. 決定 GitHub 帳號／組織，把 repo 推上去並設為公開。
2. 在 repo 設定開啟：Issues、Discussions、private vulnerability reporting、main 分支保護（需要 PR 與 CI 通過）。
3. 到 <https://www.bestpractices.dev/> 用 GitHub 登入，新增專案，照本表逐條填寫證據連結。
4. 取得徽章後，把網站給的 badge 連結與 Scorecard badge 加到 README 開頭。
