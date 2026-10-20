# Bulge — 規劃（2026-10-20 定稿）

通用 AI 代理桌面 APP：謹慎、越用越懂、省 token、低失控風險。

## 已定決策
- 語言：Rust + Tauri 2（可延伸至 WoA / Windows / macOS）；v1 只做 Linux（x64 → arm64）。
- 形態：桌面 application，自有視窗；不開任何本地 HTTP 伺服器（Tauri 程序內 IPC）。
- 模型：可插拔核心 `trait LlmProvider`，API（DeepSeek / OpenAI 相容）與本地（程序內 llama.cpp, GGUF）皆可，由使用者設定，不綁定特定模型；本地小模型可分擔分類/摘要/風險判斷。
- 沙箱：libkrun microVM（KVM），唯讀 rootfs + sandboxd（Rust 靜態執行檔）。
  - 檔案：只掛使用者指定工作區（overlay + 快照，diff 審批後寫回）。
  - 網路：允許對外網路；擋主機本身、區網掃描與異常大量連線。不映射主機 port、不額外掛主機目錄。
  - API key 只在主機端。
  - 主機↔VM：vsock（非 TCP 伺服器）。
- 防失控：動作分級（讀/寫/網路/執行）+ 風險分數審批、先計畫後執行、步數/token/時間上限、迴圈偵測、緊急停止、稽核日誌。
- 越用越懂：主機端 SQLite 記憶（偏好 / skill / 失敗教訓），**自動寫入**，按相關度取用。
- 省 token：固定前綴吃快取、上下文壓縮、長輸出 spill、工具 schema 延遲載入。

## 參考來源（只參考設計，以 Rust 重寫，附 MIT notice）
- ~/deepseek-harness：agent loop、compaction/context、guard、goal/plan、skill、spill、sandbox、DeepSeek wire extensions。
- ~/openclaw：provider 可插拔設計、crates/openclaw-node-host、custodian-skills、記憶。
- ~/opencode：工具集（read/edit/patch/bash/grep/glob）、session、system prompt。

## 分工
- dsh headless：前期轉寫與骨架搭建。
- Claude：架構、審查、整合、測試。

## 階段
- P0 參考盤點 → docs/REFERENCES.md（每零件：來源、沿用/捨棄、理由）
- P1 bulge-core + llm（headless 跑通，工具關閉）
- P2 libkrun VM + sandboxd + 網路閘門 + diff 審批 + 逃逸測試
- P3 記憶 / skill
- P4 Tauri UI（對話、審批、diff、緊急停止）
- P5 Linux 打包（.deb / AppImage）

## 驗收
在 APP 中交辦真實通用任務（例：抓資料整理成報告、裝依賴並跑專案），代理全程在 VM 內完成、能用網路與依賴、
碰不到工作區以外、所有寫回皆經審批。P1/P2 單獨完成只算原型。
