# M2 — 握手狀態機

**目標**：`crates/bulge-proto/src/handshake.rs`
**來源**：`~/openclaw/crates/openclaw-node-host/src/sidecar_handshake.rs`（全檔，含 L372 起的測試）；規格 SIDECAR_PROTOCOL.md "Negotiation" 節。
**依賴**：M1 完成後的 `crate::frame`。

## 改寫規則
- 套用 M1 的改名表；`SidecarHandshake*` → `Handshake*`、`SidecarProtocolSelection` → `ProtocolSelection`。Supervisor → Host、Runtime → Guest。
- 保留：兩幀順序（host `offer` → guest `accept`）、雙方獨立重算選擇且不一致即終止、guest 在 accept 寫出成功前維持 `AcceptancePending` 與 bootstrap 上限、綁定單一 channel 實例（替換 channel 會 retire 替換品而不動原握手）、任何錯誤 retire 握手與 channel、序號不重設。
- 不搬：Configuration exchange、runtime bridge（屬 P2 sandboxd，另行標記）。

## 驗收測試
- 來源測試全部移植（改名後）。
- 完整成功握手後雙方 `NegotiatedProtocol` 相同，且之後可互相 seal/open 一般訊息。
- 角色相同、major 不同、偽造 selection、重複/亂序訊息 → 失敗並 retire。
