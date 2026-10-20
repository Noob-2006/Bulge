# M1 — 認證幀協定

**目標**：`crates/bulge-proto/src/frame.rs`
**來源**：`~/openclaw/crates/openclaw-node-host/src/sidecar_protocol.rs` L1-790（實作）與 L791-1292（測試）；規格 `~/openclaw/crates/openclaw-node-host/SIDECAR_PROTOCOL.md` 的 "Length prefix"、"Authenticated frame"、"Negotiation" 三節。

## 改寫規則
- 來源已是 Rust：搬移並改名，**演算法、檢查順序、上限都不可放寬**。
- 命名：`Sidecar*` → 去掉前綴（`SidecarSessionKey` → `SessionKey`、`AuthenticatedSidecarChannel` → `Channel`、`SidecarFrameError` → `FrameError`、`SidecarProtocolError` → `ProtocolError`、`SidecarProtocolOffer` → `ProtocolOffer`、`NegotiatedSidecarProtocol` → `NegotiatedProtocol`、`negotiate_sidecar_protocol` → `negotiate`、`read/write_sidecar_frame` → `read_frame/write_frame`、`SidecarLimits` → `Limits`、`SidecarPeerIdentity` → `PeerIdentity`）。
- 角色：`SidecarPeerRole::{Supervisor, Runtime}` → `PeerRole::{Host, Guest}`；方向 `1` = host→guest、`2` = guest→host。
- Magic 改為 `*b"BLGC"`；`PROTOCOL_MAJOR = 1`、`PROTOCOL_MINOR = 0`。
- 移除所有 Gateway / node-lifecycle 相關的說明文字與欄位；保留：HMAC-SHA256、先檢查長度上限再配置、先驗 HMAC 再解析、方向/generation/嚴格遞增序號/session id 驗證、首次失敗即 poison、`retire()`、`SessionKey` 的 zeroize 與不印出內容的 `Debug`、53-bit feature mask 交集、`BoundedFrameWriter` 不完整物化超大 payload。
- 依賴只能用 bulge-proto/Cargo.toml 已列的（getrandom、hmac、serde、serde_json、sha2、thiserror、tokio、zeroize）。

## 驗收測試
- 來源 tests 模組中與幀、協商相關的測試全部移植並通過（改名後）。
- 竄改任一位元組 → `open` 失敗且 channel 之後所有 `seal/open` 都被拒。
- 重放同一幀 / 跳號 → 失敗。
- 方向反射（把自己 seal 的幀餵給自己 open）→ 失敗。
- 長度前綴超過上限 → `read_frame` 在配置記憶體前就失敗。
- 跨語言向量（openclaw `test/fixtures/node-sidecar-protocol-v1.json`）因 magic 已改**不移植**；改為新增一組固定 key/session/payload 的「已知答案」測試，把產出的位元組寫成常數鎖住格式。
