# M10 — 禁止的目的位址判斷（VM 網路閘門）

**目標**：`crates/bulge-vm/src/net/policy.rs` 的 `is_forbidden_destination(ip: IpAddr) -> bool` 函式本體（可在同檔加私有輔助函式；**不要動 `EgressPolicy`**）。
**來源**：
- `~/openclaw/packages/net-policy/src/ip.ts`：`isBlockedSpecialUseIpv4Address` L286、`isBlockedSpecialUseIpv6Address` L243、`extractEmbeddedIpv4FromIpv6` L313、`isRfc8215Nat64LocalUseAddress`、`isCloudMetadataIpAddress` L204、`RFC2544_BENCHMARK_PREFIX`、`CLOUD_METADATA_IP_ADDRESSES`（L60-90 一帶的常數）。
- 範圍表：openclaw 用 ipaddr.js 2.5.0 的 `range()`。實際 CIDR 表在 `~/deepseek-harness/node_modules/.pnpm/ipaddr.js@2.5.0/node_modules/ipaddr.js/lib/ipaddr.js` 的 `IPv4.prototype.SpecialRanges`（L185）與 `IPv6.prototype.SpecialRanges`（L563）。**請從這兩張表逐條抄出**被 openclaw 封鎖的分類所對應的 CIDR，寫成 Rust 常數表（附註來源分類名）。
- 測試參考：`~/openclaw/packages/net-policy/src/ip.test.ts`、`ip-test-fixtures.ts`。

## 規則
- IPv4 封鎖分類：unspecified、broadcast、multicast、linkLocal、loopback、carrierGradeNat、private、reserved，加上 198.18.0.0/15（RFC2544）與雲端 metadata `100.100.100.200`。**不提供** allowRfc2544 之類的放寬選項。
- IPv6 封鎖分類：unspecified、loopback、linkLocal、uniqueLocal、multicast、reserved、benchmarking、discard、orchid2、fec0::/10（site-local）、`fd00:ec2::254`、RFC8215 `64:ff9b:1::/48`。**不提供** allowUniqueLocal 放寬選項。
- 內嵌 IPv4：IPv4-mapped、IPv4-compatible、NAT64 well-known `64:ff9b::/96`（rfc6052）、rfc6145、6to4、Teredo（XOR 0xffff）、ISATAP → 取出 IPv4 後套 IPv4 規則；任一層禁止即禁止。
- 只用標準庫 `std::net`，不新增依賴。
- 「不在任何封鎖表」才是允許；表內順序、重疊不影響結果。

## 驗收測試
- 來源 `ip.test.ts` / `ip-test-fixtures.ts` 中封鎖/允許判斷的案例全部移植。
- 每個 IPv4/IPv6 封鎖分類至少一個邊界內、一個邊界外的位址。
- 公開位址（1.1.1.1、8.8.8.8、2606:4700:4700::1111）允許。
- `::ffff:192.168.1.1`、`64:ff9b::a00:1`、`2002:c0a8:0101::`（6to4 內嵌 192.168.1.1）、Teredo 內嵌私有位址 → 禁止；`::ffff:1.1.1.1` → 允許。
- 依 marks/README.md 共同規則：`cargo test -p bulge-vm` 與 `cargo clippy -p bulge-vm --all-targets -- -D warnings` 通過。
