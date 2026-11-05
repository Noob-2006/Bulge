# ark security：egress 代理（egress_proxy）

對應 Hermes `hermes_cli/proxy`（iron-proxy）與 OpenClaw `src/secrets/egress-proxy`。
實作在 `crates/ark-security/src/egress_proxy.rs`，本檔只記設定面與限制。

## 設定鍵

```toml
[security.egress_proxy]
enabled = false            # 預設關；開了才會啟動代理並改寫 child 的 *_PROXY
listen  = "127.0.0.1:0"    # 只綁 loopback；port 0 = 由 OS 選（實際 port 見 running_port()）
mode    = "filter"         # 或 "allowlist"（只有 allow / gate.egress_allow 的主機可通）
allow   = ["api.example.com", "*.github.com"]  # 永遠放行；列在這裡的主機可以是私有位址
deny    = ["evil.example.com"]                 # 永遠拒絕（含子網域）
[[security.egress_proxy.inject]]               # 憑證注入（只對純 HTTP 請求，CONNECT 不攔截）
host   = "api.example.com"
header = "Authorization"
value  = "Bearer {{secret:SERVICE_TOKEN}}"     # 由 Secrets 回呼展開，child 看不到值
```

`SecurityConfig` 兩層都是 `deny_unknown_fields`：拼錯的鍵（例如 `[security.egress]`、
`listen_port`）在載入設定時就報錯，不會靜默失效。

## 啟動點

* `crates/ark-kernel/src/kernel.rs` 的 `new_kernel` 呼叫 `SecurityConfig::activate()`；
  `activate()` 之後呼叫 `SecurityConfig::activate_egress(data_dir, secrets)`，
  data_dir 由 `ARK_HOME` 推導（未設定就用記憶體 ring，不自己建目錄）；
  JSONL 連線記錄寫到 `<data>/egress/proxy.jsonl`。
* `activate_egress` 內用 `Policy::from_config` 組策略，再 `ensure_started`
  （一個 process 一個代理；之後的呼叫只更新政策，不會重啟）。
* 啟動後 `envscrub::set_proxy(url)`：child 的 `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`
  指向 `http://127.0.0.1:<port>`，並移除 `NO_PROXY`/`no_proxy` 與小寫
  `http_proxy`/`https_proxy`/`all_proxy`（curl/wget 偏好小寫，留著等於繞過）。
* 查詢介面：`egress_proxy::running_url()`、`running_port()`（給 `[exec.docker] proxy_port`
  對齊）、`refusal(host)`（靜態 gate 可先問代理會不會拒）、`recent()`（最近的連線）。

## 覆蓋範圍與限制

1. 只管「會讀 `*_PROXY` 的程式」：curl、wget、git、python-requests、node、pip…
   raw socket / 自寫 TCP / 忽略代理變數的程式不受管；**UDP、DNS 外洩、直接 socket
   需要 OS sandbox（network namespace / seccomp）**，代理補不了。
2. `NO_PROXY` 一律移除：豁免 `localhost` 等於給直譯器一條繞過 SSRF 檢查的內網路徑；
   要連本機服務請把主機加進 `allow`（`allow` 內的主機允許私有位址，cloud metadata 仍拒絕）。
3. `CONNECT` 只過濾、不攔截（不做 MITM、不裝 CA），所以 HTTPS 內容無法注入或檢視；
   `inject` 只作用在純 HTTP 請求上。
4. 代理自行解析 DNS 並對「已檢查過的位址」撥號，避免 DNS rebinding 的空窗。
5. docker/podman 沙箱不是繼承 host 環境：需要 `[exec.docker] proxy_port` =
   `running_port()`，容器才會經由 `host.docker.internal:<port>` 走同一個代理。

測試：`cargo test -p ark-security` —— 單元測試
`egress_proxy::tests::{host_rules_and_config_shape, connect_tunnels_to_allowed_host_and_denies_others,
ssrf_targets_are_refused_even_when_resolved, absolute_uri_is_forwarded_with_injection}`、
`tests::egress_proxy_toml_table_parses`，整合測試 `tests/egress_activation.rs`。

## 直譯器 egress 閘的殘餘風險（interp）

實作在 `crates/ark-kernel/src/interp.rs`：`gate.rs` 的 `Effect::Exec` 分支呼叫
`interp::judge_commands`，`secgate::explain` / `approvals test` 另外用 `interp::inline_evals`
支援 `approvals.strict_inline_eval`。這一層是**靜態讀字串**，不是執行期隔離——它提高繞過成本，
不保證繞不過去。下面把「抓得到什麼」與「抓不到什麼」分開寫清楚。

### 1. 靜態分析看得到的

* inline eval：`python3 -c`、`node -e` / `--eval=` / `node eval`、`perl -e`、`ruby -e`、`php -r`、
  `deno eval`（含 `-Wc` 這類緊貼的組合旗標）；pipe 進直譯器的 here-doc / here-string
  （`python3 - <<'PY'`、`bash <<< "…"`）。
* 執行腳本：`python3 x.py`、`bash deploy.sh`、`./run.sh`（看 shebang 或副檔名）、`source env.sh`
  與 `. env.sh`；單檔上限 1 MB（`MAX_SCRIPT_BYTES`），遞迴深度上限 8（`MAX_DEPTH`）。
* 程式碼裡內嵌的 shell 字串（`os.system`、`subprocess`、`child_process.exec`、反引號、`system()`）
  會再走一次 shell 分析，所以 `python3 -c "os.system('sudo apt install x')"` 仍落到 privilege 閘。
* 外送：URL 主機比對 `gate.egress_allow` / `gate.egress_deny`（deny 名單是 hard deny）；送秘密
  （vault 值、`{{secret:…}}`、`sk-…`／`ghp_…` 之類 pattern）、送敏感檔（`~/.ssh/id_rsa`、`.env`、
  `secrets.toml`…）、把整個環境倒出去（`dict(os.environ)`、`JSON.stringify(process.env)`、`%ENV`、
  `$_ENV`…）都判 egress ask。
* raw socket：`socket.create_connection`、`IO::Socket::INET`、`Net::HTTP`、`net.connect` 等。
* 權限：`setuid`/`seteuid` 類 API，以及寫入系統路徑的字面值（`write_api` + `gate::system_path`）。
* `approvals.strict_inline_eval = true`：任何 inline eval（`-c`/`-e`/here-doc）一律要核准，
  不管內容看起來多無害——最省事的一層。

### 2. 看不到的（真正的殘餘風險）

* **混淆/編碼後才組出的字串**：`base64.b64decode(...)`、`"".join(chr(c) for c in ...)`、執行期
  串接的 URL 與 payload 在原始碼裡只是片段，靜態讀不到最後送出的內容或目的地。
* **`eval(compile(...))` / 動態 `import` / `getattr` 呼叫**：判準是對原始碼跑 regex；真正被呼叫的
  目標在執行期才決定，分析器只看到 `eval(...)` 這個字。
* **從網路下載再執行的腳本**（`curl … | bash`、`python3 -c "exec(urllib.request.urlopen(u).read())"`）：
  當下這一行可能只是下載（甚至合法），真正的外送發生在被下載的程式裡，那時已離開掃描範圍。
* **超過大小/深度上限的檔案**（> 1 MB、`exec`/`source` 鏈 > 8 層）：`read_script` 直接回 `None`、
  `judge_unit` 直接回空——等於綠燈通過，不會有任何 finding。
* **二進位/編譯後的程式**（`./payload`、`.pyc`、`.wasm`、Go/Rust binary）：`read_to_string` 讀不出、
  也沒有 shebang，`units()` 根本不產生 unit。
* **動態載入的原生擴充**（`ctypes`、`cffi`、`node-gyp` 的 `.node`、Python C extension）：網路行為
  在 `.so` 裡，原始碼只有一行 `load`。
* **UTF-8 以外的編碼**（latin-1、UTF-16 原始檔、混合編碼）：`read_to_string` 失敗即視為沒有腳本。
* **`exec` 鏈超過深度**：鏈條尾端不再分析，這是刻意的 fail-open（避免無窮遞迴），也是缺口。
* **背景 daemon 化後另開連線**（`nohup … &`、`setsid`、寫 systemd user unit、fork 後父行程結束）：
  閘只判當下這一行；之後的連線沒有對應的 tool call，自然也不會被判。
* **佔位符的引號差異**：`curl -d "{{secret:OPENAI_API_KEY}}" …` 判 egress ask，但未加引號的
  `curl -d {{secret:OPENAI_API_KEY}} …` 會被 shell 分析切開而判 allow。實務上請一律加引號，
  也提醒自動生成的指令不要依賴未加引號的佔位符。

### 3. 真正能關死的做法

1. `[security.egress_proxy] enabled = true`：child 的 `HTTP(S)_PROXY`/`ALL_PROXY` 指向本機代理，
   只有代理能出去、`NO_PROXY` 一律移除。**只對會讀 `*_PROXY` 的程式有效**（curl、wget、git、
   python-requests、node、pip…）；raw socket / UDP / DNS 直連仍可繞。
2. `[exec] backend = "bwrap"`（或 `"landlock"`、`"docker"`、`"podman"`）＋
   `[exec.sandbox] network = "none"`；docker/podman 後端會下 `--network none`，容器內連 proxy
   變數都不轉發。這是核心層斷網：直譯器怎麼寫都連不出去。
3. OS 層 network namespace / seccomp / LSM（eBPF）：ark **目前沒有內建**產生 profile 的能力，
   要自己接（bwrap/landlock 後端已經用掉一部分，其餘留給外部沙箱）。

### 4. 結論

這些措施是「**繞過成本的提高**」而不是「不可能繞過」：靜態分析擋掉順手寫的 exfil，真正的最後
防線是 sandbox 與網路政策（`network = "none"` / egress proxy / OS netns）。處理不受信任的輸入時，
請假設直譯器閘會被繞過，並以沙箱為準。

測試：`cargo test -p ark --test security_cli`（`approvals test` 的 exit 0/2/3、`suggest` 的
allowlist 提案與 `--apply`、`exec-policy show|set|preset`、`pause|resume`）；`interp` 的單元測試在
`crates/ark-kernel/src/interp.rs` 的 `tests` 模組。
