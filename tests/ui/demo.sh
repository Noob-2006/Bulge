#!/usr/bin/env bash
# UI demo: the fake model + a throwaway ark home + the app server on :8641.
# Open http://localhost:8641/#token=demo-token-not-secret
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$(mktemp -d /tmp/ark-ui-demo-XXXX)
mkdir -p "$ROOT/home/config" "$ROOT/ws"
exec 3< <(python3 -I tests/e2e/fake_provider.py)
read -r PORT <&3
cat > "$ROOT/home/config/config.toml" <<CFG
[model]
default = "fake/fake-model"
[providers.fake]
format = "openai_chat"
base_url = "http://127.0.0.1:$PORT/v1"
api_key_env = "FAKE_KEY"
[app]
enabled = true
listen = "127.0.0.1:8641"
token = "demo-token-not-secret"
nodes = true
workspace = "$ROOT/ws"
CFG
export ARK_HOME="$ROOT/home" FAKE_KEY=x XDG_RUNTIME_DIR=""
# A couple of sessions so the sidebar has content.
python3 -I - "$PORT" <<'PY'
import json, sys, urllib.request
port = sys.argv[1]
items = [{"text": "你好！我是 **ark**。\n\n- 可以讀寫檔案、執行指令\n- 透過 `channels` 接上 Telegram、Discord、LINE…\n\n```rust\nfn main() { println!(\"深緋紅與金星\"); }\n```"}] * 20
urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/__script", data=json.dumps(items).encode(), method="POST")).read()
PY
cd "$ROOT/ws"
target/release/ark run "幫我介紹一下你自己" >/dev/null 2>&1 || "$OLDPWD/target/release/ark" run "幫我介紹一下你自己" >/dev/null 2>&1 || true
exec "$OLDPWD/target/release/ark" daemon run
