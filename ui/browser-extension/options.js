// Settings page: port + pairing token, saved to chrome.storage.local, and a
// manual (re)connect. Vanilla JS, external file (MV3 CSP forbids inline).

const DEFAULT_PORT = 18792;

const portInput = document.getElementById("port");
const tokenInput = document.getElementById("token");
const saveButton = document.getElementById("save");
const connectButton = document.getElementById("connect");
const disconnectButton = document.getElementById("disconnect");
const statusLine = document.getElementById("status");
const messageLine = document.getElementById("message");

function s(v) {
  return typeof v === "string" && v ? v : "";
}

function describe(status) {
  if (!status) return { text: "Unknown state", cls: "warn" };
  const url = s(status.url) || "ws://127.0.0.1:" + (status.port || DEFAULT_PORT) + "/extension";
  if (!status.hasToken) return { text: "Not paired — paste the token below", cls: "warn" };
  switch (status.state) {
    case "connected":
      return {
        text:
          "Connected to " +
          url +
          " · " +
          (status.attached || 0) +
          " tab" +
          (status.attached === 1 ? "" : "s") +
          " attached",
        cls: "ok",
      };
    case "connecting":
      return { text: "Connecting to " + url + "…", cls: "warn" };
    case "retrying":
      return { text: "Waiting for the relay at " + url, cls: "warn" };
    case "error":
      return { text: "Error: " + (s(status.error) || "relay refused the connection"), cls: "err" };
    case "unpaired":
      return { text: "No token configured", cls: "warn" };
    case "off":
      return { text: "Disconnected" + (s(status.error) ? ": " + status.error : ""), cls: "warn" };
    default:
      return { text: "Waiting for the relay at " + url, cls: "warn" };
  }
}

async function refresh() {
  let status = null;
  try {
    status = await chrome.runtime.sendMessage({ type: "getStatus" });
  } catch (e) {
    status = null;
  }
  if (!status) {
    const stored = await chrome.storage.local.get({ arkStatus: null });
    status = stored.arkStatus;
  }
  const view = describe(status);
  statusLine.textContent = view.text;
  statusLine.className = "status " + view.cls;
  connectButton.disabled = Boolean(status && status.state === "connected");
  disconnectButton.disabled = Boolean(status && status.state === "off" && !status.paired);
}

async function loadConfig() {
  const stored = await chrome.storage.local.get({ port: DEFAULT_PORT, token: "" });
  portInput.value = String(stored.port || DEFAULT_PORT);
  tokenInput.value = s(stored.token);
}

async function save() {
  const port = Number(portInput.value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    messageLine.textContent = "Port must be a number between 1 and 65535.";
    portInput.focus();
    return;
  }
  const token = tokenInput.value.trim();
  if (!token) {
    messageLine.textContent = "Paste the contents of extension-token first.";
    tokenInput.focus();
    return;
  }
  await chrome.storage.local.set({ port, token });
  messageLine.textContent = "Saved. Reconnecting…";
  try {
    await chrome.runtime.sendMessage({ type: "reconnect" });
  } catch (e) {
    messageLine.textContent = "Saved, but the service worker did not answer; reload the extension.";
  }
  await new Promise((resolve) => setTimeout(resolve, 400));
  await refresh();
}

async function reconnect() {
  messageLine.textContent = "Reconnecting…";
  try {
    await chrome.runtime.sendMessage({ type: "reconnect" });
  } catch (e) {
    messageLine.textContent = "The service worker did not answer; reload the extension.";
  }
  await new Promise((resolve) => setTimeout(resolve, 400));
  await refresh();
}

async function disconnect() {
  try {
    await chrome.runtime.sendMessage({ type: "disconnect" });
  } catch (e) {
    /* ignore */
  }
  messageLine.textContent = "Disconnected.";
  await refresh();
}

saveButton.addEventListener("click", () => {
  void save();
});
connectButton.addEventListener("click", () => {
  void reconnect();
});
disconnectButton.addEventListener("click", () => {
  void disconnect();
});
tokenInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") void save();
});

void (async () => {
  await loadConfig();
  await refresh();
  setInterval(() => {
    void refresh();
  }, 2000);
})();
