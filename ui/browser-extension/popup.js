// Toolbar popup: pairing state, relay address, and a link to the settings page.

const statusLine = document.getElementById("status");
const relayLine = document.getElementById("relay");
const attachedLine = document.getElementById("attached");
const errorLine = document.getElementById("error");
const reconnectButton = document.getElementById("reconnect");
const settingsButton = document.getElementById("settings");

function s(v) {
  return typeof v === "string" && v ? v : "";
}

function render(status) {
  const url = s(status && status.url) || "—";
  relayLine.textContent = url;
  attachedLine.textContent = String(status && status.attached ? status.attached : 0);
  let text = "Not paired";
  let cls = "warn";
  if (!status) {
    text = "Status unavailable";
    cls = "err";
  } else if (!status.hasToken) {
    text = "Not paired — open settings";
    cls = "warn";
  } else if (status.paired || status.state === "connected") {
    text = "Paired with seagent";
    cls = "ok";
  } else if (status.state === "connecting") {
    text = "Connecting…";
  } else if (status.state === "retrying") {
    text = "Relay unavailable — retrying";
  } else if (status.state === "error") {
    text = "Error";
    cls = "err";
  } else if (status.state === "off") {
    text = "Disconnected";
  }
  statusLine.textContent = text;
  statusLine.className = "status " + cls;
  const error = s(status && status.error);
  errorLine.textContent = error;
  errorLine.hidden = !error || cls === "ok";
  reconnectButton.disabled = Boolean(status && (status.paired || status.state === "connected"));
}

async function refresh() {
  let status = null;
  try {
    status = await chrome.runtime.sendMessage({ type: "getStatus" });
  } catch (e) {
    status = null;
  }
  if (!status) {
    const stored = await chrome.storage.local.get({ seagentStatus: null });
    status = stored.seagentStatus;
  }
  render(status);
}

reconnectButton.addEventListener("click", () => {
  void (async () => {
    try {
      await chrome.runtime.sendMessage({ type: "reconnect" });
    } catch (e) {
      /* the worker restarts on the next alarm */
    }
    await new Promise((resolve) => setTimeout(resolve, 400));
    await refresh();
  })();
});

settingsButton.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

void refresh();
