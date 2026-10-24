"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

// Follow the phone's light/dark setting (theme.css reads data-theme).
const dark = window.matchMedia("(prefers-color-scheme: dark)");
const applyTheme = () => { document.documentElement.dataset.theme = dark.matches ? "dark" : "light"; };
applyTheme();
dark.addEventListener("change", applyTheme);

// The line under the host name, with its status light: connecting (no
// state), ok, live (working), bad.
function setStatus(text, state) {
  const status = $("status");
  status.textContent = text;
  if (state) status.dataset.state = state;
  else delete status.dataset.state;
}
let openHost = null;
let typingShown = false;
// The commands the connected bulge understands (it sends them on connect).
let commands = [];

function show(screen) {
  for (const section of document.querySelectorAll(".screen")) {
    section.hidden = section.id !== screen;
  }
  if (screen === "home") {
    if (openHost) {
      invoke("close_chat").catch(() => {});
      openHost = null;
    }
    loadHosts();
  }
}

async function loadHosts() {
  const list = $("hosts");
  list.replaceChildren();
  let hosts = [];
  try {
    hosts = await invoke("hosts");
  } catch (error) {
    $("no-hosts").textContent = String(error);
    $("no-hosts").hidden = false;
    return;
  }
  $("no-hosts").hidden = hosts.length > 0;
  for (const host of hosts) {
    const item = document.createElement("li");
    const info = document.createElement("div");
    const name = document.createElement("div");
    name.className = "name";
    name.textContent = host.name;
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `經 ${host.relay}・本機在該處名為「${host.device_name}」`;
    info.append(name, meta);
    const forget = document.createElement("button");
    forget.className = "forget";
    forget.textContent = "移除";
    // Two taps (WebView dialogs are not reliable on Android).
    forget.addEventListener("click", async (event) => {
      event.stopPropagation();
      if (forget.dataset.armed !== "yes") {
        forget.dataset.armed = "yes";
        forget.textContent = "確定移除？";
        return;
      }
      await invoke("forget", { name: host.name });
      loadHosts();
    });
    item.append(info, forget);
    item.addEventListener("click", () => openChat(host.name));
    list.append(item);
  }
}

function addMessage(text, kind) {
  const item = document.createElement("li");
  item.className = kind;
  item.textContent = text;
  $("messages").append(item);
  item.scrollIntoView({ block: "end" });
}

async function openChat(name) {
  openHost = name;
  typingShown = false;
  $("chat-title").textContent = name;
  $("messages").replaceChildren();
  setStatus("連線中…");
  show("chat");
  try {
    await invoke("open_chat", { name });
  } catch (error) {
    setStatus(String(error), "bad");
  }
}

listen("chat-event", ({ payload }) => {
  if (payload.host !== openHost) return;
  switch (payload.kind) {
    case "connected":
      setStatus(payload.text, "ok");
      break;
    case "disconnected":
      setStatus(`連線中斷，重新連線中（${payload.text}）`, "bad");
      break;
    case "fatal":
      setStatus(payload.text, "bad");
      addMessage(`無法連線：${payload.text}`, "note");
      break;
    case "commands":
      try { commands = JSON.parse(payload.text); } catch { commands = []; }
      break;
    case "notsent":
      addMessage(payload.text, "note");
      break;
    case "typing":
      if (!typingShown) {
        setStatus("bulge 處理中…", "live");
        typingShown = true;
      }
      break;
    case "reply":
      typingShown = false;
      setStatus("已連線", "ok");
      addMessage(payload.text, "theirs");
      break;
  }
});

$("compose").addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = $("text").value.trim();
  if (!text) return;
  $("text").value = "";
  addMessage(text, "mine");
  try {
    await invoke("send", { text });
  } catch (error) {
    addMessage(`沒有送出：${error}`, "note");
  }
});

BulgePalette.attach($("text"), () => commands);

$("text").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    $("compose").requestSubmit();
  }
});

$("go-pair").addEventListener("click", () => {
  $("pair-error").hidden = true;
  show("pair");
});

$("scan").addEventListener("click", async () => {
  const scanner = window.__TAURI__.barcodeScanner;
  if (!scanner) {
    $("pair-error").textContent = "這個裝置不能掃描，請貼上連結。";
    $("pair-error").hidden = false;
    return;
  }
  try {
    let permission = await scanner.checkPermissions();
    if (permission !== "granted") permission = await scanner.requestPermissions();
    if (permission !== "granted") throw new Error("需要相機權限才能掃描");
    const result = await scanner.scan({ formats: [scanner.Format.QRCode] });
    $("link").value = result.content;
  } catch (error) {
    $("pair-error").textContent = String(error);
    $("pair-error").hidden = false;
  }
});

$("do-pair").addEventListener("click", async () => {
  const button = $("do-pair");
  button.disabled = true;
  $("pair-error").hidden = true;
  try {
    const host = await invoke("join", {
      link: $("link").value.trim(),
      hostName: $("host-name").value,
      deviceName: $("device-name").value,
    });
    $("link").value = "";
    await openChat(host.name);
  } catch (error) {
    $("pair-error").textContent = String(error);
    $("pair-error").hidden = false;
  } finally {
    button.disabled = false;
  }
});

for (const back of document.querySelectorAll(".back")) {
  back.addEventListener("click", () => show(back.dataset.to));
}

show("home");
