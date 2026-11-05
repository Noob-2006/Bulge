// seagent browser relay — MV3 service worker.
//
// Connects to `ws://127.0.0.1:<port>/extension` (seagent: `seagent browser extension`,
// browser.extension_control.port, default 18792), authenticates with the token
// from `<seagent home>/browser/extension-token`, and then relays raw CDP JSON frames
// to/from `chrome.debugger`. Reference implementation: OpenClaw's
// chrome-extension (MIT), rewritten for the seagent relay protocol.
//
// Protocol
//   ext → seagent  {"type":"hello","token":"…","version":1,"userAgent":"…"}
//   seagent → ext  {"type":"welcome","version":1}          (pairing done)
//   seagent → ext  {"type":"error","error":"bad token"}    (then close 4401)
//   seagent → ext  {"type":"attach"} / {"type":"detach"}   (seagent's CDP client came/went)
//   both ways  raw CDP JSON: {"id":1,"method":"Page.navigate","params":{…},"sessionId":"…"}

const DEFAULT_PORT = 18792;
const PROTOCOL_VERSION = 1;
const RECONNECT_ALARM = "seagent-reconnect";
const MAX_BACKOFF_MS = 30000;
const RELAY_PATH = "/extension";

// Tabs we can drive with chrome.debugger. Everything else (chrome://, the Web
// Store, other extensions' pages, devtools…) is skipped silently.
const UNATTACHABLE = [
  "chrome://",
  "chrome-untrusted://",
  "devtools://",
  "edge://",
  "view-source:",
  "https://chromewebstore.google.com",
  "https://chrome.google.com/webstore",
  "https://microsoftedge.microsoft.com/addons",
];

/** @type {WebSocket|null} */
let socket = null;
let paired = false;
let attempt = 0;
let reconnectTimer = null;
let helloTimer = null;
let lastError = "";
let lastState = "off";
const attachedTabs = new Set();
const sessionToTab = new Map();
const tabToSession = new Map();
let sessionSeq = 0;
// Bumped by detachAll(): an attach that was in flight during a detach must not
// re-add its tab to the bookkeeping (the relay already went away).
let attachEpoch = 0;

// ---------------------------------------------------------------- helpers

function p(fn, thisArg, ...args) {
  return new Promise((resolve, reject) => {
    fn.call(thisArg, ...args, (result) => {
      const err = chrome.runtime.lastError;
      if (err) reject(new Error(err.message));
      else resolve(result);
    });
  });
}

const tabsQuery = (query) => p(chrome.tabs.query, chrome.tabs, query ?? {});
const tabCreate = (props) => p(chrome.tabs.create, chrome.tabs, props);
const tabRemove = (tabId) => p(chrome.tabs.remove, chrome.tabs, tabId);
const tabUpdate = (tabId, props) => p(chrome.tabs.update, chrome.tabs, tabId, props);
const getTab = (tabId) => p(chrome.tabs.get, chrome.tabs, tabId);
const dbgAttach = (tabId) => p(chrome.debugger.attach, chrome.debugger, { tabId }, "1.3");
const dbgDetach = (tabId) => p(chrome.debugger.detach, chrome.debugger, { tabId });
const dbgSend = (tabId, method, params) =>
  p(chrome.debugger.sendCommand, chrome.debugger, { tabId }, method, params ?? {});

function attachable(tab) {
  if (tab.id === undefined || tab.id === chrome.tabs.TAB_ID_NONE) return false;
  // A tab that has not committed yet (brand-new "about:blank") has no url: still
  // worth attaching, chrome.debugger decides. Only privileged pages are skipped.
  const url = tab.url || tab.pendingUrl || "";
  return !UNATTACHABLE.some((prefix) => url.startsWith(prefix));
}

async function readConfig() {
  const stored = await chrome.storage.local.get({ port: DEFAULT_PORT, token: "" });
  const port = Number(stored.port);
  return {
    port: Number.isInteger(port) && port > 0 && port < 65536 ? port : DEFAULT_PORT,
    token: String(stored.token || "").trim(),
  };
}

function relayUrl(port) {
  return "ws://127.0.0.1:" + port + RELAY_PATH;
}

function setStatus(state, extra) {
  lastState = state;
  const cfg = extra && extra.port ? extra.port : null;
  const status = {
    state,
    paired,
    port: cfg,
    url: cfg ? relayUrl(cfg) : null,
    attached: attachedTabs.size,
    error: lastError,
    version: chrome.runtime.getManifest().version,
    updatedAt: Date.now(),
  };
  try {
    void chrome.storage.local.set({ seagentStatus: status });
  } catch (e) {
    // storage can be unavailable while the worker is shutting down; harmless.
  }
  return status;
}

function badge(text, color) {
  try {
    void chrome.action.setBadgeText({ text });
    if (color) void chrome.action.setBadgeBackgroundColor({ color });
  } catch (e) {
    /* no action bar in some builds */
  }
}

// -------------------------------------------------------------- connection

function send(value) {
  if (!socket || socket.readyState !== WebSocket.OPEN) return false;
  try {
    socket.send(typeof value === "string" ? value : JSON.stringify(value));
    return true;
  } catch (e) {
    return false;
  }
}

function scheduleReconnect(port) {
  if (reconnectTimer) return;
  const delay = Math.min(1000 * Math.pow(2, attempt), MAX_BACKOFF_MS);
  attempt += 1;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    void connect();
  }, delay);
  setStatus(attempt > 1 ? "retrying" : "connecting", { port });
}

async function connect() {
  if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) return;
  const cfg = await readConfig();
  if (!cfg.token) {
    lastError = "no token: paste the contents of extension-token into the options page";
    setStatus("unpaired", { port: cfg.port });
    badge("!", "#B91C1C");
    return;
  }
  const url = relayUrl(cfg.port);
  let next;
  try {
    next = new WebSocket(url);
  } catch (e) {
    lastError = String(e && e.message ? e.message : e);
    scheduleReconnect(cfg.port);
    return;
  }
  socket = next;
  setStatus("connecting", { port: cfg.port });
  badge("…", "#F59E0B");

  next.onopen = () => {
    send({ type: "hello", token: cfg.token, version: PROTOCOL_VERSION, userAgent: navigator.userAgent });
    // A relay that accepts the socket but never answers must not pin us forever.
    helloTimer = setTimeout(() => {
      helloTimer = null;
      if (!paired && socket === next) {
        lastError = "the relay accepted the socket but never answered the hello";
        try {
          next.close(4001, "no welcome");
        } catch (e) {
          /* already gone */
        }
      }
    }, 10000);
  };
  next.onmessage = (event) => {
    if (typeof event.data !== "string") return;
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch (e) {
      return;
    }
    void handleMessage(msg, cfg.port);
  };
  next.onerror = () => {
    lastError = "relay unreachable at " + url;
  };
  next.onclose = (event) => {
    if (socket === next) socket = null;
    if (helloTimer) {
      clearTimeout(helloTimer);
      helloTimer = null;
    }
    const wasPaired = paired;
    paired = false;
    void detachAll();
    if (event && event.code === 4401) {
      lastError = "bad token: copy the token from extension-token again";
      setStatus("error", { port: cfg.port });
      badge("!", "#B91C1C");
      return; // never hammer the relay with a wrong token
    }
    if (!lastError) lastError = wasPaired ? "relay closed the connection" : "relay unreachable";
    badge("…", "#F59E0B");
    scheduleReconnect(cfg.port);
  };
}

async function handleMessage(msg, port) {
  if (!msg || typeof msg !== "object") return;
  if (typeof msg.type === "string") {
    switch (msg.type) {
      case "welcome":
        paired = true;
        attempt = 0;
        lastError = "";
        if (helloTimer) {
          clearTimeout(helloTimer);
          helloTimer = null;
        }
        setStatus("connected", { port });
        badge("ON", "#0F9D58");
        return;
      case "error":
        paired = false;
        lastError = msg.error ? String(msg.error) : "relay error";
        setStatus("error", { port });
        badge("!", "#B91C1C");
        return;
      case "attach":
        await attachAll(port);
        return;
      case "detach":
        await detachAll();
        setStatus(paired ? "connected" : lastState, { port });
        return;
      default:
        return;
    }
  }
  if (typeof msg.method === "string") await handleCdp(msg, port);
}

// ------------------------------------------------------------- debugger

async function attachTab(tabId, epoch) {
  if (attachedTabs.has(tabId)) return;
  const ep = epoch === undefined ? attachEpoch : epoch;
  await dbgAttach(tabId);
  if (ep !== attachEpoch) {
    // A detach happened while chrome.debugger was attaching: undo it.
    await dbgDetach(tabId).catch(() => {});
    return;
  }
  attachedTabs.add(tabId);
}

async function attachAll(port) {
  const epoch = attachEpoch;
  const tabs = await tabsQuery({});
  for (const tab of tabs) {
    if (epoch !== attachEpoch) return;
    if (!attachable(tab)) continue;
    try {
      await attachTab(tab.id, epoch);
      if (!attachedTabs.has(tab.id)) continue;
      // Start the domains seagent's browser tools expect (events go back as CDP events).
      await dbgSend(tab.id, "Page.enable", {}).catch(() => {});
      await dbgSend(tab.id, "Runtime.enable", {}).catch(() => {});
    } catch (e) {
      // chrome:// pages, tabs being dragged, or another debugger already attached.
    }
  }
  setStatus(paired ? "connected" : lastState, { port });
}

async function detachTab(tabId) {
  attachedTabs.delete(tabId);
  forgetSession(tabId);
  try {
    await dbgDetach(tabId);
  } catch (e) {
    // already detached or the tab is gone
  }
}

async function detachAll() {
  attachEpoch += 1;
  const ids = [...attachedTabs];
  sessionToTab.clear();
  tabToSession.clear();
  attachedTabs.clear();
  await Promise.all(ids.map((tabId) => dbgDetach(tabId).catch(() => {})));
}

function forgetSession(tabId) {
  const sid = tabToSession.get(tabId);
  if (sid) {
    tabToSession.delete(tabId);
    sessionToTab.delete(sid);
  }
}

function newSession(tabId) {
  forgetSession(tabId);
  const sid = "seagent-session-" + ++sessionSeq;
  sessionToTab.set(sid, tabId);
  tabToSession.set(tabId, sid);
  return sid;
}

function tabForSession(sessionId) {
  if (!sessionId) return undefined;
  const direct = sessionToTab.get(sessionId);
  if (direct !== undefined) return direct;
  // seagent may echo the target id as the session id; both are String(tab.id).
  const asTab = Number(sessionId);
  if (Number.isInteger(asTab) && attachedTabs.has(asTab)) return asTab;
  if (attachedTabs.size === 1) return [...attachedTabs][0];
  return undefined;
}

// --------------------------------------------------------------- CDP

function reply(id, extra) {
  if (id === undefined || id === null) return;
  send(Object.assign({ id }, extra));
}

async function handleCdp(msg, port) {
  const id = msg.id;
  const method = String(msg.method);
  const params = msg.params && typeof msg.params === "object" ? msg.params : {};
  const sessionId = msg.sessionId;
  try {
    const result = await route(method, params, sessionId);
    reply(id, sessionId ? { result, sessionId } : { result });
  } catch (e) {
    const message = String(e && e.message ? e.message : e);
    lastError = method + ": " + message;
    reply(id, sessionId ? { error: { code: -32000, message }, sessionId } : { error: { code: -32000, message } });
    setStatus(paired ? "connected" : lastState, { port });
  }
}

async function route(method, params, sessionId) {
  switch (method) {
    case "Target.getTargets": {
      const tabs = await tabsQuery({});
      const targetInfos = tabs.filter(attachable).map((tab) => ({
        targetId: String(tab.id),
        type: "page",
        title: tab.title || "",
        url: tab.url || tab.pendingUrl || "",
        attached: attachedTabs.has(tab.id),
      }));
      return { targetInfos };
    }
    case "Target.attachToTarget": {
      const tabId = Number(params.targetId);
      if (!Number.isInteger(tabId)) throw new Error("no such target: " + String(params.targetId));
      await attachTab(tabId);
      // seagent always asks for flattened sessions; the session id is ours either way.
      return { sessionId: newSession(tabId) };
    }
    case "Target.detachFromTarget": {
      const tabId = params.sessionId
        ? tabForSession(String(params.sessionId))
        : Number(params.targetId);
      if (tabId === undefined) throw new Error("no such target: " + String(params.targetId ?? params.sessionId));
      await detachTab(tabId);
      return {};
    }
    case "Target.createTarget": {
      const url = typeof params.url === "string" && params.url ? params.url : "about:blank";
      const tab = await tabCreate({ url, active: params.background !== true });
      if (tab && tab.id !== undefined) {
        try {
          await attachTab(tab.id);
        } catch (e) {
          // the tab exists but may not be attachable yet; seagent can retry
        }
      }
      return { targetId: tab && tab.id !== undefined ? String(tab.id) : "" };
    }
    case "Target.closeTarget": {
      const tabId = Number(params.targetId);
      if (!Number.isInteger(tabId)) throw new Error("no such target: " + String(params.targetId));
      await detachTab(tabId);
      await tabRemove(tabId).catch((e) => {
        throw new Error("cannot close target " + tabId + ": " + e.message);
      });
      return { success: true };
    }
    case "Target.activateTarget": {
      const tabId = Number(params.targetId);
      if (!Number.isInteger(tabId)) throw new Error("no such target: " + String(params.targetId));
      const tab = await getTab(tabId);
      await tabUpdate(tabId, { active: true });
      if (tab && tab.windowId !== undefined) {
        await p(chrome.windows.update, chrome.windows, tab.windowId, { focused: true }).catch(() => {});
      }
      return {};
    }
    case "Target.setDiscoverTargets":
    case "Target.setAutoAttach":
      return {}; // the relay already pushes the full tab list
    case "Browser.getVersion":
      return {
        protocolVersion: "1.3",
        product: navigator.userAgent,
        revision: "",
        userAgent: navigator.userAgent,
        jsVersion: "",
      };
    default: {
      const tabId = tabForSession(sessionId);
      if (tabId === undefined) {
        throw new Error(
          sessionId
            ? "no attached tab for session " + sessionId + " (call Target.attachToTarget first)"
            : "no attached tab: call Target.attachToTarget first",
        );
      }
      return await dbgSend(tabId, method, params);
    }
  }
}

// Forward chrome.debugger events to seagent as plain CDP events.
chrome.debugger.onEvent.addListener((source, method, params) => {
  if (!paired) return;
  const sessionId = source && source.tabId !== undefined ? tabToSession.get(source.tabId) : undefined;
  const event = { method, params: params || {} };
  if (sessionId) event.sessionId = sessionId;
  send(event);
});

chrome.debugger.onDetach.addListener((source, reason) => {
  if (!source || source.tabId === undefined) return;
  attachedTabs.delete(source.tabId);
  forgetSession(source.tabId);
  if (reason && reason !== "target_closed") lastError = "debugger detached: " + reason;
});

// ------------------------------------------------------------- lifecycle

async function ensureAlarm() {
  try {
    const existing = await chrome.alarms.get(RECONNECT_ALARM);
    if (!existing) {
      // Service workers are evicted; a 30s alarm re-establishes the relay.
      await chrome.alarms.create(RECONNECT_ALARM, { periodInMinutes: 0.5 });
    }
  } catch (e) {
    /* alarms permission missing in a stripped-down build */
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== RECONNECT_ALARM) return;
  if (!socket) void connect();
});

chrome.runtime.onStartup.addListener(() => {
  void ensureAlarm();
  void connect();
});

chrome.runtime.onInstalled.addListener(() => {
  void ensureAlarm();
  void connect();
});

// Options page / popup talk to us instead of poking the socket themselves.
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const type = message && message.type;
  if (type === "getStatus") {
    void readConfig().then((cfg) => {
      sendResponse({
        state: lastState,
        paired,
        port: cfg.port,
        url: relayUrl(cfg.port),
        hasToken: Boolean(cfg.token),
        attached: attachedTabs.size,
        error: lastError,
        version: chrome.runtime.getManifest().version,
      });
    });
    return true;
  }
  if (type === "reconnect") {
    attempt = 0;
    lastError = "";
    void (async () => {
      if (socket) {
        try {
          socket.close(1000, "reconnect requested");
        } catch (e) {
          /* ignore */
        }
        socket = null;
      }
      paired = false;
      await detachAll();
      await connect();
      sendResponse({ ok: true });
    })();
    return true;
  }
  if (type === "disconnect") {
    void (async () => {
      if (socket) {
        try {
          socket.close(1000, "disconnect requested");
        } catch (e) {
          /* ignore */
        }
        socket = null;
      }
      paired = false;
      await detachAll();
      setStatus("off", await readConfig().then((cfg) => ({ port: cfg.port })));
      badge("", "#000000");
      sendResponse({ ok: true });
    })();
    return true;
  }
  return false;
});

void (async () => {
  await ensureAlarm();
  await connect();
})();
