// SE Agent on iOS runs the whole agent inside this app process (`seagent::embed`, linked into the
// app's Rust static library): kernel, sessions, model providers, memory, skills, MCP over HTTP,
// chat channels and the App Server on 127.0.0.1, whose console the WebView loads. iOS allows no
// child processes, no JIT and no hypervisor, so there are no VMs and no native shell; commands
// run as WASI tools in the in-process WebAssembly interpreter (exec backend `wasm`).
//
// This plugin gives the Rust side what only iOS APIs can:
//   agentEnv            the agent's home (Application Support/seagent), the bundled share/ dir and
//                       the vault key, kept in the Keychain (SEAGENT_VAULT_KEY for the agent)
//   scheduleBackground  a BGProcessingTask request for cron / heartbeat work
//   discover            Bonjour `_seagent._tcp` (pairing with a computer is optional)
// and drives the agent's background life: BGTaskScheduler wakes run `seagent_mobile_bg_run`,
// going to the background books the next wake, returning to the foreground re-checks the App
// Server (iOS may reclaim a suspended app's listening socket).
//
// Info.ios.plist declares BGTaskSchedulerPermittedIdentifiers (TASK_ID), UIBackgroundModes
// (processing, fetch), NSLocalNetworkUsageDescription and NSBonjourServices.

import BackgroundTasks
import Foundation
import Network
import Security
import Tauri
import UIKit
import WebKit

// ── the Rust side (apps/desktop/plugins/seagent-mobile/src/lib.rs, module `ios`) ──
@_silgen_name("seagent_mobile_bg_run")
func seagent_mobile_bg_run(_ home: UnsafePointer<CChar>?, _ share: UnsafePointer<CChar>?, _ key: UnsafePointer<CChar>?, _ budgetSecs: UInt32) -> Int64
@_silgen_name("seagent_mobile_bg_expired")
func seagent_mobile_bg_expired()
@_silgen_name("seagent_mobile_next_due")
func seagent_mobile_next_due() -> Int64
@_silgen_name("seagent_mobile_foreground")
func seagent_mobile_foreground(_ home: UnsafePointer<CChar>?, _ share: UnsafePointer<CChar>?, _ key: UnsafePointer<CChar>?) -> Int32

struct DiscoverArgs: Decodable {
  let timeoutMs: Int?
}

struct ScheduleArgs: Decodable {
  let earliestUnix: Double?
}

/// Where the agent lives and the key that opens its vault.
enum AgentEnv {
  static let taskId = "dev.seagent.agent.refresh"
  static let keychainService = "dev.seagent.agent.vault"
  static let keychainAccount = "SEAGENT_VAULT_KEY"

  static var home: String {
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    let dir = base.appendingPathComponent("seagent", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir.path
  }

  static var share: String? {
    guard let res = Bundle.main.resourceURL?.appendingPathComponent("share", isDirectory: true) else { return nil }
    return FileManager.default.fileExists(atPath: res.path) ? res.path : nil
  }

  /// 32 random bytes (hex), created on first use. Accessible after the first unlock, so a
  /// background task can open the vault; it travels with encrypted backups like the data does.
  static func vaultKey() -> String? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: keychainService,
      kSecAttrAccount as String: keychainAccount,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data, let s = String(data: data, encoding: .utf8) {
      return s
    }
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
    let hex = bytes.map { String(format: "%02x", $0) }.joined()
    let add: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: keychainService,
      kSecAttrAccount as String: keychainAccount,
      kSecValueData as String: Data(hex.utf8),
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
    ]
    return SecItemAdd(add as CFDictionary, nil) == errSecSuccess ? hex : nil
  }

  /// Call `body` with the three C strings the Rust functions take.
  static func withC<T>(_ body: (UnsafePointer<CChar>?, UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> T) -> T {
    let (h, s, k) = (home, share ?? "", vaultKey() ?? "")
    return h.withCString { hp in s.withCString { sp in k.withCString { kp in body(hp, s.isEmpty ? nil : sp, k.isEmpty ? nil : kp) } } }
  }

  /// Book the next BGProcessingTask: at the next due cron job, at least 15 minutes from now
  /// (iOS decides the real time — while charging, on Wi-Fi, when the user is not using the phone).
  static func schedule(earliestUnix: Double?) {
    let req = BGProcessingTaskRequest(identifier: taskId)
    req.requiresNetworkConnectivity = true
    req.requiresExternalPower = false
    let soonest = Date().addingTimeInterval(15 * 60)
    if let t = earliestUnix, t > 0 {
      req.earliestBeginDate = max(Date(timeIntervalSince1970: t), soonest)
    } else {
      req.earliestBeginDate = Date().addingTimeInterval(60 * 60)
    }
    BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: taskId)
    try? BGTaskScheduler.shared.submit(req)
  }

  static func handle(_ task: BGProcessingTask) {
    let queue = DispatchQueue(label: "dev.seagent.bgtask", qos: .utility)
    task.expirationHandler = {
      seagent_mobile_bg_expired()
    }
    queue.async {
      // A few minutes is the most iOS gives a processing task; open turns resume next launch.
      let next = withC { h, s, k in seagent_mobile_bg_run(h, s, k, 240) }
      schedule(earliestUnix: next > 0 ? Double(next) : nil)
      task.setTaskCompleted(success: next >= 0)
    }
  }
}

class SeagentMobilePlugin: Plugin {
  private var bgTask: UIBackgroundTaskIdentifier = .invalid
  static var registered = false

  /// BGTaskScheduler handlers must be registered before the app finishes launching; the plugin is
  /// created from the app's setup, inside `application(_:didFinishLaunchingWithOptions:)`.
  static func registerBackgroundTask() {
    guard !registered else { return }
    registered = BGTaskScheduler.shared.register(forTaskWithIdentifier: AgentEnv.taskId, using: nil) { task in
      if let t = task as? BGProcessingTask {
        AgentEnv.handle(t)
      } else {
        task.setTaskCompleted(success: false)
      }
    }
  }

  override public func load(webview: WKWebView) {
    let nc = NotificationCenter.default
    nc.addObserver(self, selector: #selector(didEnterBackground), name: UIApplication.didEnterBackgroundNotification, object: nil)
    nc.addObserver(self, selector: #selector(willEnterForeground), name: UIApplication.willEnterForegroundNotification, object: nil)
  }

  /// Keep running for the short grace iOS gives (a reply in flight can finish), then book the
  /// next background wake for the cron schedule.
  @objc func didEnterBackground() {
    let next = seagent_mobile_next_due()
    AgentEnv.schedule(earliestUnix: next > 0 ? Double(next) : nil)
    bgTask = UIApplication.shared.beginBackgroundTask(withName: "seagent-turns") { [weak self] in
      guard let self = self else { return }
      UIApplication.shared.endBackgroundTask(self.bgTask)
      self.bgTask = .invalid
    }
  }

  @objc func willEnterForeground() {
    if bgTask != .invalid {
      UIApplication.shared.endBackgroundTask(bgTask)
      bgTask = .invalid
    }
    DispatchQueue.global(qos: .userInitiated).async {
      _ = AgentEnv.withC { h, s, k in seagent_mobile_foreground(h, s, k) }
    }
  }

  @objc public func agentEnv(_ invoke: Invoke) throws {
    var out: [String: Any] = ["home": AgentEnv.home]
    if let s = AgentEnv.share { out["share"] = s }
    guard let key = AgentEnv.vaultKey() else {
      invoke.reject("the Keychain refused to store the vault key")
      return
    }
    out["vaultKey"] = key
    invoke.resolve(out)
  }

  @objc public func scheduleBackground(_ invoke: Invoke) throws {
    let args = try? invoke.parseArgs(ScheduleArgs.self)
    AgentEnv.schedule(earliestUnix: args?.earliestUnix)
    invoke.resolve()
  }

  @objc public func discover(_ invoke: Invoke) throws {
    let args = try? invoke.parseArgs(DiscoverArgs.self)
    let timeout = Double(min(max(args?.timeoutMs ?? 3000, 500), 15000)) / 1000.0
    let queue = DispatchQueue(label: "dev.seagent.discover")
    let params = NWParameters.tcp
    params.includePeerToPeer = false
    let browser = NWBrowser(for: .bonjourWithTXTRecord(type: "_seagent._tcp", domain: nil), using: params)
    var found: [String: [String: Any]] = [:]
    var connections: [NWConnection] = []

    browser.browseResultsChangedHandler = { results, _ in
      for r in results {
        guard case let .service(name, _, _, _) = r.endpoint, found[name] == nil else { continue }
        var txt: [String: String] = [:]
        if case let .bonjour(record) = r.metadata {
          txt = record.dictionary
        }
        found[name] = ["name": name, "txt": txt]
        // Resolve the service to an address by opening (and immediately closing) a TCP connection.
        let conn = NWConnection(to: r.endpoint, using: .tcp)
        connections.append(conn)
        conn.stateUpdateHandler = { state in
          switch state {
          case .ready:
            if let remote = conn.currentPath?.remoteEndpoint, case let .hostPort(host, port) = remote {
              var h = "\(host)"
              if let pct = h.firstIndex(of: "%") { h = String(h[..<pct]) }  // drop an IPv6 zone
              found[name]?["host"] = h
              found[name]?["port"] = Int(port.rawValue)
            }
            conn.cancel()
          case .failed(_), .waiting(_):
            conn.cancel()
          default:
            break
          }
        }
        conn.start(queue: queue)
      }
    }
    browser.stateUpdateHandler = { state in
      if case let .failed(err) = state {
        queue.async {
          browser.cancel()
          invoke.reject("local network discovery failed: \(err)")
        }
      }
    }
    browser.start(queue: queue)

    queue.asyncAfter(deadline: .now() + timeout) {
      browser.cancel()
      connections.forEach { $0.cancel() }
      let hosts = found.values.filter { $0["host"] != nil }
      invoke.resolve(["hosts": Array(hosts)])
    }
  }
}

@_cdecl("init_plugin_seagent_mobile")
func initPlugin() -> Plugin {
  SeagentMobilePlugin.registerBackgroundTask()
  return SeagentMobilePlugin()
}
