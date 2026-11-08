// SE Agent on iOS is a pure client: no VM, no local shell, no subprocesses (platform policy).
// This plugin only finds SE Agent hosts on the local network (Bonjour `_seagent._tcp`).
// Info.ios.plist declares NSLocalNetworkUsageDescription and NSBonjourServices; the first
// browse shows the system's "find devices on your local network" prompt.

import Foundation
import Network
import Tauri
import UIKit
import WebKit

struct DiscoverArgs: Decodable {
  let timeoutMs: Int?
}

class SeagentMobilePlugin: Plugin {
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
  return SeagentMobilePlugin()
}
