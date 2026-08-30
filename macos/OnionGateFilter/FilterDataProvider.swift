// OnionGate NEFilterDataProvider.
//
// LuLu-style intercept on Apple's Network Extension API.
// Policy is OnionGate's: default drop for anything that is not already Tor.
// We return drop immediately (no pause-and-wait) so a dead app or an Apple
// flood cannot fail open through this provider. pf remains the packet lock.
//
// Prior art: Objective-See LuLu (GPL-3.0) — same Apple API class, not their
// tree, not their allow-installed / framework-default-allow policy.

import AppKit
import Darwin
import Foundation
import NetworkExtension

@_silgen_name("audit_token_to_pid")
func audit_token_to_pid(_ token: audit_token_t) -> pid_t

@_silgen_name("proc_pidpath")
func proc_pidpath(_ pid: pid_t, _ buffer: UnsafeMutableRawPointer?, _ buffersize: UInt32) -> Int32

final class FilterDataProvider: NEFilterDataProvider {
    private let state = FilterStateStore()
    private let queue = DispatchQueue(label: "com.adamsiwiec.oniongate.filter")
    private var heartbeatTimer: DispatchSourceTimer?

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        startHeartbeat()
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        heartbeatTimer?.cancel()
        heartbeatTimer = nil
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let identity = FlowIdentity.from(flow)
        let allowlist = state.readAllowlist()
        let verdict = FilterClassifier.classify(
            remoteHost: identity.remoteHost,
            remotePort: identity.remotePort,
            proto: identity.proto,
            allowlist: allowlist
        )
        state.noteSeen(identity)
        if verdict == .allow {
            return .allow()
        }
        state.noteHeld(identity)
        return .drop()
    }

    private func startHeartbeat() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: 2)
        timer.setEventHandler { [weak self] in
            self?.state.writeHeartbeat()
        }
        timer.resume()
        heartbeatTimer = timer
        state.writeHeartbeat()
    }
}

struct FlowIdentity {
    var pid: pid_t
    var process: String
    var path: String
    var bundleId: String
    var remoteHost: String
    var remotePort: UInt16
    var proto: String

    static func from(_ flow: NEFilterFlow) -> FlowIdentity {
        var host = ""
        var port: UInt16 = 0
        var proto = "tcp"
        if let socket = flow as? NEFilterSocketFlow {
            if let endpoint = socket.remoteEndpoint as? NWHostEndpoint {
                host = endpoint.hostname
                port = UInt16(endpoint.port) ?? 0
            }
            if host.isEmpty, let name = socket.remoteHostname, !name.isEmpty {
                host = name
            }
            proto = socket.socketProtocol == IPPROTO_UDP ? "udp" : "tcp"
        }
        let pid = pidFromAuditToken(flow.sourceAppAuditToken)
        let path = pathForPid(pid)
        var process = (path as NSString).lastPathComponent
        var bundle = ""
        if pid > 0, let app = NSRunningApplication(processIdentifier: pid) {
            bundle = app.bundleIdentifier ?? ""
            if process.isEmpty {
                process = app.executableURL?.lastPathComponent ?? ""
            }
        }
        if process.isEmpty {
            process = "unknown"
        }
        return FlowIdentity(
            pid: pid,
            process: process,
            path: path,
            bundleId: bundle,
            remoteHost: host,
            remotePort: port,
            proto: proto
        )
    }

    static func pidFromAuditToken(_ data: Data?) -> pid_t {
        guard let data, data.count >= MemoryLayout<audit_token_t>.size else {
            return 0
        }
        return data.withUnsafeBytes { raw -> pid_t in
            guard let base = raw.baseAddress else { return 0 }
            return audit_token_to_pid(base.load(as: audit_token_t.self))
        }
    }

    static func pathForPid(_ pid: pid_t) -> String {
        guard pid > 0 else { return "" }
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let n = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        if n > 0 {
            return String(cString: buffer)
        }
        return ""
    }
}
