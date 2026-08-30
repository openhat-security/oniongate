// Root-owned filter state. The app reads heartbeat + held flows; it never
// writes a clearnet-allow opcode. Allowlist is published by the OnionGate
// core into the console user's data directory.

import Foundation

enum FilterPaths {
    static let supportDir = "/Library/Application Support/OnionGate/filter"
    static let heartbeat = supportDir + "/heartbeat.json"
    static let held = supportDir + "/held.json"
    static let seen = supportDir + "/seen.json"
    static let allowlistName = "filter-allowlist.json"
}

final class FilterStateStore {
    private let lock = NSLock()
    private var held: [HeldFlow] = []
    private var seen: [SeenFlow] = []

    func writeHeartbeat() {
        ensureDir()
        let payload: [String: Any] = [
            "unix": Int(Date().timeIntervalSince1970),
            "pid": ProcessInfo.processInfo.processIdentifier,
        ]
        writeJSON(payload, to: FilterPaths.heartbeat)
    }

    func noteHeld(_ identity: FlowIdentity) {
        lock.lock()
        held.append(HeldFlow(identity: identity, unix: Int(Date().timeIntervalSince1970)))
        if held.count > 64 {
            held.removeFirst(held.count - 64)
        }
        let snapshot = held
        lock.unlock()
        writeJSON(["flows": snapshot.map(\.json)], to: FilterPaths.held)
    }

    func noteSeen(_ identity: FlowIdentity) {
        lock.lock()
        seen.append(SeenFlow(identity: identity, unix: Int(Date().timeIntervalSince1970)))
        if seen.count > 256 {
            seen.removeFirst(seen.count - 256)
        }
        let snapshot = seen
        lock.unlock()
        writeJSON(["flows": snapshot.map(\.json)], to: FilterPaths.seen)
    }

    func readAllowlist() -> FilterAllowlist {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: allowlistPath())),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return FilterAllowlist(sessionActive: false, torEndpoints: [])
        }
        let active = obj["session_active"] as? Bool ?? false
        let endpoints = Set((obj["tor_endpoints"] as? [String]) ?? [])
        return FilterAllowlist(sessionActive: active, torEndpoints: endpoints)
    }

    private func allowlistPath() -> String {
        let uid = consoleUid()
        if uid > 0,
           let home = homeFor(uid: uid)
        {
            return home + "/Library/Application Support/oniongate/" + FilterPaths.allowlistName
        }
        return "/Library/Application Support/OnionGate/filter/allowlist.json"
    }

    private func consoleUid() -> uid_t {
        var statBuf = stat()
        if stat("/dev/console", &statBuf) == 0 {
            return statBuf.st_uid
        }
        return 0
    }

    private func homeFor(uid: uid_t) -> String? {
        guard let pw = getpwuid(uid), let dir = pw.pointee.pw_dir else { return nil }
        return String(cString: dir)
    }

    private func ensureDir() {
        try? FileManager.default.createDirectory(
            atPath: FilterPaths.supportDir,
            withIntermediateDirectories: true
        )
    }

    private func writeJSON(_ obj: Any, to path: String) {
        ensureDir()
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted])
        else { return }
        try? data.write(to: URL(fileURLWithPath: path), options: .atomic)
    }
}

struct HeldFlow {
    var identity: FlowIdentity
    var unix: Int
    var json: [String: Any] {
        [
            "pid": Int(identity.pid),
            "process": identity.process,
            "path": identity.path,
            "bundle_id": identity.bundleId,
            "remote_host": identity.remoteHost,
            "remote_port": Int(identity.remotePort),
            "proto": identity.proto,
            "unix": unix,
        ]
    }
}

struct SeenFlow {
    var identity: FlowIdentity
    var unix: Int
    var json: [String: Any] {
        [
            "pid": Int(identity.pid),
            "remote_host": identity.remoteHost,
            "remote_port": Int(identity.remotePort),
            "unix": unix,
        ]
    }
}
