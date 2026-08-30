// OnionGate connection filter — flow classifier.
//
// Same rules as src-tauri/src/ne_filter.rs::classify. Keep them in lockstep.
// Default is drop. Allow is only loopback, DHCP, live Tor endpoints, and
// local OnionGate SOCKS/control/DNS.

import Foundation

enum FilterVerdict: String {
    case allow
    case drop
}

struct FilterAllowlist {
    var sessionActive: Bool
    var torEndpoints: Set<String>
}

enum FilterClassifier {
    static func isLoopback(_ host: String) -> Bool {
        host == "127.0.0.1" || host == "::1" || host == "localhost"
    }

    static func isDhcp(port: UInt16, proto: String) -> Bool {
        proto.lowercased() == "udp" && (port == 67 || port == 68)
    }

    static func isTunV4(_ host: String) -> Bool {
        let parts = host.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return false }
        return parts[0] == 172 && parts[1] == 19 && parts[2] == 0 && parts[3] <= 3
    }

    static func classify(
        remoteHost: String,
        remotePort: UInt16,
        proto: String,
        allowlist: FilterAllowlist
    ) -> FilterVerdict {
        if !allowlist.sessionActive {
            return .allow
        }
        if isLoopback(remoteHost) {
            return .allow
        }
        if isDhcp(port: remotePort, proto: proto) {
            return .allow
        }
        if isTunV4(remoteHost) {
            return .allow
        }
        if allowlist.torEndpoints.contains(remoteHost) {
            return .allow
        }
        return .drop
    }
}
