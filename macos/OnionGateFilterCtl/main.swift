// Activates or deactivates the OnionGate content filter.
// Must run from inside OnionGate.app so the container ID matches.
// Loads the system extension, then enables NEFilterManager. Default
// provider verdict is drop; this tool never sends an allow-clearnet opcode.

import Foundation
import NetworkExtension
import SystemExtensions

let identifier = "com.adamsiwiec.oniongate.filter"

enum Command: String {
    case activate
    case deactivate
    case status
}

final class ExtensionDelegate: NSObject, OSSystemExtensionRequestDelegate {
    var onDone: ((Int32, String) -> Void)?

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        onDone?(0, "result=\(result.rawValue)")
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        onDone?(1, error.localizedDescription)
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        FileHandle.standardError.write(
            Data("Approve the OnionGate connection filter in System Settings → Network Extensions.\n".utf8)
        )
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
}

func wait(_ seconds: Double, work: (@escaping (Int32, String) -> Void) -> Void) -> (Int32, String) {
    let semaphore = DispatchSemaphore(value: 0)
    var code: Int32 = 1
    var message = "timeout"
    work { nextCode, nextMessage in
        code = nextCode
        message = nextMessage
        semaphore.signal()
    }
    _ = semaphore.wait(timeout: .now() + seconds)
    return (code, message)
}

func configureFilter(enable: Bool, done: @escaping (Int32, String) -> Void) {
    let manager = NEFilterManager.shared()
    manager.loadFromPreferences { loadError in
        if let loadError {
            done(1, loadError.localizedDescription)
            return
        }
        if enable {
            let config = NEFilterProviderConfiguration()
            config.filterSockets = true
            config.filterPackets = false
            config.username = "OnionGate"
            config.organization = "OnionGate"
            config.filterDataProviderBundleIdentifier = identifier
            manager.providerConfiguration = config
            manager.isEnabled = true
        } else {
            manager.isEnabled = false
        }
        manager.saveToPreferences { saveError in
            if let saveError {
                done(1, saveError.localizedDescription)
                return
            }
            done(0, enable ? "filter-enabled" : "filter-disabled")
        }
    }
}

var retainedDelegate: ExtensionDelegate?

func submitExtension(activate: Bool, done: @escaping (Int32, String) -> Void) {
    let delegate = ExtensionDelegate()
    delegate.onDone = done
    retainedDelegate = delegate
    let request = activate
        ? OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: identifier,
            queue: .main
        )
        : OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: identifier,
            queue: .main
        )
    request.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(request)
}

let args = CommandLine.arguments.dropFirst()
let command = Command(rawValue: args.first ?? "status") ?? .status

if command == .status {
    let path = "/Library/Application Support/OnionGate/filter/heartbeat.json"
    var heartbeat = 0
    if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
       let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
       let unix = obj["unix"] as? Int
    {
        heartbeat = unix
    }
    print("{\"installed\":\(heartbeat > 0),\"heartbeat_unix\":\(heartbeat)}")
    exit(0)
}

DispatchQueue.global().async {
    if command == .activate {
        let (extCode, extMessage) = wait(120) { done in
            submitExtension(activate: true, done: done)
        }
        FileHandle.standardError.write(Data((extMessage + "\n").utf8))
        if extCode != 0 {
            exit(extCode)
        }
        let (cfgCode, cfgMessage) = wait(60) { done in
            configureFilter(enable: true, done: done)
        }
        FileHandle.standardError.write(Data((cfgMessage + "\n").utf8))
        exit(cfgCode)
    }

    let (cfgCode, cfgMessage) = wait(60) { done in
        configureFilter(enable: false, done: done)
    }
    FileHandle.standardError.write(Data((cfgMessage + "\n").utf8))
    let (extCode, extMessage) = wait(120) { done in
        submitExtension(activate: false, done: done)
    }
    FileHandle.standardError.write(Data((extMessage + "\n").utf8))
    exit(cfgCode != 0 ? cfgCode : extCode)
}

RunLoop.main.run()
