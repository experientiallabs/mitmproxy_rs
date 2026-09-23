import Darwin
import Foundation
import NetworkExtension

/// The signed app retains authority over exactly one Capture manager until cleanup ends.
@MainActor
final class CaptureSupervisor {
    private let arguments: CaptureSupervisorArguments
    private let sessionID = UUID().uuidString
    private let owner = CaptureOwnerPipe(descriptor: STDIN_FILENO)
    private let manager = NETransparentProxyManager()
    private var saved = false
    private var proxyStartRequested = false
    private var stopping = false
    private var startupResult: Result<Void, Error>?

    init(arguments: CaptureSupervisorArguments) { self.arguments = arguments }

    func run() async -> Int32 {
        // Rust also gives this child its own process group. Terminal closure is
        // represented by stdin EOF, which must reach cleanup instead of killing it.
        signal(SIGHUP, SIG_IGN)
        signal(SIGINT, SIG_IGN)
        signal(SIGPIPE, SIG_IGN)
        let startup = Task {
            do {
                try await self.start()
                self.startupResult = .success(())
            } catch {
                self.startupResult = .failure(error)
            }
        }
        do {
            let deadline = captureMonotonicTime() + 160
            while startupResult == nil {
                try requireOwner()
                guard captureMonotonicTime() < deadline else { throw CaptureSupervisorError.startupTimedOut }
                await pause()
            }
            try startupResult!.get()
            while manager.connection.status != .connected {
                try requireOwner()
                guard captureMonotonicTime() < deadline else { throw CaptureSupervisorError.startupTimedOut }
                if manager.connection.status == .invalid { throw CaptureSupervisorError.startFailed }
                await pause()
            }
            try await confirmNativePolicy(until: min(deadline, captureMonotonicTime() + 3))
            try requireOwner()
            emit("CAPTURE_READY")
            while owner.isOpen() {
                if manager.connection.status == .disconnected || manager.connection.status == .invalid { break }
                await pause()
            }
        } catch {
            stopping = true
            startup.cancel()
            do {
                try await stop()
            } catch {
                emit("CAPTURE_STOP_FAILED")
                return 1
            }
            emit("CAPTURE_START_FAILED")
            // Startup can fail after the OS began activating the provider. Give
            // that path the same resolver verification as an ordinary stop.
            if proxyStartRequested {
                if !(await CaptureDNSProbe.check(arguments.domains)) { emit("CAPTURE_DNS_UNAVAILABLE") }
            }
            return 1
        }
        stopping = true
        startup.cancel()
        do {
            try await stop()
        } catch {
            emit("CAPTURE_STOP_FAILED")
            return 1
        }
        emit("CAPTURE_STOPPED")
        guard await CaptureDNSProbe.check(arguments.domains) else {
            emit("CAPTURE_DNS_UNAVAILABLE")
            return 1
        }
        return 0
    }

    private func requireOwner() throws {
        guard !stopping, !Task.isCancelled, owner.isOpen() else { throw CaptureSupervisorError.ownerDisconnected }
    }

    private func start() async throws {
        try requireOwner()
        try await SystemExtensionInstaller.run()
        try requireOwner()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = networkExtensionIdentifier
        configuration.serverAddress = arguments.socketPath
        configuration.providerConfiguration = ["captureSafety": true, "captureSessionID": sessionID]
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "mitmproxy Capture"
        manager.isEnabled = true
        // Always create a dedicated manager. Never borrow a generic proxy's manager.
        // A pending save may complete after cancellation. Remember it before the
        // await so cleanup cannot silently leave an unverified registry entry.
        saved = true
        try await manager.saveToPreferences()
        try requireOwner()
        try await manager.loadFromPreferences()
        try requireOwner()
        guard ownsManager() else { throw CaptureSupervisorError.ownershipChanged }
        proxyStartRequested = true
        try manager.connection.startVPNTunnel()
    }

    private func ownsManager() -> Bool {
        let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol
        return CaptureSupervisorOwnership.matches(
            expectedBundle: networkExtensionIdentifier, expectedSocket: arguments.socketPath, expectedSession: sessionID,
            bundle: configuration?.providerBundleIdentifier, socket: configuration?.serverAddress,
            session: configuration?.providerConfiguration?["captureSessionID"] as? String,
            captureSafety: configuration?.providerConfiguration?["captureSafety"] as? Bool
        )
    }

    private func confirmNativePolicy(until deadline: TimeInterval) async throws {
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw CaptureSupervisorError.startFailed
        }
        try await bounded(until: deadline) {
            let request = Data("CAPTURE_SAFETY_V1".utf8)
            let response: Data? = try await withCheckedThrowingContinuation { continuation in
                do {
                    try session.sendProviderMessage(request) { continuation.resume(returning: $0) }
                } catch {
                    continuation.resume(throwing: error)
                }
            }
            guard response == request else { throw CaptureSupervisorError.startFailed }
        }
    }

    private func stop() async throws {
        guard saved else { return }
        let deadline = captureMonotonicTime() + 8
        try await bounded(until: deadline) { try await self.manager.loadFromPreferences() }
        guard ownsManager() else { throw CaptureSupervisorError.ownershipChanged }
        manager.connection.stopVPNTunnel()
        while manager.connection.status != .disconnected && manager.connection.status != .invalid {
            guard captureMonotonicTime() < deadline else { throw CaptureSupervisorError.shutdownTimedOut }
            await pause()
        }
        // Recheck persisted ownership before removing this session's obsolete entry.
        try await bounded(until: deadline) { try await self.manager.loadFromPreferences() }
        guard ownsManager() else { throw CaptureSupervisorError.ownershipChanged }
        guard manager.connection.status == .disconnected || manager.connection.status == .invalid else {
            throw CaptureSupervisorError.ownershipChanged
        }
        try await bounded(until: deadline) { try await self.manager.removeFromPreferences() }
        saved = false
    }

    /// Unstructured tasks avoid waiting forever for a non-cancellable OS callback.
    private func bounded(until deadline: TimeInterval, operation: @escaping @MainActor () async throws -> Void) async throws {
        let result = CaptureOperationResult()
        let task = Task {
            do { try await operation(); result.value = .success(()) }
            catch { result.value = .failure(error) }
        }
        while result.value == nil {
            guard captureMonotonicTime() < deadline else {
                task.cancel()
                throw CaptureSupervisorError.shutdownTimedOut
            }
            await pause()
        }
        try result.value!.get()
    }

    private func pause() async { try? await Task.sleep(nanoseconds: 50_000_000) }

    private func emit(_ message: String) {
        // Never print request data, resolver output, or configuration to this pipe.
        // The owner may already be dead, leaving no stdout reader.
        let bytes = Array((message + "\n").utf8)
        _ = bytes.withUnsafeBytes { write(STDOUT_FILENO, $0.baseAddress, $0.count) }
    }
}

@MainActor
private final class CaptureOperationResult {
    var value: Result<Void, Error>?
}
