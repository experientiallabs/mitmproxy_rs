import Darwin
import Foundation
import Network
import NetworkExtension

enum TransparentProxyError: Error {
    case serverAddressMissing
    case noRemoteEndpoint
    case noLocalEndpoint
    case unexpectedFlow
    case controlChannelClosed
}

class TransparentProxyProvider: NETransparentProxyProvider {
    private let stateLock = NSLock()
    private var unixSocket: String?
    private var controlChannel: NWConnection?
    private var spec: InterceptConf?
    private var captureEnabled = false
    private var captureLease: CaptureLease?
    private var leaseTimer: DispatchSourceTimer?
    private var rulesInstalled = false
    private var stopped = false
    private static let captureSafetyMessage = Data("CAPTURE_SAFETY_V1".utf8)

    override func startProxy(options: [String: Any]? = nil) async throws {
        log.debug("Starting proxy...")

        guard let unixSocket = self.protocolConfiguration.serverAddress
        else { throw TransparentProxyError.serverAddressMissing }
        let captureEnabled =
            (self.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerConfiguration?["captureSafety"] as? Bool == true
        log.debug("Establishing control channel via \(unixSocket, privacy: .public)...")
        let control = NWConnection(
            to: .unix(path: unixSocket),
            using: .tcp
        )
        beginRun(unixSocket: unixSocket, control: control, captureEnabled: captureEnabled)
        var startupComplete = false
        defer {
            if !startupComplete {
                stopInterception(error: nil, notifySystem: false)
            }
        }
        try await control.establish()
        control.stateUpdateHandler = { state in
            switch state {
            case .failed(.posix(.ENETDOWN)):
                log.debug("control channel closed, stopping proxy.")
                self.stopInterception(error: nil)
            case .failed(let err):
                log.error("control channel failed: \(err, privacy: .public)")
                self.stopInterception(error: err)
            default:
                break
            }
        }
        Task {
            do {
                while let spec = try await control.receive(ipc: MitmproxyIpc_InterceptConf.self) {
                    log.debug("Received spec: \(String(describing: spec), privacy: .public)")
                    guard self.receiveSpec(try InterceptConf(from: spec)) else {
                        self.stopInterception(error: nil)
                        return
                    }
                }
                // EOF is terminal even when Network.framework reports no connection error.
                self.stopInterception(error: nil)
            } catch {
                log.error("Error on control channel: \(String(describing: error), privacy: .public)")
                self.stopInterception(error: error)
            }
        }
        guard runIsActive() else { throw TransparentProxyError.controlChannelClosed }
        log.debug("Established. Applying tunnel settings...")

        let proxySettings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        proxySettings.includedNetworkRules = [
            NENetworkRule(
                remoteNetwork: nil,
                remotePrefix: 0,
                localNetwork: nil,
                localPrefix: 0,
                protocol: captureEnabled ? .TCP : .any,
                // https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings/3143656-includednetworkrules:
                // The matchDirection property must be NETrafficDirection.outbound.
                direction: .outbound
            )
        ]

        try await setTunnelNetworkSettings(proxySettings)
        let ready = stateLock.withLock {
            guard !stopped, !(captureLease?.shouldStop(at: Self.monotonicNow()) ?? false) else {
                return false
            }
            rulesInstalled = true
            return true
        }
        guard ready else { throw TransparentProxyError.controlChannelClosed }
        startupComplete = true
        log.debug("Applied. Proxy start complete.")
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard messageData == Self.captureSafetyMessage else {
            completionHandler?(nil)
            return
        }
        // Prove the running extension has installed Capture's policy. Archive metadata
        // alone cannot prove that macOS has finished replacing an older extension.
        let ready = stateLock.withLock {
            captureEnabled && rulesInstalled && !stopped
                && captureLease?.shouldStop(at: Self.monotonicNow()) == false
        }
        if !ready { _ = runIsActive() }
        completionHandler?(ready ? Self.captureSafetyMessage : nil)
    }

    override func stopProxy(with reason: NEProviderStopReason) async {
        log.debug("stopProxy \(String(describing: reason), privacy: .public)")
        stopInterception(error: nil, notifySystem: false)
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let configuration = flowConfiguration() else {
            return false
        }
        let transport: CaptureAdmission.Transport
        let remotePort: UInt16?
        if let tcp = flow as? NEAppProxyTCPFlow {
            transport = .tcp
            remotePort = (tcp.remoteEndpoint as? NWHostEndpoint).flatMap { UInt16($0.port) }
        } else {
            transport = flow is NEAppProxyUDPFlow ? .udp : .other
            remotePort = nil
        }
        // Returning false from a transparent provider leaves this unopened flow with macOS.
        guard CaptureAdmission.shouldIntercept(
            captureEnabled: configuration.captureEnabled,
            transport: transport,
            remotePort: remotePort
        ) else {
            return false
        }
        // Called for every new flow that is started.
        // We first want to figure out if we want to intercept this one.
        // Our intercept specs are based on process name and pid, so we first need to convert from
        // audit token to that.
        
        let processInfo = ProcessInfoCache.getInfo(fromAuditToken: flow.metaData.sourceAppAuditToken)
        guard let processInfo = processInfo else {
            log.debug("Skipping flow without process info.")
            return false
        }
        log.debug("Handling new flow: \(String(describing: processInfo), privacy: .public)")

        guard configuration.spec.shouldIntercept(processInfo) else {
            log.debug("Flow not in scope, leaving it to the system.")
            return false
        }
        
        let message: MitmproxyIpc_NewFlow
        do {
            message = try self.makeIpcHandshake(flow: flow, processInfo: processInfo)
        } catch {
            log.error("Failed to create IPC handshake: \(error, privacy: .public), flow=\(flow, privacy: .public)")
            return false
        }
        Task {
            do {
                // A queued task may outlive its admission decision or a sleep/wake cycle.
                guard self.runIsActive() else { throw TransparentProxyError.controlChannelClosed }
                log.debug("Intercepting...")
                try await flow.open(withLocalEndpoint: nil)
                
                let conn = NWConnection(
                    to: .unix(path: configuration.unixSocket),
                    using: .tcp
                )
                do {
                    try await conn.establish()
                } catch {
                    flow.closeReadWithError(error)
                    flow.closeWriteWithError(error)
                    throw error
                }
                
                try await conn.send(ipc: message)
                log.debug("Handshake sent.")
                
                if let tcp_flow = flow as? NEAppProxyTCPFlow {
                    tcp_flow.outboundCopier(conn)
                    tcp_flow.inboundCopier(conn)
                } else if let udp_flow = flow as? NEAppProxyUDPFlow {
                    udp_flow.outboundCopier(conn)
                    udp_flow.inboundCopier(conn)
                }
            } catch {
                log.error("Error handling flow: \(String(describing: error), privacy: .public)")
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
            }
        }
        return true
    }

    /// Start the deadline before waiting for the control connection to become ready.
    private func beginRun(unixSocket: String, control: NWConnection, captureEnabled: Bool) {
        stateLock.withLock {
            self.unixSocket = unixSocket
            self.controlChannel = control
            self.captureEnabled = captureEnabled
            self.spec = nil
            self.rulesInstalled = false
            self.stopped = false
            self.captureLease = captureEnabled ? CaptureLease(startedAt: Self.monotonicNow()) : nil
            if captureEnabled {
                let timer = DispatchSource.makeTimerSource(
                    queue: DispatchQueue(label: "org.mitmproxy.capture-lease")
                )
                timer.schedule(deadline: .now() + 1, repeating: 1)
                timer.setEventHandler { [weak self] in
                    _ = self?.runIsActive()
                }
                self.leaseTimer = timer
                timer.resume()
            }
        }
    }

    /// Only a still-live control channel can replace the selector or renew its deadline.
    private func receiveSpec(_ spec: InterceptConf) -> Bool {
        stateLock.withLock {
            guard !stopped, captureLease?.renew(at: Self.monotonicNow()) ?? true else {
                return false
            }
            self.spec = spec
            return true
        }
    }

    /// The timer and every new flow check the same monotonic deadline under one lock.
    private func runIsActive() -> Bool {
        let active = stateLock.withLock {
            !stopped && !(captureLease?.shouldStop(at: Self.monotonicNow()) ?? false)
        }
        if !active {
            stopInterception(error: nil)
        }
        return active
    }

    private func flowConfiguration() -> (spec: InterceptConf, captureEnabled: Bool, unixSocket: String)? {
        let configuration = stateLock.withLock {
            () -> (spec: InterceptConf, captureEnabled: Bool, unixSocket: String)? in
            guard !stopped,
                  rulesInstalled,
                  !(captureLease?.shouldStop(at: Self.monotonicNow()) ?? false),
                  let spec, let unixSocket else { return nil }
            return (spec, captureEnabled, unixSocket)
        }
        if configuration == nil {
            _ = runIsActive()
        }
        return configuration
    }

    /// Clear admission before closing IPC; a late heartbeat cannot revive this run.
    private func stopInterception(error: Error?, notifySystem: Bool = true) {
        let resources: (NWConnection?, DispatchSourceTimer?)? = stateLock.withLock {
            guard !stopped else { return nil }
            stopped = true
            spec = nil
            rulesInstalled = false
            captureLease?.close()
            let resources = (controlChannel, leaseTimer)
            controlChannel = nil
            leaseTimer = nil
            return resources
        }
        guard let (control, timer) = resources else { return }
        timer?.cancel()
        control?.forceCancel()
        if notifySystem {
            cancelProxyWithError(error)
        }
    }

    private static func monotonicNow() -> Double {
        // Count sleep as elapsed time, so wakeup cannot extend an abandoned lease.
        var timebase = mach_timebase_info_data_t()
        mach_timebase_info(&timebase)
        return Double(mach_continuous_time()) * Double(timebase.numer) / Double(timebase.denom) / 1_000_000_000
    }
    
    func makeIpcHandshake(flow: NEAppProxyFlow, processInfo: ProcessInfo) throws -> MitmproxyIpc_NewFlow {
        let tunnelInfo = MitmproxyIpc_TunnelInfo.with {
            $0.pid = processInfo.pid
            if let path = processInfo.path {
                $0.processName = path
            }
        }
        
        // Do not use remoteHostname property; for DNS UDP flows that's already pointing at the name that we want to look up.
        // log.debug("remoteHostname: \(String(describing: flow.remoteHostname), privacy: .public) flow:\(String(describing: flow), privacy: .public)")
    
        let message: MitmproxyIpc_NewFlow
        if let tcp_flow = flow as? NEAppProxyTCPFlow {
            guard let remoteEndpoint = tcp_flow.remoteEndpoint as? NWHostEndpoint else {
                throw TransparentProxyError.noRemoteEndpoint
            }
            // log.debug("remoteEndpoint: \(String(describing: remoteEndpoint), privacy: .public)")
            // It would be nice if we could also include info on the local endpoint here, but that's not exposed.
            message = MitmproxyIpc_NewFlow.with {
                $0.tcp = MitmproxyIpc_TcpFlow.with {
                    $0.remoteAddress = MitmproxyIpc_Address.init(endpoint: remoteEndpoint)
                    $0.tunnelInfo = tunnelInfo
                }
            }
        } else if let udp_flow = flow as? NEAppProxyUDPFlow {
            guard let localEndpoint = udp_flow.localEndpoint as? NWHostEndpoint else {
                throw TransparentProxyError.noLocalEndpoint
            }
            message = MitmproxyIpc_NewFlow.with {
                $0.udp = MitmproxyIpc_UdpFlow.with {
                    $0.localAddress = MitmproxyIpc_Address.init(endpoint: localEndpoint)
                    $0.tunnelInfo = tunnelInfo
                }
            }
        } else {
            throw TransparentProxyError.unexpectedFlow
        }
        return message
    }
}
