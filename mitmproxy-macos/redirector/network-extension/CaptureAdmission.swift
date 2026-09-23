/// Limits Capture to HTTPS connections before the provider claims a flow.
enum CaptureAdmission {
    enum Transport: CaseIterable {
        case tcp
        case udp
        case other
    }

    /// A false result leaves an unopened transparent-proxy flow with macOS.
    static func shouldIntercept(
        captureEnabled: Bool,
        transport: Transport,
        remotePort: UInt16?
    ) -> Bool {
        guard captureEnabled else {
            return true
        }
        return transport == .tcp && remotePort == 443
    }
}
