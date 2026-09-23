/// Pure native policy checks, runnable with Command Line Tools and no system extension.
@main
enum CaptureSafetyTests {
    static func main() throws {
        testCaptureOnlyAdmitsTCP443AcrossEveryPort()
        testCaptureLeavesUnknownEndpointsWithMacOS()
        testGenericProxyKeepsItsExistingAdmission()
        testStartupLeaseHasAFiniteDeadline()
        testResponsiveControlRenewsTheDeadline()
        testExpiryCannotBeRevived()
        testControlClosureCannotBeRevived()
        try testEmptySelectorDisablesInterception()
        print("8 Capture safety policy tests passed")
    }

    static func testCaptureOnlyAdmitsTCP443AcrossEveryPort() {
        for transport in CaptureAdmission.Transport.allCases {
            for port in UInt16.min...UInt16.max {
                precondition(
                    CaptureAdmission.shouldIntercept(
                        captureEnabled: true,
                        transport: transport,
                        remotePort: port
                    ) == (transport == .tcp && port == 443),
                    "Unexpected Capture admission for \(transport) port \(port)"
                )
            }
        }
    }

    static func testCaptureLeavesUnknownEndpointsWithMacOS() {
        for transport in CaptureAdmission.Transport.allCases {
            precondition(!CaptureAdmission.shouldIntercept(
                captureEnabled: true,
                transport: transport,
                remotePort: nil
            ))
        }
    }

    static func testGenericProxyKeepsItsExistingAdmission() {
        for transport in CaptureAdmission.Transport.allCases {
            for port: UInt16? in [nil, 0, 53, 80, 443, 853, 5353, 8443, .max] {
                precondition(CaptureAdmission.shouldIntercept(
                    captureEnabled: false,
                    transport: transport,
                    remotePort: port
                ))
            }
        }
    }

    static func testStartupLeaseHasAFiniteDeadline() {
        var lease = CaptureLease(startedAt: 100)
        precondition(!lease.shouldStop(at: 100))
        precondition(!lease.shouldStop(at: 114.999))
        precondition(lease.shouldStop(at: 115))
    }

    static func testResponsiveControlRenewsTheDeadline() {
        var lease = CaptureLease(startedAt: 100)
        precondition(lease.renew(at: 102))
        precondition(lease.renew(at: 104))
        precondition(!lease.shouldStop(at: 118.999))
        precondition(lease.shouldStop(at: 119))
    }

    static func testExpiryCannotBeRevived() {
        var lease = CaptureLease(startedAt: 100)
        precondition(!lease.renew(at: 115))
        precondition(!lease.renew(at: 116))
        precondition(lease.shouldStop(at: 116))
        precondition(!lease.renew(at: 101))
    }

    static func testControlClosureCannotBeRevived() {
        var lease = CaptureLease(startedAt: 100)
        lease.close()
        precondition(lease.shouldStop(at: 101))
        precondition(!lease.renew(at: 102))
        precondition(lease.shouldStop(at: 102))
    }

    static func testEmptySelectorDisablesInterception() throws {
        let selector = try InterceptConf(from: MitmproxyIpc_InterceptConf())
        for process in [
            ProcessInfo(pid: 0, path: nil),
            ProcessInfo(pid: 123, path: "/Applications/Codex.app"),
            ProcessInfo(pid: 456, path: "/usr/sbin/mDNSResponder"),
        ] {
            precondition(!selector.shouldIntercept(process))
        }
    }
}
