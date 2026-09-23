import Darwin
import Foundation

/// Harmless process fixtures exercise owner death and resolver bounds, never NetworkExtension.
final class CaptureSupervisorTests {
    func testArgumentsRejectUnboundedOrNonPublicInputs() throws {
        let valid = try CaptureSupervisorArguments(["--capture-safety", "api.openai.com,chatgpt.com", "/tmp/mitmproxy-123"])
        requireEqual(valid.domains, ["api.openai.com", "chatgpt.com"])
        requireNoThrow(try CaptureSupervisorArguments(["--capture-safety", Array(repeating: "chatgpt.com", count: 32).joined(separator: ","), "/tmp/mitmproxy-1"]))
        for domains in ["", "localhost", "127.0.0.1", "api.local", "foo.123", "ChatGPT.com", "chatgpt.com,", "chatgpt.com\n", "a..com", "-a.com", "a-.com", String(repeating: "a", count: 64) + ".com", Array(repeating: "chatgpt.com", count: 33).joined(separator: ",")] {
            requireThrows(try CaptureSupervisorArguments(["--capture-safety", domains, "/tmp/mitmproxy-123"]), domains)
        }
        for socket in ["/tmp/other", "/tmp/mitmproxy-", "/tmp/mitmproxy-../123", "/private/tmp/mitmproxy-123"] {
            requireThrows(try CaptureSupervisorArguments(["--capture-safety", "chatgpt.com", socket]))
        }
    }

    func testCleanupRequiresAllOwnershipFields() {
        func matches(_ bundle: String? = "bundle", _ socket: String? = "/tmp/mitmproxy-123", _ session: String? = "nonce", _ enabled: Bool? = true) -> Bool {
            CaptureSupervisorOwnership.matches(expectedBundle: "bundle", expectedSocket: "/tmp/mitmproxy-123", expectedSession: "nonce", bundle: bundle, socket: socket, session: session, captureSafety: enabled)
        }
        requireTrue(matches())
        requireFalse(matches("unrelated"))
        requireFalse(matches("bundle", "/tmp/mitmproxy-456"))
        requireFalse(matches("bundle", "/tmp/mitmproxy-123", "replacement"))
        requireFalse(matches("bundle", "/tmp/mitmproxy-123", nil))
        requireFalse(matches("bundle", "/tmp/mitmproxy-123", "nonce", false))
    }

    func testResolverRequiresAnActualAddress() {
        for text in ["", "name: chatgpt.com\n", "ip_address: nonsense\n", "ipv6_address: invalid\n"] {
            requireFalse(CaptureDNSProbe.containsAddress(Data(text.utf8)))
        }
        requireTrue(CaptureDNSProbe.containsAddress(Data("name: example.com\nip_address: 192.0.2.1\n".utf8)))
        requireTrue(CaptureDNSProbe.containsAddress(Data("ipv6_address: 2001:db8::1\n".utf8)))
    }

    func testOwnedProbeTimesOutAndReapsChild() {
        var child: Int32 = -1
        let before = captureMonotonicTime()
        let healthy = awaitResult {
            await CaptureDNSProbe.run(executable: "/bin/sleep", arguments: ["10"], timeout: 0.05, onStarted: { child = $0 })
        }
        requireFalse(healthy)
        requireLessThan(captureMonotonicTime() - before, 2)
        requireGreaterThan(child, 0)
        requireEqual(kill(child, 0), -1)
        requireEqual(errno, ESRCH)
    }

    func testOwnedProbeAcceptsAddressAndRejectsEmptyOrOversizedOutput() {
        requireTrue(awaitResult { await CaptureDNSProbe.run(executable: "/usr/bin/printf", arguments: ["ip_address: 192.0.2.1\n"]) })
        requireFalse(awaitResult { await CaptureDNSProbe.run(executable: "/usr/bin/true", arguments: []) })
        requireFalse(awaitResult { await CaptureDNSProbe.run(executable: "/usr/bin/printf", arguments: [String(repeating: "x", count: CaptureDNSProbe.outputLimit + 1)]) })
    }

    func testWatchdogSurvivesGracefulOwnerExit() throws { try ownerFixture(killed: false) }
    func testWatchdogSurvivesOwnerSIGKILL() throws { try ownerFixture(killed: true) }

    private func ownerFixture(killed: Bool) throws {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        process.arguments = ["--owner-fixture", killed ? "wait" : "exit"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        pipe.fileHandleForWriting.closeFile()
        let fd = pipe.fileHandleForReading.fileDescriptor
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        defer {
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            pipe.fileHandleForReading.closeFile()
        }
        var text = ""
        let deadline = captureMonotonicTime() + 5
        var didKill = false
        while captureMonotonicTime() < deadline && !text.contains("WATCHDOG_OWNER_CLOSED") {
            var bytes = [UInt8](repeating: 0, count: 1024)
            let count = read(fd, &bytes, bytes.count)
            if count > 0 { text += String(decoding: bytes.prefix(count), as: UTF8.self) }
            if killed && !didKill && text.contains("OWNER_READY") {
                requireEqual(kill(process.processIdentifier, SIGKILL), 0)
                didKill = true
            }
            usleep(10_000)
        }
        requireTrue(text.contains("OWNER_READY"), text)
        requireTrue(text.contains("WATCHDOG_OWNER_CLOSED"), text)
        requireEqual(didKill, killed)
        requireFalse(process.isRunning)
        if !process.isRunning { process.waitUntilExit() }
    }

    private func awaitResult(_ operation: @escaping () async -> Bool) -> Bool {
        let semaphore = DispatchSemaphore(value: 0)
        var result = false
        Task {
            result = await operation()
            semaphore.signal()
        }
        requireEqual(semaphore.wait(timeout: .now() + 5), .success)
        return result
    }
}

@main
enum CaptureSupervisorTestRunner {
    static func main() throws {
        if CommandLine.arguments.dropFirst().first == "--watchdog-fixture" {
            let owner = CaptureOwnerPipe(descriptor: STDIN_FILENO)
            let deadline = captureMonotonicTime() + 4
            while owner.isOpen() && captureMonotonicTime() < deadline { usleep(1_000) }
            if !owner.isOpen() { writeLine("WATCHDOG_OWNER_CLOSED") }
            return
        }
        if CommandLine.arguments.dropFirst().first == "--owner-fixture" {
            let child = Process()
            let owner = Pipe()
            child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
            child.arguments = ["--watchdog-fixture"]
            child.standardInput = owner
            child.standardOutput = FileHandle.standardOutput
            child.standardError = FileHandle.nullDevice
            try child.run()
            writeLine("OWNER_READY")
            if CommandLine.arguments.last == "exit" { _exit(0) }
            while true { usleep(100_000) }
        }
        let tests = CaptureSupervisorTests()
        try tests.testArgumentsRejectUnboundedOrNonPublicInputs()
        tests.testCleanupRequiresAllOwnershipFields()
        tests.testResolverRequiresAnActualAddress()
        tests.testOwnedProbeTimesOutAndReapsChild()
        tests.testOwnedProbeAcceptsAddressAndRejectsEmptyOrOversizedOutput()
        try tests.testWatchdogSurvivesGracefulOwnerExit()
        try tests.testWatchdogSurvivesOwnerSIGKILL()
        print("7 Capture supervisor policy/process tests passed")
    }

    private static func writeLine(_ text: String) {
        let bytes = Array((text + "\n").utf8)
        _ = bytes.withUnsafeBytes { write(STDOUT_FILENO, $0.baseAddress, $0.count) }
    }
}

private func requireTrue(_ condition: @autoclosure () -> Bool, _ message: String = "", file: StaticString = #file, line: UInt = #line) {
    precondition(condition(), "Expected true. " + message, file: file, line: line)
}
private func requireFalse(_ condition: @autoclosure () -> Bool, _ message: String = "", file: StaticString = #file, line: UInt = #line) {
    precondition(!condition(), "Expected false. " + message, file: file, line: line)
}
private func requireEqual<T: Equatable>(_ left: T, _ right: T, file: StaticString = #file, line: UInt = #line) {
    precondition(left == right, "Values differ: \(left) / \(right)", file: file, line: line)
}
private func requireLessThan<T: Comparable>(_ left: T, _ right: T, file: StaticString = #file, line: UInt = #line) {
    precondition(left < right, "Expected smaller value", file: file, line: line)
}
private func requireGreaterThan<T: Comparable>(_ left: T, _ right: T, file: StaticString = #file, line: UInt = #line) {
    precondition(left > right, "Expected larger value", file: file, line: line)
}
private func requireNoThrow<T>(_ expression: @autoclosure () throws -> T, file: StaticString = #file, line: UInt = #line) {
    do { _ = try expression() } catch { preconditionFailure("Unexpected error: \(error)", file: file, line: line) }
}
private func requireThrows<T>(_ expression: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #file, line: UInt = #line) {
    do { _ = try expression() } catch { return }
    preconditionFailure("Expected error. " + message, file: file, line: line)
}
