import Darwin
import Foundation

enum CaptureSupervisorError: Error {
    case invalidArguments
    case ownerDisconnected
    case startupTimedOut
    case startFailed
    case ownershipChanged
    case shutdownTimedOut
    case probeFailed
}

/// The only opt-in command line accepted by the Capture supervisor.
struct CaptureSupervisorArguments {
    let domains: [String]
    let socketPath: String

    init(_ arguments: [String]) throws {
        guard arguments.count == 3, arguments[0] == "--capture-safety" else {
            throw CaptureSupervisorError.invalidArguments
        }
        let domains = arguments[1].split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        let path = arguments[2]
        let prefix = "/tmp/mitmproxy-"
        guard (1...32).contains(domains.count), domains.allSatisfy(Self.validDomain),
              path.hasPrefix(prefix), !path.dropFirst(prefix.count).isEmpty,
              path.dropFirst(prefix.count).allSatisfy({ $0.isASCII && $0.isNumber }),
              path.utf8.count < 104 else {
            throw CaptureSupervisorError.invalidArguments
        }
        self.domains = domains
        self.socketPath = path
    }

    static func validDomain(_ host: String) -> Bool {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard !host.isEmpty, host.utf8.count <= 253, labels.count >= 2,
              !["localhost", "local", "test", "invalid", "internal"].contains(String(labels.last!)),
              !labels.last!.allSatisfy({ $0 >= "0" && $0 <= "9" }) else {
            return false
        }
        return labels.allSatisfy { label in
            guard (1...63).contains(label.utf8.count), label.first != "-", label.last != "-" else {
                return false
            }
            return label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
        }
    }
}

/// Includes time spent asleep, so a wakeup never extends a safety deadline.
func captureMonotonicTime() -> TimeInterval {
    var timebase = mach_timebase_info_data_t()
    mach_timebase_info(&timebase)
    return Double(mach_continuous_time()) * Double(timebase.numer) / Double(timebase.denom) / 1_000_000_000
}

/// Observes the inherited owner pipe without a reader thread that can get stuck.
struct CaptureOwnerPipe {
    let descriptor: Int32

    func isOpen() -> Bool {
        var descriptor = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP | POLLERR), revents: 0)
        let result = poll(&descriptor, 1, 0)
        if result < 0 { return errno == EINTR }
        if result == 0 { return true }
        if descriptor.revents & Int16(POLLHUP | POLLERR | POLLNVAL) != 0 { return false }
        if descriptor.revents & Int16(POLLIN) != 0 {
            var byte: UInt8 = 0
            return read(descriptor.fd, &byte, 1) > 0
        }
        return true
    }
}

enum CaptureSupervisorOwnership {
    static func matches(
        expectedBundle: String, expectedSocket: String, expectedSession: String,
        bundle: String?, socket: String?, session: String?, captureSafety: Bool?
    ) -> Bool {
        bundle == expectedBundle && socket == expectedSocket && session == expectedSession && captureSafety == true
    }
}

/// Small owned subprocesses bound native resolver calls even if the resolver hangs.
enum CaptureDNSProbe {
    static let outputLimit = 16 * 1024

    static func containsAddress(_ data: Data) -> Bool {
        guard let text = String(data: data, encoding: .utf8) else { return false }
        return text.split(separator: "\n").contains { line in
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count == 2 else { return false }
            var ipv4 = in_addr()
            var ipv6 = in6_addr()
            if fields[0] == "ip_address:" {
                return String(fields[1]).withCString { inet_pton(AF_INET, $0, &ipv4) } == 1
            }
            if fields[0] == "ipv6_address:" {
                return String(fields[1]).withCString { inet_pton(AF_INET6, $0, &ipv6) } == 1
            }
            return false
        }
    }

    static func check(_ domains: [String]) async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            for domain in domains {
                group.addTask {
                    await run(executable: "/usr/bin/dscacheutil", arguments: ["-q", "host", "-a", "name", domain])
                }
            }
            var healthy = true
            for await result in group { healthy = healthy && result }
            return healthy
        }
    }

    /// Exposed internally for harmless process fixtures; production always uses dscacheutil.
    static func run(
        executable: String, arguments: [String], timeout: TimeInterval = 3,
        onStarted: ((Int32) -> Void)? = nil
    ) async -> Bool {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let fd = output.fileHandleForReading.fileDescriptor
        guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) != -1 else { return false }
        do { try process.run() } catch { return false }
        onStarted?(process.processIdentifier)
        output.fileHandleForWriting.closeFile()
        defer { output.fileHandleForReading.closeFile() }

        var bytes = Data()
        var scratch = [UInt8](repeating: 0, count: 2048)
        let deadline = captureMonotonicTime() + timeout
        var failed = false
        while true {
            while true {
                let count = read(fd, &scratch, scratch.count)
                if count > 0 {
                    if bytes.count + count > outputLimit { failed = true; break }
                    bytes.append(contentsOf: scratch.prefix(count))
                } else {
                    if count < 0 && errno != EAGAIN && errno != EINTR { failed = true }
                    break
                }
            }
            if !process.isRunning { break }
            if failed || Task.isCancelled || captureMonotonicTime() >= deadline {
                failed = true
                // This Process still owns the live child; never signal an unrelated PID.
                kill(process.processIdentifier, SIGKILL)
                let reapDeadline = captureMonotonicTime() + 1
                while process.isRunning && captureMonotonicTime() < reapDeadline {
                    try? await Task.sleep(nanoseconds: 10_000_000)
                }
                break
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        guard !process.isRunning else { return false }
        // Foundation has observed child termination; reap before dropping the process.
        process.waitUntilExit()
        // The child can write its final bytes between the last EAGAIN and exit.
        while true {
            let count = read(fd, &scratch, scratch.count)
            guard count > 0 else { break }
            guard bytes.count + count <= outputLimit else { return false }
            bytes.append(contentsOf: scratch.prefix(count))
        }
        return !failed && process.terminationStatus == 0 && containsAddress(bytes)
    }
}
