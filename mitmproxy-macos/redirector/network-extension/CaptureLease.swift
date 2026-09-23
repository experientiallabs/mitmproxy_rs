/// A monotonic deadline that cannot be renewed after expiry or control-channel closure.
struct CaptureLease {
    static let lifetime = 15.0

    private var deadline: Double
    private var closed = false

    init(startedAt now: Double) {
        deadline = now + Self.lifetime
    }

    /// A selector received before expiry proves the controlling event loop is responsive.
    mutating func renew(at now: Double) -> Bool {
        guard !shouldStop(at: now) else {
            return false
        }
        deadline = now + Self.lifetime
        return true
    }

    /// Exact deadline expiry is terminal, including when checked by a new flow.
    mutating func shouldStop(at now: Double) -> Bool {
        if now >= deadline {
            closed = true
        }
        return closed
    }

    /// EOF and explicit shutdown release the lease regardless of its remaining time.
    mutating func close() {
        closed = true
    }
}
