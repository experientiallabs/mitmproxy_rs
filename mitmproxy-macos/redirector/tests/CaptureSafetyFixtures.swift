// Minimal dependencies for testing the real InterceptConf without loading an extension
// or fetching SwiftProtobuf. These fixtures are not part of either application target.
struct ProcessInfo {
    var pid: UInt32
    var path: String?
}

struct MitmproxyIpc_InterceptConf {
    var actions: [String] = []
}
