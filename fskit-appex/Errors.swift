import Foundation

struct SandboxFSError: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}
