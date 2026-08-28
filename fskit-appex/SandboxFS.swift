import ExtensionFoundation
import Foundation
import FSKit

@main
struct SandboxFS: UnaryFileSystemExtension {
    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        SandboxFSFileSystem()
    }
}
