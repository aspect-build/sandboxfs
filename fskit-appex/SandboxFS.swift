//
//  SandboxFS.swift
//  sandbox-fs
//
//  Created by Sahin Yort on 2026-05-28.
//

import ExtensionFoundation
import Foundation
import FSKit

@main
struct SandboxFS: UnaryFileSystemExtension {
    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        SandboxFSFileSystem()
    }
}
