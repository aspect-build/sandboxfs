import Foundation
import FSKit
import os


@objc
class SandboxFSFileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations & FSManageableResourceMaintenanceOperations {
    private let logger = Logger(subsystem: "sandboxfs", category: "FS")

    func startCheck(task: FSTask, options: FSTaskOptions) throws -> Progress {
        task.didComplete(error: nil)
        let p = Progress(totalUnitCount: 1); p.completedUnitCount = 1
        return p
    }
    func startFormat(task: FSTask, options: FSTaskOptions) throws -> Progress {
        task.didComplete(error: nil)
        let p = Progress(totalUnitCount: 1); p.completedUnitCount = 1
        return p
    }

    func unloadResource(resource: FSResource, options: FSTaskOptions, replyHandler reply: @escaping ((any Error)?) -> Void) {
        logger.debug("unloadResource: \(resource, privacy: .public)")
        if let pathResource = resource as? FSPathURLResource {
            pathResource.url.stopAccessingSecurityScopedResource()
        }
        reply(nil)
    }

    func probeResource(resource: FSResource, replyHandler: @escaping (FSProbeResult?, (any Error)?) -> Void) {
        logger.debug("probeResource: \(resource, privacy: .public)")
        replyHandler(
            FSProbeResult.usable(
                name: "sandboxfs",
                containerID: FSContainerIdentifier(uuid: UUID(uuidString: "4912d97f-937f-499e-8270-3abf7b69bc49")!)
            ),
            nil
        )
    }

    func loadResource(resource: FSResource, options: FSTaskOptions, replyHandler: @escaping (FSVolume?, (any Error)?) -> Void) {
        logger.debug("loadResource: \(resource, privacy: .public)")
        guard let pathResource = resource as? FSPathURLResource else {
            replyHandler(nil, fs_errorForPOSIXError(POSIXError.EINVAL.rawValue))
            return
        }
        // Best-effort: with FSRequiresSecurityScopedPathURLResources=false the kernel hands
        // a NON-scoped path URL, so this returns false — which is NOT fatal. The appex reads
        // the manifest (and host content) via its absolute-path entitlement, not this scope.
        // Hard-failing here was the "Loading resource: Permission denied" (EACCES) mount fail.
        if !pathResource.url.startAccessingSecurityScopedResource() {
            logger.debug("resource \(pathResource.url.path, privacy: .public) is not security-scoped; proceeding")
        }
        containerStatus = .ready
        guard #available(macOS 27.0, *) else {
            // The controller mounts a DIRECTORY of manifests and expects one subroot per sandbox,
            // built on first lookup. Only the mmap volume serves that; the legacy volume still
            // reads a single manifest file, so refuse rather than mount something that would
            // answer every lookup with ENOENT.
            logger.error("sandboxfs needs macOS 27 or later")
            replyHandler(nil, fs_errorForPOSIXError(POSIXError.ENOTSUP.rawValue))
            return
        }
        replyHandler(VolumeMmap(resource: pathResource), nil)
    }
}
