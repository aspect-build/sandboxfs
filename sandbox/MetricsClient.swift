//
//  MetricsClient.swift
//  sandbox
//
//  Tails the build-metrics daemon over XPC (build.aspect.sandbox.metricsd, served by the root
//  `sandboxfs metricsd` LaunchDaemon). The daemon is the central sink: it retains the
//  per-workspace timeline + build spans and answers `feed(since:<cursor_ms>)` with
//  everything after the cursor — since=0 backfills all history, tailing with the last
//  cursor streams the live edge. JSON keys are camelCase so we decode raw (a snake-case
//  remap would mangle the op map's `posix_spawn`). The sandboxed app reaches the system
//  daemon via the mach-lookup exception in sandbox.entitlements.
//

import Foundation
import XPC

// Wire DTOs — mirror the daemon's feed_json (crates/metrics/src/lib.rs). `nonisolated`
// keeps Codable usable from the nonisolated client (the target defaults to MainActor).
nonisolated struct Feed: Codable {
    let now: UInt64
    let workspaces: [WSMetrics]
    let builds: [SpanDTO]
}

nonisolated struct WSMetrics: Codable {
    let workspace: String              // execroot path; "" == unattributed
    let backend: String                // cfs | lazyfs
    let active: Bool
    let startMs: UInt64
    let endMs: UInt64?
    let totals: Totals                 // cumulative headline numbers
    let samples: [BucketDTO]           // timeline buckets with t > cursor (100ms)
    let creates: [CreateDTO]           // create-rate samples with t > cursor (~1s)
}

nonisolated struct Totals: Codable {
    let creates, files, dirs, laydownUs, bytesRead, bytesWritten, procs: UInt64
    let ops: [String: UInt64]          // raw per-syscall cumulative counts
    let diskioBytes, dropped, unattributedOps: UInt64
    let mnemonics: [MnemDTO]
}

nonisolated struct MnemDTO: Codable { let name: String; let creates, laydownUs, maxUs: UInt64 }

nonisolated struct BucketDTO: Codable {
    let t: UInt64                      // bucket start, epoch ms
    let ops: [String: UInt64]
    let readBytes, writeBytes: UInt64
}

nonisolated struct CreateDTO: Codable {
    let t: UInt64                      // sample time, epoch ms
    let n: UInt64                      // sandbox creates in this interval
    let laydownUs: UInt64              // summed laydown µs (avg = laydownUs / n)
}

/// One build window as a span on the timeline (begin→end), with the window's own deltas.
nonisolated struct SpanDTO: Codable {
    let workspace, backend: String
    let startMs: UInt64
    let endMs: UInt64?                 // nil while the build runs
    let creates, files, bytesRead, bytesWritten, syscalls: UInt64
}

nonisolated enum MetricsError: LocalizedError {
    case unreachable
    case daemon(String)
    var errorDescription: String? {
        switch self {
        case .unreachable: return "metrics daemon not responding (build.aspect.sandbox.metricsd not loaded?)"
        case .daemon(let m): return m
        }
    }
}

// `nonisolated`: these block on XPC for up to 5s and must run off the main actor.
nonisolated enum MetricsClient {
    static let serviceName = "build.aspect.sandbox.metricsd"

    /// Tail the feed from `since` (epoch ms; 0 backfills all retained history). Blocks up
    /// to 5s; call off the main thread.
    static func feed(since: UInt64) throws -> Feed {
        let empty = #"{"now":0,"workspaces":[],"builds":[]}"#
        let json = try call(method: "feed", payload: String(since)) ?? empty
        return try JSONDecoder().decode(Feed.self, from: Data(json.utf8))
    }

    /// Drop the daemon's retained history (live windows keep running).
    static func clear() throws { _ = try call(method: "clear", payload: "") }

    private static func call(method: String, payload: String) throws -> String? {
        let queue = DispatchQueue(label: "\(serviceName).client")
        let conn = xpc_connection_create_mach_service(serviceName, queue, 0)
        xpc_connection_set_event_handler(conn) { _ in } // required before resume
        xpc_connection_resume(conn)
        defer { xpc_connection_cancel(conn) }

        let msg = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(msg, "method", method)
        xpc_dictionary_set_string(msg, "build_id", "")
        xpc_dictionary_set_string(msg, "clone_prefix", "")
        xpc_dictionary_set_string(msg, "payload", payload) // feed cursor (since_ms)

        // Async reply + a bounded wait: a sync reply to a down/stale service can block
        // forever (the same hazard the Rust client guards against).
        let box = ReplyBox()
        let sem = DispatchSemaphore(value: 0)
        xpc_connection_send_message_with_reply(conn, msg, queue) { reply in
            box.reply = reply
            sem.signal()
        }
        guard sem.wait(timeout: .now() + 5) == .success, let reply = box.reply else {
            throw MetricsError.unreachable
        }
        if xpc_get_type(reply) == XPC_TYPE_ERROR { throw MetricsError.unreachable }
        guard xpc_dictionary_get_int64(reply, "ok") == 1 else {
            throw MetricsError.daemon(string(reply, "error") ?? "unknown daemon error")
        }
        let result = string(reply, "result")
        return (result?.isEmpty ?? true) ? nil : result
    }

    private static func string(_ dict: xpc_object_t, _ key: String) -> String? {
        guard let p = xpc_dictionary_get_string(dict, key) else { return nil }
        return String(cString: p)
    }
}

// Carries the reply out of the XPC handler; the semaphore provides the happens-after,
// so the unchecked Sendable is sound.
private nonisolated final class ReplyBox: @unchecked Sendable {
    var reply: xpc_object_t?
}
