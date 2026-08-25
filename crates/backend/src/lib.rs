// Shared surface for every sandbox projection backend: the wire codec, the syscall
// primitives + instrumentation, the per-workspace locked pool location, and the
// trait the daemon dispatches through.

pub mod blobstore;
pub mod pool;
pub mod proto;
pub mod stats;

pub use blobstore::BlobStore;
pub use proto::ContentSource;

use std::io;

/// The outcome of a `create`. `Created` carries the sandbox root path Bazel runs the action in.
/// `MissingContent` is the recoverable case — the input tree references digests absent from the
/// session store (directory structure blobs or captured leaf content) — carrying their digest
/// hashes so Bazel can `Push` them and retry; it is kept distinct from an `Err` (permanent:
/// malformed manifest, unresolvable tree, IO fault) so the controller answers with
/// `Create.Result.MissingContent` rather than failing the action.
pub enum CreateOutcome {
    Created(String),
    MissingContent(Vec<String>),
}

/// A sandbox backend
pub trait Backend: Send + Sync {
    /// One-time setup after open, before serving. Default: nothing.
    fn start(&self) {}
    fn create(&self, sandbox_id: &str, manifest_bytes: &[u8], store: &BlobStore) -> io::Result<CreateOutcome>;
    fn collect(&self, sandbox_id: &str, exec_root: &str) -> io::Result<()>;
    fn destroy(&self, sandbox_id: &str);

    /// Path prefix the metrics daemon should attribute to this backend during a build
    /// window, or `None` if the backend isn't observed via kdebug. Default: `None` — a
    /// backend opts in by returning its store subtree.
    fn metrics_prefix(&self) -> Option<String> {
        None
    }

    /// A `Push` landed these directory-blob digests in the session store. Purely advisory: the
    /// clone backend pre-stages farms for known-hot digests during the push window, before their
    /// Creates arrive. Default: nothing.
    fn blobs_pushed(&self, _hashes: &[String]) {}

    /// Capture one leaf's content into the backend's OWN store while processing a `Push`, per the
    /// capture-on-receipt contract (a `location` path is live only at push time). Returns the
    /// controller-lifetime host path the digest now serves from (recorded in `BlobStore::captured`),
    /// or `None` if this backend does not capture — content then falls through to the default
    /// `exec_root/<tree path>` derivation. Default: `None`.
    fn capture_content(&self, _digest: &str, _source: ContentSource) -> Option<String> {
        None
    }

    /// The line-based metrics snapshot pushed to the daemon. The default carries the generic
    /// create volume and per-mnemonic table; a backend overrides to append its own counters.
    fn report_text(&self, label: &str) -> String {
        stats::report_text(label)
    }
}
