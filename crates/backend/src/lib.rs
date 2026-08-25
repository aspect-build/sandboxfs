// The protocol every sandbox projection backend is driven through: the wire codec, the session
// blob store, shared instrumentation, and the trait the daemon dispatches on.

pub mod blobstore;
pub mod manifest;
pub mod proto;
pub mod tree;
pub mod wire;

pub use blobstore::BlobStore;
pub use manifest::{Manifest, Outputs};
pub use proto::ContentSource;

use std::io;
use std::path::{Path, PathBuf};

/// Why a `create` did not return a sandbox path. `MissingContent` asks for more input -- Bazel
/// pushes the named digests and re-sends the create, so the action still runs. `Failed` fails it.
#[derive(Debug)]
pub enum CreateError {
    /// Every digest the store lacked, not just the first: Bazel pushes the list in one round trip.
    MissingContent(Vec<String>),
    Failed(io::Error),
}

impl From<io::Error> for CreateError {
    fn from(e: io::Error) -> CreateError {
        CreateError::Failed(e)
    }
}

/// The backend args Bazel relays in the `Negotiate` handshake
/// (`--sandbox_backend_arg=<name>=<opt>`), parsed once and handed to `Backend::start`.
#[derive(Debug, Default)]
pub struct Options {
    /// `--pool-root=<path>`: where to put the pool, for when the default is not on the workspace's
    /// volume. Projection and `collect`'s rename are same-device-only.
    pub pool_root: Option<PathBuf>,
    /// `--metrics`: arm kdebug attribution for this workspace.
    pub metrics: bool,
}

impl Options {
    pub fn parse(args: &[String]) -> Options {
        Options {
            pool_root: args.iter().find_map(|a| a.strip_prefix("--pool-root=")).map(PathBuf::from),
            metrics: args.iter().any(|a| a == "--metrics"),
        }
    }
}

/// One way of projecting an action's input tree onto a real filesystem path. The daemon owns the
/// protocol and calls in here for the projection itself.
///
/// A cross-repository interface: the shipping backend is built from its own repository against this
/// crate, so a signature change here is a coordinated change in both.
///
/// `start` runs first, before anything else here. `create`, `collect` and `destroy` then run
/// concurrently on the worker pool, never twice for one `sandbox_id` at once; `push` runs on the
/// reader thread instead.
pub trait Backend: Send + Sync {
    /// Also the namespace a backend keys its on-disk state by, so one workspace built under two
    /// backends keys to two subtrees and neither adopts the other's.
    fn name(&self) -> &'static str;

    /// The root every path this backend materializes lives under. The daemon attributes filesystem
    /// activity by matching against it, so it has to cover the projection and reach no further.
    /// Same device as the workspace, stable for the backend's lifetime.
    fn mount_path(&self) -> &Path;

    /// The first call on this seam: the handshake has landed and nothing is in flight yet, which is
    /// what makes it the place for background reapers and global latches.
    fn start(&self, _options: &Options) {}

    /// Project one action's input tree and return the path Bazel runs it in. Returning a path also
    /// declares the sandbox unconfined: the projected view IS the confinement, and a Seatbelt jail
    /// on top would deny the action its own `$TMPDIR`.
    ///
    /// `manifest` carries no tree, and decodes lazily, so a backend that recognizes a tree it
    /// already has on disk decides from a byte scan. Resolving the tree is the separate, expensive
    /// step -- `tree::resolve(manifest.input_root_digest(), .., store)` -- and the only one that can
    /// report `MissingContent`.
    fn create(&self, sandbox_id: &str, manifest: &Manifest<'_>, store: &BlobStore) -> Result<String, CreateError>;

    /// Move the declared outputs out to `exec_root`, after the action exits and before `destroy`.
    /// An unproduced output is a skip; anything reported here fails the action.
    fn collect(&self, sandbox_id: &str, exec_root: &str) -> io::Result<()>;

    /// Release the sandbox. Infallible by contract, and never guaranteed to arrive at all, so keep
    /// slow or failure-prone teardown off it.
    fn destroy(&self, sandbox_id: &str);

    /// `digests` just landed, ahead of the creates that reference them.
    ///
    /// Take leaf content with `store.take_content` and capture it NOW -- a location is a path we
    /// may only read during this call -- then record it with `store.insert_captured`. Directory
    /// blobs are the pre-staging window, purely advisory. Runs on the reader thread and blocks the
    /// next frame.
    fn push(&self, _store: &BlobStore, _digests: &[String]) {}
}
