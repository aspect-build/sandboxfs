// The controller's session-scoped, content-addressed store for REAPI `Directory` blobs and
// captured leaf content. Bazel ships the input tree's directory bytes out of band via `Push`
// (fire-and-forget) and references them from a `Manifest` only by `input_root_digest`; a `Create`
// then reconstructs the tree by walking those digests against this store. Blobs are immutable — a
// hash maps to exactly one byte string forever — so a `Push` of an already-present digest is a
// no-op and re-pushing is never needed for the life of the controller. A digest a `Create` needs
// but the store lacks (never pushed, evicted, or a stale client belief) comes back as
// `Create.Result.MissingContent`; Bazel pushes those and retries, the safety net for a lost `Push`.

use rustc_hash::FxHashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard};

/// Content-addressed captured leaf content: digest -> the controller's OWN host path holding that
/// content (a `.content/<digest>` COW clone the backend minted while processing a `Push`, per the
/// capture-on-receipt contract). Unlike Bazel's momentary `Push.content` location, this path is the
/// controller's own snapshot: valid for the controller's lifetime regardless of what happens to the
/// path it was captured from, so it is session-scoped, never per-build.
pub type LocationMap = FxHashMap<String, String>;

#[derive(Default)]
pub struct BlobStore {
    blobs: RwLock<FxHashMap<String, Arc<[u8]>>>,
    // Captured leaf content from `Push.content` (field 2): digest -> the controller's captured
    // host path. Resolution precedence for a tree node with digest D: Manifest.host_mapping[D]
    // (our persisted form) > captured[D] > derived exec_root/<tree path>. Content-addressed and
    // pinned for the controller's lifetime (the backend never evicts a captured entry mid-session;
    // Bazel only re-pushes on controller respawn). A digest never captured falls through to the
    // default derivation.
    captured: RwLock<LocationMap>,
    // The session's canonical exec root, stashed from the first decoded manifest (field 2 is
    // session-stable). Lets push-time capture resolve exec_root-relative `location` values before
    // any manifest of its own is in hand.
    exec_root: RwLock<Option<String>>,
}

impl BlobStore {
    pub fn new() -> BlobStore {
        BlobStore::default()
    }

    /// Apply one `Push`: insert each `(digest hash, Directory bytes)`. Content-addressed and
    /// immutable, so a digest already present keeps its bytes (no realloc, no overwrite).
    pub fn insert_many(&self, blobs: impl IntoIterator<Item = (String, Vec<u8>)>) {
        let mut g = self.blobs.write().unwrap();
        for (hash, bytes) in blobs {
            g.entry(hash).or_insert_with(|| Arc::from(bytes.into_boxed_slice()));
        }
    }

    /// The Directory bytes for a digest, or None if the store lacks it (→ a MissingContent reply).
    pub fn get(&self, hash: &str) -> Option<Arc<[u8]>> {
        self.blobs.read().unwrap().get(hash).cloned()
    }

    /// Record one captured leaf: digest -> the controller's own captured host path (see
    /// `LocationMap`). Content-addressed, so last write wins for a given digest. Pinned: entries
    /// are never dropped for the controller's lifetime.
    pub fn insert_captured(&self, digest: String, host: String) {
        self.captured.write().unwrap().insert(digest, host);
    }

    /// Read view of the captured-content table for the duration of one manifest decode. Held
    /// briefly; Push frames (the only writers) are rare and serialized on the read loop.
    pub fn captured(&self) -> RwLockReadGuard<'_, LocationMap> {
        self.captured.read().unwrap()
    }

    /// Record the session's exec root (idempotent — field 2 is session-stable).
    pub fn set_exec_root(&self, er: &str) {
        let mut g = self.exec_root.write().unwrap();
        if g.is_none() {
            *g = Some(er.to_string());
        }
    }

    /// The session exec root, once any manifest has been decoded.
    pub fn exec_root(&self) -> Option<String> {
        self.exec_root.read().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.blobs.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_content_and_blobs_are_pinned_for_the_session() {
        let store = BlobStore::new();
        store.insert_many([("dg1".to_string(), b"dir".to_vec())]);
        store.insert_captured("aaaa".to_string(), "/pool/.content/aaaa".to_string());

        // Content-addressed: re-capturing a digest just refreshes the host (last write wins).
        store.insert_captured("aaaa".to_string(), "/pool/.content/aaaa2".to_string());
        assert_eq!(store.captured().get("aaaa").map(String::as_str), Some("/pool/.content/aaaa2"));

        // Both tiers survive for the controller's lifetime — nothing retires them.
        assert!(store.get("dg1").is_some());
        assert_eq!(store.captured().len(), 1);
    }
}
