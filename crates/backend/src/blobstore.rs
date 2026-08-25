// The session's content-addressed store: `Directory` blobs and captured leaf content, both shipped
// out of band by `Push`. Everything here is immutable, so a re-push is a no-op, and a digest a
// create needs but the store lacks comes back as `CreateError::MissingContent`.
//
// Sharded, and no read handle outlives the call that took it: an earlier shape held one read guard
// for a whole tree decode, which stalled every `Push` behind it.

use crate::proto::ContentSource;
use rustc_hash::FxHashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

const SHARDS: usize = 64;

/// Digests are lowercase hex; `'1'` and `'a'` collide on the low nibble, merging a few buckets.
/// Harmless — this splits locks, it does not index a table.
fn shard(digest: &str) -> usize {
    let b = digest.as_bytes();
    let nibble = |i: usize| b.get(i).map_or(0, |c| (*c & 0xf) as usize);
    (nibble(0) << 3 | nibble(1)) & (SHARDS - 1)
}

type Shards<V> = [RwLock<FxHashMap<String, V>>; SHARDS];

fn shards<V>() -> Shards<V> {
    std::array::from_fn(|_| RwLock::new(FxHashMap::default()))
}

pub struct BlobStore {
    /// Directory structure blobs: digest -> the `Directory` bytes the tree walk parses.
    dirs: Shards<Arc<[u8]>>,
    /// Digest -> the controller's OWN copy of that leaf, minted during a `Push` and valid for the
    /// session whatever happens to the path it came from. Resolution order for a node with digest
    /// D: `Manifest.host_mapping[D]` > `captured[D]` > derived `exec_root/<tree path>`.
    captured: Shards<String>,
    /// Leaf content staged for the `Backend::push` in progress and drained by it; whatever is left
    /// is dropped, never trusted later. One thread stages and drains it, hence a plain Mutex.
    pending: Mutex<FxHashMap<String, ContentSource>>,
    /// Latched from the first decoded manifest (field 2 is session-stable), so push-time capture
    /// can resolve relative `location` values before it has a manifest of its own.
    exec_root: OnceLock<String>,
}

impl Default for BlobStore {
    fn default() -> BlobStore {
        BlobStore {
            dirs: shards(),
            captured: shards(),
            pending: Mutex::new(FxHashMap::default()),
            exec_root: OnceLock::new(),
        }
    }
}

impl BlobStore {
    pub fn new() -> BlobStore {
        BlobStore::default()
    }

    /// Immutable and content-addressed, so a digest already present keeps its bytes.
    pub fn insert_dirs(&self, blobs: impl IntoIterator<Item = (String, Vec<u8>)>) {
        for (hash, bytes) in blobs {
            self.dirs[shard(&hash)].write().unwrap().entry(hash).or_insert_with(|| Arc::from(bytes.into_boxed_slice()));
        }
    }

    /// The `Directory` bytes for a digest, or None if the store lacks it (→ `MissingContent`).
    pub fn dir(&self, hash: &str) -> Option<Arc<[u8]>> {
        self.dirs[shard(hash)].read().unwrap().get(hash).cloned()
    }

    /// Stage leaf content for the `Backend::push` that follows.
    pub fn stage_content(&self, content: impl IntoIterator<Item = (String, ContentSource)>) {
        self.pending.lock().unwrap().extend(content);
    }

    /// Take one staged leaf, to capture it now. Drains: the second call returns None.
    pub fn take_content(&self, digest: &str) -> Option<ContentSource> {
        self.pending.lock().unwrap().remove(digest)
    }

    /// End the staging window. An undrained digest is simply absent, which a dependent `Create`
    /// reports as `MissingContent` and Bazel answers by pushing it again.
    pub fn clear_pending(&self) -> usize {
        let mut g = self.pending.lock().unwrap();
        let n = g.len();
        g.clear();
        n
    }

    /// Record a captured leaf. Pinned for the session; last write wins for a digest.
    pub fn insert_captured(&self, digest: String, host: String) {
        self.captured[shard(&digest)].write().unwrap().insert(digest, host);
    }

    /// The captured copy of a digest, if this session captured it.
    pub fn captured(&self, digest: &str) -> Option<String> {
        self.captured[shard(digest)].read().unwrap().get(digest).cloned()
    }

    /// Latch the session exec root (idempotent — field 2 is session-stable).
    pub fn set_exec_root(&self, er: &str) {
        let _ = self.exec_root.set(er.to_string());
    }

    pub fn exec_root(&self) -> Option<&str> {
        self.exec_root.get().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.dirs.iter().map(|s| s.read().unwrap().len()).sum()
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
        store.insert_dirs([("dg1".to_string(), b"dir".to_vec())]);
        store.insert_captured("aaaa".to_string(), "/pool/.content/aaaa".to_string());

        // Content-addressed: re-capturing a digest just refreshes the host (last write wins).
        store.insert_captured("aaaa".to_string(), "/pool/.content/aaaa2".to_string());
        assert_eq!(store.captured("aaaa").as_deref(), Some("/pool/.content/aaaa2"));

        // Both tiers survive for the controller's lifetime — nothing retires them.
        assert!(store.dir("dg1").is_some());
    }

    /// Immutability: a second push of a digest keeps the bytes already stored.
    #[test]
    fn re_pushing_a_digest_keeps_the_original_bytes() {
        let store = BlobStore::new();
        store.insert_dirs([("dg".to_string(), b"first".to_vec())]);
        store.insert_dirs([("dg".to_string(), b"second".to_vec())]);
        assert_eq!(&*store.dir("dg").unwrap(), b"first");
    }

    /// Staged content is drainable exactly once, and what a backend leaves behind does not
    /// outlive its push — a `Location` path is only an assertion about push time.
    #[test]
    fn staged_content_is_taken_once_and_the_rest_is_dropped() {
        let store = BlobStore::new();
        store.stage_content([
            ("a".to_string(), ContentSource::Inline(b"x".to_vec())),
            ("b".to_string(), ContentSource::Location("/tmp/gone".to_string())),
        ]);
        assert!(matches!(store.take_content("a"), Some(ContentSource::Inline(_))));
        assert!(store.take_content("a").is_none(), "a staged leaf is drained exactly once");
        assert_eq!(store.clear_pending(), 1, "the undrained location is dropped, not remembered");
        assert!(store.take_content("b").is_none());
    }

    #[test]
    fn exec_root_latches_the_first_value() {
        let store = BlobStore::new();
        assert_eq!(store.exec_root(), None);
        store.set_exec_root("/exec/root");
        store.set_exec_root("/other");
        assert_eq!(store.exec_root(), Some("/exec/root"));
    }

    /// Every digest must land in a shard that exists, including degenerate short keys.
    #[test]
    fn sharding_stays_in_bounds_for_any_key() {
        for k in ["", "a", "0", "e3b0c442", "ZZZ"] {
            assert!(shard(k) < SHARDS, "{k:?}");
        }
    }
}
