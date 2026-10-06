//! Stage one host directory as fskit sandboxes, the way `create` does for an action, and report
//! what each step cost. `bench-stage <base> <src> [n]` mounts under `<base>`, creates the same
//! tree `n` times, and prints one JSON object with the mount time and every create's path and
//! nanoseconds. bench.py drives it for the fskit column. Nothing in the timed sections hashes a
//! byte: the tree is digested up front, as Bazel ships it.

use backend::wire::{sha256_hex, Writer};
use backend::{Backend, BlobStore, Manifest};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn digest(hash: &str, size: usize) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, hash);
    w.uint(2, size as u64);
    w.out
}

fn node(name: &str, hash: &str, size: usize, executable: bool) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, name);
    w.msg(2, &digest(hash, size));
    if executable {
        w.uint(4, 1);
    }
    w.out
}

/// Serialize `dir` as a REAPI `Directory`, registering every subdirectory's blob in `store`.
fn directory(dir: &Path, store: &BlobStore) -> Vec<u8> {
    let mut entries: Vec<_> = fs::read_dir(dir).expect("read_dir").flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    let (mut files, mut dirs, mut links) = (Vec::new(), Vec::new(), Vec::new());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let meta = fs::symlink_metadata(e.path()).expect("lstat");
        if meta.is_dir() {
            let blob = directory(&e.path(), store);
            let hash = sha256_hex(&blob);
            dirs.push(node(&name, &hash, blob.len(), false));
            store.insert_dirs([(hash, blob)]);
        } else if meta.file_type().is_symlink() {
            let target = fs::read_link(e.path()).expect("readlink");
            let mut w = Writer::default();
            w.str(1, &name);
            w.str(2, &target.to_string_lossy());
            links.push(w.out);
        } else {
            let bytes = fs::read(e.path()).expect("read");
            files.push(node(&name, &sha256_hex(&bytes), bytes.len(), meta.permissions().mode() & 0o111 != 0));
        }
    }
    let mut w = Writer::default();
    for (field, nodes) in [(1u32, files), (2, dirs), (3, links)] {
        for n in nodes {
            w.msg(field, &n);
        }
    }
    w.out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let base = PathBuf::from(&args[1]);
    let src = fs::canonicalize(&args[2]).expect("src");
    let creates: usize = args.get(3).and_then(|n| n.parse().ok()).unwrap_or(1);

    // The tree's host paths derive as `exec_root/<tree path>`, so the sandbox root holds the source
    // directory by name and the exec root is its parent.
    let store = BlobStore::new();
    let inner = directory(&src, &store);
    let inner_hash = sha256_hex(&inner);
    let mut root = Writer::default();
    root.msg(2, &node(&src.file_name().unwrap().to_string_lossy(), &inner_hash, inner.len(), false));
    let root = root.out;
    let root_hash = sha256_hex(&root);
    store.insert_dirs([(inner_hash, inner), (root_hash.clone(), root.clone())]);

    let mut m = Writer::default();
    m.str(1, "Bench");
    m.str(2, &src.parent().unwrap().to_string_lossy());
    m.msg(4, &digest(&root_hash, root.len()));
    let manifest = m.out;

    let t = Instant::now();
    let fskit = backend_fskit::Fskit::open(&base, "bench").expect("open + mount");
    let mount_ns = t.elapsed().as_nanos();

    let mut out = Vec::new();
    for i in 0..creates {
        let t = Instant::now();
        let path = fskit
            .create(&format!("sbx{i}"), &Manifest::new(&manifest), &store)
            .unwrap_or_else(|e| panic!("create: {e:?}"));
        out.push(format!("{{\"path\":\"{path}\",\"ns\":{}}}", t.elapsed().as_nanos()));
    }
    println!(
        "{{\"root\":\"{}\",\"mount_ns\":{mount_ns},\"creates\":[{}]}}",
        fskit.mount_path().display(),
        out.join(",")
    );
}
