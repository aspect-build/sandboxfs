// FSKit backend (lazyfs): ONE persistent appex mount serves every sandbox as a
// per-id subroot, lazily materialized by the appex on first access from a manifest
// file this backend drops. A create is therefore just "write <id>.pb" — no clone,
// no per-sandbox mount — so it costs sub-millisecond regardless of closure size,
// which is what an eager backend's giant-closure tail cannot reach.
//
// Layout under the pool dir: `manifests/<id>.pb` (the appex reads these), `mnt` (the
// single mount; `mnt/<id>` is a sandbox's exec root), `scratch/<id>` (output
// write-through target — the appex projects each declared output as a symlink into
// here, the action writes through, and collect harvests the tree out to exec_root).

use backend::proto::ManifestDecode;
use backend::{proto, Backend, BlobStore, CreateOutcome};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Create `p` and any missing parents. Existing is not an error.
fn mkdir_p(p: &Path) -> io::Result<()> {
    std::fs::create_dir_all(p).map_err(|e| io::Error::new(e.kind(), format!("mkdir_p {}: {e}", p.display())))
}

/// Delete a path — file, symlink, or whole subtree. Missing is not an error.
fn remove(p: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io::Error::new(e.kind(), format!("symlink_metadata {}: {e}", p.display()))),
    }
    .map_err(|e| io::Error::new(e.kind(), format!("remove {}: {e}", p.display())))
}

pub struct Fskit {
    mnt: PathBuf,
    manifests: PathBuf,
    scratch: PathBuf,
}

impl Fskit {
    pub fn open(base: &Path, ns: &str, workspace: &str) -> io::Result<Fskit> {
        let key = backend::pool::workspace_key(ns, workspace);
        let root = base.join(key);
        let (mnt, manifests, scratch) = (root.join("mnt"), root.join("manifests"), root.join("scratch"));
        for d in [&mnt, &manifests, &scratch] {
            mkdir_p(d)?;
        }
        let fs = Fskit { mnt, manifests, scratch };
        fs.ensure_mounted()?;
        Ok(fs)
    }

    fn ensure_mounted(&self) -> io::Result<()> {
        let mnt = self.mnt.to_string_lossy();
        let mounted = Command::new("/sbin/mount")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.contains(&*mnt) && l.contains("sandboxfs")))
            .unwrap_or(false);
        if mounted {
            return Ok(());
        }
        // One mount for the whole daemon. Resource is the manifests DIR; the appex
        // starts with an empty root and loads <id>.pb on the first lookup of <id>.
        let st = Command::new("/sbin/mount")
            .args(["-F", "-t", "sandboxfs", "-o", "nobrowse"])
            .arg(&self.manifests)
            .arg(&self.mnt)
            .status()?;
        if !st.success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("mount sandboxfs at {mnt} failed ({st})")));
        }
        Ok(())
    }

    fn manifest_path(&self, id: &str) -> PathBuf {
        self.manifests.join(format!("{id}.pb"))
    }
}

/// Join a sandbox-relative manifest path (`/_main/...`) under a host root.
fn join_under(root: &Path, rel: &str) -> PathBuf {
    root.join(rel.trim_start_matches('/'))
}

/// Rewrite the controller's outputs/writable_dirs (path -> kind) so each value is the
/// host SCRATCH target the appex symlinks to, and pre-create that target writable so
/// the action's write-through lands on a real file. Returns the rewritten manifest.
fn stage_outputs(mut m: proto::Manifest, scratch: &Path) -> io::Result<proto::Manifest> {
    let retarget = |map: &BTreeMap<String, String>, dir_kind_only: bool| -> io::Result<BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        for (path, kind) in map {
            let target = join_under(scratch, path);
            if dir_kind_only || kind == "dir" {
                mkdir_p(&target)?;
            } else if let Some(parent) = target.parent() {
                mkdir_p(parent)?;
            }
            out.insert(path.clone(), target.to_string_lossy().into_owned());
        }
        Ok(out)
    };
    m.outputs = retarget(&m.outputs, false)?;
    m.writable_dirs = retarget(&m.writable_dirs, true)?;
    Ok(m)
}

/// Move everything the action produced under `src` to the matching path under
/// `exec_root` (rename, same volume). Walks the scratch tree; only produced paths
/// exist, so undeclared/unproduced outputs are naturally skipped.
fn harvest(src: &Path, exec_root: &Path) -> io::Result<()> {
    fn walk(dir: &Path, base: &Path, exec_root: &Path) -> io::Result<()> {
        for e in std::fs::read_dir(dir)?.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(base).unwrap_or(&p);
            let dst = exec_root.join(rel);
            let ft = e.file_type()?;
            if ft.is_dir() {
                mkdir_p(&dst)?;
                walk(&p, base, exec_root)?;
            } else {
                if let Some(parent) = dst.parent() {
                    mkdir_p(parent)?;
                }
                let _ = remove(&dst);
                std::fs::rename(&p, &dst)?;
            }
        }
        Ok(())
    }
    if src.exists() {
        walk(src, src, exec_root)?;
    }
    Ok(())
}

impl Backend for Fskit {
    fn create(&self, sandbox_id: &str, manifest_bytes: &[u8], store: &BlobStore) -> io::Result<CreateOutcome> {
        let m = match proto::decode_wire(manifest_bytes, store) {
            Some(ManifestDecode::Ready(m)) => m,
            Some(ManifestDecode::Missing(hashes)) => return Ok(CreateOutcome::MissingContent(hashes)),
            None => return Err(io::Error::new(io::ErrorKind::InvalidData, "manifest decode failed")),
        };
        let m = stage_outputs(m, &self.scratch.join(sandbox_id))?;
        // Re-encode self-contained (tree inline) for the appex, which reads these manifest files.
        std::fs::write(self.manifest_path(sandbox_id), proto::encode(&m))?;
        // The appex materializes mnt/<id> lazily on the action's first access.
        Ok(CreateOutcome::Created(self.mnt.join(sandbox_id).to_string_lossy().into_owned()))
    }

    fn collect(&self, sandbox_id: &str, exec_root: &str) -> io::Result<()> {
        harvest(&self.scratch.join(sandbox_id), Path::new(exec_root))
    }

    fn destroy(&self, sandbox_id: &str) {
        // Drop the appex's in-memory subroot so a long build doesn't accumulate every
        // sandbox's tree: a lookup of the magic name evicts root.children[<id>].
        let _ = std::fs::symlink_metadata(self.mnt.join(format!("sandboxfs_evict_{sandbox_id}")));
        let _ = remove(&self.manifest_path(sandbox_id));
        let _ = remove(&self.scratch.join(sandbox_id));
    }
}
