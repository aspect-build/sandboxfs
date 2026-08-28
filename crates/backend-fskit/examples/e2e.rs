//! End-to-end check of the fskit backend against a real mount: build a small input tree, create a
//! sandbox, read the projection back through the mount, write an output the way an action does,
//! collect it, and tear it down. Needs the appex registered (build + launch the embedding app,
//! then `killall fskit-appex`); run with `cargo run -p backend-fskit --example e2e`.

use backend::wire::{sha256_hex, Writer};
use backend::{Backend, BlobStore, Manifest};
use std::fs;
use std::path::{Path, PathBuf};

fn digest(hash: &str, size: u64) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, hash);
    w.uint(2, size);
    w.out
}

fn file_node(name: &str, content: &[u8], exec: bool) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, name);
    w.msg(2, &digest(&sha256_hex(content), content.len() as u64));
    if exec {
        w.uint(4, 1);
    }
    w.out
}

fn dir_node(name: &str, blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, name);
    w.msg(2, &digest(&sha256_hex(blob), blob.len() as u64));
    w.out
}

fn symlink_node(name: &str, target: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, name);
    w.str(2, target);
    w.out
}

/// REAPI `Directory{ files = 1, directories = 2, symlinks = 3 }`.
fn directory(files: &[Vec<u8>], dirs: &[Vec<u8>], symlinks: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Writer::default();
    for f in files {
        w.msg(1, f);
    }
    for d in dirs {
        w.msg(2, d);
    }
    for s in symlinks {
        w.msg(3, s);
    }
    w.out
}

fn map_entry(key: &str, value: &[u8]) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, key);
    w.msg(2, value);
    w.out
}

fn output(kind: &str) -> Vec<u8> {
    let mut w = Writer::default();
    w.str(1, kind);
    w.out
}

fn write(path: &PathBuf, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    names.sort();
    names
}

fn check(what: &str, ok: bool) {
    println!("{} {what}", if ok { "ok  " } else { "FAIL" });
    if !ok {
        std::process::exit(1);
    }
}

/// Unmount anything this harness left mounted under `tmp`, so a re-run starts clean instead of
/// deleting through a live mount.
fn unmount_under(tmp: &Path) {
    let out = std::process::Command::new("/sbin/mount").output().expect("mount");
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.contains("sandboxfs") {
            if let Some(on) = line.split(" on ").nth(1).and_then(|r| r.split(" (").next()) {
                if on.contains(tmp.to_str().unwrap_or("\0")) {
                    let _ = std::process::Command::new("/sbin/umount").arg("-f").arg(on).status();
                }
            }
        }
    }
}

fn main() {
    let tmp = PathBuf::from(std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into())).join("fskit-e2e");
    unmount_under(&tmp);
    let _ = fs::remove_dir_all(&tmp);
    let exec_root = tmp.join("exec");

    // The host content the tree names. Nothing is copied: the appex reads these paths.
    let hello = "hello from the host\n";
    let deep = "deeper\n";
    write(&exec_root.join("_main/hello.txt"), hello);
    write(&exec_root.join("_main/sub/deep.txt"), deep);

    // The input tree, as Bazel would ship it: root -> _main -> {hello.txt, sub/deep.txt, link}.
    let sub = directory(&[file_node("deep.txt", deep.as_bytes(), false)], &[], &[]);
    let main = directory(
        &[file_node("hello.txt", hello.as_bytes(), false)],
        &[dir_node("sub", &sub)],
        &[symlink_node("link", "hello.txt")],
    );
    let root = directory(&[], &[dir_node("_main", &main)], &[]);

    let store = BlobStore::new();
    store.insert_dirs([
        (sha256_hex(&root), root.clone()),
        (sha256_hex(&main), main.clone()),
        (sha256_hex(&sub), sub.clone()),
    ]);

    let mut m = Writer::default();
    m.str(1, "E2ECheck");
    m.str(2, exec_root.to_str().unwrap());
    m.msg(4, &digest(&sha256_hex(&root), root.len() as u64));
    m.msg(5, &map_entry("/_main/out.txt", &output("file")));
    m.msg(5, &map_entry("/_main/bazel-out/cfg/bin/pkg/deep-out.json", &output("file")));
    m.msg(6, &map_entry("/_main/scratch", &[]));
    m.msg(6, &map_entry("/tmp", &[]));
    let manifest_bytes = m.out;

    let backend = backend_fskit::Fskit::open(&tmp.join("base"), "e2e-workspace").expect("open + mount");
    println!("mount root: {}", backend.mount_path().display());

    let path = backend
        .create("sbx1", &Manifest::new(&manifest_bytes), &store)
        .expect("create");
    println!("sandbox:    {path}\n");
    let sandbox = Path::new(&path);

    check("input file reads through the mount", fs::read_to_string(sandbox.join("_main/hello.txt")).ok().as_deref() == Some(hello));
    check("nested file reads through the mount", fs::read_to_string(sandbox.join("_main/sub/deep.txt")).ok().as_deref() == Some(deep));
    check(
        "tree symlink resolves",
        fs::read_link(sandbox.join("_main/link")).ok().map(|t| t.to_string_lossy().into_owned()).as_deref() == Some("hello.txt"),
    );
    // The declared output is deliberately NOT listed until it exists on host scratch, so a tool
    // that globs its own output directory doesn't take an unwritten output for an input.
    check(
        "directory enumerates its inputs, hiding the unwritten output",
        names(&sandbox.join("_main")) == ["bazel-out", "hello.txt", "link", "scratch", "sub"],
    );
    check("writable dir is a directory the action can enter", sandbox.join("_main/scratch").is_dir());

    // What an action does with a declared output: write it at its sandbox path. The appex projects
    // that path as a symlink to host scratch, so the bytes land on a real file.
    let produced = "built\n";
    check(
        "action writes its output through the projection",
        fs::write(sandbox.join("_main/out.txt"), produced).is_ok(),
    );

    check("the output appears once written", names(&sandbox.join("_main")).contains(&"out.txt".to_string()));
    // What Bazel actually declares: an output nested under bazel-out, whose parent chain does not
    // exist in the input tree at all.
    let deep = sandbox.join("_main/bazel-out/cfg/bin/pkg/deep-out.json");
    check("a deep output path is projected", fs::symlink_metadata(&deep).is_ok());
    // An action commonly looks at its output directory before writing (a glob, a `ls`, a tool
    // scanning for existing outputs). That enumeration must not convince the kernel the output
    // cannot exist — if it does, the action's own create fails EROFS on a read-only mount.
    let _ = names(deep.parent().unwrap());
    check("a deep output is writable after its directory was enumerated", fs::write(&deep, produced).is_ok());
    check("an absolute writable dir is projected", sandbox.join("tmp").exists());
    // The projection is a symlink to host scratch, so the bytes never live in the mount.
    check(
        "the written bytes reach host scratch, not the mount",
        fs::read_link(sandbox.join("_main/out.txt"))
            .and_then(fs::read_to_string)
            .ok()
            .as_deref()
            == Some(produced),
    );

    backend.collect("sbx1", exec_root.to_str().unwrap()).expect("collect");
    check(
        "collect moves the output to the exec root",
        fs::read_to_string(exec_root.join("_main/out.txt")).ok().as_deref() == Some(produced),
    );

    backend.destroy("sbx1");
    check(
        "destroy drops the sandbox from the mount, leaving only its own root items",
        names(backend.mount_path().join("mnt").as_path())
            == [".fseventsd", ".metadata_never_index", "@sandboxfs", "@sandboxfs_perf"],
    );
    println!("\nall checks passed");
}
