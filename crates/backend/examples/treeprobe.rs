fn main() {
    let mut args = std::env::args().skip(1);
    let manifest = args.next().expect("usage: treeprobe <manifest.pb> <needle>");
    let needle = args.next().expect("needle");
    let m = backend::proto::decode_manifest(&std::fs::read(&manifest).unwrap()).expect("decode");
    fn walk(d: &backend::proto::Dir, path: &str, needle: &str) {
        for f in &d.files {
            if f.name.contains(needle) {
                println!("FILE {path}/{} digest={} host={}", f.name, f.digest, f.host_path);
            }
        }
        for s in &d.symlinks {
            if s.name.contains(needle) {
                println!("SYMLINK {path}/{} -> {}", s.name, s.target);
            }
        }
        for sub in &d.directories {
            if sub.name.contains(needle) {
                println!(
                    "DIR {path}/{} digest={} host={} files={} dirs={} symlinks={}",
                    sub.name, sub.digest, sub.host_path, sub.files.len(), sub.directories.len(), sub.symlinks.len()
                );
            }
            walk(sub, &format!("{path}/{}", sub.name), needle);
        }
    }
    if let Some(r) = &m.root {
        walk(r, "", &needle);
    }
}
