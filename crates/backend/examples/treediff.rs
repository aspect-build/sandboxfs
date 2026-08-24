// Diff two persisted manifests of the same action: descend only into dirs whose digests differ
// and print the leaf files that actually changed — the provenance trail for a churning root.
fn main() {
    let mut args = std::env::args().skip(1);
    let a = backend::proto::decode_manifest(&std::fs::read(args.next().expect("a.pb")).unwrap()).expect("decode a");
    let b = backend::proto::decode_manifest(&std::fs::read(args.next().expect("b.pb")).unwrap()).expect("decode b");

    fn diff(a: &backend::proto::Dir, b: &backend::proto::Dir, path: &str, out: &mut u32) {
        if *out > 40 {
            return;
        }
        for fa in &a.files {
            match b.files.iter().find(|f| f.name == fa.name) {
                Some(fb) if fb.digest == fa.digest => {}
                Some(fb) => {
                    *out += 1;
                    println!("FILE {path}/{} {} ({}B) -> {} ({}B)", fa.name, &fa.digest[..12.min(fa.digest.len())], fa.size, &fb.digest[..12.min(fb.digest.len())], fb.size);
                }
                None => {
                    *out += 1;
                    println!("GONE {path}/{}", fa.name);
                }
            }
        }
        for fb in &b.files {
            if !a.files.iter().any(|f| f.name == fb.name) {
                *out += 1;
                println!("NEW  {path}/{}", fb.name);
            }
        }
        for sa in &a.symlinks {
            match b.symlinks.iter().find(|s| s.name == sa.name) {
                Some(sb) if sb.target == sa.target => {}
                Some(sb) => {
                    *out += 1;
                    println!("SYM  {path}/{} {} -> {}", sa.name, sa.target, sb.target);
                }
                None => {
                    *out += 1;
                    println!("GONE {path}/{} (symlink)", sa.name);
                }
            }
        }
        for da in &a.directories {
            match b.directories.iter().find(|d| d.name == da.name) {
                Some(db) if db.digest == da.digest => {}
                Some(db) => diff(da, db, &format!("{path}/{}", da.name), out),
                None => {
                    *out += 1;
                    println!("GONE {path}/{}/", da.name);
                }
            }
        }
        for db in &b.directories {
            if !a.directories.iter().any(|d| d.name == db.name) {
                *out += 1;
                println!("NEW  {path}/{}/", db.name);
            }
        }
    }
    let (ra, rb) = (a.root.expect("root a"), b.root.expect("root b"));
    let mut out = 0u32;
    diff(&ra, &rb, "", &mut out);
    println!("--- {out} differing entries (capped at 40)");
}
