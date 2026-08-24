// The shipping `sandboxfs`: the controller plus the projection backend it defaults to.

use backend::Backend;
use std::io;
use std::path::Path;
use std::sync::Arc;

fn open(root: &Path, workspace: &str) -> io::Result<Arc<dyn Backend>> {
    Ok(Arc::new(cfs::Pool::open(root, "cfs", workspace)?))
}

fn main() {
    sandboxd::register_cfs(open);
    sandboxd::run()
}
