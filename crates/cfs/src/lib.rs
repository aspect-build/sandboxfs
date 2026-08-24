// Stand-in for the projection backend, which is developed in its own (private) repository.
//
// The controller links this by default so an ordinary build of this workspace resolves entirely
// from paths and never reaches for that repo — a cargo feature could not do that, since the
// resolver reads every dependency's manifest whether or not a feature enables it. Release builds
// swap the dependency over to the git source (see packaging/package.sh); this `open` mirrors the
// real crate's, and refusing here is what a build that did not swap reports at runtime.

use backend::Backend;
use std::io;
use std::path::Path;
use std::sync::Arc;

pub fn open(_base: &Path, _ns: &str, _workspace: &str) -> io::Result<Arc<dyn Backend>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this build carries no cfs backend; build a release (packaging/package.sh) or use --backend lazyfs",
    ))
}
