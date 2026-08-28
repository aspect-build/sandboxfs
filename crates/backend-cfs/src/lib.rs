use backend::{Backend, Options};
use std::io;
use std::sync::Arc;

pub fn open(_workspace: &str, _options: &Options) -> io::Result<Arc<dyn Backend>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "cfs is not supported on this build.",
    ))
}
