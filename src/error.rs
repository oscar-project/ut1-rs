use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Ut1Error {
    #[error("{0} is not a directory.")]
    NotADirectory(PathBuf),
    #[error("No blocklist named {0} found")]
    BlocklistNotFound(PathBuf),
}
