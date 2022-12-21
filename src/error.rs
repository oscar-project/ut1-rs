use std::path::PathBuf;
use thiserror::Error;
use url::ParseError;

#[derive(Error, Debug)]
pub enum Ut1Error {
    #[error("{0} is not a directory.")]
    NotADirectory(PathBuf),
    #[error("No blocklist named {0} found")]
    BlocklistNotFound(PathBuf),
    #[error("Malformed URL {0}")]
    MalformedUrl(#[from] ParseError),
    #[error("No host/domain found")]
    NoHostname(String),
}
