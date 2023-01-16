#![doc = include_str!("../README.md")]

pub mod blocklist;
pub mod blocklist_multi;
mod error;

pub use blocklist::Blocklist;
pub use blocklist_multi::Blocklist as MultipleBlocklist;
pub use error::Ut1Error as Error;
