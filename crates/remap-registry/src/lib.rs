//! Authoritative, single-writer registry implementation for `remapd`.

mod advisory;
mod project;
mod registry;
mod schema;

pub use registry::Registry;
