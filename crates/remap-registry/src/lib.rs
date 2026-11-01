// SPDX-License-Identifier: GPL-3.0-or-later
//! Authoritative, single-writer registry implementation for `remapd`.

mod advisory;
mod peer_address;
mod project;
mod registry;
mod schema;

pub use registry::Registry;
