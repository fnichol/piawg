// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This crate executes a highly specialized algorithm to dynamically generate a greeting in
//! english to a given subject. It is serious business.
//!
//! ## Usage
//!
//! This crate is on [crates.io](https://crates.io/crates/piawg) and can be used by adding
//! the crate to your dependencies in your project's `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! piawg = { version = "0.1.0", default-features = false }
//! ```
//!
//! Note that the default features include dependencies which are required to build a CLI and are
//! not needed for the library.
//!
//! ## Examples

#![doc(html_root_url = "https://docs.rs/piawg/0.1.0-dev")]
//#![deny(missing_docs)]

pub mod pia;
pub mod wg;
