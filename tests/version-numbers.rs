// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[test]
fn test_readme_deps() {
    // If the current version is a `*-dev` string, then ignore the check in README. We'd like to
    // keep the *last* released version string in the README as instructions in the main source
    // code branch.
    if !env!("CARGO_PKG_VERSION").ends_with("-dev") {
        version_sync::assert_markdown_deps_updated!("README.md");
    }
}

#[test]
fn test_html_root_url() {
    version_sync::assert_html_root_url_updated!("src/lib.rs");
}
