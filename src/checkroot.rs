// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use nix::unistd;

#[must_use]
pub fn is_root() -> bool {
    unistd::geteuid().is_root()
}
