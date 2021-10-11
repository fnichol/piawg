// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::env::args;

use crate::args::{Args, ConfigArgs, RegionArgs, WireguardArgs};

mod args;
mod cmd;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    match args().nth(1).as_deref() {
        #[cfg(feature = "ipc")]
        Some("__wgctl__") => cmd::wgctl(args::parse_wgctl()).await,
        Some(_) | None => match args::parse() {
            Args::Config { sub } => match sub {
                ConfigArgs::Export(args) => cmd::config::export(args).await,
                ConfigArgs::Import(args) => cmd::config::import(args).await,
            },
            Args::Region { sub } => match sub {
                RegionArgs::Get(args) => cmd::region::get(args).await,
                RegionArgs::List(args) => cmd::region::list(args).await,
            },
            Args::Run(args) => cmd::run(args).await,
            Args::Wireguard { sub } => match sub {
                WireguardArgs::Down(args) => cmd::wireguard::down(args).await,
            },
        },
    }
}
