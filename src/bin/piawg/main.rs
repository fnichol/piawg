// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(
    clippy::missing_errors_doc,
    clippy::module_inception,
    clippy::module_name_repetitions
)]

use std::{env::args, io};

use crate::args::{Args, ConfigArgs, RegionArgs, WireguardArgs};

mod args;
mod cmd;
mod telemetry;

const CONFIG_FILE_PATH: &str = "/etc/piawg/config.json";
const STATE_FILE_PATH: &str = "/var/run/piawg/state.json";

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let config = telemetry::Config::builder()
        .service_name("piawg")
        .service_namespace("piawg")
        .app_modules(vec!["piawg"])
        .build()?;
    let telemetry = match args().nth(1).as_deref() {
        #[cfg(feature = "ipc")]
        Some("__wgctl__") => telemetry::init_with_writer(config, io::stderr)?,
        Some(_) | None => telemetry::init(config)?,
    };

    match args().nth(1).as_deref() {
        #[cfg(feature = "ipc")]
        Some("__wgctl__") => cmd::wgctl(args::parse_wgctl(), telemetry).await,
        Some(_) | None => match args::parse() {
            Args::Config { sub } => match sub {
                ConfigArgs::Export(args) => cmd::config::export(args).await,
                ConfigArgs::Get(args) => cmd::config::get(args).await,
                ConfigArgs::Import(args) => cmd::config::import(args).await,
            },
            Args::Region { sub } => match sub {
                RegionArgs::Get(args) => cmd::region::get(args).await,
                RegionArgs::List(args) => cmd::region::list(args).await,
            },
            Args::Run(args) => cmd::run(args, telemetry).await,
            Args::Wireguard { sub } => match sub {
                WireguardArgs::Down(args) => cmd::wireguard::down(args).await,
            },
        },
    }
}
