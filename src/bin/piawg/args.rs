// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::{AppSettings, Clap};
use piawg::server::Config;

const AFTER_HELP: &str =
    "Note: Use `-h` for a short and concise overview and `--help` for full usage.";

/// An examples section at the end of the help message.
const AFTER_LONG_HELP: &str = concat!(
    include_str!("cli_examples.txt"),
    "\n",
    "Note: Use `-h` for a short and concise overview and `--help` for full usage."
);

/// Parse, validate, and return the CLI arguments as a typed struct.
pub(crate) fn parse() -> Args {
    Args::parse()
}

/// Parse, validate, and return the CLI arguments as a typed struct.
#[cfg(feature = "ipc")]
pub(crate) fn parse_wgctl() -> WgctlArgs {
    Wgctl::parse().into()
}

/// Private Internet Access WireGuard Service
///
/// TODO(fnichol): fill in
///
/// Project home page: <https://github.com/fnichol/piawg>
#[derive(Clap, Debug)]
#[clap(
    global_setting = AppSettings::ColoredHelp,
    global_setting = AppSettings::DisableVersionForSubcommands,
    global_setting = AppSettings::UnifiedHelpMessage,
    max_term_width = 100,
    author = concat!("Author: ", env!("CARGO_PKG_AUTHORS"), "\n\n"),
    version = env!("CARGO_PKG_VERSION"),
    long_version = env!("CARGO_PKG_VERSION"),
    after_help = AFTER_HELP,
    after_long_help = AFTER_LONG_HELP,
)]
pub(crate) enum Args {
    Config {
        #[clap(subcommand)]
        sub: ConfigArgs,
    },
    Region {
        #[clap(subcommand)]
        sub: RegionArgs,
    },
    Run(RunArgs),
    Wireguard {
        #[clap(subcommand)]
        sub: WireguardArgs,
    },
}

/// Configures the piawg service.
///
/// TODO(fnichol): fill in
#[derive(Clap, Debug)]
pub(crate) enum ConfigArgs {
    Export(ConfigExportArgs),
    Get(ConfigGetArgs),
    Import(ConfigImportArgs),
}

/// Exports the service configuration.
///
/// TODO(fnichol): fill in
#[derive(Clap, Debug)]
pub(crate) struct ConfigExportArgs {}

/// Gets a value from the service configuration.
///
/// TODO(fnichol): fill in
#[derive(Clap, Debug)]
pub(crate) struct ConfigGetArgs {
    #[clap(possible_values = Config::KEYS)]
    pub(crate) key: String,
}

/// Imports the service configuration.
///
/// TODO(fnichol): fill in
#[derive(Clap, Debug)]
pub(crate) struct ConfigImportArgs {}

/// Manages the Private Internet Access regions.
///
/// TODO(fnichol): fill in
#[derive(Clap, Debug)]
pub(crate) enum RegionArgs {
    Get(RegionGetArgs),
    List(RegionListArgs),
}

/// Gets information for a Private Internet Access region.
///
/// TODO(fnichol): fill in
#[derive(Clap, Debug)]
pub(crate) struct RegionGetArgs {}

/// Lists the Private Internet Access regions.
///
/// TODO(fnichol): fill in
#[derive(Clap, Debug)]
pub(crate) struct RegionListArgs {}

/// Runs the piawg service
///
/// TODO(fnichol): fill in
#[derive(Clap, Debug)]
pub(crate) struct RunArgs {
    /// Sets the verbosity mode.
    ///
    /// Multiple -v options increase verbosity. The maximum is 3.
    #[clap(short = 'v', long = "verbose", parse(from_occurrences))]
    pub(crate) verbose: usize,
}

/// Manages the PIA WireGuard interface.
///
/// TODO(fnichol): fill in
#[derive(Clap, Debug)]
pub(crate) enum WireguardArgs {
    Down(WireguardDownArgs),
}

/// Brings the PIA WireGuard interface down.
///
/// TODO(fnichol): fill in
#[derive(Clap, Debug)]
pub(crate) struct WireguardDownArgs {}

#[derive(Clap, Debug)]
#[clap(
    global_setting = AppSettings::ColoredHelp,
    global_setting = AppSettings::UnifiedHelpMessage,
    max_term_width = 100,
)]
pub(crate) enum Wgctl {
    #[clap(name = "__wgctl__")]
    Wgctl(WgctlArgs),
}

#[derive(Clap, Debug)]
pub(crate) struct WgctlArgs {}

impl From<Wgctl> for WgctlArgs {
    fn from(val: Wgctl) -> Self {
        match val {
            Wgctl::Wgctl(val) => val,
        }
    }
}
