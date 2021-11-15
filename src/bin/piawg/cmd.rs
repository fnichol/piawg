use color_eyre::{eyre::WrapErr, Result};
use piawg::server::{Config, FileStateStore, Server};
use tracing::{debug, trace};

use crate::{args::RunArgs, CONFIG_FILE_PATH, STATE_FILE_PATH};

pub(crate) mod config;
pub(crate) mod region;
pub(crate) mod wireguard;

pub(crate) async fn run(args: RunArgs, mut telemetry: piawg::telemetry::Client) -> Result<()> {
    if args.verbose > 0 {
        telemetry.set_verbosity(args.verbose.into()).await?;
    }
    debug!(arguments = ?args, "parsed cli arguments");

    #[cfg(all(unix, feature = "checkroot"))]
    if !piawg::checkroot::is_root() {
        return Err(color_eyre::eyre::eyre!(
            "you must run this program with root privileges"
        ));
    }

    let config = Config::load(CONFIG_FILE_PATH)
        .await
        .wrap_err("failed to load config")?;
    let state_store = FileStateStore::new(STATE_FILE_PATH, config.privdrop_user())
        .wrap_err("failed to initialize state store")?;

    #[cfg(unix)]
    crate::telemetry::start_tracing_level_signal_handler_task(&telemetry)?;

    Server::init(config, state_store, args.verbose)
        .await
        .wrap_err("failed to initialize server")?
        .run()
        .await
        .wrap_err("server encountered an error while running")
}

#[cfg(feature = "ipc")]
pub(crate) async fn wgctl(
    args: crate::args::WgctlArgs,
    mut telemetry: piawg::telemetry::Client,
) -> Result<()> {
    use tokio::io;

    if args.verbose > 0 {
        telemetry.set_verbosity(args.verbose.into()).await?;
    }
    debug!(arguments = ?args, "parsed cli arguments");

    let manager = piawg::ipc::InterfaceManager::init(io::stdin(), io::stdout())
        .await
        .wrap_err("failed to initialize the WireGuard interface manager")?;

    ignore_sigint()?;
    #[cfg(unix)]
    crate::telemetry::start_tracing_level_signal_handler_task(&telemetry)?;

    manager
        .run()
        .await
        .wrap_err("the WireGuard interface manager failed to run to completion")
}

#[cfg(unix)]
fn ignore_sigint() -> Result<()> {
    use tokio::signal::unix::{self, SignalKind};

    let mut sigint = unix::signal(SignalKind::interrupt())?;
    drop(tokio::spawn(async move {
        while sigint.recv().await.is_some() {
            trace!("__wgctl__ received SIGINT, ignoring");
        }
    }));
    Ok(())
}

#[cfg(windows)]
fn ignore_sigint() -> Result<()> {
    use tokio::signal::windows;

    let mut signint = windows::ctrl_c()?;
    drop(tokio::spawn(async move {
        while signint.recv().await.is_some() {
            trace!("__wgctl__ received Ctrl+C, ignoring");
        }
    }));
    Ok(())
}
