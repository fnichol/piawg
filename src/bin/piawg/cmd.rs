use color_eyre::eyre::{eyre, WrapErr};

use piawg::{
    pia::WireGuardAPI,
    wg::{self, WgConfig},
    InterfaceManagerClient,
};

use crate::args::{RunArgs, WgctlArgs};

pub(crate) mod config;
pub(crate) mod region;
pub(crate) mod wireguard;

pub(crate) async fn run(args: RunArgs) -> color_eyre::Result<()> {
    // In a real application, use the `log` framework or something similar. In this
    // example case, we'll do this which avoids more dependencies for one call.
    if args.verbose > 0 {
        eprintln!("[debug] parsed cli arguments; args={:?}", args);
    }

    let username = std::env::var("PIA_USER").wrap_err("TODO: PIA_USER is required")?;
    let password = std::env::var("PIA_PASS").wrap_err("TODO: PIA_USER is required")?;
    let region_id = "ca_vancouver";

    #[cfg(all(unix, feature = "checkroot"))]
    if !piawg::checkroot::is_root() {
        return Err(eyre!("you must run this program with root privileges"));
    }

    let mut interface_manager = InterfaceManagerClient::start()
        .await
        .wrap_err("failed to start the WireGuard interface manager")?;

    #[cfg(all(unix, feature = "privs", feature = "ipc"))]
    piawg::privs::privdrop(&piawg::privs::PrivDropInfo::new("nobody"))
        .wrap_err("failed to drop privs")?;

    let region = WireGuardAPI::get_region(region_id)
        .await
        .wrap_err_with(|| format!("failed to get a PIA region for id: {}", region_id))?;
    let mut api = WireGuardAPI::for_region(&region).wrap_err_with(|| {
        format!(
            "failed to create a PIA API instance for region id: {}",
            region_id
        )
    })?;

    let token = WireGuardAPI::get_token(username, password)
        .await
        .wrap_err("failed to get a PIA token")?;

    let (secret_key, public_key) = wg::generate_keypair();

    let akr = api
        .add_key(&token, &public_key)
        .await
        .wrap_err("failed to add public key to API")?;

    let config = WgConfig::from(akr, secret_key);

    interface_manager
        .write_wg_config(config)
        .await
        .wrap_err("failed to write the WireGuard configuration")?;

    interface_manager
        .wg_interface_up()
        .await
        .wrap_err("failed to bring up the WireGuard interface")?;

    interface_manager
        .terminate()
        .await
        .wrap_err("failed to terminate the WireGuard interface manager")?;

    let gsr = api
        .get_signature(&token)
        .await
        .wrap_err("failed to get a PIA signature to setup port forwarding")?;
    dbg!(&gsr);

    let bind_port = api
        .bind_port(gsr.payload_raw(), &gsr.signature)
        .await
        .wrap_err("failed to bind port for port forwarding")?;
    dbg!(bind_port);

    Ok(())
}

#[cfg(feature = "ipc")]
pub(crate) async fn wgctl(_args: WgctlArgs) -> color_eyre::Result<()> {
    use tokio::io;

    piawg::ipc::InterfaceManager::new(io::stdin(), io::stdout())
        .run()
        .await
        .wrap_err("the WireGuard interface manager failed to run to completion")
}
