// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::env::args;

mod cli;

#[tokio::main]
async fn main() {
    match args().nth(1).as_deref() {
        #[cfg(feature = "ipc")]
        Some("__wgctl__") => cmd::wgctl(cli::parse_wgctl()).await,
        Some(_) | None => cmd::run(cli::parse()).await,
    }
}

mod cmd {
    use piawg::{
        pia::WireGuardAPI,
        wg::{self, WgConfig},
        InterfaceManagerClient,
    };

    pub(crate) async fn run(args: crate::cli::Args) {
        // In a real application, use the `log` framework or something similar. In this example
        // case, we'll do this which avoids more dependencies for one call.
        if args.verbose > 0 {
            eprintln!("[debug] parsed cli arguments; args={:?}", args);
        }

        let username = std::env::var("PIA_USER").expect("PIA_USER is required");
        let password = std::env::var("PIA_PASS").expect("PIA_USER is required");

        #[cfg(all(unix, feature = "checkroot"))]
        if !piawg::checkroot::is_root() {
            panic!("TODO: you must run this program as root");
        }

        let mut interface_manager = InterfaceManagerClient::start()
            .await
            .expect("failed to start interface manager");

        #[cfg(all(unix, feature = "privs", feature = "ipc"))]
        piawg::privs::privdrop(piawg::privs::PrivDropInfo::new("nobody"))
            .expect("failed to drop privs");

        let region = WireGuardAPI::get_region("ca_vancouver")
            .await
            .expect("failed to get region");
        dbg!(&region);

        let token = WireGuardAPI::get_token(username, password)
            .await
            .expect("failed to get_token");
        dbg!(&token);

        let (secret_key, public_key) = wg::generate_keypair();

        let mut api = WireGuardAPI::for_region(&region).expect("failed to create api");

        let akr = api
            .add_key(&token, &public_key)
            .await
            .expect("failed to add key");
        dbg!(&akr);
        let config = WgConfig::from(akr, secret_key);
        dbg!(&config);

        interface_manager
            .write_wg_config(config)
            .await
            .expect("failed to write config");
        println!("written out: pia.conf");

        interface_manager
            .wg_interface_up()
            .await
            .expect("failed to bring interface up");

        interface_manager
            .terminate()
            .await
            .expect("failed to terminate interface manager");

        let gsr = api
            .get_signature(&token)
            .await
            .expect("failed to get signature");
        dbg!(&gsr);

        let bind_port = api
            .bind_port(gsr.payload_raw(), &gsr.signature)
            .await
            .expect("failed to bind port");
        dbg!(&bind_port);
    }

    #[cfg(feature = "ipc")]
    pub(crate) async fn wgctl(_args: crate::cli::WgctlArgs) {
        use tokio::io;
        piawg::ipc::InterfaceManager::new(io::stdin(), io::stdout())
            .run()
            .await
            .expect("manager failed to continue running");
    }
}
