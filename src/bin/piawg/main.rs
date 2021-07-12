// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use piawg::{
    pia::WireGuardAPI,
    wg::{self, WgConfig},
};
use tokio::fs::File;

mod cli;

#[tokio::main]
async fn main() {
    let args = cli::parse();
    // In a real application, use the `log` framework or something similar. In this example case,
    // we'll do this which avoids more dependencies for one call.
    if args.verbose > 0 {
        eprintln!("[debug] parsed cli arguments; args={:?}", args);
    }

    let username = std::env::var("PIA_USER").expect("PIA_USER is required");
    let password = std::env::var("PIA_PASS").expect("PIA_USER is required");

    let token = WireGuardAPI::get_token(username, password)
        .await
        .expect("failed to get_token");
    let (secret_key, public_key) = wg::generate_keypair();
    let api = WireGuardAPI::create(
        "vancouver406",
        "162.216.47.234".parse().expect("failed to parse IpAddr"),
    )
    .expect("failed to create api");
    let akr = api
        .add_key(&token, &public_key)
        .await
        .expect("failed to add key");
    let wg_cfg = WgConfig::from(akr, secret_key);

    let mut file = File::create("pia.conf")
        .await
        .expect("failed to create pia.conf");
    wg_cfg
        .write(&mut file)
        .await
        .expect("failed to write out pia.conf");

    dbg!(&wg_cfg);
    println!("written out: pia.conf");
}
