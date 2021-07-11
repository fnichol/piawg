// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
    match piawg::pia::get_token(username, password).await {
        Ok(token) => {
            println!("pia api token: {}", token);
        }
        Err(err) => {
            eprintln!("error: {:?}", err);
            std::process::exit(1);
        }
    }
}
