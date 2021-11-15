use color_eyre::Result;
use piawg::server::Config;
use tokio::io::{stdin, stdout, AsyncWriteExt};

use crate::{
    args::{ConfigExportArgs, ConfigGetArgs, ConfigImportArgs},
    CONFIG_FILE_PATH,
};

pub(crate) async fn get(args: ConfigGetArgs) -> Result<()> {
    need_root()?;

    let config = Config::load(CONFIG_FILE_PATH).await?;

    match args.key.as_str() {
        "username" => stdout().write_all(config.username().as_bytes()).await?,
        "password" => stdout().write_all(config.password().as_bytes()).await?,
        "region_id" => stdout().write_all(config.region_id().as_bytes()).await?,
        "privdrop_user" => {
            stdout()
                .write_all(config.privdrop_user().as_bytes())
                .await?;
        }
        "port_forward" => {
            stdout()
                .write_all(format!("{:?}", config.port_forward()).as_bytes())
                .await?;
        }
        invalid => unimplemented!("no config key: {}", invalid,),
    }
    stdout().write_all(b"\n").await?;
    stdout().flush().await?;

    Ok(())
}

pub(crate) async fn export(_args: ConfigExportArgs) -> Result<()> {
    need_root()?;

    Config::load(CONFIG_FILE_PATH)
        .await?
        .write(&mut stdout())
        .await?;

    Ok(())
}

pub(crate) async fn import(_args: ConfigImportArgs) -> Result<()> {
    need_root()?;

    Config::read(&mut stdin())
        .await?
        .store(CONFIG_FILE_PATH)
        .await?;

    Ok(())
}

pub fn need_root() -> Result<()> {
    #[cfg(all(unix, feature = "checkroot"))]
    if !piawg::checkroot::is_root() {
        return Err(color_eyre::eyre::eyre!(
            "you must run this program with root privileges"
        ));
    }
    Ok(())
}
