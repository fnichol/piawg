use color_eyre::Result;

use crate::args::{ConfigExportArgs, ConfigImportArgs};

pub(crate) async fn import(args: ConfigImportArgs) -> Result<()> {
    dbg!(args);
    todo!()
}

pub(crate) async fn export(args: ConfigExportArgs) -> Result<()> {
    dbg!(args);
    todo!()
}
