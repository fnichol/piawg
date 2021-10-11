use color_eyre::Result;

use crate::args::{RegionGetArgs, RegionListArgs};

pub(crate) async fn get(args: RegionGetArgs) -> Result<()> {
    dbg!(args);
    todo!()
}

pub(crate) async fn list(args: RegionListArgs) -> Result<()> {
    dbg!(args);
    todo!()
}
