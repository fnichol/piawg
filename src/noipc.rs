// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::wg::{WgConfig, WgQuick};

#[cfg(not(feature = "ipc"))]
pub struct InterfaceManagerClient {}

#[cfg(not(feature = "ipc"))]
impl InterfaceManagerClient {
    pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {})
    }

    pub async fn wg_interface_up(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        WgQuick::for_existing_interface(crate::INTERFACE)?
            .up()
            .await
            .map_err(From::from)
    }

    pub async fn wg_interface_down(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        WgQuick::for_existing_interface(crate::INTERFACE)?
            .down()
            .await
            .map_err(From::from)
    }

    pub async fn write_wg_config(
        &mut self,
        config: WgConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        WgQuick::for_interface(crate::INTERFACE, &config)
            .await
            .map_err(From::from)
            .map(|_| ())
    }

    pub async fn terminate(self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
