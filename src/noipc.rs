// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use thiserror::Error;

use crate::wg::{WGError, WgConfig, WgQuick};

#[derive(Debug, Error)]
pub enum NoIpcError {
    #[error("wireguard error")]
    WG(#[from] WGError),
}

#[cfg(not(feature = "ipc"))]
#[derive(Debug)]
pub struct InterfaceManagerClient {}

#[cfg(not(feature = "ipc"))]
impl InterfaceManagerClient {
    pub async fn start() -> Result<Self, NoIpcError> {
        Ok(Self {})
    }

    pub async fn wg_interface_up(&mut self) -> Result<(), NoIpcError> {
        WgQuick::for_existing_interface(crate::INTERFACE)?
            .up()
            .await
            .map_err(From::from)
    }

    pub async fn wg_interface_down(&mut self) -> Result<(), NoIpcError> {
        WgQuick::for_existing_interface(crate::INTERFACE)?
            .down()
            .await
            .map_err(From::from)
    }

    pub async fn write_wg_config(&mut self, config: WgConfig) -> Result<(), NoIpcError> {
        WgQuick::for_interface(crate::INTERFACE, &config)
            .await
            .map_err(From::from)
            .map(|_| ())
    }

    pub async fn terminate(self) -> Result<(), NoIpcError> {
        Ok(())
    }
}
