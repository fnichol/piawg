// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::wg::{WGError, WgConfig, WgQuick};
use futures::{SinkExt, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use std::{process::Stdio, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncWriteExt, Stdin, Stdout},
    process::{Child, ChildStdin, ChildStdout, Command},
    time,
};
use tokio_serde::{
    formats::{Json, SymmetricalJson},
    Framed, SymmetricallyFramed,
};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

const RX_TIMEOUT_SECS: Duration = Duration::from_secs(5);
const TX_TIMEOUT_SECS: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("ipc wireguard error")]
    WG(#[from] WGError),
}

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Start,
    WriteWgConfig(WgConfig),
    WgInterfaceUp,
    WgInterfaceDown,
    Terminate,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResponseError {
    message: String,
}

impl From<IpcError> for ResponseError {
    fn from(val: IpcError) -> Self {
        Self {
            message: val.to_string(),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
enum Response {
    Ready,
    WriteWgConfig(Result<(), ResponseError>),
    WgInterfaceUp(Result<(), ResponseError>),
    WgInterfaceDown(Result<(), ResponseError>),
    Terminated,
}

#[derive(Debug)]
pub struct InterfaceManagerClient {
    child: Child,
    rx: Framed<
        FramedRead<ChildStdout, LengthDelimitedCodec>,
        Response,
        Response,
        Json<Response, Response>,
    >,
    tx: Framed<
        FramedWrite<ChildStdin, LengthDelimitedCodec>,
        Request,
        Request,
        Json<Request, Request>,
    >,
}

impl InterfaceManagerClient {
    pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = Command::new(std::env::current_exe()?)
            .arg("__wgctl__")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut rx = {
            let stdout = child.stdout.take().expect("TODO: fix me");
            let codec = FramedRead::new(stdout, LengthDelimitedCodec::new());
            SymmetricallyFramed::new(codec, SymmetricalJson::default())
        };
        let mut tx = {
            let stdin = child.stdin.take().expect("TODO_ fix me");
            let codec = FramedWrite::new(stdin, LengthDelimitedCodec::new());
            SymmetricallyFramed::new(codec, SymmetricalJson::default())
        };

        time::timeout(Duration::from_secs(5), tx.send(Request::Start)).await??;
        eprintln!("InterfaceManagerClient: sent Request::Start");

        match time::timeout(Duration::from_secs(5), rx.try_next()).await?? {
            Some(msg) => match msg {
                Response::Ready => eprintln!("InterfaceManagerClient: get Response::Ready"),
                invalid => panic!("TODO: invalid message: {:?}", invalid),
            },
            None => panic!("TODO: stream closed before first message"),
        };

        Ok(Self { child, rx, tx })
    }

    pub async fn write_wg_config(
        &mut self,
        config: WgConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.send(Request::WriteWgConfig(config)).await? {
            Response::WriteWgConfig(result) => {
                result.map_err(|err| panic!("TODO: failed to write config: {:?}", err))
            }
            invalid => panic!("TODO: invalid message: {:?}", invalid),
        }
    }

    pub async fn wg_interface_up(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self.send(Request::WgInterfaceUp).await? {
            Response::WgInterfaceUp(result) => {
                result.map_err(|err| panic!("TODO: failed to bring interface up: {:?}", err))
            }
            invalid => panic!("TODO: invalid message: {:?}", invalid),
        }
    }

    pub async fn wg_interface_down(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self.send(Request::WgInterfaceDown).await? {
            Response::WgInterfaceDown(result) => {
                result.map_err(|err| panic!("TODO: failed to bring interface down: {:?}", err))
            }
            invalid => panic!("TODO: invalid message: {:?}", invalid),
        }
    }

    pub async fn terminate(mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self.send(Request::Terminate).await? {
            Response::Terminated => (),
            invalid => panic!("TODO: invalid message: {:?}", invalid),
        };
        self.tx.into_inner().into_inner().shutdown().await?;
        self.child.wait().await?;
        Ok(())
    }

    async fn send(&mut self, request: Request) -> Result<Response, Box<dyn std::error::Error>> {
        time::timeout(TX_TIMEOUT_SECS, self.tx.send(request)).await??;
        time::timeout(RX_TIMEOUT_SECS, self.rx.try_next())
            .await??
            .ok_or_else(|| panic!("TODO: stream closed before reading response message"))
    }
}

pub struct InterfaceManager {
    rx: Framed<FramedRead<Stdin, LengthDelimitedCodec>, Request, Request, Json<Request, Request>>,
    tx: Framed<
        FramedWrite<Stdout, LengthDelimitedCodec>,
        Response,
        Response,
        Json<Response, Response>,
    >,
}

impl InterfaceManager {
    pub fn new(stdin: Stdin, stdout: Stdout) -> Self {
        let rx = {
            let codec = FramedRead::new(stdin, LengthDelimitedCodec::new());
            SymmetricallyFramed::new(codec, SymmetricalJson::default())
        };
        let tx = {
            let codec = FramedWrite::new(stdout, LengthDelimitedCodec::new());
            SymmetricallyFramed::new(codec, SymmetricalJson::default())
        };
        Self { rx, tx }
    }

    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        match time::timeout(RX_TIMEOUT_SECS, self.rx.try_next()).await?? {
            Some(msg) => match msg {
                Request::Start => eprintln!("InterfaceManager: got Request::Start"),
                invalid => panic!("TODO: invalid message: {:?}", invalid),
            },
            None => panic!("TODO: stream closed before reading start message"),
        };
        self.send(Response::Ready).await?;
        eprintln!("InterfaceManager: sent Response::Ready");

        while let Some(item) = time::timeout(RX_TIMEOUT_SECS, self.rx.next()).await? {
            let request = match item {
                Ok(request) => request,
                Err(err) => {
                    eprintln!("TODO: error rx next item: {:?}", err);
                    continue;
                }
            };

            match request {
                Request::Start => {
                    eprintln!("TODO: already started, invalid message");
                    continue;
                }
                Request::WgInterfaceUp => {
                    let result = match Self::wg_interface_up().await {
                        Ok(()) => Ok(()),
                        Err(err) => {
                            eprintln!("TODO: error bringing up wg interface: {:?}", err);
                            Err(err.into())
                        }
                    };
                    self.send(Response::WgInterfaceUp(result)).await?
                }
                Request::WgInterfaceDown => {
                    let result = match Self::wg_interface_down().await {
                        Ok(()) => Ok(()),
                        Err(err) => {
                            eprintln!("TODO: error bringing down wg interface: {:?}", err);
                            Err(err.into())
                        }
                    };
                    self.send(Response::WgInterfaceDown(result)).await?
                }
                Request::WriteWgConfig(config) => {
                    let result = match Self::write_wg_config(&config).await {
                        Ok(()) => Ok(()),
                        Err(err) => {
                            eprintln!("TODO: error writing wg config: {:?}", err);
                            Err(err.into())
                        }
                    };
                    self.send(Response::WriteWgConfig(result)).await?
                }
                Request::Terminate => {
                    eprintln!("InterfaceManager: shutting down");
                    self.send(Response::Terminated).await?;
                    break;
                }
            }
        }

        self.tx.into_inner().into_inner().shutdown().await?;
        eprintln!("InterfaceManager: shutdown");
        Ok(())
    }

    async fn send(&mut self, response: Response) -> Result<(), Box<dyn std::error::Error>> {
        time::timeout(TX_TIMEOUT_SECS, self.tx.send(response)).await??;
        Ok(())
    }

    async fn wg_interface_up() -> Result<(), IpcError> {
        WgQuick::for_existing_interface(crate::INTERFACE)?
            .up()
            .await
            .map_err(From::from)
    }

    async fn wg_interface_down() -> Result<(), IpcError> {
        WgQuick::for_existing_interface(crate::INTERFACE)?
            .down()
            .await
            .map_err(From::from)
    }

    async fn write_wg_config(config: &WgConfig) -> Result<(), IpcError> {
        WgQuick::for_interface(crate::INTERFACE, config)
            .await
            .map_err(From::from)
            .map(|_| ())
    }
}
