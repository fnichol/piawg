// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::wg::{WGError, WgConfig, WgQuick};
use futures::{SinkExt, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use std::{env, fmt, process::Stdio, time::Duration};
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
    #[error("failed to consume the {0} stream for the child process")]
    ChildIO(&'static str),
    #[error("failed to spawn child process")]
    ChildSpawn(#[source] std::io::Error),
    #[error("failed to wait on child process")]
    ChildWait(#[source] std::io::Error),
    #[error("failed to determine path to current executable")]
    CurrentExePath(#[source] std::io::Error),
    #[error("invalid request message: {0:?}")]
    InvalidMessageRequest(Request),
    #[error("invalid response message: {0:?}")]
    InvalidMessageReponse(Response),
    #[error("read io error")]
    ReadIO(#[source] std::io::Error),
    #[error("read timeout")]
    ReadTimeout(#[source] tokio::time::error::Elapsed),
    #[error("send io error")]
    SendIO(#[source] std::io::Error),
    #[error("send timeout")]
    SendTimeout(#[source] tokio::time::error::Elapsed),
    #[error("error shutting down send stream")]
    SendShutdown,
    #[error("IPC stream closed before first message")]
    StreamClosedOnStart,
    #[error("IPC stream closed before reponse message was read")]
    StreamClosedBeforeResponse,
    #[error("ipc wireguard error")]
    WG(#[from] WGError),
    #[error("failed to write WireGuard configuration file: {0}")]
    WGWriteConfig(ResponseError),
    #[error("failed to bring WireGuard interface down: {0}")]
    WGInterfaceDown(ResponseError),
    #[error("failed to bring WireGuard interface up: {0}")]
    WGInterfaceUp(ResponseError),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Start,
    WriteWgConfig(WgConfig),
    WgInterfaceUp,
    WgInterfaceDown,
    Terminate,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseError {
    message: String,
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<IpcError> for ResponseError {
    fn from(val: IpcError) -> Self {
        Self {
            message: val.to_string(),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
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
    pub async fn start() -> Result<Self, IpcError> {
        let current_exe = env::current_exe().map_err(IpcError::CurrentExePath)?;
        let mut child = Command::new(current_exe)
            .arg("__wgctl__")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(IpcError::ChildSpawn)?;
        let mut rx = {
            let stdout = child.stdout.take().ok_or(IpcError::ChildIO("stdout"))?;
            let codec = FramedRead::new(stdout, LengthDelimitedCodec::new());
            SymmetricallyFramed::new(codec, SymmetricalJson::default())
        };
        let mut tx = {
            let stdin = child.stdin.take().ok_or(IpcError::ChildIO("stdin"))?;
            let codec = FramedWrite::new(stdin, LengthDelimitedCodec::new());
            SymmetricallyFramed::new(codec, SymmetricalJson::default())
        };

        time::timeout(Duration::from_secs(5), tx.send(Request::Start))
            .await
            .map_err(IpcError::SendTimeout)?
            .map_err(IpcError::SendIO)?;
        eprintln!("InterfaceManagerClient: sent Request::Start");

        match time::timeout(Duration::from_secs(5), rx.try_next())
            .await
            .map_err(IpcError::ReadTimeout)?
            .map_err(IpcError::ReadIO)?
        {
            Some(msg) => match msg {
                Response::Ready => eprintln!("InterfaceManagerClient: get Response::Ready"),
                invalid => return Err(IpcError::InvalidMessageReponse(invalid)),
            },
            None => return Err(IpcError::StreamClosedOnStart),
        };

        Ok(Self { child, rx, tx })
    }

    pub async fn write_wg_config(&mut self, config: WgConfig) -> Result<(), IpcError> {
        match self.send(Request::WriteWgConfig(config)).await? {
            Response::WriteWgConfig(result) => result.map_err(IpcError::WGWriteConfig),
            invalid => Err(IpcError::InvalidMessageReponse(invalid)),
        }
    }

    pub async fn wg_interface_up(&mut self) -> Result<(), IpcError> {
        match self.send(Request::WgInterfaceUp).await? {
            Response::WgInterfaceUp(result) => result.map_err(IpcError::WGInterfaceUp),
            invalid => Err(IpcError::InvalidMessageReponse(invalid)),
        }
    }

    pub async fn wg_interface_down(&mut self) -> Result<(), IpcError> {
        match self.send(Request::WgInterfaceDown).await? {
            Response::WgInterfaceDown(result) => result.map_err(IpcError::WGInterfaceDown),
            invalid => Err(IpcError::InvalidMessageReponse(invalid)),
        }
    }

    pub async fn terminate(mut self) -> Result<(), IpcError> {
        match self.send(Request::Terminate).await? {
            Response::Terminated => (),
            invalid => return Err(IpcError::InvalidMessageReponse(invalid)),
        };
        self.tx
            .into_inner()
            .into_inner()
            .shutdown()
            .await
            .map_err(|_| IpcError::SendShutdown)?;
        self.child.wait().await.map_err(IpcError::ChildWait)?;
        Ok(())
    }

    async fn send(&mut self, request: Request) -> Result<Response, IpcError> {
        time::timeout(TX_TIMEOUT_SECS, self.tx.send(request))
            .await
            .map_err(IpcError::SendTimeout)?
            .map_err(IpcError::SendIO)?;
        time::timeout(RX_TIMEOUT_SECS, self.rx.try_next())
            .await
            .map_err(IpcError::ReadTimeout)?
            .map_err(IpcError::ReadIO)?
            .ok_or(IpcError::StreamClosedBeforeResponse)
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

    pub async fn run(mut self) -> Result<(), IpcError> {
        match time::timeout(RX_TIMEOUT_SECS, self.rx.try_next())
            .await
            .map_err(IpcError::ReadTimeout)?
            .map_err(IpcError::ReadIO)?
        {
            Some(msg) => match msg {
                Request::Start => eprintln!("InterfaceManager: got Request::Start"),
                invalid => return Err(IpcError::InvalidMessageRequest(invalid)),
            },
            None => return Err(IpcError::StreamClosedOnStart),
        };
        self.send(Response::Ready).await?;
        eprintln!("InterfaceManager: sent Response::Ready");

        while let Some(item) = time::timeout(RX_TIMEOUT_SECS, self.rx.next())
            .await
            .map_err(IpcError::ReadTimeout)?
        {
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

        self.tx
            .into_inner()
            .into_inner()
            .shutdown()
            .await
            .map_err(|_| IpcError::SendShutdown)?;
        eprintln!("InterfaceManager: shutdown");
        Ok(())
    }

    async fn send(&mut self, response: Response) -> Result<(), IpcError> {
        time::timeout(TX_TIMEOUT_SECS, self.tx.send(response))
            .await
            .map_err(IpcError::SendTimeout)?
            .map_err(IpcError::SendIO)?;
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
