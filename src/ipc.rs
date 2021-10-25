// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{env, fmt, process::Stdio, time::Duration};

use futures::{SinkExt, StreamExt, TryStreamExt};
use opentelemetry::trace::SpanKind;
use serde::{Deserialize, Serialize};
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
use tracing::{debug, error, field::Empty, info, instrument, trace, warn, Span};

use crate::{
    tracing::SpanExt,
    wg::{WGError, WgConfig, WgQuick},
    Graceful,
};

const RX_TIMEOUT: Duration = Duration::from_secs(5);
const TX_TIMEOUT: Duration = Duration::from_secs(5);

const TF_M_SYSTEM: &str = "stdio-framed-json";
const TF_M_DESTINATION_KIND: &str = "queue";

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
    #[error("IPC stream closed before request message was read")]
    StreamClosedBeforeRequest,
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
    WgInterfaceDown(Graceful),
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
    #[instrument(
        name = "interface_manager_client init",
        skip_all,
        fields(
            net.transport = "pipe",
            otel.kind = %SpanKind::Client,
            otel.status_code = Empty,
            otel.status_message = Empty,
        )
    )]
    pub async fn init(verbosity: usize) -> Result<Self, IpcError> {
        let span = Span::current();

        let current_exe =
            env::current_exe().map_err(|err| span.record_err(IpcError::CurrentExePath(err)))?;
        let mut cmd = Command::new(current_exe);
        cmd.arg("__wgctl__")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        if verbosity > 0 {
            for _ in 0..verbosity {
                cmd.arg("--verbose");
            }
        }
        debug!(command = ?cmd, "spawning command");
        let mut child = cmd
            .spawn()
            .map_err(|err| span.record_err(IpcError::ChildSpawn(err)))?;
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

        send_to_child(&mut tx, Request::Start, TX_TIMEOUT)
            .await
            .map_err(|err| span.record_err(err))?;
        match receive_from_child(&mut rx, RX_TIMEOUT)
            .await
            .map_err(|err| span.record_err(err))?
        {
            Response::Ready => {}
            invalid => return Err(span.record_err(IpcError::InvalidMessageReponse(invalid))),
        };

        span.record_ok();
        Ok(Self { child, rx, tx })
    }

    #[instrument(
        name = "piawg.ipc.InterfaceManager/write_wg_config",
        skip_all,
        fields(
            net.transport = "pipe",
            otel.kind = %SpanKind::Client,
            otel.status_code = Empty,
            otel.status_message = Empty,
            rpc.system = "stdio-rpc",
            rpc.service = "piawg.ipc.InterfaceManager",
            rpc.method = "write_wg_config",
        )
    )]
    pub async fn write_wg_config(&mut self, config: WgConfig) -> Result<(), IpcError> {
        let span = Span::current();

        match self
            .send(Request::WriteWgConfig(config))
            .await
            .map_err(|err| span.record_err(err))?
        {
            Response::WriteWgConfig(result) => {
                result.map_err(|err| span.record_err(IpcError::WGWriteConfig(err)))?;
            }
            invalid => return Err(span.record_err(IpcError::InvalidMessageReponse(invalid))),
        }

        span.record_ok();
        Ok(())
    }

    #[instrument(
        name = "piawg.ipc.InterfaceManager/wg_interface_up",
        skip_all,
        fields(
            net.transport = "pipe",
            otel.kind = %SpanKind::Client,
            otel.status_code = Empty,
            otel.status_message = Empty,
            rpc.system = "stdio-rpc",
            rpc.service = "piawg.ipc.InterfaceManager",
            rpc.method = "wg_interface_up",
        )
    )]
    pub async fn wg_interface_up(&mut self) -> Result<(), IpcError> {
        let span = Span::current();

        match self
            .send(Request::WgInterfaceUp)
            .await
            .map_err(|err| span.record_err(err))?
        {
            Response::WgInterfaceUp(result) => {
                result.map_err(|err| span.record_err(IpcError::WGInterfaceUp(err)))?;
            }
            invalid => return Err(span.record_err(IpcError::InvalidMessageReponse(invalid))),
        }

        span.record_ok();
        Ok(())
    }

    #[instrument(
        name = "piawg.ipc.InterfaceManager/wg_interface_down",
        skip_all,
        fields(
            net.transport = "pipe",
            otel.kind = %SpanKind::Client,
            otel.status_code = Empty,
            otel.status_message = Empty,
            rpc.system = "stdio-rpc",
            rpc.service = "piawg.ipc.InterfaceManager",
            rpc.method = "wg_interface_down",
        )
    )]
    pub async fn wg_interface_down(
        &mut self,
        graceful: impl Into<Graceful>,
    ) -> Result<(), IpcError> {
        let span = Span::current();

        let graceful = graceful.into();
        trace!(graceful = graceful.as_bool());

        match self
            .send(Request::WgInterfaceDown(graceful))
            .await
            .map_err(|err| span.record_err(err))?
        {
            Response::WgInterfaceDown(result) => {
                result.map_err(|err| span.record_err(IpcError::WGInterfaceDown(err)))?;
            }
            invalid => return Err(span.record_err(IpcError::InvalidMessageReponse(invalid))),
        }

        span.record_ok();
        Ok(())
    }

    #[instrument(
        name = "piawg.ipc.InterfaceManager/terminate",
        skip_all,
        fields(
            net.transport = "pipe",
            otel.kind = %SpanKind::Client,
            otel.status_code = Empty,
            otel.status_message = Empty,
            rpc.system = "stdio-rpc",
            rpc.service = "piawg.ipc.InterfaceManager",
            rpc.method = "terminate",
        )
    )]
    pub async fn terminate(&mut self) -> Result<(), IpcError> {
        let span = Span::current();

        match self
            .send(Request::Terminate)
            .await
            .map_err(|err| span.record_err(err))?
        {
            Response::Terminated => {}
            invalid => return Err(span.record_err(IpcError::InvalidMessageReponse(invalid))),
        }
        self.tx
            .close()
            .await
            .map_err(|_| span.record_err(IpcError::SendShutdown))?;
        self.child
            .wait()
            .await
            .map_err(|err| span.record_err(IpcError::ChildWait(err)))?;

        span.record_ok();
        Ok(())
    }

    async fn send(&mut self, request: Request) -> Result<Response, IpcError> {
        send_to_child(&mut self.tx, request, TX_TIMEOUT).await?;
        receive_from_child(&mut self.rx, RX_TIMEOUT).await
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
    #[instrument(
        name = "interface_manager init",
        skip_all,
        fields(
            net.transport = "pipe",
            otel.kind = %SpanKind::Client,
            otel.status_code = Empty,
            otel.status_message = Empty,
        )
    )]
    pub async fn init(stdin: Stdin, stdout: Stdout) -> Result<Self, IpcError> {
        let span = Span::current();

        let mut rx = {
            let codec = FramedRead::new(stdin, LengthDelimitedCodec::new());
            SymmetricallyFramed::new(codec, SymmetricalJson::default())
        };
        let mut tx = {
            let codec = FramedWrite::new(stdout, LengthDelimitedCodec::new());
            SymmetricallyFramed::new(codec, SymmetricalJson::default())
        };

        match receive_from_parent(&mut rx, RX_TIMEOUT)
            .await
            .map_err(|err| span.record_err(err))?
        {
            Request::Start => {}
            invalid => return Err(span.record_err(IpcError::InvalidMessageRequest(invalid))),
        };
        send_to_parent(&mut tx, Response::Ready, TX_TIMEOUT)
            .await
            .map_err(|err| span.record_err(err))?;

        span.record_ok();
        Ok(Self { rx, tx })
    }

    #[instrument(
        name = "interface_manager run",
        skip_all,
        fields(
            net.transport = "pipe",
            otel.kind = %SpanKind::Server,
            otel.status_code = Empty,
            otel.status_message = Empty,
        )
    )]
    pub async fn run(mut self) -> Result<(), IpcError> {
        let span = Span::current();

        while let Some(item) = self.rx.next().await {
            let request = match item {
                Ok(request) => request,
                Err(err) => {
                    warn!(error = %err, "error while reading message, skipping and continuing");
                    continue;
                }
            };

            match request {
                Request::Start => {
                    error!(request = ?request, "received start after initial start, shutting down");
                    return Err(span.record_err(IpcError::InvalidMessageRequest(request)));
                }
                Request::WgInterfaceUp => {
                    let result = match Self::wg_interface_up().await {
                        Ok(()) => Ok(()),
                        Err(err) => {
                            warn!(error = %err, "error bringing up WireGuard interface");
                            Err(err.into())
                        }
                    };
                    self.send_to_parent(Response::WgInterfaceUp(result), TX_TIMEOUT)
                        .await
                        .map_err(|err| span.record_err(err))?;
                }
                Request::WgInterfaceDown(graceful) => {
                    let result = match Self::wg_interface_down(graceful).await {
                        Ok(()) => Ok(()),
                        Err(err) => {
                            warn!(error = ?err, "error bringing down WireGuard interface");
                            Err(err.into())
                        }
                    };
                    self.send_to_parent(Response::WgInterfaceDown(result), TX_TIMEOUT)
                        .await
                        .map_err(|err| span.record_err(err))?;
                }
                Request::WriteWgConfig(config) => {
                    let result = match Self::write_wg_config(&config).await {
                        Ok(()) => Ok(()),
                        Err(err) => {
                            warn!(error = %err, "error writing WireGuard config");
                            Err(err.into())
                        }
                    };
                    self.send_to_parent(Response::WriteWgConfig(result), TX_TIMEOUT)
                        .await
                        .map_err(|err| span.record_err(err))?;
                }
                Request::Terminate => {
                    info!("interface manager shutting down");
                    self.send_to_parent(Response::Terminated, TX_TIMEOUT)
                        .await
                        .map_err(|err| span.record_err(err))?;
                    break;
                }
            }
        }

        self.tx
            .into_inner()
            .into_inner()
            .shutdown()
            .await
            .map_err(|_| span.record_err(IpcError::SendShutdown))?;
        info!("shutdown.");

        span.record_ok();
        Ok(())
    }

    async fn send_to_parent(
        &mut self,
        response: Response,
        timeout: Duration,
    ) -> Result<(), IpcError> {
        send_to_parent(&mut self.tx, response, timeout).await
    }

    async fn wg_interface_up() -> Result<(), IpcError> {
        WgQuick::for_existing_interface(crate::INTERFACE)?
            .up()
            .await
            .map_err(Into::into)
    }

    async fn wg_interface_down(graceful: impl Into<Graceful>) -> Result<(), IpcError> {
        let mut interface = WgQuick::for_existing_interface(crate::INTERFACE)?;

        match interface.down().await {
            Ok(()) => Ok(()),
            Err(WGError::ConfigFileNotFound(c)) => {
                if graceful.into().as_bool() {
                    Ok(())
                } else {
                    Err(WGError::ConfigFileNotFound(c).into())
                }
            }
            Err(WGError::CommandFailed(c, s)) => {
                if graceful.into().as_bool() {
                    Ok(())
                } else {
                    Err(WGError::CommandFailed(c, s).into())
                }
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn write_wg_config(config: &WgConfig) -> Result<(), IpcError> {
        WgQuick::for_interface(crate::INTERFACE, config)
            .await
            .map_err(Into::into)
            .map(|_| ())
    }
}

#[instrument(
    name = "interface_manager send",
    level = "trace",
    skip_all,
    fields(
        messaging.destination = "interface_manager",
        messaging.destination_kind = TF_M_DESTINATION_KIND,
        messaging.system = TF_M_SYSTEM,
        net.transport = "pipe",
        otel.kind = %SpanKind::Client,
        otel.status_code = Empty,
        otel.status_message = Empty,
    )
)]
async fn send_to_child(
    tx: &mut Framed<
        FramedWrite<ChildStdin, LengthDelimitedCodec>,
        Request,
        Request,
        Json<Request, Request>,
    >,
    request: Request,
    timeout: Duration,
) -> Result<(), IpcError> {
    let span = Span::current();
    debug!(request = ?request, "sending request");
    time::timeout(timeout, tx.send(request))
        .await
        .map_err(|err| span.record_err(IpcError::SendTimeout(err)))?
        .map_err(|err| span.record_err(IpcError::SendIO(err)))?;
    trace!(message._type = "SENT", message.id = 1);

    span.record_ok();
    Ok(())
}

#[instrument(
    name = "interface_manager receive",
    level = "trace",
    skip_all,
    fields(
        messaging.destination = "interface_manager",
        messaging.destination_kind = TF_M_DESTINATION_KIND,
        messaging.system = TF_M_SYSTEM,
        net.transport = "pipe",
        otel.kind = %SpanKind::Server,
        otel.status_code = Empty,
        otel.status_message = Empty,
    )
)]
async fn receive_from_child(
    rx: &mut Framed<
        FramedRead<ChildStdout, LengthDelimitedCodec>,
        Response,
        Response,
        Json<Response, Response>,
    >,
    timeout: Duration,
) -> Result<Response, IpcError> {
    let span = Span::current();
    let response = time::timeout(timeout, rx.try_next())
        .await
        .map_err(|err| span.record_err(IpcError::ReadTimeout(err)))?
        .map_err(|err| span.record_err(IpcError::ReadIO(err)))?
        .ok_or_else(|| span.record_err(IpcError::StreamClosedBeforeResponse))?;
    trace!(message._type = "RECEIVED", message.id = 1);
    debug!(response = ?response, "received response");

    span.record_ok();
    Ok(response)
}

#[instrument(
    name = "interface_manager_client send",
    level = "trace",
    skip_all,
    fields(
        messaging.destination = "interface_manager_client",
        messaging.destination_kind = TF_M_DESTINATION_KIND,
        messaging.system = TF_M_SYSTEM,
        net.transport = "pipe",
        otel.kind = %SpanKind::Client,
        otel.status_code = Empty,
        otel.status_message = Empty,
    )
)]
async fn send_to_parent(
    tx: &mut Framed<
        FramedWrite<Stdout, LengthDelimitedCodec>,
        Response,
        Response,
        Json<Response, Response>,
    >,
    response: Response,
    timeout: Duration,
) -> Result<(), IpcError> {
    let span = Span::current();

    debug!(response = ?response, "sending response");
    time::timeout(timeout, tx.send(response))
        .await
        .map_err(|err| span.record_err(IpcError::SendTimeout(err)))?
        .map_err(|err| span.record_err(IpcError::SendIO(err)))?;
    trace!(message._type = "SENT", message.id = 1);

    span.record_ok();
    Ok(())
}

#[instrument(
    name = "interface_manager_client receive",
    level = "trace",
    skip_all,
    fields(
        messaging.destination = "interface_manager_client",
        messaging.destination_kind = TF_M_DESTINATION_KIND,
        messaging.system = TF_M_SYSTEM,
        net.transport = "pipe",
        otel.kind = %SpanKind::Server,
        otel.status_code = Empty,
        otel.status_message = Empty,
    )
)]
async fn receive_from_parent(
    rx: &mut Framed<
        FramedRead<Stdin, LengthDelimitedCodec>,
        Request,
        Request,
        Json<Request, Request>,
    >,
    timeout: Duration,
) -> Result<Request, IpcError> {
    let span = Span::current();

    let request = time::timeout(timeout, rx.try_next())
        .await
        .map_err(IpcError::ReadTimeout)?
        .map_err(IpcError::ReadIO)?
        .ok_or(IpcError::StreamClosedBeforeRequest)?;
    trace!(message._type = "RECEIVED", message.id = 1);
    debug!(request = ?request, "receiving request");

    span.record_ok();
    Ok(request)
}
