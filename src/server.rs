use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, FixedOffset, Utc};
#[cfg(unix)]
use nix::unistd::{self, Uid, User};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use thiserror::Error;
#[cfg(unix)]
use tokio::signal::unix::{self, SignalKind};
#[cfg(windows)]
use tokio::signal::windows;
use tokio::{
    fs::{self, File, OpenOptions},
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite},
    sync::{oneshot, Mutex, RwLock},
    time,
};
use tracing::{debug, info, instrument, trace, warn};
use typed_builder::TypedBuilder;

use crate::{
    datetime,
    pia::{
        client::{GetSignaturePayloadRaw, GetSignatureSignature},
        PIAError, PIAToken, WireGuardAPI,
    },
    wg::{self, WgConfig},
    InterfaceManagerClient,
};

const DEFAULT_PRIVDROP_USER: &str = "nobody";

#[derive(Debug)]
pub struct Server<S> {
    state: Arc<RwLock<State>>,
    state_store: Arc<Mutex<S>>,
    api: WireGuardAPI,
    interface_manager: Arc<Mutex<InterfaceManagerClient>>,
    enable_port_forwarding: bool,
}

impl Server<()> {
    pub async fn init<S>(
        config: Config,
        mut state_store: S,
        verbosity: usize,
    ) -> Result<Server<S>, ServerError>
    where
        S: StateStore,
    {
        let interface_manager = Self::init_privileged(&config, &mut state_store, verbosity).await?;

        let region = WireGuardAPI::get_region(config.region_id()).await?;
        let api = WireGuardAPI::for_region(&region)?;

        let mut state = match state_store.load().await {
            Ok(state) => state,
            Err(StateError::NotFound(_) | StateError::Empty) => {
                Self::init_state(&config, &mut state_store, None).await?
            }
            Err(err) => return Err(err.into()),
        };

        if state.token_expires_at <= Utc::now() {
            info!(
                expired_at = %state.token_expires_at,
                "token expired, acquiring new token"
            );
            state = Self::init_state(&config, &mut state_store, state.port_forwarding).await?;
        } else {
            info!(expires_at = %state.token_expires_at, "token has not expired, re-using token");
        }

        Ok(Server {
            state: Arc::new(RwLock::new(state)),
            state_store: Arc::new(Mutex::new(state_store)),
            api,
            interface_manager: Arc::new(Mutex::new(interface_manager)),
            enable_port_forwarding: config.port_forward(),
        })
    }

    async fn init_privileged<S>(
        #[allow(unused_variables)] config: &Config,
        state_store: &mut S,
        verbosity: usize,
    ) -> Result<InterfaceManagerClient, ServerError>
    where
        S: StateStore,
    {
        state_store.init().await?;

        let interface_manager = InterfaceManagerClient::init(verbosity)
            .await
            .map_err(|err| ServerError::InterfaceManager(Box::new(err)))?;

        #[cfg(all(unix, feature = "privs", feature = "ipc"))]
        {
            let mut info = crate::privs::PrivDropInfo::new(DEFAULT_PRIVDROP_USER);
            info.user_name(config.privdrop_user());
            crate::privs::privdrop(&info).map_err(ServerError::PrivDrop)?;
        }

        Ok(interface_manager)
    }

    async fn init_state<S>(
        config: &Config,
        state_store: &mut S,
        port_forwarding: Option<PortForwarding>,
    ) -> Result<State, ServerError>
    where
        S: StateStore,
    {
        let token = WireGuardAPI::get_token(config.username(), config.password()).await?;

        let mut token_expires_at = Utc::now().into();
        token_expires_at = token_expires_at + chrono::Duration::days(1);

        let state = State {
            token,
            token_expires_at,
            port_forwarding,
        };

        state_store.store(&state).await?;

        Ok(state)
    }
}

impl<S> Server<S>
where
    S: StateStore,
{
    pub async fn run(mut self) -> Result<(), ServerError> {
        // Generate a WireGuard keypair
        let (secret_key, public_key) = wg::generate_keypair();
        // Register the generated public key with PIA
        let add_key_response = self
            .api
            .add_key(&self.state.read().await.token, &public_key)
            .await?;
        // Derive a local WireGuard configuration with PIA server/peer details
        let wg_config = WgConfig::from(add_key_response, secret_key);

        {
            let mut interface_manager = self.interface_manager.lock().await;

            // Write out the WireGuard INI configuration file
            interface_manager
                .write_wg_config(wg_config)
                .await
                .map_err(|err| ServerError::InterfaceManager(Box::new(err)))?;
            // Bring down any previously active WireGuard interface, but don't fail as one might
            // not be running
            if let Err(err) = interface_manager.wg_interface_down(true).await {
                debug!(
                    "attempted to bring down wireguard interface and encountered error: {}",
                    err
                );
            };
            // Bring up with WireGuard interface
            interface_manager
                .wg_interface_up()
                .await
                .map_err(|err| ServerError::InterfaceManager(Box::new(err)))?;
        }

        let mut port_forward_shutdown_tx = None;
        if self.enable_port_forwarding {
            let shutdown = oneshot::channel();
            port_forward_shutdown_tx = Some(shutdown.0);

            tokio::spawn(manage_port_forwarding(
                self.api.clone(),
                self.state.clone(),
                self.state_store.clone(),
                shutdown.1,
            ));
        }

        self.wait_on_signals(port_forward_shutdown_tx).await?;

        Ok(())
    }

    #[cfg(unix)]
    async fn wait_on_signals(
        self,
        port_forward_shutdown_tx: Option<oneshot::Sender<()>>,
    ) -> Result<(), ServerError> {
        let mut sigint = unix::signal(SignalKind::interrupt()).map_err(ServerError::SigIO)?;
        let mut sigterm = unix::signal(SignalKind::terminate()).map_err(ServerError::SigIO)?;

        loop {
            tokio::select! {
                _ = sigint.recv() => {
                    info!("received SIGINT signal, shutting down");
                    self.shutdown(port_forward_shutdown_tx).await?;
                    break;
                }
                _ = sigterm.recv() => {
                    info!("received SIGTERM signal, shutting down");
                    self.shutdown(port_forward_shutdown_tx).await?;
                    break;
                }
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    async fn wait_on_signals(
        self,
        port_forward_shutdown_tx: Option<oneshot::Sender<()>>,
    ) -> Result<(), ServerError> {
        let mut ctrlc = windows::ctrl_c().map_err(ServerError::SigIO)?;

        if ctrlc.recv().await.is_some() {
            info!("received Ctrl+C signal, shutting down");
            self.shutdown(port_forward_shutdown_tx).await?;
        }

        Ok(())
    }

    async fn shutdown(
        self,
        port_forward_shutdown_tx: Option<oneshot::Sender<()>>,
    ) -> Result<(), ServerError> {
        if let Some(tx) = port_forward_shutdown_tx {
            if tx.send(()).is_err() {
                warn!("failed to send port forwarding shutdown, receiver closed");
            }
        }

        {
            let mut interface_manager = self.interface_manager.lock().await;

            interface_manager
                .wg_interface_down(false)
                .await
                .map_err(|err| ServerError::InterfaceManager(Box::new(err)))?;
            interface_manager
                .terminate()
                .await
                .map_err(|err| ServerError::InterfaceManager(Box::new(err)))?;
        }

        Ok(())
    }
}

#[instrument(skip_all)]
async fn manage_port_forwarding(
    api: WireGuardAPI,
    state: Arc<RwLock<State>>,
    state_store: Arc<Mutex<impl StateStore + 'static>>,
    shutdown_rx: oneshot::Receiver<()>,
) {
    tokio::pin!(shutdown_rx);

    loop {
        let (task_shutdown_tx, task_shutdown_rx) = oneshot::channel();
        let (task_result_tx, task_result_rx) = oneshot::channel();

        tokio::spawn(port_forwarding_task(
            api.clone(),
            state.clone(),
            state_store.clone(),
            task_shutdown_rx,
            task_result_tx,
        ));

        tokio::select! {
            _ = (&mut shutdown_rx) => {
                trace!("manage_port_forwarding task received shutdown");
                if task_shutdown_tx.send(()).is_err() {
                    warn!("failed to send port forwarding task shutdown, receiver closed");
                }
                break;
            }
            result = task_result_rx => {
                if result.is_ok() {
                    trace!("port forwarding task returned Ok(()), so returning");
                    break;
                }
                trace!("port forwarding task returned Err(_), so respawn task");
            }
        }
    }
}

#[instrument(skip_all)]
async fn port_forwarding_task(
    mut api: WireGuardAPI,
    state: Arc<RwLock<State>>,
    state_store: Arc<Mutex<impl StateStore>>,
    shutdown_rx: oneshot::Receiver<()>,
    result_tx: oneshot::Sender<Result<(), ServerError>>,
) {
    tokio::pin!(shutdown_rx);
    let mut port_forward_interval = time::interval(Duration::from_secs(60 * 14));

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                debug!("port_forwarding_task received shutdown message");
                if result_tx.send(Ok(())).is_err() {
                    warn!("failed to send port forwarding task result, receiver closed");
                }
                return;
            }
            _ = port_forward_interval.tick() => {
                debug!("port forward interval ticked, checking state");
                if let Err(err) = port_forward(&mut api, &state, &state_store).await {
                    warn!(error = ?err, "failed to port forward");
                    if result_tx.send(Err(err)).is_err() {
                        warn!("failed to send port forwarding task result, receiver closed");
                    }
                    break;
                }
            }
            else => {
                warn!("port_forwarding_task all select arms are closed, ending task");
                break;
            }
        }
    }
}

#[instrument(skip_all)]
async fn port_forward(
    api: &mut WireGuardAPI,
    state: &RwLock<State>,
    state_store: &Mutex<impl StateStore>,
) -> Result<(), ServerError> {
    // Determine if port forwarding is enabled, and if so when the token expires. We do this
    // seperately to release the read lock on `state` so that it isn't held across a call to
    // `init_port_forward()` which attempts to acquire a write lock on `state` to update it.
    let pf_info = state
        .read()
        .await
        .port_forwarding
        .as_ref()
        .map(|pf| pf.expires_at);

    match pf_info {
        None => {
            debug!("port forwarding entry not found in state, running init_port_forward");
            init_port_forward(api, state, state_store).await?;
        }
        Some(expires_at) if expires_at <= Utc::now() => {
            debug!(
                expires_at = %expires_at,
                "port forwarding state entry has expired, running init_port_forward"
            );
            init_port_forward(api, state, state_store).await?;
        }
        Some(_) => {
            trace!("port forwarding state entry is not expired, using it");
        }
    };

    if let Some(port_forwarding) = &state.read().await.port_forwarding {
        let _bind_port = api
            .bind_port(&port_forwarding.payload, &port_forwarding.signature)
            .await?;
        info!(port = port_forwarding.port, "port forwarding enabled");
    }

    Ok(())
}

#[instrument(skip_all)]
async fn init_port_forward(
    api: &mut WireGuardAPI,
    state: &RwLock<State>,
    state_store: &Mutex<impl StateStore>,
) -> Result<(), ServerError> {
    let get_signature_response = api.get_signature(&state.read().await.token).await?;

    let port_forwarding = PortForwarding {
        port: get_signature_response.payload.port,
        expires_at: get_signature_response.payload.expires_at,
        payload: get_signature_response.payload_raw,
        signature: get_signature_response.signature,
    };

    {
        let mut lock = state.write().await;
        lock.port_forwarding = Some(port_forwarding);
    }

    state_store.lock().await.store(&*state.read().await).await?;

    Ok(())
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("interface manager error")]
    InterfaceManager(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    PIA(#[from] PIAError),
    #[cfg(all(unix, feature = "privs", feature = "ipc"))]
    #[error(transparent)]
    PrivDrop(#[from] crate::privs::PrivError),
    #[error("signal io error")]
    SigIO(#[source] io::Error),
    #[error(transparent)]
    State(#[from] StateError),
}

#[skip_serializing_none]
#[derive(Debug, Deserialize, Serialize, TypedBuilder)]
pub struct Config {
    #[builder(setter(into))]
    username: String,
    #[builder(setter(into))]
    password: String,
    #[builder(setter(into))]
    region_id: String,
    #[builder(default, setter(into, strip_option))]
    privdrop_user: Option<String>,
    #[builder(default, setter(strip_option))]
    port_forward: Option<bool>,
}

impl Config {
    pub const KEYS: &'static [&'static str] = &[
        "username",
        "password",
        "region_id",
        "privdrop_user",
        "port_forward",
    ];

    pub async fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        if !path.as_ref().is_file() {
            return Err(ConfigError::NotFound(path.as_ref().to_path_buf()));
        }
        let mut file = File::open(path).await?;

        Self::read(&mut file).await
    }

    pub async fn store(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        let path = path.as_ref();
        let parent_dir = path
            .parent()
            .ok_or_else(|| ConfigError::ParentDir(path.to_path_buf()))?;
        fs::create_dir_all(parent_dir)
            .await
            .map_err(ConfigError::Create)?;
        let mut open_options = OpenOptions::new();
        open_options.write(true).truncate(true).create(true);
        #[cfg(unix)]
        open_options.mode(0o600);
        let mut file = open_options.open(path).await.map_err(ConfigError::Create)?;

        self.write(&mut file).await
    }

    /// Reads the config from the given reader.
    pub async fn read<R: ?Sized>(reader: &mut R) -> Result<Self, ConfigError>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = vec![];
        reader
            .read_to_end(&mut buf)
            .await
            .map_err(ConfigError::IO)?;

        serde_json::from_slice(&buf).map_err(ConfigError::Deserialize)
    }

    /// Writes the config to the given writer.
    pub async fn write<W: ?Sized>(&self, writer: &mut W) -> Result<(), ConfigError>
    where
        W: AsyncWrite + Unpin,
    {
        let json = serde_json::to_vec_pretty(self).map_err(ConfigError::Serialize)?;
        let mut json_bytes = json.as_ref();

        io::copy(&mut json_bytes, writer)
            .await
            .map_err(ConfigError::IO)
            .map(|_| ())
    }

    /// Gets the config's username.
    #[must_use]
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    /// Sets the config's username.
    pub fn set_username(&mut self, username: impl Into<String>) {
        self.username = username.into();
    }

    /// Gets the config's password.
    #[must_use]
    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    /// Sets the config's password.
    pub fn set_password(&mut self, password: impl Into<String>) {
        self.password = password.into();
    }

    /// Gets the config's region id.
    #[must_use]
    pub fn region_id(&self) -> &str {
        self.region_id.as_str()
    }

    /// Sets the config's region id.
    pub fn set_region_id(&mut self, region_id: impl Into<String>) {
        self.region_id = region_id.into();
    }

    /// Gets the config's privdrop user.
    #[must_use]
    pub fn privdrop_user(&self) -> &str {
        self.privdrop_user
            .as_deref()
            .unwrap_or(DEFAULT_PRIVDROP_USER)
    }

    /// Sets the config's privdrop user.
    pub fn set_privdrop_user(&mut self, privdrop_user: impl Into<String>) {
        self.privdrop_user = Some(privdrop_user.into());
    }

    /// Gets the config's port forward.
    #[must_use]
    pub fn port_forward(&self) -> bool {
        self.port_forward.unwrap_or(false)
    }

    /// Sets the config's port forward.
    pub fn set_port_forward(&mut self, port_forward: bool) {
        self.port_forward = Some(port_forward);
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to create or write config file")]
    Create(#[source] std::io::Error),
    #[error("failed to deserialize config from json")]
    Deserialize(#[source] serde_json::Error),
    #[error("config io error")]
    IO(#[from] std::io::Error),
    #[error("config file not found: {0}")]
    NotFound(PathBuf),
    #[error("failed to find parent directory of config file")]
    ParentDir(PathBuf),
    #[error("failed to serialize config to json")]
    Serialize(#[source] serde_json::Error),
}

#[async_trait]
pub trait StateStore: Send + 'static {
    async fn init(&mut self) -> Result<(), StateError>;
    async fn load(&mut self) -> Result<State, StateError>;
    async fn store(&mut self, state: &State) -> Result<(), StateError>;
}

#[derive(Debug)]
pub struct FileStateStore {
    path: PathBuf,
    #[cfg(unix)]
    owner: Uid,
}

impl FileStateStore {
    pub fn new(
        path: impl Into<PathBuf>,
        #[allow(unused_variables)] owner: impl AsRef<str>,
    ) -> Result<Self, StateError> {
        #[cfg(unix)]
        let user = User::from_name(owner.as_ref())
            .map_err(|_| StateError::OwnerNotFound(owner.as_ref().to_string()))?
            .ok_or_else(|| StateError::OwnerNotFound(owner.as_ref().to_string()))?;

        Ok(Self {
            path: path.into(),
            #[cfg(unix)]
            owner: user.uid,
        })
    }

    async fn create_file(&self) -> Result<File, StateError> {
        let mut open_options = OpenOptions::new();
        open_options.write(true).truncate(true).create(true);
        #[cfg(unix)]
        open_options.mode(0o600);

        open_options
            .open(&self.path)
            .await
            .map_err(StateError::Create)
    }
}

#[async_trait]
impl StateStore for FileStateStore {
    async fn init(&mut self) -> Result<(), StateError> {
        let parent_dir = self
            .path
            .parent()
            .ok_or_else(|| StateError::ParentDir(self.path.clone()))?;
        fs::create_dir_all(parent_dir)
            .await
            .map_err(StateError::Create)?;

        if !self.path.is_file() {
            let _ignored = self.create_file().await?;
        }

        #[cfg(unix)]
        {
            let path = self.path.clone();
            let owner = self.owner;
            tokio::task::spawn_blocking(move || unistd::chown(&path, Some(owner), None))
                .await
                .map_err(|err| StateError::Init(Box::new(err)))?
                .map_err(|err| StateError::Init(Box::new(err)))?;
        }

        Ok(())
    }

    async fn load(&mut self) -> Result<State, StateError> {
        if !self.path.is_file() {
            return Err(StateError::NotFound(self.path.clone()));
        }
        if fs::metadata(&self.path).await?.len() == 0 {
            return Err(StateError::Empty);
        }
        let mut file = File::open(&self.path).await?;

        State::read(&mut file).await
    }

    async fn store(&mut self, state: &State) -> Result<(), StateError> {
        let mut file = self.create_file().await?;

        state.write(&mut file).await
    }
}

#[skip_serializing_none]
#[derive(Debug, Deserialize, Serialize, TypedBuilder)]
pub struct State {
    token: PIAToken,
    #[serde(
        deserialize_with = "datetime::deserialize_date_time",
        serialize_with = "datetime::serialize_date_time"
    )]
    token_expires_at: DateTime<FixedOffset>,
    port_forwarding: Option<PortForwarding>,
}

impl State {
    /// Reads the config from the given reader.
    pub async fn read<R: ?Sized>(reader: &mut R) -> Result<Self, StateError>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = vec![];
        reader.read_to_end(&mut buf).await.map_err(StateError::IO)?;

        serde_json::from_slice(&buf).map_err(StateError::Deserialize)
    }

    /// Writes the config to the given writer.
    pub async fn write<W: ?Sized>(&self, writer: &mut W) -> Result<(), StateError>
    where
        W: AsyncWrite + Unpin,
    {
        let json = serde_json::to_vec_pretty(self).map_err(StateError::Serialize)?;
        let mut json_bytes = json.as_ref();

        io::copy(&mut json_bytes, writer)
            .await
            .map_err(StateError::IO)
            .map(|_| ())
    }
}

#[skip_serializing_none]
#[derive(Debug, Deserialize, Serialize, TypedBuilder)]
pub struct PortForwarding {
    port: u16,
    #[serde(
        deserialize_with = "datetime::deserialize_date_time",
        serialize_with = "datetime::serialize_date_time"
    )]
    expires_at: DateTime<FixedOffset>,
    payload: GetSignaturePayloadRaw,
    signature: GetSignatureSignature,
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("failed to create or write state file")]
    Create(#[source] std::io::Error),
    #[error("failed to deserialize state from json")]
    Deserialize(#[source] serde_json::Error),
    #[error("state file is empty")]
    Empty,
    #[error("state io error")]
    IO(#[from] std::io::Error),
    #[error("state file not found: {0}")]
    NotFound(PathBuf),
    #[cfg(unix)]
    #[error("owner uid not found and must exist: {0}")]
    OwnerNotFound(String),
    #[error("failed to find parent directory of state file")]
    ParentDir(PathBuf),
    #[error("failed to serialize state to json")]
    Serialize(#[source] serde_json::Error),
    #[error("failed to init state store")]
    Init(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::*;

    #[tokio::test]
    async fn serializes_minimal() {
        let expected = indoc! {r#"
            {
              "username": "human",
              "password": "idonteven",
              "region_id": "ca_vancouver"
            }"#};

        let cfg = Config::builder()
            .username("human")
            .password("idonteven")
            .region_id("ca_vancouver")
            .build();

        let mut actual: Vec<u8> = Vec::new();
        cfg.write(&mut actual)
            .await
            .expect("failed to serialize cfg");
        let actual = std::str::from_utf8(&actual).expect("failed to parse as utf8 string");

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn serializes_full() {
        let expected = indoc! {r#"
            {
              "username": "human",
              "password": "idonteven",
              "region_id": "ca_vancouver",
              "privdrop_user": "puser",
              "port_forward": false
            }"#};

        let cfg = Config::builder()
            .username("human")
            .password("idonteven")
            .region_id("ca_vancouver")
            .privdrop_user("puser")
            .port_forward(false)
            .build();

        let mut actual: Vec<u8> = Vec::new();
        cfg.write(&mut actual)
            .await
            .expect("failed to serialize cfg");
        let actual = std::str::from_utf8(&actual).expect("failed to parse as utf8 string");

        assert_eq!(actual, expected);
    }
}
