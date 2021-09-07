// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::pia::client::AddKeyResponse;
use base64::encode_config;
use ipnet::IpNet;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::{
    convert::Infallible,
    env,
    ffi::OsStr,
    fmt,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
};
use thiserror::Error;
use tokio::{
    fs::{self, OpenOptions},
    io::{self, AsyncWrite},
    process::Command,
};
use typed_builder::TypedBuilder;
use x25519_dalek::{PublicKey as InnerPublicKey, StaticSecret};

const CONFIG_FILE_PREFIX: &str = "/etc/wireguard";

#[derive(Debug, Error)]
pub enum WGError {
    #[error("failed to wait on child process")]
    ChildFailed,
    #[error("command failed; exit={0}, stderr=\"{1}\"")]
    CommandFailed(i32, String),
    #[error("serializing wireguard config failed")]
    ConfigSerialize(serde_ini::ser::Error),
    #[error("failed to create config file")]
    ConfigFileCreate(std::io::Error),
    #[error("wireguard config io error")]
    IO(std::io::Error),
    #[error("program not found on PATH: {0}")]
    CommandNotFound(String),
    #[error("wireguard config not found; config_file={0}")]
    ConfigFileNotFound(PathBuf),
    #[error("failed to spawn and execute process")]
    SpawnFailed,
}

#[derive(Deserialize, Serialize)]
pub struct SecretKey(String);

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey").finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PublicKey(String);

impl PublicKey {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for PublicKey {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerKey(String);

impl ServerKey {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for ServerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ServerKey {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let raw_secret = StaticSecret::new(OsRng);
    let raw_public = InnerPublicKey::from(&raw_secret);

    let secret = encode_config(raw_secret.to_bytes(), base64::STANDARD);
    let public = encode_config(raw_public.to_bytes(), base64::STANDARD);

    (SecretKey(secret), PublicKey(public))
}

#[skip_serializing_none]
#[derive(Debug, Deserialize, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct WgConfigInterface {
    address: IpAddr,
    private_key: SecretKey,
    #[builder(default, setter(strip_option))]
    #[serde(rename = "DNS")]
    dns: Option<IpAddr>,
}

#[derive(Debug, Deserialize, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct WgConfigPeer {
    #[builder(default = 25)]
    persistent_keepalive: u64,
    public_key: ServerKey,
    #[builder(default)]
    #[serde(rename = "AllowedIPs")]
    allowed_ips: IpNet,
    endpoint: SocketAddr,
}

#[derive(Debug, Deserialize, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct WgConfig {
    interface: WgConfigInterface,
    peer: WgConfigPeer,
}

impl WgConfig {
    pub fn from(akr: AddKeyResponse, secret_key: SecretKey) -> Self {
        Self::builder()
            .interface(
                WgConfigInterface::builder()
                    .address(akr.peer_ip)
                    .private_key(secret_key)
                    .build(),
            )
            .peer(
                WgConfigPeer::builder()
                    .public_key(akr.server_key)
                    .endpoint(SocketAddr::new(akr.server_ip, akr.server_port))
                    .build(),
            )
            .build()
    }

    pub async fn write<W: ?Sized>(&self, writer: &mut W) -> Result<(), WGError>
    where
        W: AsyncWrite + Unpin,
    {
        let ini = serde_ini::to_vec(self).map_err(WGError::ConfigSerialize)?;
        let mut ini_bytes = ini.as_ref();

        io::copy(&mut ini_bytes, writer)
            .await
            .map_err(WGError::IO)
            .map(|_| ())
    }
}

pub struct WgQuick {
    config_file: PathBuf,
    wg_quick_path: Option<PathBuf>,
}

impl WgQuick {
    pub fn for_existing_interface(interface: impl AsRef<str>) -> Result<Self, WGError> {
        Self::for_existing_config_file(config_file_path_for_interface(interface))
    }

    pub fn for_existing_config_file(config_file: impl Into<PathBuf>) -> Result<Self, WGError> {
        let config_file = config_file.into();
        if !config_file.exists() {
            return Err(WGError::ConfigFileNotFound(config_file));
        }

        Ok(Self {
            config_file,
            wg_quick_path: None,
        })
    }

    pub async fn for_interface(
        interface: impl AsRef<str>,
        config: &WgConfig,
    ) -> Result<Self, WGError> {
        Self::for_config_file(config_file_path_for_interface(interface), config).await
    }

    pub async fn for_config_file(
        config_file: impl Into<PathBuf>,
        config: &WgConfig,
    ) -> Result<Self, WGError> {
        let config_file = config_file.into();
        fs::create_dir_all(config_file.parent().expect("parent dir should exist"))
            .await
            .map_err(WGError::ConfigFileCreate)?;
        let mut open_options = OpenOptions::new();
        open_options.write(true).truncate(true).create(true);
        #[cfg(unix)]
        open_options.mode(0o600);
        let mut file = open_options
            .open(&config_file)
            .await
            .map_err(WGError::ConfigFileCreate)?;
        config.write(&mut file).await?;

        Ok(Self {
            config_file,
            wg_quick_path: None,
        })
    }

    pub async fn up(&mut self) -> Result<(), WGError> {
        run(Command::new(self.wg_quick_path()?)
            .arg("up")
            .arg(&self.config_file))
        .await?;
        Ok(())
    }

    pub async fn down(&mut self) -> Result<(), WGError> {
        run(Command::new(self.wg_quick_path()?)
            .arg("down")
            .arg(&self.config_file))
        .await?;
        Ok(())
    }

    fn wg_quick_path(&mut self) -> Result<&Path, WGError> {
        if self.wg_quick_path.is_none() {
            self.wg_quick_path.replace(find_program("wg-quick")?);
        }

        Ok(self.wg_quick_path.as_ref().expect("wg_quick_path is set"))
    }
}

fn config_file_path_for_interface(interface: impl AsRef<str>) -> PathBuf {
    Path::new(CONFIG_FILE_PREFIX).join(format!("{}.conf", interface.as_ref()))
}

fn find_program(program: impl AsRef<OsStr>) -> Result<PathBuf, WGError> {
    let path = Path::new(program.as_ref());

    if path.is_absolute() {
        if path.is_file() {
            Ok(path.to_path_buf())
        } else {
            Err(WGError::CommandNotFound(
                program.as_ref().to_string_lossy().to_string(),
            ))
        }
    } else {
        env::split_paths(&env::var("PATH").unwrap_or_else(|_| "".to_string()))
            .map(|path| path.join(program.as_ref()))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| WGError::CommandNotFound(program.as_ref().to_string_lossy().to_string()))
    }
}

async fn run(command: &mut Command) -> Result<(), WGError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| WGError::SpawnFailed)?
        .wait_with_output()
        .await
        .map_err(|_| WGError::ChildFailed)
        .and_then(|output| {
            if output.status.success() {
                Ok(())
            } else {
                Err(WGError::CommandFailed(
                    output.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                ))
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[tokio::test]
    async fn serializes() {
        let expected = indoc! {"
            [Interface]\r
            Address=192.168.1.101\r
            PrivateKey=abc123\r
            [Peer]\r
            PersistentKeepalive=25\r
            PublicKey=def456\r
            AllowedIPs=0.0.0.0/0\r
            Endpoint=10.12.13.14:8888\r
        "};

        let cfg = WgConfig::builder()
            .interface(
                WgConfigInterface::builder()
                    .address("192.168.1.101".parse().expect("failed to parse IpAddr"))
                    .private_key(SecretKey("abc123".to_string()))
                    .build(),
            )
            .peer(
                WgConfigPeer::builder()
                    .public_key(ServerKey("def456".to_string()))
                    .endpoint(
                        "10.12.13.14:8888"
                            .parse()
                            .expect("failed to parse SocketAddr"),
                    )
                    .build(),
            )
            .build();

        let mut actual: Vec<u8> = Vec::new();
        cfg.write(&mut actual)
            .await
            .expect("failed to serialize cfg");
        let actual = std::str::from_utf8(&actual).expect("failed to parse as utf8 string");

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn serializes_with_dns() {
        let expected = indoc! {"
            [Interface]\r
            Address=192.168.1.101\r
            PrivateKey=abc123\r
            DNS=172.16.0.1\r
            [Peer]\r
            PersistentKeepalive=25\r
            PublicKey=def456\r
            AllowedIPs=0.0.0.0/0\r
            Endpoint=10.12.13.14:8888\r
        "};

        let cfg = WgConfig::builder()
            .interface(
                WgConfigInterface::builder()
                    .address("192.168.1.101".parse().expect("failed to parse IpAddr"))
                    .private_key(SecretKey("abc123".to_string()))
                    .dns("172.16.0.1".parse().expect("failed to parse IpAddr"))
                    .build(),
            )
            .peer(
                WgConfigPeer::builder()
                    .public_key(ServerKey("def456".to_string()))
                    .endpoint(
                        "10.12.13.14:8888"
                            .parse()
                            .expect("failed to parse IPv4Addr"),
                    )
                    .build(),
            )
            .build();

        let mut actual: Vec<u8> = Vec::new();
        cfg.write(&mut actual)
            .await
            .expect("failed to serialize cfg");
        let actual = std::str::from_utf8(&actual).expect("failed to parse as utf8 string");

        assert_eq!(actual, expected);
    }
}
