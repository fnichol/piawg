use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use thiserror::Error;
use tokio::{
    fs::{self, File, OpenOptions},
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite},
};
use typed_builder::TypedBuilder;

const DEFAULT_PRIVDROP_USER: &str = "nobody";

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
            .ok_or(ConfigError::ParentDir(path.to_path_buf()))?;
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
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    /// Sets the config's username.
    pub fn set_username(&mut self, username: impl Into<String>) {
        self.username = username.into();
    }

    /// Gets the config's password.
    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    /// Sets the config's password.
    pub fn set_password(&mut self, password: impl Into<String>) {
        self.password = password.into();
    }

    /// Gets the config's region id.
    pub fn region_id(&self) -> &str {
        self.region_id.as_str()
    }

    /// Sets the config's region id.
    pub fn set_region_id(&mut self, region_id: impl Into<String>) {
        self.region_id = region_id.into();
    }

    /// Gets the config's privdrop user.
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
