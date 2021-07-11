use base64::encode_config;
use ipnet::IpNet;
use rand_core::OsRng;
use serde::Serialize;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};
use thiserror::Error;
use tokio::io::{self, AsyncWrite};
use typed_builder::TypedBuilder;
use x25519_dalek::{PublicKey as InnerPublicKey, StaticSecret};

#[derive(Debug, Error)]
pub enum WGError {
    #[error("serializing wireguard config failed")]
    ConfigSerialize(serde_ini::ser::Error),
    #[error("wireguard config io error")]
    IO(std::io::Error),
}

#[derive(Serialize)]
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

#[derive(Serialize)]
pub struct PublicKey(String);

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey").finish_non_exhaustive()
    }
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let raw_secret = StaticSecret::new(OsRng);
    let raw_public = InnerPublicKey::from(&raw_secret);

    let secret = encode_config(raw_secret.to_bytes(), base64::STANDARD);
    let public = encode_config(raw_public.to_bytes(), base64::STANDARD);

    (SecretKey(secret), PublicKey(public))
}

#[derive(Debug, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct WgConfigInterface {
    address: IpNet,
    private_key: SecretKey,
    #[builder(default, setter(strip_option))]
    #[serde(rename = "DNS", skip_serializing_if = "Option::is_none")]
    dns: Option<IpAddr>,
}

#[derive(Debug, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct WgConfigPeer {
    #[builder(default = 25)]
    persistent_keepalive: u64,
    public_key: PublicKey,
    #[builder(default)]
    #[serde(rename = "AllowedIPs")]
    allowed_ips: IpNet,
    endpoint: SocketAddr,
}

#[derive(Debug, Serialize, TypedBuilder)]
#[serde(rename_all = "PascalCase")]
pub struct WgConfig {
    interface: WgConfigInterface,
    peer: WgConfigPeer,
}

impl WgConfig {
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

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[tokio::test]
    async fn serializes() {
        let expected = indoc! {"
            [Interface]\r
            Address=192.168.1.101/24\r
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
                    .address("192.168.1.101/24".parse().expect("failed to parse IpNet"))
                    .private_key(SecretKey("abc123".to_string()))
                    .build(),
            )
            .peer(
                WgConfigPeer::builder()
                    .public_key(PublicKey("def456".to_string()))
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
            Address=192.168.1.101/24\r
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
                    .address(
                        "192.168.1.101/24"
                            .parse()
                            .expect("failed to parse IPv4Addr"),
                    )
                    .private_key(SecretKey("abc123".to_string()))
                    .dns("172.16.0.1".parse().expect("failed to parse IpAddr"))
                    .build(),
            )
            .peer(
                WgConfigPeer::builder()
                    .public_key(PublicKey("def456".to_string()))
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