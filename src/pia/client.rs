use super::PIAError;
use crate::{
    http,
    wg::{PublicKey, ServerKey},
};
use hyper::{
    body::{self, Buf},
    Body, Method, Request, Uri,
};
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use std::{fmt, net::IpAddr, net::SocketAddr};

const GENERATE_TOKEN_URL: &str = "https://privateinternetaccess.com/gtoken/generateToken";

const PIA_CA: &[u8] = include_bytes!("ca.rsa.4096.crt");

pub struct WireGuardAPI {
    uri: Uri,
    socket_addr: SocketAddr,
}

impl WireGuardAPI {
    pub fn create(hostname: impl AsRef<str>, server: IpAddr) -> Result<Self, PIAError> {
        let uri = format!("https://{}:1337/addKey", hostname.as_ref())
            .parse()
            .map_err(PIAError::InvalidUri)?;
        let socket_addr = SocketAddr::new(server, 1337);

        Ok(Self { uri, socket_addr })
    }

    pub async fn add_key(
        &self,
        token: &PIAToken,
        public_key: &PublicKey,
    ) -> Result<AddKeyResponse, PIAError> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!(
                "{}?pt={}&pubkey={}",
                self.uri,
                urlencoding::encode(token.as_str()),
                urlencoding::encode(public_key.as_str()),
            ))
            .body(Body::empty())
            .map_err(PIAError::AddKeyRequest)?;
        let res = http::https_client_with_custom_sni_and_ca(PIA_CA, self.socket_addr)
            .request(req)
            .await
            .map_err(PIAError::AddKeyResponse)?;
        let body = body::aggregate(res)
            .await
            .map_err(PIAError::ReadResponseBody)?;
        let add_key_response: AddKeyResponse =
            serde_json::from_reader(body.reader()).map_err(PIAError::GetTokenResponseParse)?;
        if add_key_response.status != "OK" {
            return Err(PIAError::AddKeyResponseStatus(add_key_response.status));
        }

        Ok(add_key_response)
    }

    pub async fn get_token(
        pia_username: impl AsRef<str>,
        pia_password: impl AsRef<str>,
    ) -> Result<PIAToken, PIAError> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(GENERATE_TOKEN_URL)
            .header(
                "Authorization",
                http::basic_auth_value(pia_username, pia_password),
            )
            .body(Body::empty())
            .map_err(PIAError::GetTokenRequest)?;
        let res = http::https_client_native_roots()
            .request(req)
            .await
            .map_err(PIAError::GetTokenResponse)?;
        let body = body::aggregate(res)
            .await
            .map_err(PIAError::ReadResponseBody)?;
        let get_token_response: GetTokenResponse =
            serde_json::from_reader(body.reader()).map_err(PIAError::GetTokenResponseParse)?;

        Ok(get_token_response.into())
    }
}

#[derive(Debug)]
pub struct PIAToken(String);

impl PIAToken {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for PIAToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Deserialize)]
struct GetTokenResponse {
    status: String,
    token: String,
}

impl From<GetTokenResponse> for PIAToken {
    fn from(val: GetTokenResponse) -> Self {
        Self(val.token)
    }
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct AddKeyResponse {
    pub dns_servers: Vec<IpAddr>,
    pub peer_ip: IpAddr,
    #[serde_as(as = "DisplayFromStr")]
    pub peer_pubkey: PublicKey,
    pub server_ip: IpAddr,
    #[serde_as(as = "DisplayFromStr")]
    pub server_key: ServerKey,
    pub server_port: u16,
    pub server_vip: IpAddr,
    pub status: String,
}
