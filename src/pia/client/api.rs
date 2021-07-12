use super::super::PIAError;
use crate::wg::{PublicKey, ServerKey};
use base64::write::EncoderWriter;
use hyper::{
    body::{self, Buf},
    client::{connect::dns::Name, HttpConnector},
    Body, Client, Method, Request, Uri,
};
use hyper_rustls::HttpsConnector;
use rustls::ClientConfig;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use std::{
    fmt,
    future::Future,
    io::{BufReader, Write},
    net::IpAddr,
    net::SocketAddr,
    pin::Pin,
    task::Poll,
    vec,
};
use tower::Service;

const GENERATE_TOKEN_URL: &str = "https://privateinternetaccess.com/gtoken/generateToken";

const PIA_CA: &[u8] = include_bytes!("ca.rsa.4096.crt");

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

pub async fn get_token(
    pia_username: impl AsRef<str>,
    pia_password: impl AsRef<str>,
) -> Result<PIAToken, PIAError> {
    let req = Request::builder()
        .method(Method::GET)
        .uri(GENERATE_TOKEN_URL)
        .header(
            "Authorization",
            basic_auth_value(pia_username, pia_password),
        )
        .body(Body::empty())
        .map_err(PIAError::GetTokenRequest)?;
    let res = https_client_native_roots()
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
        let res = https_client_pia_ca(self.socket_addr)
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

fn https_client_native_roots() -> Client<HttpsConnector<HttpConnector>, Body> {
    let connector = HttpsConnector::with_native_roots();
    Client::builder().build(connector)
}

fn https_client_pia_ca(
    socket_addr: SocketAddr,
) -> Client<HttpsConnector<HttpConnector<StaticResolver>>, Body> {
    let resolver = StaticResolver::new(socket_addr);
    let mut connector = HttpConnector::new_with_resolver(resolver);
    connector.enforce_http(false);

    let mut tls = ClientConfig::new();
    tls.root_store
        .add_pem_file(&mut BufReader::new(PIA_CA))
        .expect("failed to load PIA CA file--this is a bug!");

    let connector = HttpsConnector::from((connector, tls));
    Client::builder().build(connector)
}

fn basic_auth_value(username: impl AsRef<str>, password: impl AsRef<str>) -> Vec<u8> {
    let mut value = b"Basic ".to_vec();
    {
        let mut encoder = EncoderWriter::new(&mut value, base64::STANDARD);
        // `Vec::write` is infallible so unwrap is okay
        write!(encoder, "{}:{}", username.as_ref(), password.as_ref()).unwrap();
    }
    value
}

#[derive(Clone, Debug)]
struct StaticResolver {
    socket_addr: SocketAddr,
}

impl StaticResolver {
    fn new(socket_addr: SocketAddr) -> Self {
        Self { socket_addr }
    }
}

impl Service<Name> for StaticResolver {
    type Response = StaticAddrs;
    type Error = std::io::Error;
    type Future = StaticFuture;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Name) -> Self::Future {
        StaticFuture {
            inner: self.socket_addr,
        }
    }
}

struct StaticFuture {
    inner: SocketAddr,
}

impl Future for StaticFuture {
    type Output = Result<StaticAddrs, std::io::Error>;

    fn poll(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        Ok(StaticAddrs {
            iter: vec![self.inner].into_iter(),
        })
        .into()
    }
}

struct StaticAddrs {
    iter: vec::IntoIter<SocketAddr>,
}

impl Iterator for StaticAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}
