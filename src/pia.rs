use thiserror::Error;

pub mod client;

pub use client::api::{get_token, PIAToken, WireGuardAPI};

#[derive(Debug, Error)]
pub enum PIAError {
    #[error("cannot create pia addkey request")]
    AddKeyRequest(hyper::http::Error),
    #[error("response for pia addkey failed")]
    AddKeyResponse(hyper::Error),
    #[error("parsing pia addkey json response body failed")]
    AddKeyResponseParse(serde_json::Error),
    #[error("pia addkey status was not okay; status={0}")]
    AddKeyResponseStatus(String),
    #[error("cannot create pia gettoken request")]
    GetTokenRequest(hyper::http::Error),
    #[error("response for pia gettoken failed")]
    GetTokenResponse(hyper::Error),
    #[error("parsing pia gettoken json response body failed")]
    GetTokenResponseParse(serde_json::Error),
    #[error("reading response body failed")]
    ReadResponseBody(hyper::Error),
    #[error("error parsing pia wireguard api uri")]
    InvalidUri(hyper::http::uri::InvalidUri),
}
