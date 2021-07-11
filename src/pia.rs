use thiserror::Error;

pub mod client;

pub use client::api::{get_token, PIAToken};

#[derive(Debug, Error)]
pub enum PIAError {
    #[error("cannot create pia api request")]
    CreateRequest(hyper::http::Error),
    #[error("response for get token failed")]
    GetTokenResponse(hyper::Error),
    #[error("parsing json response body failed")]
    GetTokenResponseParse(serde_json::Error),
    #[error("reading response body failed")]
    ReadResponseBody(hyper::Error),
}
