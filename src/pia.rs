// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use thiserror::Error;

pub mod client;

pub use client::{PIAToken, WireGuardAPI};

#[derive(Debug, Error)]
pub enum PIAError {
    #[error("cannot create pia addkey request")]
    AddKeyRequest(#[source] hyper::http::Error),
    #[error("response for pia addkey failed")]
    AddKeyResponse(#[source] hyper::Error),
    #[error("parsing pia addkey json response body failed")]
    AddKeyResponseParse(#[source] serde_json::Error),
    #[error("pia addkey status was not okay; status={0}")]
    AddKeyResponseStatus(String),
    #[error("cannot create pia bindport request")]
    BindPortRequest(#[source] hyper::http::Error),
    #[error("response for pia bindport failed")]
    BindPortResponse(#[source] hyper::Error),
    #[error("parsing pia bindport json response body failed")]
    BindPortResponseParse(#[source] serde_json::Error),
    #[error("pia bindport status was not okay; status={0}")]
    BindPortResponseStatus(String),
    #[error("cannot create pia getsignature request")]
    GetSignatureRequest(#[source] hyper::http::Error),
    #[error("response for pia getsignature failed")]
    GetSignatureResponse(#[source] hyper::Error),
    #[error("parsing pia getsignature json response body failed")]
    GetSignatureResponseParse(#[source] serde_json::Error),
    #[error("response for pia getsignature payload failed")]
    GetSignatureResponsePayload(#[from] PayloadError),
    #[error("pia getsignature status was not okay; status={0}")]
    GetSignatureResponseStatus(String),
    #[error("cannot create pia gettoken request")]
    GetTokenRequest(#[source] hyper::http::Error),
    #[error("response for pia gettoken failed")]
    GetTokenResponse(#[source] hyper::Error),
    #[error("parsing pia gettoken json response body failed")]
    GetTokenResponseParse(#[source] serde_json::Error),
    #[error("cannot create pia getregions request")]
    GetWGRegionsRequest(#[source] hyper::http::Error),
    #[error("response for pia getregions failed")]
    GetWGRegionsResponse(#[source] hyper::Error),
    #[error("parsing pia getregions json response body failed")]
    GetWGRegionsResponseParse(#[source] serde_json::Error),
    #[error("reading response body failed")]
    ReadResponseBody(#[source] hyper::Error),
    #[error("region not found; region_id={0}")]
    RegionNotFound(String),
    #[error("server vip not set, add_key must be called first")]
    ServerVipNotSet,
    #[error("error parsing pia wireguard api uri")]
    InvalidUri(#[source] hyper::http::uri::InvalidUri),
}

#[derive(Debug, Error)]
pub enum PayloadError {
    #[error("payload base64 decode error")]
    Decode(#[from] base64::DecodeError),
    #[error("json deserialize error")]
    Json(#[from] serde_json::Error),
}
