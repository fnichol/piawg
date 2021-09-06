// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use thiserror::Error;

pub mod client;

pub use client::{PIAToken, WireGuardAPI};

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
    #[error("cannot create pia getsignature request")]
    GetSignatureRequest(hyper::http::Error),
    #[error("response for pia getsignature failed")]
    GetSignatureResponse(hyper::Error),
    #[error("parsing pia getsignature json response body failed")]
    GetSignatureResponseParse(serde_json::Error),
    #[error("cannot create pia gettoken request")]
    GetTokenRequest(hyper::http::Error),
    #[error("response for pia gettoken failed")]
    GetTokenResponse(hyper::Error),
    #[error("parsing pia gettoken json response body failed")]
    GetTokenResponseParse(serde_json::Error),
    #[error("cannot create pia getregions request")]
    GetWGRegionsRequest(hyper::http::Error),
    #[error("response for pia getregions failed")]
    GetWGRegionsResponse(hyper::Error),
    #[error("parsing pia getregions json response body failed")]
    GetWGRegionsResponseParse(serde_json::Error),
    #[error("reading response body failed")]
    ReadResponseBody(hyper::Error),
    #[error("region not found; region_id={0}")]
    RegionNotFound(String),
    #[error("error parsing pia wireguard api uri")]
    InvalidUri(hyper::http::uri::InvalidUri),
}
