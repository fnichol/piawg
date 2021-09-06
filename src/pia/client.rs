// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::PIAError;
use crate::{
    http,
    wg::{PublicKey, ServerKey},
};
use hyper::{
    body::{self, Buf},
    Body, Method, Request, Uri, Version,
};
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use std::{collections::HashMap, fmt, io::BufRead, net::IpAddr, net::SocketAddr};

const GENERATE_TOKEN_URL: &str = "https://privateinternetaccess.com/gtoken/generateToken";
const GET_REGIONS_URL: &str = "https://serverlist.piaservers.net/vpninfo/servers/v4";
const API_ADD_KEY_PORT: u16 = 1337;
const API_GET_SIGNATURE_PORT: u16 = 19999;

const PIA_CA: &[u8] = include_bytes!("ca.rsa.4096.crt");

#[derive(Debug)]
pub struct WireGuardAPI {
    base_uri: Uri,
    server: IpAddr,
}

impl WireGuardAPI {
    pub fn for_region(region: &Region) -> Result<Self, PIAError> {
        Self::create(&region.server_cn, region.server_ip)
    }

    pub fn create(hostname: impl AsRef<str>, server: IpAddr) -> Result<Self, PIAError> {
        let uri = format!("https://{}", hostname.as_ref())
            .parse()
            .map_err(PIAError::InvalidUri)?;

        Ok(Self {
            base_uri: uri,
            server,
        })
    }

    pub async fn add_key(
        &self,
        token: &PIAToken,
        public_key: &PublicKey,
    ) -> Result<AddKeyResponse, PIAError> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!(
                "{}:{}/addKey?pt={}&pubkey={}",
                self.base_uri.to_string().trim_end_matches('/'),
                API_ADD_KEY_PORT,
                urlencoding::encode(token.as_str()),
                urlencoding::encode(public_key.as_str()),
            ))
            .body(Body::empty())
            .map_err(PIAError::AddKeyRequest)?;
        let socket_addr = SocketAddr::new(self.server, API_ADD_KEY_PORT);
        let res = http::https_client_with_custom_sni_and_ca(PIA_CA, socket_addr)
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

    pub async fn get_signature(&self, token: &PIAToken) -> Result<serde_json::Value, PIAError> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!(
                "{}:{}/getSignature?token={}",
                self.base_uri.to_string().trim_end_matches('/'),
                API_GET_SIGNATURE_PORT,
                urlencoding::encode(token.as_str()),
            ))
            .version(Version::HTTP_2)
            .body(Default::default())
            .map_err(PIAError::GetSignatureRequest)?;
        // dbg!(token);
        // dbg!(self);
        // dbg!(&req);
        // todo!();
        let socket_addr = SocketAddr::new(self.server, API_GET_SIGNATURE_PORT);
        let res = dbg!(
            http::https_client_with_custom_sni_and_ca(PIA_CA, socket_addr)
                .request(dbg!(req))
                .await
        )
        .map_err(PIAError::GetSignatureResponse)?;
        let body = body::aggregate(res)
            .await
            .map_err(PIAError::ReadResponseBody)?;
        let add_key_response: serde_json::Value =
            serde_json::from_reader(body.reader()).map_err(PIAError::GetSignatureResponseParse)?;

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

    pub async fn get_regions() -> Result<Regions, PIAError> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(GET_REGIONS_URL)
            .body(Body::empty())
            .map_err(PIAError::GetWGRegionsRequest)?;
        let res = http::https_client_native_roots()
            .request(req)
            .await
            .map_err(PIAError::GetWGRegionsResponse)?;
        let body = body::aggregate(res)
            .await
            .map_err(PIAError::ReadResponseBody)?
            .reader()
            .lines()
            .next()
            .expect("failed to get first line in response")
            .expect("io error");
        let get_regions_response: GetRegionsResponse =
            serde_json::from_str(&body).map_err(PIAError::GetTokenResponseParse)?;

        Ok(get_regions_response.into())
    }

    pub async fn get_region(id: impl AsRef<str>) -> Result<Region, PIAError> {
        let mut regions = Self::get_regions().await?;
        regions
            .0
            .remove(id.as_ref())
            .ok_or_else(|| PIAError::RegionNotFound(id.as_ref().to_string()))
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

#[derive(Debug, Deserialize)]
struct GetRegionsResponseGroup {
    name: String,
    ports: Vec<u16>,
}

#[derive(Debug, Deserialize)]
struct GetRegionsResponseRegionServer {
    ip: IpAddr,
    cn: String,
}

#[derive(Debug, Deserialize)]
struct GetRegionsResponseRegion {
    id: String,
    name: String,
    country: String,
    auto_region: bool,
    dns: String,
    port_forward: bool,
    geo: bool,
    servers: HashMap<String, Vec<GetRegionsResponseRegionServer>>,
}

#[derive(Debug, Deserialize)]
pub struct GetRegionsResponse {
    groups: HashMap<String, Vec<GetRegionsResponseGroup>>,
    regions: Vec<GetRegionsResponseRegion>,
}

#[derive(Debug, Deserialize)]
pub struct Region {
    pub id: String,
    pub name: String,
    pub country: String,
    pub auto_region: bool,
    pub dns: String,
    pub port_forward: bool,
    pub geo: bool,
    pub server_ip: IpAddr,
    pub server_cn: String,
}

#[derive(Debug)]
pub struct Regions(HashMap<String, Region>);

impl Regions {
    pub fn get(&self, id: impl AsRef<str>) -> Option<&Region> {
        self.0.get(id.as_ref())
    }

    pub fn get_regions_in_country<'a>(
        &'a self,
        country_id: &'a str,
    ) -> impl Iterator<Item = &Region> {
        self.0
            .values()
            .filter(move |region| region.country == country_id)
    }
}

impl From<GetRegionsResponse> for Regions {
    fn from(val: GetRegionsResponse) -> Self {
        let inner: HashMap<_, _> = val
            .regions
            .into_iter()
            .filter_map(|region| {
                if let Some(server) = region
                    .servers
                    .into_iter()
                    .find(|(key, _)| key == "wg")
                    .map(|(_, value)| value)
                    .map(|mut vec| {
                        vec.reverse();
                        vec.pop()
                    })
                    .flatten()
                {
                    let wg_region = Region {
                        id: region.id.clone(),
                        name: region.name,
                        country: region.country,
                        auto_region: region.auto_region,
                        dns: region.dns,
                        port_forward: region.port_forward,
                        geo: region.geo,
                        server_ip: server.ip,
                        server_cn: server.cn,
                    };

                    Some((region.id, wg_region))
                } else {
                    None
                }
            })
            .collect();
        Self(inner)
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
