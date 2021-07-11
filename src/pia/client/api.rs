use super::super::PIAError;
use base64::write::EncoderWriter;
use hyper::{
    body::{self, Buf},
    client::HttpConnector,
    Body, Client, Method, Request,
};
use hyper_rustls::HttpsConnector;
use serde::Deserialize;
use std::fmt;
use std::io::Write;

const GENERATE_TOKEN_URL: &str = "https://privateinternetaccess.com/gtoken/generateToken";

#[derive(Debug)]
pub struct PIAToken(String);

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
        .map_err(PIAError::CreateRequest)?;
    let res = http_client()
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

fn http_client() -> Client<HttpsConnector<HttpConnector>, Body> {
    let connector = HttpsConnector::with_native_roots();
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
