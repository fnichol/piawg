// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use base64::write::EncoderWriter;
use hyper::{
    client::{connect::dns::Name, HttpConnector},
    Body, Client,
};
use hyper_rustls::HttpsConnector;
use rustls::ClientConfig;
use std::{
    future::Future,
    io::{BufReader, Write},
    net::SocketAddr,
    pin::Pin,
    task::Poll,
    vec,
};
use tower::Service;

pub(crate) fn https_client_native_roots() -> Client<HttpsConnector<HttpConnector>, Body> {
    let connector = HttpsConnector::with_native_roots();
    Client::builder().build(connector)
}

pub(crate) fn https_client_with_custom_sni_and_ca(
    certificate_authority: &[u8],
    socket_addr: SocketAddr,
) -> Client<HttpsConnector<HttpConnector<StaticResolver>>, Body> {
    let resolver = StaticResolver::new(socket_addr);
    let mut connector = HttpConnector::new_with_resolver(resolver);
    connector.enforce_http(false);

    let mut tls = ClientConfig::new();
    tls.root_store
        .add_pem_file(&mut BufReader::new(certificate_authority))
        .expect("failed to load CA file--this is a bug!");

    let connector = HttpsConnector::from((connector, tls));
    Client::builder().build(connector)
}

pub(crate) fn basic_auth_value(username: impl AsRef<str>, password: impl AsRef<str>) -> Vec<u8> {
    let mut value = b"Basic ".to_vec();
    {
        let mut encoder = EncoderWriter::new(&mut value, base64::STANDARD);
        // `Vec::write` is infallible so unwrap is okay
        write!(encoder, "{}:{}", username.as_ref(), password.as_ref()).unwrap();
    }
    value
}

#[derive(Clone, Debug)]
pub(crate) struct StaticResolver {
    socket_addr: SocketAddr,
}

impl StaticResolver {
    pub(crate) fn new(socket_addr: SocketAddr) -> Self {
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

pub(crate) struct StaticFuture {
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

pub(crate) struct StaticAddrs {
    iter: vec::IntoIter<SocketAddr>,
}

impl Iterator for StaticAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}
