use crate::DynResult;
use bytes::Bytes;
use crate::config::{AppConfig, HttpsTransportConfig, OdohConfig, QuicTransportConfig};
use crate::forwarder::Forwarder;
use h2::server::SendResponse;
use hickory_server::proto::rustls::default_provider;
use hickory_server::proto::{
    http::{Version as HttpVersion, request as http_request, response as http_response},
    serialize::binary::{BinDecodable, BinDecoder, BinEncoder},
    xfer::Protocol,
};
use hickory_server::server::{
    Request as DnsRequest, RequestHandler, ResponseHandler, ResponseInfo,
};
use hickory_server::{
    ServerFuture, authority::MessageRequest, authority::MessageResponse, proto::rr::Record,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::ResolvesServerCert,
    sign::{CertifiedKey, SingleCertAndKey},
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

const ODOH_CONFIGS_PATH: &str = "/.well-known/odohconfigs";
const ODOH_CONTENT_TYPE: &str = "application/odohconfigs";
const ODOH_CONFIG_VERSION: u16 = 0x0001;
const DOH_BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
const DOH_H2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) async fn register_secure_transports(
    server: &mut ServerFuture<Forwarder>,
    config: &AppConfig,
    forwarder: Forwarder,
) -> DynResult<()> {
    if let Some(dot) = &config.transports.dot {
        let resolver = load_cert_resolver(&dot.cert_path, &dot.key_path)?;
        let listener = TcpListener::bind(dot.listen_addr).await?;
        info!("listening on dot {}", dot.listen_addr);
        server.register_tls_listener(listener, Duration::from_secs(10), resolver)?;
    }

    if let Some(doh) = &config.transports.doh {
        let resolver = load_cert_resolver(&doh.cert_path, &doh.key_path)?;
        let listener = TcpListener::bind(doh.listen_addr).await?;
        info!("listening on doh (h2) {}", doh.listen_addr);
        register_doh_listener(doh, listener, resolver, forwarder.clone())?;
    }

    if let Some(doq) = &config.transports.doq {
        let resolver = load_cert_resolver(&doq.cert_path, &doq.key_path)?;
        let socket = UdpSocket::bind(doq.listen_addr).await?;
        info!("listening on doq {}", doq.listen_addr);
        register_doq_listener(server, doq, socket, resolver)?;
    }

    if let Some(doh3) = &config.transports.doh3 {
        let resolver = load_cert_resolver(&doh3.cert_path, &doh3.key_path)?;
        let socket = UdpSocket::bind(doh3.listen_addr).await?;
        info!("listening on doh (h3) {}", doh3.listen_addr);
        register_doh3_listener(server, doh3, socket, resolver)?;
    }

    Ok(())
}

fn load_cert_resolver(cert_path: &str, key_path: &str) -> DynResult<Arc<dyn ResolvesServerCert>> {
    let cert_chain = CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider())?;
    Ok(Arc::new(SingleCertAndKey::from(certified_key)))
}

fn register_doh_listener(
    cfg: &HttpsTransportConfig,
    listener: TcpListener,
    resolver: Arc<dyn ResolvesServerCert>,
    handler: Forwarder,
) -> DynResult<()> {
    let tls_acceptor = TlsAcceptor::from(Arc::new(build_doh_tls_config(resolver)?));
    let dns_hostname = cfg.dns_hostname.clone().map(Arc::<str>::from);
    let http_endpoint: Arc<str> = Arc::from(cfg.endpoint.clone());
    let max_doh_body_bytes = cfg.max_doh_body_bytes;
    let max_streams_per_connection = cfg.max_doh_h2_streams_per_connection as usize;
    let connection_limiter = Arc::new(Semaphore::new(cfg.max_doh_h2_connections as usize));
    let odoh_payload = cfg
        .odoh
        .as_ref()
        .map(build_odoh_configs_payload)
        .map(Arc::new);

    if let Some(odoh) = &cfg.odoh {
        info!(
            "odoh hpke profile configured: kem_id={:#06x} kdf_id={:#06x} aead_id={:#06x}",
            odoh.kem_id, odoh.kdf_id, odoh.aead_id
        );
    }

    tokio::spawn(async move {
        loop {
            let accepted = listener.accept().await;
            let (tcp_stream, src_addr) = match accepted {
                Ok(pair) => pair,
                Err(err) => {
                    warn!("error accepting DoH TCP stream: {err}");
                    continue;
                }
            };
            let permit = match connection_limiter.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    warn!("dropping DoH TCP stream from {src_addr}: connection limit reached");
                    continue;
                }
            };

            let tls_acceptor = tls_acceptor.clone();
            let handler = handler.clone();
            let dns_hostname = dns_hostname.clone();
            let http_endpoint = http_endpoint.clone();
            let odoh_payload = odoh_payload.clone();
            tokio::spawn(async move {
                let tls_stream =
                    match timeout(Duration::from_secs(10), tls_acceptor.accept(tcp_stream)).await {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(err)) => {
                            warn!("doh tls handshake error from {src_addr}: {err}");
                            return;
                        }
                        Err(_) => {
                            warn!("doh tls handshake timeout from {src_addr}");
                            return;
                        }
                    };

                handle_doh_h2_connection(
                    tls_stream,
                    src_addr,
                    handler,
                    dns_hostname,
                    http_endpoint,
                    odoh_payload,
                    max_streams_per_connection,
                    max_doh_body_bytes,
                    permit,
                )
                .await;
            });
        }
    });

    Ok(())
}

async fn handle_doh_h2_connection<I>(
    io: I,
    src_addr: SocketAddr,
    handler: Forwarder,
    dns_hostname: Option<Arc<str>>,
    http_endpoint: Arc<str>,
    odoh_payload: Option<Arc<Vec<u8>>>,
    max_streams_per_connection: usize,
    max_doh_body_bytes: usize,
    _connection_permit: OwnedSemaphorePermit,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream_limiter = Arc::new(Semaphore::new(max_streams_per_connection));
    let mut h2 = match timeout(DOH_H2_HANDSHAKE_TIMEOUT, h2::server::handshake(io)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(err)) => {
            warn!("doh h2 handshake error from {src_addr}: {err}");
            return;
        }
        Err(_) => {
            warn!("doh h2 handshake timeout from {src_addr}");
            return;
        }
    };

    loop {
        let next = h2.accept().await;
        let (request, respond) = match next {
            Some(Ok(req)) => req,
            Some(Err(err)) => {
                warn!("doh h2 stream accept error from {src_addr}: {err}");
                return;
            }
            None => return,
        };

        let handler = handler.clone();
        let dns_hostname = dns_hostname.clone();
        let http_endpoint = http_endpoint.clone();
        let odoh_payload = odoh_payload.clone();
        let stream_limiter = stream_limiter.clone();

        tokio::spawn(async move {
            let stream_permit = stream_limiter.try_acquire_owned().ok();
            handle_doh_h2_stream(
                request,
                respond,
                src_addr,
                handler,
                dns_hostname,
                http_endpoint,
                odoh_payload,
                max_doh_body_bytes,
                stream_permit,
            )
            .await;
        });
    }
}

async fn handle_doh_h2_stream(
    request: http::Request<h2::RecvStream>,
    respond: SendResponse<Bytes>,
    src_addr: SocketAddr,
    handler: Forwarder,
    dns_hostname: Option<Arc<str>>,
    http_endpoint: Arc<str>,
    odoh_payload: Option<Arc<Vec<u8>>>,
    max_doh_body_bytes: usize,
    _stream_permit: Option<OwnedSemaphorePermit>,
) {
    if _stream_permit.is_none() {
        let _ = send_binary_response(
            respond,
            http::StatusCode::TOO_MANY_REQUESTS,
            "text/plain",
            b"doh stream concurrency limit reached".to_vec(),
        )
        .await;
        return;
    }

    if request.method() == http::Method::GET && request.uri().path() == ODOH_CONFIGS_PATH {
        if let Some(payload) = odoh_payload {
            let _ = send_binary_response(
                respond,
                http::StatusCode::OK,
                ODOH_CONTENT_TYPE,
                payload.to_vec(),
            )
            .await;
        } else {
            let _ = send_binary_response(
                respond,
                http::StatusCode::NOT_FOUND,
                "text/plain",
                b"odoh not configured".to_vec(),
            )
            .await;
        }
        return;
    }

    if request.method() != http::Method::POST {
        let _ = send_binary_response(
            respond,
            http::StatusCode::METHOD_NOT_ALLOWED,
            "text/plain",
            b"method not allowed".to_vec(),
        )
        .await;
        return;
    }

    if let Err(err) = http_request::verify(
        HttpVersion::Http2,
        dns_hostname.as_deref(),
        &http_endpoint,
        &request,
    ) {
        let _ = send_binary_response(
            respond,
            http::StatusCode::BAD_REQUEST,
            "text/plain",
            format!("invalid doh request: {err}").into_bytes(),
        )
        .await;
        return;
    }

    let content_length = request
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());

    let body = match read_h2_body(
        request.into_body(),
        content_length,
        max_doh_body_bytes,
        DOH_BODY_READ_TIMEOUT,
    )
    .await
    {
        Ok(body) => body,
        Err(err) => {
            let status = if err.contains("body too large") {
                http::StatusCode::PAYLOAD_TOO_LARGE
            } else {
                http::StatusCode::BAD_REQUEST
            };
            let _ = send_binary_response(
                respond,
                status,
                "text/plain",
                format!("invalid doh body: {err}").into_bytes(),
            )
            .await;
            return;
        }
    };

    let mut decoder = BinDecoder::new(&body);
    let message = match MessageRequest::read(&mut decoder) {
        Ok(message) => message,
        Err(err) => {
            let _ = send_binary_response(
                respond,
                http::StatusCode::BAD_REQUEST,
                "text/plain",
                format!("invalid dns wire format: {err}").into_bytes(),
            )
            .await;
            return;
        }
    };

    let request = DnsRequest::new(message, src_addr, Protocol::Https);
    let response_handle = H2DnsResponseHandle(Arc::new(Mutex::new(respond)));
    let _ = handler.handle_request(&request, response_handle).await;
}

async fn read_h2_body(
    stream: h2::RecvStream,
    expected_len: Option<usize>,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Vec<u8>, String> {
    match timeout(
        read_timeout,
        read_h2_body_without_timeout(stream, expected_len, max_body_bytes),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(format!("body read timeout after {read_timeout:?}")),
    }
}

async fn read_h2_body_without_timeout(
    mut stream: h2::RecvStream,
    expected_len: Option<usize>,
    max_body_bytes: usize,
) -> Result<Vec<u8>, String> {
    validate_doh_body_size(expected_len, max_body_bytes)?;

    let mut bytes = Vec::with_capacity(expected_len.unwrap_or(0).clamp(512, 4096));
    while let Some(frame) = stream.data().await {
        let chunk = frame.map_err(|err| format!("failed to read body frame: {err}"))?;
        if bytes.len().saturating_add(chunk.len()) > max_body_bytes {
            return Err(format!("body too large: exceeds max {}", max_body_bytes));
        }
        bytes.extend_from_slice(&chunk);
    }
    if let Some(expected) = expected_len {
        if bytes.len() != expected {
            return Err(format!(
                "content-length mismatch: expected {expected}, got {}",
                bytes.len()
            ));
        }
    }
    Ok(bytes)
}

fn validate_doh_body_size(
    expected_len: Option<usize>,
    max_body_bytes: usize,
) -> Result<(), String> {
    if let Some(expected) = expected_len {
        if expected > max_body_bytes {
            return Err(format!(
                "body too large: content-length {} exceeds max {}",
                expected, max_body_bytes
            ));
        }
    }
    Ok(())
}

async fn send_binary_response(
    mut respond: SendResponse<Bytes>,
    status: http::StatusCode,
    content_type: &str,
    body: Vec<u8>,
) -> Result<(), h2::Error> {
    let response = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())
        .map_err(|_| h2::Error::from(h2::Reason::INTERNAL_ERROR))?;
    let mut stream = respond.send_response(response, false)?;
    stream.send_data(Bytes::from(body), true)?;
    Ok(())
}

fn build_doh_tls_config(
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
) -> io::Result<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("error creating TLS config: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(server_cert_resolver);
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

fn build_odoh_configs_payload(odoh: &OdohConfig) -> Vec<u8> {
    let public_key = odoh
        .decode_public_key_bytes()
        .expect("odoh public key should be pre-validated at config load");

    let mut contents = Vec::with_capacity(8 + public_key.len());
    contents.extend_from_slice(&odoh.kem_id.to_be_bytes());
    contents.extend_from_slice(&odoh.kdf_id.to_be_bytes());
    contents.extend_from_slice(&odoh.aead_id.to_be_bytes());
    contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    contents.extend_from_slice(&public_key);

    let mut single = Vec::with_capacity(4 + contents.len());
    single.extend_from_slice(&ODOH_CONFIG_VERSION.to_be_bytes());
    single.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    single.extend_from_slice(&contents);

    let mut configs = Vec::with_capacity(2 + single.len());
    configs.extend_from_slice(&(single.len() as u16).to_be_bytes());
    configs.extend_from_slice(&single);
    configs
}

#[derive(Clone)]
struct H2DnsResponseHandle(Arc<Mutex<SendResponse<Bytes>>>);

#[async_trait::async_trait]
impl ResponseHandler for H2DnsResponseHandle {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let mut bytes = Vec::with_capacity(512);
        let info = {
            let mut encoder = BinEncoder::new(&mut bytes);
            response
                .destructive_emit(&mut encoder)
                .map_err(|err| io::Error::other(format!("failed to encode DNS response: {err}")))?
        };

        let response = http_response::new(HttpVersion::Http2, bytes.len())
            .map_err(|err| io::Error::other(format!("failed to create h2 response: {err}")))?;
        let mut stream = self
            .0
            .lock()
            .await
            .send_response(response, false)
            .map_err(|err| io::Error::other(format!("failed to send response headers: {err}")))?;
        stream
            .send_data(Bytes::from(bytes), true)
            .map_err(|err| io::Error::other(format!("failed to send response body: {err}")))?;
        Ok(info)
    }
}

fn register_doq_listener(
    server: &mut ServerFuture<Forwarder>,
    cfg: &QuicTransportConfig,
    socket: UdpSocket,
    resolver: Arc<dyn ResolvesServerCert>,
) -> DynResult<()> {
    server.register_quic_listener(
        socket,
        Duration::from_secs(10),
        resolver,
        cfg.dns_hostname.clone(),
    )?;
    Ok(())
}

fn register_doh3_listener(
    server: &mut ServerFuture<Forwarder>,
    cfg: &QuicTransportConfig,
    socket: UdpSocket,
    resolver: Arc<dyn ResolvesServerCert>,
) -> DynResult<()> {
    server.register_h3_listener(
        socket,
        Duration::from_secs(10),
        resolver,
        cfg.dns_hostname.clone(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_doh_body_size_rejects_large_content_length() {
        let err = validate_doh_body_size(Some(5000), 4096).expect_err("should fail");
        assert!(err.contains("body too large"));
    }
    #[tokio::test]
    async fn read_h2_body_timeout_releases_stream_capacity() {
        let limiter = Arc::new(Semaphore::new(1));
        let limiter_for_server = limiter.clone();
        let (client_io, server_io) = tokio::io::duplex(1024);

        let server = tokio::spawn(async move {
            let mut h2 = h2::server::handshake(server_io)
                .await
                .expect("server h2 handshake should succeed");
            let (request, _respond) = h2
                .accept()
                .await
                .expect("client should send one stream")
                .expect("server should accept request");
            let _permit = limiter_for_server
                .try_acquire_owned()
                .expect("first stream should acquire capacity");

            let err = read_h2_body(
                request.into_body(),
                Some(1),
                4096,
                Duration::from_millis(50),
            )
            .await
            .expect_err("stalled body should time out");
            assert!(err.contains("body read timeout"));
        });

        let (mut client, connection) = h2::client::handshake(client_io)
            .await
            .expect("client h2 handshake should succeed");
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("/dns-query")
            .header(http::header::CONTENT_LENGTH, "1")
            .body(())
            .expect("request should build");
        let (_response, _body) = client
            .send_request(request, false)
            .expect("client should send open body stream");

        server.await.expect("server task should complete");
        let _permit = timeout(Duration::from_secs(1), limiter.acquire_owned())
            .await
            .expect("stream capacity should be released after body timeout")
            .expect("semaphore should not be closed");
    }
    #[test]
    fn odoh_payload_uses_real_public_key_bytes() {
        let odoh = OdohConfig {
            kem_id: 0x0020,
            kdf_id: 0x0001,
            aead_id: 0x0001,
            public_key_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        };
        assert!(build_odoh_configs_payload(&odoh).len() >= 44);
    }
}
