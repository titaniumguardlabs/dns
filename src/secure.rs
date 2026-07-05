use crate::DynResult;
use crate::config::AppConfig;
#[cfg(any(feature = "doq", feature = "doh3"))]
use crate::config::QuicTransportConfig;
#[cfg(feature = "doh")]
use crate::config::{HttpsTransportConfig, OdohConfig};
#[cfg(feature = "dot")]
use crate::dns::TransportProtocol as DnsTransportProtocol;
#[cfg(any(feature = "doh", feature = "doh3", feature = "doq"))]
use crate::dns::{DnsMessage, DnsRequest as WireDnsRequest, TransportProtocol};
use crate::forwarder::Forwarder;
#[cfg(feature = "dot")]
use crate::server;
#[cfg(any(feature = "doh", feature = "doh3"))]
use base64::Engine;
#[cfg(any(feature = "doh", feature = "doh3"))]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "doh3")]
use bytes::Buf;
#[cfg(any(feature = "doh", feature = "doh3"))]
use bytes::Bytes;
#[cfg(feature = "doh")]
use h2::server::SendResponse;
#[cfg(feature = "doh3")]
use h3::server::RequestStream as H3RequestStream;
#[cfg(any(feature = "doq", feature = "doh3"))]
use quinn::crypto::rustls::QuicServerConfig;
#[cfg(any(feature = "dot", feature = "doh"))]
use rustls::ServerConfig;
#[cfg(any(feature = "dot", feature = "doh", feature = "doq", feature = "doh3"))]
use rustls::crypto::ring::default_provider;
#[cfg(any(feature = "dot", feature = "doh", feature = "doq", feature = "doh3"))]
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::ResolvesServerCert,
    sign::{CertifiedKey, SingleCertAndKey},
};
#[cfg(any(feature = "doh", feature = "doq"))]
use std::io;
#[cfg(any(feature = "doh", feature = "doh3", feature = "doq"))]
use std::net::SocketAddr;
#[cfg(any(feature = "dot", feature = "doh", feature = "doq", feature = "doh3"))]
use std::sync::Arc;
#[cfg(any(feature = "dot", feature = "doh", feature = "doq", feature = "doh3"))]
use std::time::Duration;
#[cfg(feature = "doh")]
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(any(feature = "dot", feature = "doh"))]
use tokio::net::TcpListener;
#[cfg(feature = "doh")]
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
#[cfg(any(feature = "dot", feature = "doh", feature = "doq", feature = "doh3"))]
use tokio::time::timeout;
#[cfg(any(feature = "dot", feature = "doh"))]
use tokio_rustls::TlsAcceptor;
#[cfg(any(feature = "dot", feature = "doh", feature = "doq", feature = "doh3"))]
use tracing::info;
#[cfg(any(feature = "dot", feature = "doh", feature = "doq", feature = "doh3"))]
use tracing::warn;

#[cfg(feature = "doh")]
const ODOH_CONFIGS_PATH: &str = "/.well-known/odohconfigs";
#[cfg(feature = "doh")]
const ODOH_CONTENT_TYPE: &str = "application/odohconfigs";
#[cfg(any(feature = "doh", feature = "doh3"))]
const DOH_CONTENT_TYPE: &str = "application/dns-message";
#[cfg(feature = "doh")]
const ODOH_CONFIG_VERSION: u16 = 0x0001;
#[cfg(any(feature = "doh", feature = "doh3"))]
const DOH_BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "doh")]
const DOH_H2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(any(feature = "doq", feature = "doh3"))]
const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(feature = "doq")]
const DOQ_STREAM_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(feature = "doq")]
const DOQ_MAX_STREAM_BYTES: usize = 65_537;

pub(crate) async fn register_secure_transports(
    #[cfg_attr(
        not(any(feature = "dot", feature = "doh", feature = "doq", feature = "doh3")),
        allow(unused_variables)
    )]
    config: &AppConfig,
    #[cfg_attr(
        not(any(feature = "doh", feature = "doq", feature = "doh3")),
        allow(unused_variables)
    )]
    forwarder: Forwarder,
) -> DynResult<()> {
    #[cfg(feature = "dot")]
    if let Some(dot) = &config.transports.dot {
        let tls_config = build_tls_config(&dot.cert_path, &dot.key_path, Vec::new())?;
        let listener = TcpListener::bind(dot.listen_addr).await?;
        info!("listening on dot {}", dot.listen_addr);
        register_dot_listener(listener, tls_config, forwarder.clone());
    }

    #[cfg(feature = "doh")]
    if let Some(doh) = &config.transports.doh {
        let resolver = load_cert_resolver(&doh.cert_path, &doh.key_path)?;
        let listener = TcpListener::bind(doh.listen_addr).await?;
        info!("listening on doh (h2) {}", doh.listen_addr);
        register_doh_listener(doh, listener, resolver, forwarder.clone())?;
    }

    #[cfg(feature = "doq")]
    if let Some(doq) = &config.transports.doq {
        let endpoint = build_quic_endpoint(doq, b"doq")?;
        info!("listening on doq {}", endpoint.local_addr()?);
        register_doq_listener(endpoint, forwarder.clone());
    }

    #[cfg(feature = "doh3")]
    if let Some(doh3) = &config.transports.doh3 {
        let endpoint = build_quic_endpoint(doh3, b"h3")?;
        info!("listening on doh3 {}", endpoint.local_addr()?);
        register_doh3_listener(doh3, endpoint, forwarder.clone());
    }

    Ok(())
}

#[cfg(feature = "dot")]
fn register_dot_listener(listener: TcpListener, tls_config: ServerConfig, handler: Forwarder) {
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    tokio::spawn(async move {
        loop {
            let accepted = listener.accept().await;
            let (tcp_stream, src_addr) = match accepted {
                Ok(pair) => pair,
                Err(err) => {
                    warn!("error accepting DoT TCP stream: {err}");
                    continue;
                }
            };

            let tls_acceptor = tls_acceptor.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let tls_stream =
                    match timeout(Duration::from_secs(10), tls_acceptor.accept(tcp_stream)).await {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(err)) => {
                            warn!("dot tls handshake error from {src_addr}: {err}");
                            return;
                        }
                        Err(_) => {
                            warn!("dot tls handshake timeout from {src_addr}");
                            return;
                        }
                    };

                if let Err(err) = server::handle_stream_connection(
                    tls_stream,
                    src_addr,
                    handler,
                    Duration::from_secs(10),
                    DnsTransportProtocol::Tls,
                )
                .await
                {
                    warn!("dot dns connection from {src_addr} stopped: {err}");
                }
            });
        }
    });
}

#[cfg(any(feature = "dot", feature = "doh", feature = "doq", feature = "doh3"))]
fn load_cert_resolver(cert_path: &str, key_path: &str) -> DynResult<Arc<dyn ResolvesServerCert>> {
    let cert_chain = CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider())?;
    Ok(Arc::new(SingleCertAndKey::from(certified_key)))
}

#[cfg(any(feature = "doq", feature = "doh3"))]
fn build_quic_endpoint(cfg: &QuicTransportConfig, alpn: &[u8]) -> DynResult<quinn::Endpoint> {
    let resolver = load_cert_resolver(&cfg.cert_path, &cfg.key_path)?;
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    crypto.alpn_protocols = vec![alpn.to_vec()];
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    let transport =
        Arc::get_mut(&mut server_config.transport).ok_or("failed to configure quic transport")?;
    transport.max_concurrent_uni_streams(0_u8.into());
    Ok(quinn::Endpoint::server(server_config, cfg.listen_addr)?)
}

#[cfg(feature = "doq")]
fn register_doq_listener(endpoint: quinn::Endpoint, handler: Forwarder) {
    tokio::spawn(async move {
        while let Some(connecting) = endpoint.accept().await {
            let handler = handler.clone();
            tokio::spawn(async move {
                let remote = connecting.remote_address();
                let connection = match timeout(QUIC_HANDSHAKE_TIMEOUT, connecting).await {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(err)) => {
                        warn!("doq handshake error from {remote}: {err}");
                        return;
                    }
                    Err(_) => {
                        warn!("doq handshake timeout from {remote}");
                        return;
                    }
                };

                while let Ok((send, recv)) = connection.accept_bi().await {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_doq_stream(send, recv, remote, handler).await {
                            warn!("doq stream from {remote} failed: {err}");
                        }
                    });
                }
            });
        }
    });
}

#[cfg(feature = "doq")]
async fn handle_doq_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    handler: Forwarder,
) -> io::Result<()> {
    let stream_bytes = timeout(DOQ_STREAM_TIMEOUT, recv.read_to_end(DOQ_MAX_STREAM_BYTES))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "doq stream read timed out"))?
        .map_err(|err| io::Error::other(format!("failed to read doq stream: {err}")))?;
    let request = decode_length_prefixed_dns_message(&stream_bytes)?;
    let mut message = DnsMessage::from_wire(request)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    message.header.id = 0;

    let mut response = handler
        .handle_dns_request(WireDnsRequest {
            client_ip: peer.ip(),
            protocol: TransportProtocol::Quic,
            message,
        })
        .await;
    response.header.id = 0;
    let wire = response
        .to_wire()
        .map_err(|err| io::Error::other(format!("failed to encode doq response: {err}")))?;
    let mut framed = Vec::with_capacity(wire.len() + 2);
    let len = u16::try_from(wire.len())
        .map_err(|_| io::Error::other("doq response exceeds u16 length prefix"))?;
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&wire);
    send.write_all(&framed)
        .await
        .map_err(|err| io::Error::other(format!("failed to write doq response: {err}")))?;
    send.finish()
        .map_err(|err| io::Error::other(format!("failed to finish doq stream: {err}")))?;
    Ok(())
}

#[cfg(feature = "doq")]
fn decode_length_prefixed_dns_message(bytes: &[u8]) -> io::Result<&[u8]> {
    if bytes.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing dns length prefix",
        ));
    }
    let len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    if bytes.len() != len + 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns message length prefix does not match stream payload",
        ));
    }
    Ok(&bytes[2..])
}

#[cfg(any(feature = "dot", feature = "doh"))]
fn build_tls_config(
    cert_path: &str,
    key_path: &str,
    alpn_protocols: Vec<Vec<u8>>,
) -> std::io::Result<ServerConfig> {
    let resolver = load_cert_resolver(cert_path, key_path)
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| std::io::Error::other(format!("error creating TLS config: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = alpn_protocols;
    Ok(config)
}

#[cfg(feature = "doh")]
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

#[cfg(feature = "doh3")]
fn register_doh3_listener(
    cfg: &QuicTransportConfig,
    endpoint: quinn::Endpoint,
    handler: Forwarder,
) {
    let dns_hostname = cfg.dns_hostname.clone().map(Arc::<str>::from);
    tokio::spawn(async move {
        while let Some(connecting) = endpoint.accept().await {
            let handler = handler.clone();
            let dns_hostname = dns_hostname.clone();
            tokio::spawn(async move {
                let remote = connecting.remote_address();
                let connection = match timeout(QUIC_HANDSHAKE_TIMEOUT, connecting).await {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(err)) => {
                        warn!("doh3 handshake error from {remote}: {err}");
                        return;
                    }
                    Err(_) => {
                        warn!("doh3 handshake timeout from {remote}");
                        return;
                    }
                };

                let quic_connection = h3_quinn::Connection::new(connection);
                let mut h3_connection = match h3::server::Connection::new(quic_connection).await {
                    Ok(connection) => connection,
                    Err(err) => {
                        warn!("doh3 connection setup error from {remote}: {err}");
                        return;
                    }
                };

                loop {
                    let accepted = h3_connection.accept().await;
                    let Some(resolver) = (match accepted {
                        Ok(resolver) => resolver,
                        Err(err) => {
                            warn!("doh3 request accept error from {remote}: {err}");
                            return;
                        }
                    }) else {
                        return;
                    };

                    let handler = handler.clone();
                    let dns_hostname = dns_hostname.clone();
                    tokio::spawn(async move {
                        let resolved = resolver.resolve_request().await;
                        let (request, stream) = match resolved {
                            Ok(request) => request,
                            Err(err) => {
                                warn!("doh3 request decode error from {remote}: {err}");
                                return;
                            }
                        };
                        if let Err(err) =
                            handle_doh3_request(request, stream, remote, handler, dns_hostname)
                                .await
                        {
                            warn!("doh3 request from {remote} failed: {err}");
                        }
                    });
                }
            });
        }
    });
}

#[cfg(feature = "doh")]
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

#[cfg(feature = "doh")]
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

    if request.method() != http::Method::POST && request.method() != http::Method::GET {
        let _ = send_binary_response(
            respond,
            http::StatusCode::METHOD_NOT_ALLOWED,
            "text/plain",
            b"method not allowed".to_vec(),
        )
        .await;
        return;
    }

    if let Err(err) = verify_doh_request(dns_hostname.as_deref(), &http_endpoint, &request) {
        let _ = send_binary_response(
            respond,
            http::StatusCode::BAD_REQUEST,
            "text/plain",
            format!("invalid doh request: {err}").into_bytes(),
        )
        .await;
        return;
    }

    let request_method = request.method().clone();
    let get_query = request.uri().query().map(str::to_string);
    let body = if request_method == http::Method::GET {
        match decode_doh_get_body(get_query.as_deref()) {
            Ok(body) => body,
            Err(err) => {
                let _ = send_binary_response(
                    respond,
                    http::StatusCode::BAD_REQUEST,
                    "text/plain",
                    format!("invalid doh get request: {err}").into_bytes(),
                )
                .await;
                return;
            }
        }
    } else {
        let content_length = request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        match read_h2_body(
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
        }
    };

    let response = match resolve_doh_wire_body(handler, src_addr, TransportProtocol::Https, &body)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let _ =
                send_binary_response(respond, err.status, "text/plain", err.message.into_bytes())
                    .await;
            return;
        }
    };
    let _ = send_doh_response(respond, response).await;
}

#[cfg(feature = "doh3")]
async fn handle_doh3_request(
    request: http::Request<()>,
    mut stream: H3RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    src_addr: SocketAddr,
    handler: Forwarder,
    dns_hostname: Option<Arc<str>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if request.method() != http::Method::POST && request.method() != http::Method::GET {
        send_h3_binary_response(
            &mut stream,
            http::StatusCode::METHOD_NOT_ALLOWED,
            "text/plain",
            Bytes::from_static(b"method not allowed"),
        )
        .await?;
        return Ok(());
    }

    if let Err(err) = verify_doh_request(dns_hostname.as_deref(), "/dns-query", &request) {
        send_h3_binary_response(
            &mut stream,
            http::StatusCode::BAD_REQUEST,
            "text/plain",
            Bytes::from(format!("invalid doh3 request: {err}")),
        )
        .await?;
        return Ok(());
    }

    let body = if request.method() == http::Method::GET {
        match decode_doh_get_body(request.uri().query()) {
            Ok(body) => body,
            Err(err) => {
                send_h3_binary_response(
                    &mut stream,
                    http::StatusCode::BAD_REQUEST,
                    "text/plain",
                    Bytes::from(format!("invalid doh3 get request: {err}")),
                )
                .await?;
                return Ok(());
            }
        }
    } else {
        let content_length = request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        match read_h3_body(&mut stream, content_length, 4096, DOH_BODY_READ_TIMEOUT).await {
            Ok(body) => body,
            Err(err) => {
                let status = if err.contains("body too large") {
                    http::StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    http::StatusCode::BAD_REQUEST
                };
                send_h3_binary_response(
                    &mut stream,
                    status,
                    "text/plain",
                    Bytes::from(format!("invalid doh3 body: {err}")),
                )
                .await?;
                return Ok(());
            }
        }
    };

    let response =
        match resolve_doh_wire_body(handler, src_addr, TransportProtocol::Https3, &body).await {
            Ok(response) => response,
            Err(err) => {
                send_h3_binary_response(
                    &mut stream,
                    err.status,
                    "text/plain",
                    Bytes::from(err.message),
                )
                .await?;
                return Ok(());
            }
        };
    send_h3_binary_response(
        &mut stream,
        http::StatusCode::OK,
        DOH_CONTENT_TYPE,
        Bytes::from(response),
    )
    .await?;
    Ok(())
}

#[cfg(feature = "doh3")]
async fn read_h3_body(
    stream: &mut H3RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    expected_len: Option<usize>,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Vec<u8>, String> {
    match timeout(
        read_timeout,
        read_h3_body_without_timeout(stream, expected_len, max_body_bytes),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(format!("body read timeout after {read_timeout:?}")),
    }
}

#[cfg(feature = "doh3")]
async fn read_h3_body_without_timeout(
    stream: &mut H3RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    expected_len: Option<usize>,
    max_body_bytes: usize,
) -> Result<Vec<u8>, String> {
    validate_doh_body_size(expected_len, max_body_bytes)?;
    let mut bytes = Vec::with_capacity(expected_len.unwrap_or(0).clamp(512, 4096));
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|err| format!("failed to read body frame: {err}"))?
    {
        let len = chunk.remaining();
        if bytes.len().saturating_add(len) > max_body_bytes {
            return Err(format!("body too large: exceeds max {max_body_bytes}"));
        }
        while chunk.has_remaining() {
            let part = chunk.chunk();
            bytes.extend_from_slice(part);
            let part_len = part.len();
            chunk.advance(part_len);
        }
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

#[cfg(feature = "doh3")]
async fn send_h3_binary_response(
    stream: &mut H3RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: http::StatusCode,
    content_type: &str,
    body: Bytes,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let response = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())?;
    stream.send_response(response).await?;
    if !body.is_empty() {
        stream.send_data(body).await?;
    }
    stream.finish().await?;
    Ok(())
}

#[cfg(any(feature = "doh", feature = "doh3"))]
struct DohHttpError {
    status: http::StatusCode,
    message: String,
}

#[cfg(any(feature = "doh", feature = "doh3"))]
fn verify_doh_request<B>(
    dns_hostname: Option<&str>,
    endpoint: &str,
    request: &http::Request<B>,
) -> Result<(), String> {
    if request.uri().path() != endpoint {
        return Err(format!(
            "unexpected DoH path: expected {endpoint}, got {}",
            request.uri().path()
        ));
    }
    if let Some(expected_host) = dns_hostname {
        let actual_host = request
            .headers()
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .or_else(|| {
                request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str())
            });
        if actual_host != Some(expected_host) {
            return Err("unexpected DoH authority".to_string());
        }
    }
    if request.method() == http::Method::GET {
        return Ok(());
    }
    let Some(content_type) = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return Err("missing content-type".to_string());
    };
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type != DOH_CONTENT_TYPE {
        return Err(format!("unsupported content-type: {content_type}"));
    }
    Ok(())
}

#[cfg(any(feature = "doh", feature = "doh3"))]
fn decode_doh_get_body(query: Option<&str>) -> Result<Vec<u8>, String> {
    let query = query.ok_or("missing dns query parameter")?;
    let encoded = query
        .split('&')
        .find_map(|part| part.strip_prefix("dns="))
        .ok_or("missing dns query parameter")?;
    if encoded.is_empty() {
        return Err("empty dns query parameter".to_string());
    }
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|err| format!("invalid dns query parameter: {err}"))
}

#[cfg(any(feature = "doh", feature = "doh3"))]
async fn resolve_doh_wire_body(
    handler: Forwarder,
    src_addr: SocketAddr,
    protocol: TransportProtocol,
    body: &[u8],
) -> Result<Vec<u8>, DohHttpError> {
    let message = DnsMessage::from_wire(body).map_err(|err| DohHttpError {
        status: http::StatusCode::BAD_REQUEST,
        message: format!("invalid dns wire format: {err}"),
    })?;
    let response = handler
        .handle_dns_request(WireDnsRequest {
            client_ip: src_addr.ip(),
            protocol,
            message,
        })
        .await;
    response.to_wire().map_err(|err| DohHttpError {
        status: http::StatusCode::INTERNAL_SERVER_ERROR,
        message: format!("failed to encode dns response: {err}"),
    })
}

#[cfg(feature = "doh")]
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

#[cfg(feature = "doh")]
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

#[cfg(any(feature = "doh", feature = "doh3"))]
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

#[cfg(feature = "doh")]
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

#[cfg(feature = "doh")]
async fn send_doh_response(respond: SendResponse<Bytes>, body: Vec<u8>) -> Result<(), h2::Error> {
    send_binary_response(respond, http::StatusCode::OK, DOH_CONTENT_TYPE, body).await
}

#[cfg(feature = "doh")]
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

#[cfg(feature = "doh")]
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

#[cfg(all(test, feature = "doh"))]
mod tests {
    use super::*;

    #[test]
    fn validate_doh_body_size_rejects_large_content_length() {
        let err = validate_doh_body_size(Some(5000), 4096).expect_err("should fail");
        assert!(err.contains("body too large"));
    }

    #[test]
    fn verify_doh_post_request_requires_dns_message_content_type() {
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("/dns-query")
            .header(http::header::HOST, "dns.example")
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .body(())
            .expect("request should build");

        verify_doh_request(Some("dns.example"), "/dns-query", &request).expect("valid DoH request");

        let missing_content_type = http::Request::builder()
            .method(http::Method::POST)
            .uri("/dns-query")
            .body(())
            .expect("request should build");
        let err = verify_doh_request(None, "/dns-query", &missing_content_type)
            .expect_err("missing content-type should fail");
        assert!(err.contains("content-type"));
    }

    #[test]
    fn verify_doh_get_allows_dns_query_parameter_without_content_type() {
        let dns_query = URL_SAFE_NO_PAD.encode([0_u8, 1, 2, 3]);
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("/dns-query?dns={dns_query}"))
            .body(())
            .expect("request should build");

        verify_doh_request(None, "/dns-query", &request).expect("valid DoH GET");
        assert_eq!(
            decode_doh_get_body(request.uri().query()).expect("dns query should decode"),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    fn decode_doh_get_body_rejects_missing_dns_parameter() {
        let err = decode_doh_get_body(Some("x=abc")).expect_err("missing dns should fail");
        assert!(err.contains("missing dns"));
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

#[cfg(all(test, feature = "doq"))]
mod doq_tests {
    use super::*;

    #[test]
    fn decode_length_prefixed_dns_message_accepts_exact_payload() {
        let bytes = [0, 3, 1, 2, 3];
        assert_eq!(
            decode_length_prefixed_dns_message(&bytes).expect("valid frame"),
            &[1, 2, 3]
        );
    }

    #[test]
    fn decode_length_prefixed_dns_message_rejects_truncated_payload() {
        let bytes = [0, 4, 1, 2, 3];
        let err = decode_length_prefixed_dns_message(&bytes).expect_err("truncated frame");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
