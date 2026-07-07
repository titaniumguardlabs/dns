use crate::dns::{DnsMessage, DnsRequest, ResponseCode, TransportProtocol};
use crate::forwarder::Forwarder;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tracing::warn;

const MAX_UDP_MESSAGE_BYTES: usize = 4096;

pub(crate) async fn serve_udp(socket: UdpSocket, forwarder: Forwarder) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; MAX_UDP_MESSAGE_BYTES];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let packet = buf[..len].to_vec();
        let socket = socket.clone();
        let forwarder = forwarder.clone();
        tokio::spawn(async move {
            let response =
                handle_wire_request(&forwarder, &packet, peer, TransportProtocol::Udp, false).await;
            if let Err(err) = socket.send_to(&response, peer).await {
                warn!("failed to send udp dns response to {peer}: {err}");
            }
        });
    }
}

pub(crate) async fn serve_tcp(
    listener: TcpListener,
    forwarder: Forwarder,
    idle_timeout: Duration,
) -> io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let forwarder = forwarder.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_stream_connection(
                stream,
                peer,
                forwarder,
                idle_timeout,
                TransportProtocol::Tcp,
            )
            .await
            {
                warn!("tcp dns connection from {peer} stopped: {err}");
            }
        });
    }
}

pub(crate) async fn handle_stream_connection<S>(
    mut stream: S,
    peer: SocketAddr,
    forwarder: Forwarder,
    idle_timeout: Duration,
    protocol: TransportProtocol,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let keep_going = timeout(
            idle_timeout,
            handle_stream_message(&mut stream, peer, &forwarder, protocol),
        )
        .await;
        match keep_going {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => return Ok(()),
            Ok(Err(err)) => return Err(err),
            Err(_) => return Ok(()),
        }
    }
}

async fn handle_stream_message<S>(
    stream: &mut S,
    peer: SocketAddr,
    forwarder: &Forwarder,
    protocol: TransportProtocol,
) -> io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut len_bytes = [0u8; 2];
    match stream.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(err) => return Err(err),
    }
    let len = usize::from(u16::from_be_bytes(len_bytes));
    if len == 0 {
        return Ok(false);
    }

    let mut request = vec![0u8; len];
    stream.read_exact(&mut request).await?;
    let response = handle_wire_request(forwarder, &request, peer, protocol, true).await;
    let response_len = u16::try_from(response.len())
        .map_err(|_| io::Error::other("dns tcp response exceeds u16 length prefix"))?;
    stream.write_all(&response_len.to_be_bytes()).await?;
    stream.write_all(&response).await?;
    Ok(true)
}

async fn handle_wire_request(
    forwarder: &Forwarder,
    request_bytes: &[u8],
    peer: SocketAddr,
    protocol: TransportProtocol,
    tcp: bool,
) -> Vec<u8> {
    let request = match DnsMessage::from_wire(request_bytes) {
        Ok(message) => message,
        Err(_) => {
            return DnsMessage::response_for_request(
                &DnsMessage {
                    header: crate::dns::DnsHeader::query(0),
                    questions: Vec::new(),
                    answers: Vec::new(),
                    authorities: Vec::new(),
                    additionals: Vec::new(),
                },
                ResponseCode::FormErr,
            )
            .to_wire()
            .unwrap_or_default();
        }
    };
    let mut response = forwarder
        .handle_dns_request(DnsRequest {
            client_ip: peer.ip(),
            protocol,
            message: request,
        })
        .await;
    if !tcp {
        apply_udp_payload_limit(&mut response);
    }
    response.to_wire().unwrap_or_default()
}

fn apply_udp_payload_limit(response: &mut DnsMessage) {
    let Ok(bytes) = response.to_wire() else {
        return;
    };
    if bytes.len() <= usize::from(Forwarder::MAX_RESPONSE_UDP_PAYLOAD) {
        return;
    }
    response.header.truncated = true;
    response.answers.clear();
    response.authorities.clear();
    response.additionals.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caching::MokaDnsRecordCache;
    use crate::config::{ZoneConfig, ZoneRecordSetConfig, ZoneSoaConfig};
    use crate::dns::{DnsClass, DnsName, DnsQuestion, RecordType};
    use crate::logging::{LoggingConfig, LoggingPipeline};
    use crate::policy::{PolicyRuntime, RuleEngineConfig};
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    async fn test_forwarder() -> Forwarder {
        let mut api_records = BTreeMap::new();
        api_records.insert(
            "A".to_string(),
            ZoneRecordSetConfig {
                ttl: 300,
                values: vec!["192.0.2.10".to_string()],
            },
        );
        let mut records = BTreeMap::new();
        records.insert("api".to_string(), api_records);
        let zones = vec![ZoneConfig {
            name: "corp.internal.".to_string(),
            soa: ZoneSoaConfig {
                mname: "ns1.corp.internal.".to_string(),
                rname: "dns-admin.corp.internal.".to_string(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 1209600,
                minimum: 300,
                ttl: 3600,
            },
            records,
            dnssec: None,
        }];
        Forwarder::with_cache(
            &[IpAddr::from([198, 41, 0, 4])],
            &zones,
            Arc::new(MokaDnsRecordCache::new(100_000)),
            Arc::new(LoggingPipeline::from_config(&LoggingConfig::default())),
            Arc::new(
                PolicyRuntime::from_file_or_default(None, RuleEngineConfig::default())
                    .await
                    .expect("policy runtime"),
            ),
            Default::default(),
        )
        .expect("forwarder")
    }

    fn query_wire() -> Vec<u8> {
        let mut message = DnsMessage::query(
            42,
            DnsQuestion {
                name: DnsName::parse_ascii("api.corp.internal.").expect("valid name"),
                record_type: RecordType::A,
                class: DnsClass::IN,
            },
        );
        message.header.recursion_desired = true;
        message.to_wire().expect("query wire")
    }

    #[tokio::test]
    async fn udp_wire_request_returns_authoritative_wire_response() {
        let forwarder = test_forwarder().await;
        let response = handle_wire_request(
            &forwarder,
            &query_wire(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53000)),
            TransportProtocol::Udp,
            false,
        )
        .await;

        let message = DnsMessage::from_wire(&response).expect("response parses");
        assert_eq!(message.header.id, 42);
        assert_eq!(message.header.response_code, ResponseCode::NoError);
        assert!(message.header.authoritative);
        assert_eq!(message.answers.len(), 1);
    }

    #[tokio::test]
    async fn tcp_message_uses_two_octet_length_prefix() {
        let forwarder = test_forwarder().await;
        let (mut client, mut server) = tokio::io::duplex(4096);
        let request = query_wire();
        let server_task = tokio::spawn(async move {
            handle_stream_message(
                &mut server,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 53000)),
                &forwarder,
                TransportProtocol::Tcp,
            )
            .await
        });

        client
            .write_all(&(request.len() as u16).to_be_bytes())
            .await
            .expect("write length");
        client.write_all(&request).await.expect("write request");
        let mut len = [0u8; 2];
        client
            .read_exact(&mut len)
            .await
            .expect("read response len");
        let response_len = usize::from(u16::from_be_bytes(len));
        let mut response = vec![0u8; response_len];
        client
            .read_exact(&mut response)
            .await
            .expect("read response");

        assert!(server_task.await.expect("join").expect("server result"));
        assert_eq!(
            DnsMessage::from_wire(&response)
                .expect("response")
                .header
                .response_code,
            ResponseCode::NoError
        );
    }
}
