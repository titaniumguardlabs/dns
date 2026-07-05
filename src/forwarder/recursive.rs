use super::DynResult;
use crate::dns::{DnsMessage, DnsRequest};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const DNS_PORT: u16 = 53;
const UDP_RECV_BYTES: usize = 4096;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct RecursiveResolver {
    upstreams: Arc<Vec<SocketAddr>>,
    timeout: Duration,
}

impl RecursiveResolver {
    pub(super) fn new(upstreams: &[IpAddr]) -> DynResult<Self> {
        if upstreams.is_empty() {
            return Err("at least one resolver address must be configured".into());
        }
        Ok(Self {
            upstreams: Arc::new(
                upstreams
                    .iter()
                    .copied()
                    .map(|ip| SocketAddr::new(ip, DNS_PORT))
                    .collect(),
            ),
            timeout: QUERY_TIMEOUT,
        })
    }

    #[cfg(test)]
    fn for_upstreams(upstreams: Vec<SocketAddr>, timeout: Duration) -> Self {
        Self {
            upstreams: Arc::new(upstreams),
            timeout,
        }
    }

    pub(super) async fn resolve(&self, request: &DnsRequest) -> DynResult<DnsMessage> {
        let query = upstream_query(&request.message);
        let query_wire = query.to_wire()?;
        let mut last_error: Option<Box<dyn std::error::Error + Send + Sync>> = None;

        for upstream in self.upstreams.iter().copied() {
            match self.resolve_one(upstream, &query, &query_wire).await {
                Ok(response) => return Ok(response),
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.unwrap_or_else(|| "no upstream resolvers configured".into()))
    }

    async fn resolve_one(
        &self,
        upstream: SocketAddr,
        query: &DnsMessage,
        query_wire: &[u8],
    ) -> DynResult<DnsMessage> {
        let udp_response = timeout(self.timeout, udp_exchange(upstream, query_wire)).await??;
        let response = DnsMessage::from_wire(&udp_response)?;
        validate_upstream_response(query, &response)?;
        if response.header.truncated {
            let tcp_response = timeout(self.timeout, tcp_exchange(upstream, query_wire)).await??;
            let response = DnsMessage::from_wire(&tcp_response)?;
            validate_upstream_response(query, &response)?;
            return Ok(response);
        }
        Ok(response)
    }
}

fn upstream_query(request: &DnsMessage) -> DnsMessage {
    let mut query = DnsMessage::query(
        request.header.id,
        request
            .first_question()
            .expect("recursive requests are checked before resolver call")
            .clone(),
    );
    query.header.recursion_desired = request.header.recursion_desired;
    query.header.checking_disabled = request.header.checking_disabled;
    query.additionals = request
        .additionals
        .iter()
        .filter(|record| record.record_type() == crate::dns::RecordType::OPT)
        .cloned()
        .collect();
    query
}

async fn udp_exchange(upstream: SocketAddr, query_wire: &[u8]) -> io::Result<Vec<u8>> {
    let bind_addr = if upstream.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.send_to(query_wire, upstream).await?;

    let mut buf = vec![0u8; UDP_RECV_BYTES];
    let (len, peer) = socket.recv_from(&mut buf).await?;
    if peer.ip() != upstream.ip() {
        return Err(io::Error::other(
            "dns response came from unexpected upstream",
        ));
    }
    buf.truncate(len);
    Ok(buf)
}

async fn tcp_exchange(upstream: SocketAddr, query_wire: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(upstream).await?;
    let len = u16::try_from(query_wire.len())
        .map_err(|_| io::Error::other("dns tcp query exceeds u16 length prefix"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(query_wire).await?;

    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes).await?;
    let response_len = usize::from(u16::from_be_bytes(len_bytes));
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

fn validate_upstream_response(query: &DnsMessage, response: &DnsMessage) -> DynResult<()> {
    if response.header.id != query.header.id {
        return Err("dns response id does not match query id".into());
    }
    if !response.header.response {
        return Err("upstream returned a dns query instead of a response".into());
    }
    if response.questions != query.questions {
        return Err("dns response question does not match query".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{
        DnsClass, DnsHeader, DnsName, DnsQuestion, DnsRecord, RData, RecordType, ResponseCode,
        TransportProtocol,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;

    fn recursive_request(id: u16) -> DnsRequest {
        let mut message = DnsMessage::query(
            id,
            DnsQuestion {
                name: DnsName::parse_ascii("www.example.com.").expect("valid name"),
                record_type: RecordType::A,
                class: DnsClass::IN,
            },
        );
        message.header.recursion_desired = true;
        DnsRequest {
            client_ip: IpAddr::from([127, 0, 0, 1]),
            protocol: TransportProtocol::Udp,
            message,
        }
    }

    fn upstream_answer(query: &DnsMessage) -> DnsMessage {
        DnsMessage {
            header: DnsHeader {
                id: query.header.id,
                response: true,
                authoritative: false,
                truncated: false,
                recursion_desired: query.header.recursion_desired,
                recursion_available: true,
                authentic_data: false,
                checking_disabled: query.header.checking_disabled,
                opcode: query.header.opcode,
                response_code: ResponseCode::NoError,
            },
            questions: query.questions.clone(),
            answers: vec![DnsRecord {
                name: DnsName::parse_ascii("www.example.com.").expect("valid name"),
                ttl: 60,
                class: DnsClass::IN,
                data: RData::A(Ipv4Addr::new(203, 0, 113, 10)),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    #[tokio::test]
    async fn resolver_uses_udp_wire_exchange_without_dns_library() {
        let upstream = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream addr");
        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = upstream.recv_from(&mut buf).await.expect("receive query");
            let query = DnsMessage::from_wire(&buf[..len]).expect("decode query");
            assert_eq!(query.header.id, 4242);
            assert!(query.header.recursion_desired);
            let response = upstream_answer(&query).to_wire().expect("encode response");
            upstream
                .send_to(&response, peer)
                .await
                .expect("send response");
        });

        let resolver =
            RecursiveResolver::for_upstreams(vec![upstream_addr], Duration::from_secs(1));
        let response = resolver
            .resolve(&recursive_request(4242))
            .await
            .expect("recursive response");
        responder.await.expect("responder task");

        assert_eq!(response.header.response_code, ResponseCode::NoError);
        assert!(response.header.recursion_available);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].record_type(), RecordType::A);
    }
}
