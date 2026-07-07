use crate::DynResult;
use crate::config::{
    DNSCRYPT_CLIENT_MAGIC_BYTES, DNSCRYPT_KEY_BYTES, DnsCryptTransportConfig,
    decode_dnscrypt_key_file,
};
use crate::dns::{
    DnsClass, DnsMessage, DnsName, DnsRecord, DnsRequest, RData, RecordType, ResponseCode,
    TransportProtocol,
};
use crate::forwarder::Forwarder;
use chacha20::{R20, hchacha};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{Duration, timeout};
use tracing::{info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

const CERT_QUERY_PREFIX: &str = "2.dnscrypt-cert.";
const CERT_MAGIC: &[u8; 4] = b"DNSC";
const QUERY_NONCE_HALF_BYTES: usize = 12;
const DNSCRYPT_RESPONSE_MAGIC: &[u8; 8] = b"r6fnvWj8";
const DNSCRYPT_ES_VERSION_XCHACHA20_POLY1305: u16 = 0x0002;
const DNSCRYPT_PROTOCOL_MINOR_VERSION: u16 = 0;
const DNSCRYPT_TAG_BYTES: usize = 16;
const DNSCRYPT_UDP_READ_BYTES: usize = 4096;
const DNSCRYPT_TCP_MAX_PACKET_BYTES: usize = 65_535;
const DNSCRYPT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) async fn register_dnscrypt_transport(
    config: &DnsCryptTransportConfig,
    forwarder: Forwarder,
) -> DynResult<()> {
    let runtime = Arc::new(DnsCryptRuntime::from_config(config)?);
    let udp_socket = UdpSocket::bind(config.listen_addr).await?;
    let tcp_listener = TcpListener::bind(config.listen_addr).await?;
    info!("listening on dnscrypt udp {}", config.listen_addr);
    info!("listening on dnscrypt tcp {}", config.listen_addr);
    register_dnscrypt_udp_listener(udp_socket, runtime.clone(), forwarder.clone());
    register_dnscrypt_tcp_listener(tcp_listener, runtime, forwarder);
    Ok(())
}

struct DnsCryptRuntime {
    certificate_name: DnsName,
    resolver_secret_key: StaticSecret,
    client_magic: [u8; DNSCRYPT_CLIENT_MAGIC_BYTES],
    certificate_payload: Vec<u8>,
}

impl DnsCryptRuntime {
    fn from_config(config: &DnsCryptTransportConfig) -> DynResult<Self> {
        let provider_name = DnsName::parse_ascii(&config.provider_name)?;
        let certificate_name =
            DnsName::parse_ascii(&format!("{CERT_QUERY_PREFIX}{}", provider_name.to_ascii()))?;
        let provider_secret =
            decode_dnscrypt_key_file(&config.provider_secret_key_path, "provider secret key")?;
        let resolver_secret =
            decode_dnscrypt_key_file(&config.resolver_secret_key_path, "resolver secret key")?;
        let signing_key = SigningKey::from_bytes(&provider_secret);
        let resolver_secret_key = StaticSecret::from(resolver_secret);
        let resolver_public_key = PublicKey::from(&resolver_secret_key);
        let client_magic = match config.client_magic.as_deref() {
            Some(encoded) => decode_client_magic(encoded)?,
            None => derive_client_magic(resolver_public_key.as_bytes(), config.cert_serial),
        };
        let certificate_payload = build_certificate_payload(
            &signing_key,
            resolver_public_key.as_bytes(),
            &client_magic,
            config.cert_serial,
            config.cert_valid_from,
            config.cert_valid_until,
        );
        Ok(Self {
            certificate_name,
            resolver_secret_key,
            client_magic,
            certificate_payload,
        })
    }

    fn is_certificate_question(&self, message: &DnsMessage) -> bool {
        let Some(question) = message.first_question() else {
            return false;
        };
        question.record_type == RecordType::TXT
            && question.class == DnsClass::IN
            && question.name == self.certificate_name
    }

    fn certificate_response(&self, request: &DnsMessage) -> DnsMessage {
        let mut response = DnsMessage::response_for_request(request, ResponseCode::NoError);
        response.answers.push(DnsRecord {
            name: self.certificate_name.clone(),
            ttl: 3600,
            class: DnsClass::IN,
            data: RData::TXT(split_txt_chunks(&self.certificate_payload)),
        });
        response
    }
}

fn register_dnscrypt_udp_listener(
    socket: UdpSocket,
    runtime: Arc<DnsCryptRuntime>,
    forwarder: Forwarder,
) {
    tokio::spawn(async move {
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; DNSCRYPT_UDP_READ_BYTES];
        loop {
            let received = socket.recv_from(&mut buf).await;
            let (len, peer) = match received {
                Ok(received) => received,
                Err(err) => {
                    warn!("error receiving dnscrypt udp packet: {err}");
                    continue;
                }
            };
            let packet = buf[..len].to_vec();
            let socket = socket.clone();
            let runtime = runtime.clone();
            let forwarder = forwarder.clone();
            tokio::spawn(async move {
                let response = handle_dnscrypt_udp_packet(&runtime, forwarder, &packet, peer).await;
                if let Some(response) = response {
                    if let Err(err) = socket.send_to(&response, peer).await {
                        warn!("failed to send dnscrypt udp response to {peer}: {err}");
                    }
                }
            });
        }
    });
}

fn register_dnscrypt_tcp_listener(
    listener: TcpListener,
    runtime: Arc<DnsCryptRuntime>,
    forwarder: Forwarder,
) {
    tokio::spawn(async move {
        loop {
            let accepted = listener.accept().await;
            let (stream, peer) = match accepted {
                Ok(pair) => pair,
                Err(err) => {
                    warn!("error accepting dnscrypt tcp stream: {err}");
                    continue;
                }
            };
            let runtime = runtime.clone();
            let forwarder = forwarder.clone();
            tokio::spawn(async move {
                if let Err(err) = timeout(
                    DNSCRYPT_TCP_IDLE_TIMEOUT,
                    handle_dnscrypt_tcp_stream(runtime, forwarder, stream, peer),
                )
                .await
                .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "idle timeout")))
                {
                    warn!("dnscrypt tcp connection from {peer} stopped: {err}");
                }
            });
        }
    });
}

async fn handle_dnscrypt_udp_packet(
    runtime: &DnsCryptRuntime,
    forwarder: Forwarder,
    packet: &[u8],
    peer: SocketAddr,
) -> Option<Vec<u8>> {
    if let Ok(message) = DnsMessage::from_wire(packet) {
        if runtime.is_certificate_question(&message) {
            return runtime.certificate_response(&message).to_wire().ok();
        }
    }
    let decrypted = runtime.decrypt_query(packet).ok()?;
    let response = resolve_dnscrypt_message(forwarder, peer, decrypted)
        .await
        .ok()?;
    runtime.encrypt_response(&response, packet.len(), true).ok()
}

async fn handle_dnscrypt_tcp_stream<S>(
    runtime: Arc<DnsCryptRuntime>,
    forwarder: Forwarder,
    mut stream: S,
    peer: SocketAddr,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes).await?;
    let len = usize::from(u16::from_be_bytes(len_bytes));
    if len == 0 || len > DNSCRYPT_TCP_MAX_PACKET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid dnscrypt tcp packet length",
        ));
    }
    let mut packet = vec![0u8; len];
    stream.read_exact(&mut packet).await?;
    if let Ok(message) = DnsMessage::from_wire(&packet) {
        if runtime.is_certificate_question(&message) {
            let response = runtime
                .certificate_response(&message)
                .to_wire()
                .map_err(|err| io::Error::other(err.to_string()))?;
            write_length_prefixed(&mut stream, &response).await?;
            return Ok(());
        }
    }
    let decrypted = runtime
        .decrypt_query(&packet)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let response = resolve_dnscrypt_message(forwarder, peer, decrypted)
        .await
        .map_err(io::Error::other)?;
    let encrypted = runtime
        .encrypt_response(&response, packet.len(), false)
        .map_err(io::Error::other)?;
    write_length_prefixed(&mut stream, &encrypted).await?;
    Ok(())
}

async fn write_length_prefixed<S>(stream: &mut S, bytes: &[u8]) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let len = u16::try_from(bytes.len())
        .map_err(|_| io::Error::other("dnscrypt tcp response exceeds u16 length prefix"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(bytes).await
}

async fn resolve_dnscrypt_message(
    forwarder: Forwarder,
    peer: SocketAddr,
    decrypted: DecryptedQuery,
) -> Result<DnsCryptResponseContext, String> {
    let mut message = DnsMessage::from_wire(&decrypted.query)
        .map_err(|err| format!("invalid decrypted dns query: {err}"))?;
    let mut response = forwarder
        .handle_dns_request(DnsRequest {
            client_ip: peer.ip(),
            protocol: TransportProtocol::DnsCrypt,
            message: message.clone(),
        })
        .await;
    let wire = response
        .to_wire()
        .map_err(|err| format!("failed to encode dnscrypt response: {err}"))?;
    if wire.len() > decrypted.encrypted_query_len {
        message.header.truncated = true;
        response = DnsMessage::response_for_request(&message, ResponseCode::NoError);
    }
    Ok(DnsCryptResponseContext {
        client_public_key: decrypted.client_public_key,
        client_nonce_half: decrypted.client_nonce_half,
        response,
    })
}

struct DecryptedQuery {
    client_public_key: PublicKey,
    client_nonce_half: [u8; QUERY_NONCE_HALF_BYTES],
    encrypted_query_len: usize,
    query: Vec<u8>,
}

struct DnsCryptResponseContext {
    client_public_key: PublicKey,
    client_nonce_half: [u8; QUERY_NONCE_HALF_BYTES],
    response: DnsMessage,
}

impl DnsCryptRuntime {
    fn decrypt_query(&self, packet: &[u8]) -> Result<DecryptedQuery, String> {
        if packet.len()
            < DNSCRYPT_CLIENT_MAGIC_BYTES
                + DNSCRYPT_KEY_BYTES
                + QUERY_NONCE_HALF_BYTES
                + DNSCRYPT_TAG_BYTES
        {
            return Err("dnscrypt query too short".to_string());
        }
        if packet[..DNSCRYPT_CLIENT_MAGIC_BYTES] != self.client_magic {
            return Err("dnscrypt client magic mismatch".to_string());
        }
        let mut client_public_key = [0u8; DNSCRYPT_KEY_BYTES];
        client_public_key.copy_from_slice(
            &packet[DNSCRYPT_CLIENT_MAGIC_BYTES..DNSCRYPT_CLIENT_MAGIC_BYTES + DNSCRYPT_KEY_BYTES],
        );
        let client_public_key = PublicKey::from(client_public_key);
        let nonce_offset = DNSCRYPT_CLIENT_MAGIC_BYTES + DNSCRYPT_KEY_BYTES;
        let mut client_nonce_half = [0u8; QUERY_NONCE_HALF_BYTES];
        client_nonce_half
            .copy_from_slice(&packet[nonce_offset..nonce_offset + QUERY_NONCE_HALF_BYTES]);
        let encrypted = &packet[nonce_offset + QUERY_NONCE_HALF_BYTES..];
        let cipher = self.cipher_for_client(&client_public_key);
        let nonce = build_query_nonce(&client_nonce_half);
        let plaintext = decrypt_dnscrypt_payload(&cipher, &nonce, encrypted)?;
        let query = strip_dnscrypt_padding(&plaintext)?;
        Ok(DecryptedQuery {
            client_public_key,
            client_nonce_half,
            encrypted_query_len: packet.len(),
            query,
        })
    }

    fn encrypt_response(
        &self,
        context: &DnsCryptResponseContext,
        encrypted_query_len: usize,
        enforce_udp_size: bool,
    ) -> Result<Vec<u8>, String> {
        let cipher = self.cipher_for_client(&context.client_public_key);
        let resolver_nonce_half = random_nonce_half()?;
        let nonce = build_response_nonce(&context.client_nonce_half, &resolver_nonce_half);
        let mut wire = context
            .response
            .to_wire()
            .map_err(|err| format!("failed to encode dnscrypt response: {err}"))?;
        pad_dnscrypt_message(&mut wire, None);
        let encrypted = encrypt_dnscrypt_payload(&cipher, &nonce, &wire)?;
        let mut response = Vec::with_capacity(
            DNSCRYPT_RESPONSE_MAGIC.len() + QUERY_NONCE_HALF_BYTES + encrypted.len(),
        );
        response.extend_from_slice(DNSCRYPT_RESPONSE_MAGIC);
        response.extend_from_slice(&context.client_nonce_half);
        response.extend_from_slice(&resolver_nonce_half);
        response.extend_from_slice(&encrypted);
        if enforce_udp_size && response.len() > encrypted_query_len {
            let mut truncated = context.response.clone();
            truncated.header.truncated = true;
            truncated.answers.clear();
            truncated.authorities.clear();
            truncated.additionals.clear();
            let mut wire = truncated
                .to_wire()
                .map_err(|err| format!("failed to encode dnscrypt truncated response: {err}"))?;
            pad_dnscrypt_message(&mut wire, None);
            let encrypted = encrypt_dnscrypt_payload(&cipher, &nonce, &wire)?;
            response.truncate(DNSCRYPT_RESPONSE_MAGIC.len() + QUERY_NONCE_HALF_BYTES * 2);
            response.extend_from_slice(&encrypted);
        }
        Ok(response)
    }

    fn cipher_for_client(&self, client_public_key: &PublicKey) -> XChaCha20Poly1305 {
        let shared_secret = self.resolver_secret_key.diffie_hellman(client_public_key);
        let key = derive_dnscrypt_aead_key(shared_secret.as_bytes());
        let key = Key::from(key);
        XChaCha20Poly1305::new(&key)
    }
}

fn build_certificate_payload(
    signing_key: &SigningKey,
    resolver_public_key: &[u8; DNSCRYPT_KEY_BYTES],
    client_magic: &[u8; DNSCRYPT_CLIENT_MAGIC_BYTES],
    serial: u32,
    valid_from: u32,
    valid_until: u32,
) -> Vec<u8> {
    let mut signed = Vec::with_capacity(52);
    signed.extend_from_slice(resolver_public_key);
    signed.extend_from_slice(client_magic);
    signed.extend_from_slice(&serial.to_be_bytes());
    signed.extend_from_slice(&valid_from.to_be_bytes());
    signed.extend_from_slice(&valid_until.to_be_bytes());
    let signature = signing_key.sign(&signed);

    let mut payload = Vec::with_capacity(124);
    payload.extend_from_slice(CERT_MAGIC);
    payload.extend_from_slice(&DNSCRYPT_ES_VERSION_XCHACHA20_POLY1305.to_be_bytes());
    payload.extend_from_slice(&DNSCRYPT_PROTOCOL_MINOR_VERSION.to_be_bytes());
    payload.extend_from_slice(&signature.to_bytes());
    payload.extend_from_slice(&signed);
    payload
}

fn derive_dnscrypt_aead_key(shared_secret: &[u8; DNSCRYPT_KEY_BYTES]) -> [u8; DNSCRYPT_KEY_BYTES] {
    let key = (*shared_secret).into();
    let nonce = [0u8; 16].into();
    hchacha::<R20>(&key, &nonce).into()
}

fn encrypt_dnscrypt_payload(
    cipher: &XChaCha20Poly1305,
    nonce: &[u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let nonce = XNonce::from(*nonce);
    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| "dnscrypt encryption failed".to_string())?;
    Ok(move_tag_to_front(encrypted))
}

fn decrypt_dnscrypt_payload(
    cipher: &XChaCha20Poly1305,
    nonce: &[u8; 24],
    encrypted: &[u8],
) -> Result<Vec<u8>, String> {
    if encrypted.len() < DNSCRYPT_TAG_BYTES {
        return Err("dnscrypt encrypted payload too short".to_string());
    }
    let mut crate_order = Vec::with_capacity(encrypted.len());
    crate_order.extend_from_slice(&encrypted[DNSCRYPT_TAG_BYTES..]);
    crate_order.extend_from_slice(&encrypted[..DNSCRYPT_TAG_BYTES]);
    let nonce = XNonce::from(*nonce);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &crate_order,
                aad: &[],
            },
        )
        .map_err(|_| "dnscrypt authentication failed".to_string())
}

fn move_tag_to_front(mut encrypted: Vec<u8>) -> Vec<u8> {
    let tag = encrypted.split_off(encrypted.len() - DNSCRYPT_TAG_BYTES);
    let mut out = Vec::with_capacity(tag.len() + encrypted.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&encrypted);
    out
}

fn build_query_nonce(client_nonce_half: &[u8; QUERY_NONCE_HALF_BYTES]) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..QUERY_NONCE_HALF_BYTES].copy_from_slice(client_nonce_half);
    nonce
}

fn build_response_nonce(
    client_nonce_half: &[u8; QUERY_NONCE_HALF_BYTES],
    resolver_nonce_half: &[u8; QUERY_NONCE_HALF_BYTES],
) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..QUERY_NONCE_HALF_BYTES].copy_from_slice(client_nonce_half);
    nonce[QUERY_NONCE_HALF_BYTES..].copy_from_slice(resolver_nonce_half);
    nonce
}

fn random_nonce_half() -> Result<[u8; QUERY_NONCE_HALF_BYTES], String> {
    let mut nonce = [0u8; QUERY_NONCE_HALF_BYTES];
    getrandom::fill(&mut nonce)
        .map_err(|err| format!("failed to generate dnscrypt nonce: {err}"))?;
    Ok(nonce)
}

fn pad_dnscrypt_message(message: &mut Vec<u8>, min_len: Option<usize>) {
    message.push(0x80);
    let minimum = min_len.unwrap_or(0);
    while message.len() < minimum || !message.len().is_multiple_of(64) {
        message.push(0);
    }
}

fn strip_dnscrypt_padding(message: &[u8]) -> Result<Vec<u8>, String> {
    let Some(padding_start) = message.iter().rposition(|byte| *byte == 0x80) else {
        return Err("missing dnscrypt padding marker".to_string());
    };
    if message[padding_start + 1..].iter().any(|byte| *byte != 0) {
        return Err("invalid dnscrypt padding".to_string());
    }
    Ok(message[..padding_start].to_vec())
}

fn split_txt_chunks(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes.chunks(255).map(Vec::from).collect()
}

fn decode_client_magic(encoded: &str) -> Result<[u8; DNSCRYPT_CLIENT_MAGIC_BYTES], String> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let decoded = STANDARD
        .decode(encoded.trim())
        .map_err(|err| format!("invalid dnscrypt client magic base64: {err}"))?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "dnscrypt client magic must decode to {DNSCRYPT_CLIENT_MAGIC_BYTES} bytes, got {}",
            bytes.len()
        )
    })
}

fn derive_client_magic(
    resolver_public_key: &[u8; DNSCRYPT_KEY_BYTES],
    serial: u32,
) -> [u8; DNSCRYPT_CLIENT_MAGIC_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(resolver_public_key);
    hasher.update(serial.to_be_bytes());
    let digest = hasher.finalize();
    let mut magic = [0u8; DNSCRYPT_CLIENT_MAGIC_BYTES];
    magic.copy_from_slice(&digest[..DNSCRYPT_CLIENT_MAGIC_BYTES]);
    if magic[..7] == [0; 7] {
        magic[7] = 1;
    }
    magic
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caching::MokaDnsRecordCache;
    use crate::config::{ZoneConfig, ZoneRecordSetConfig, ZoneSoaConfig};
    use crate::dns::DnsQuestion;
    use crate::logging::{LoggingConfig, LoggingPipeline};
    use crate::policy::{PolicyRuntime, RuleEngineConfig};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::collections::BTreeMap;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }

    fn write_key(prefix: &str, bytes: [u8; DNSCRYPT_KEY_BYTES]) -> std::path::PathBuf {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;

        let path = unique_temp_path(prefix);
        fs::write(&path, STANDARD.encode(bytes)).expect("key write");
        path
    }

    fn test_runtime() -> (DnsCryptRuntime, StaticSecret) {
        let provider = write_key("dnscrypt-provider", [7u8; DNSCRYPT_KEY_BYTES]);
        let resolver = write_key("dnscrypt-resolver", [9u8; DNSCRYPT_KEY_BYTES]);
        let config = DnsCryptTransportConfig {
            listen_addr: "127.0.0.1:443".parse().expect("addr"),
            provider_name: "dnscrypt.example.".to_string(),
            provider_secret_key_path: provider.display().to_string(),
            resolver_secret_key_path: resolver.display().to_string(),
            cert_serial: 1,
            cert_valid_from: 1800000000,
            cert_valid_until: 1800086400,
            client_magic: Some("MTIzNDU2Nzg=".to_string()),
        };
        let runtime = DnsCryptRuntime::from_config(&config).expect("runtime");
        let _ = fs::remove_file(provider);
        let _ = fs::remove_file(resolver);
        (runtime, StaticSecret::from([3u8; DNSCRYPT_KEY_BYTES]))
    }

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
        DnsMessage::query(
            42,
            DnsQuestion {
                name: DnsName::parse_ascii("api.corp.internal.").expect("valid name"),
                record_type: RecordType::A,
                class: DnsClass::IN,
            },
        )
        .to_wire()
        .expect("query wire")
    }

    fn client_cipher(runtime: &DnsCryptRuntime, client_secret: &StaticSecret) -> XChaCha20Poly1305 {
        let resolver_public = PublicKey::from(&runtime.resolver_secret_key);
        let shared_secret = client_secret.diffie_hellman(&resolver_public);
        let key = derive_dnscrypt_aead_key(shared_secret.as_bytes());
        let key = Key::from(key);
        XChaCha20Poly1305::new(&key)
    }

    fn encrypted_client_packet(
        runtime: &DnsCryptRuntime,
        client_secret: &StaticSecret,
        wire: &[u8],
    ) -> Vec<u8> {
        let client_public = PublicKey::from(client_secret);
        let client_nonce_half = [5u8; QUERY_NONCE_HALF_BYTES];
        let cipher = client_cipher(runtime, client_secret);
        let nonce = build_query_nonce(&client_nonce_half);
        let mut padded = wire.to_vec();
        pad_dnscrypt_message(&mut padded, Some(256));
        let encrypted = encrypt_dnscrypt_payload(&cipher, &nonce, &padded).expect("encrypt");
        let mut packet = Vec::new();
        packet.extend_from_slice(&runtime.client_magic);
        packet.extend_from_slice(client_public.as_bytes());
        packet.extend_from_slice(&client_nonce_half);
        packet.extend_from_slice(&encrypted);
        packet
    }

    fn decrypt_server_response(
        runtime: &DnsCryptRuntime,
        client_secret: &StaticSecret,
        response: &[u8],
    ) -> DnsMessage {
        assert_eq!(
            &response[..DNSCRYPT_RESPONSE_MAGIC.len()],
            DNSCRYPT_RESPONSE_MAGIC
        );
        let mut client_nonce_half = [0u8; QUERY_NONCE_HALF_BYTES];
        client_nonce_half.copy_from_slice(
            &response[DNSCRYPT_RESPONSE_MAGIC.len()..DNSCRYPT_RESPONSE_MAGIC.len() + 12],
        );
        let mut resolver_nonce_half = [0u8; QUERY_NONCE_HALF_BYTES];
        resolver_nonce_half.copy_from_slice(
            &response[DNSCRYPT_RESPONSE_MAGIC.len() + 12..DNSCRYPT_RESPONSE_MAGIC.len() + 24],
        );
        let nonce = build_response_nonce(&client_nonce_half, &resolver_nonce_half);
        let cipher = client_cipher(runtime, client_secret);
        let decrypted = decrypt_dnscrypt_payload(
            &cipher,
            &nonce,
            &response[DNSCRYPT_RESPONSE_MAGIC.len() + 24..],
        )
        .expect("decrypt response");
        let wire = strip_dnscrypt_padding(&decrypted).expect("strip padding");
        DnsMessage::from_wire(&wire).expect("dns response")
    }

    #[test]
    fn padding_roundtrip_strips_iso_marker() {
        let mut message = b"dns-query".to_vec();
        pad_dnscrypt_message(&mut message, Some(64));

        assert_eq!(message.len(), 64);
        assert_eq!(
            strip_dnscrypt_padding(&message).expect("padding strips"),
            b"dns-query"
        );
    }

    #[test]
    fn padding_rejects_missing_marker() {
        let err = strip_dnscrypt_padding(&[1, 2, 3]).expect_err("should fail");
        assert!(err.contains("padding marker"));
    }

    #[test]
    fn certificate_payload_signs_expected_fields() {
        let provider_secret = [7u8; DNSCRYPT_KEY_BYTES];
        let signing_key = SigningKey::from_bytes(&provider_secret);
        let resolver_public = [9u8; DNSCRYPT_KEY_BYTES];
        let client_magic = *b"12345678";
        let payload =
            build_certificate_payload(&signing_key, &resolver_public, &client_magic, 7, 10, 20);

        assert_eq!(&payload[..4], CERT_MAGIC);
        assert_eq!(
            u16::from_be_bytes([payload[4], payload[5]]),
            DNSCRYPT_ES_VERSION_XCHACHA20_POLY1305
        );
        assert_eq!(payload.len(), 124);
        let signature = Signature::from_slice(&payload[8..72]).expect("signature");
        let signed = &payload[72..];
        let verify_key = VerifyingKey::from(&signing_key);
        verify_key
            .verify(signed, &signature)
            .expect("signature verifies");
        assert_eq!(&signed[..DNSCRYPT_KEY_BYTES], &resolver_public);
        assert_eq!(
            &signed[DNSCRYPT_KEY_BYTES..DNSCRYPT_KEY_BYTES + DNSCRYPT_CLIENT_MAGIC_BYTES],
            &client_magic
        );
    }

    #[test]
    fn dnscrypt_payload_uses_tag_prefix_wire_shape() {
        let key = [42u8; DNSCRYPT_KEY_BYTES];
        let key = Key::from(key);
        let cipher = XChaCha20Poly1305::new(&key);
        let nonce = [11u8; 24];
        let plaintext = b"payload";

        let encrypted = encrypt_dnscrypt_payload(&cipher, &nonce, plaintext).expect("encrypt");
        assert_eq!(encrypted.len(), plaintext.len() + DNSCRYPT_TAG_BYTES);

        let decrypted = decrypt_dnscrypt_payload(&cipher, &nonce, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn derived_client_magic_is_nonzero_prefix() {
        let magic = derive_client_magic(&[1u8; DNSCRYPT_KEY_BYTES], 1);
        assert_ne!(magic[..7], [0; 7]);
    }

    #[tokio::test]
    async fn udp_certificate_query_returns_txt_certificate() {
        let (runtime, _) = test_runtime();
        let query = DnsMessage::query(
            10,
            DnsQuestion {
                name: runtime.certificate_name.clone(),
                record_type: RecordType::TXT,
                class: DnsClass::IN,
            },
        )
        .to_wire()
        .expect("query wire");

        let response = handle_dnscrypt_udp_packet(
            &runtime,
            test_forwarder().await,
            &query,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53000)),
        )
        .await
        .expect("certificate response");

        let message = DnsMessage::from_wire(&response).expect("response parses");
        assert_eq!(message.header.id, 10);
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].record_type(), RecordType::TXT);
    }

    #[tokio::test]
    async fn udp_encrypted_query_roundtrips_through_forwarder() {
        let (runtime, client_secret) = test_runtime();
        let packet = encrypted_client_packet(&runtime, &client_secret, &query_wire());

        let response = handle_dnscrypt_udp_packet(
            &runtime,
            test_forwarder().await,
            &packet,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53000)),
        )
        .await
        .expect("encrypted response");

        let message = decrypt_server_response(&runtime, &client_secret, &response);
        assert_eq!(message.header.id, 42);
        assert_eq!(message.header.response_code, ResponseCode::NoError);
        assert_eq!(message.answers.len(), 1);
    }

    #[tokio::test]
    async fn udp_invalid_magic_is_dropped() {
        let (runtime, client_secret) = test_runtime();
        let mut packet = encrypted_client_packet(&runtime, &client_secret, &query_wire());
        packet[0] ^= 0xff;

        let response = handle_dnscrypt_udp_packet(
            &runtime,
            test_forwarder().await,
            &packet,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53000)),
        )
        .await;

        assert!(response.is_none());
    }

    #[tokio::test]
    async fn tcp_encrypted_query_uses_length_prefix_and_closes() {
        let (runtime, client_secret) = test_runtime();
        let packet = encrypted_client_packet(&runtime, &client_secret, &query_wire());
        let (mut client, server) = tokio::io::duplex(8192);
        let runtime = Arc::new(runtime);
        let server_runtime = runtime.clone();
        let server = tokio::spawn(async move {
            handle_dnscrypt_tcp_stream(
                server_runtime,
                test_forwarder().await,
                server,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 53000)),
            )
            .await
        });

        client
            .write_all(&(packet.len() as u16).to_be_bytes())
            .await
            .expect("write len");
        client.write_all(&packet).await.expect("write packet");
        let mut len_bytes = [0u8; 2];
        client.read_exact(&mut len_bytes).await.expect("read len");
        let len = usize::from(u16::from_be_bytes(len_bytes));
        let mut response = vec![0u8; len];
        client
            .read_exact(&mut response)
            .await
            .expect("read response");

        let message = decrypt_server_response(&runtime, &client_secret, &response);
        assert_eq!(message.header.id, 42);
        assert_eq!(message.answers.len(), 1);
        server.await.expect("server join").expect("server ok");
    }
}
