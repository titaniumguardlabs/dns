use crate::forwarder::RuntimeState;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub(crate) async fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

pub(crate) async fn serve(listener: TcpListener, state: RuntimeState) -> std::io::Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let mut request = [0u8; 512];
            let read = stream.read(&mut request).await.unwrap_or(0);
            let path = request_path(&request[..read]).unwrap_or("/");
            let (status, body) = match path {
                "/live" => ("200 OK", "ok\n".to_string()),
                "/ready" if state.ready() => ("200 OK", "ready\n".to_string()),
                "/ready" => ("503 Service Unavailable", "not ready\n".to_string()),
                "/metrics" => ("200 OK", state.metrics()),
                _ => ("404 Not Found", "not found\n".to_string()),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

fn request_path(request: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(request).ok()?;
    let line = text.split("\r\n").next()?;
    let mut parts = line.split_whitespace();
    let _method = parts.next()?;
    parts.next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn health_endpoint_reports_ready_and_metrics() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let state = RuntimeState::default();
        state.mark_ready();
        let _guard = state.query_guard();
        state.inc_policy_denies();
        tokio::spawn(serve(listener, state));

        let ready = request(addr, "/ready").await;
        assert!(ready.starts_with("HTTP/1.1 200 OK\r\n"));
        let metrics = request(addr, "/metrics").await;
        assert!(metrics.contains("# HELP dns_active_queries DNS queries currently being handled.\n"));
        assert!(metrics.contains("# TYPE dns_policy_denials_total counter\n"));
        assert!(metrics.contains("dns_active_queries 1\n"));
        assert!(metrics.contains("dns_policy_denials_total 1\n"));
    }

    #[tokio::test]
    async fn readiness_fails_while_draining() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let state = RuntimeState::default();
        state.mark_ready();
        state.mark_draining();
        tokio::spawn(serve(listener, state));

        let ready = request(addr, "/ready").await;
        assert!(ready.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    }

    async fn request(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nhost: local\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read");
        String::from_utf8(response).expect("utf8")
    }
}
