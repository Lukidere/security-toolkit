use owo_colors::{OwoColorize, colors::*};
use rustls::{self, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::sync::Arc;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

pub fn connect_to_remote(
    request: String,
    remote_address: SocketAddr,
    https: Option<String>,
) -> Result<String, String> {
    let mut is_https: bool = false;
    let mut hostname: String = String::from("localhost");
    if let Some(host) = https {
        hostname = host;
        is_https = true
    } else {
    }

    let stream = TcpStream::connect_timeout(&remote_address, Duration::from_secs(5))
        .map_err(|e| format!("Couldn't connect: {}", e.fg::<Red>().bold()))?;

    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

    if !is_https {
        send_and_receive(stream, request.as_bytes())
    } else {
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let config = Arc::new(config);

        let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
            .map_err(|e| format!("Invalid hostname for TLS SNI: {e}"))?;

        let mut conn = ClientConnection::new(config, server_name)
            .map_err(|e| format!("TLS client init failed: {e}"))?;

        let mut tls_stream = StreamOwned::new(conn, stream);

        tls_stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("TLS write failed: {e}"))?;

        // Czytaj odpowiedź
        let mut response = String::new();
        let mut buf = [0u8; 4096];
        loop {
            match tls_stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => response.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(format!("TLS read error: {e}")),
            }
        }
        Ok(response)
    }
}

fn send_and_receive(mut stream: TcpStream, data: &[u8]) -> Result<String, String> {
    stream
        .write_all(data)
        .map_err(|e| format!("write failed: {e}"))?;

    let mut response = String::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("read error: {e}")),
        }
    }
    Ok(response)
}
