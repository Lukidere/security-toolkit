use futures_rustls::pki_types::ServerName;
use regex::Regex;
use tokio_rustls::{TlsConnector,  rustls::{ClientConfig, RootCertStore}};
use owo_colors::{OwoColorize,colors::*};
use ping_async::IcmpEchoStatus;
use socket2::SockRef;
use tokio::{io::{AsyncWriteExt,AsyncReadExt}, net::TcpStream, time::timeout};
use std::{net::IpAddr, sync::Arc};
use serde::Serialize;
use tracing::*;
use std::{fmt,io::ErrorKind, time::Duration};
#[derive(Debug,PartialEq,Serialize)]
pub enum ConnectResponse {
    OK,
    TIMEOUT,
    REJECTED,
    OTHER,
    CLOSED
}
pub enum ServiceType {
    HTTP,
    HTTPS,
    FTP,
    SSH
}
#[derive(Serialize)]
pub struct PortResponse {
    pub banner: Option<String>,
    pub port: u16,
    pub response: ConnectResponse
}
impl ServiceType {
    fn from_port(port:u16) -> Option<ServiceType> {
        match port {
            80 => Some(ServiceType::HTTP),
            22=> Some(ServiceType::SSH),
            21=> Some(ServiceType::FTP),
            443=> Some(ServiceType::HTTPS),
            _ => None
        }
    }
    
    async fn fetch_banner(&self,mut conn:TcpStream,ip:&str) -> Option<String> {
        let mut buf: [u8;100000] = [0;100000];
        match &self {
            ServiceType::HTTP => {
                let request = b"GET / HTTP/1.0\r\nHost:rust-scanner.com\r\n\r\n";
                 if conn.write_all(request).await.is_err() {
                     return None
                 };
                 let future_stream = conn.read(&mut buf);
                 match timeout(Duration::from_secs(5), future_stream).await {
                    
                    Ok(Ok(size )) if size >0 => {

                       Some(analyze_http_banner(String::from_utf8_lossy(&buf[..size]).to_string().as_str()))
                    },
                    _ => None
                }
                
            },
            ServiceType::HTTPS => {
                
let mut root_cert_store = RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
let config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
let connector = TlsConnector::from(Arc::new(config));
        let ip_addr: IpAddr = ip.parse().unwrap();
        let servername = ServerName::from(ip_addr);
        let mut tls_stream = connector.connect(servername, conn).await.unwrap();
        let request = b"GET / HTTP/1.0\r\nHost:rust-scanner.com";
        tls_stream.write_all(request).await.unwrap();

        let mut buf: [u8;1024] = [0;1024];
        let size = tls_stream.read(&mut buf).await.unwrap();
        Some(String::from_utf8_lossy(&buf[..size]).to_string())
            }
            _ => {
                let size = conn.read(&mut buf).await.unwrap();
                Some(analyze_http_banner(String::from_utf8_lossy(&buf[..size]).to_string().as_str()))

            }

        }
    }
}
impl fmt::Display for ConnectResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,"{:?}",self)

    }

}
impl PortResponse {
    fn new(connresp:ConnectResponse,port:u16) -> Self {
        PortResponse{
            banner: None,
            port,
            response: connresp
        }
    }
}
impl fmt::Display for PortResponse {
    fn fmt(&self, f:&mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ban) = &self.banner {


        write!(f," {}/{}:{}",self.port.fg::<Blue>().bold(),self.response.fg::<Green>().italic(),ban)
        } else if self.response == ConnectResponse::OK {
            
        write!(f," {}/{}",self.port.fg::<Blue>().bold(),self.response.fg::<Green>().italic())
        } else {

        write!(f," {}/{}",self.port.fg::<Blue>().bold(),self.response.fg::<Red>().italic())
        }
    }

}
pub async fn scan_port(port:u16,ip:&str) -> PortResponse {
    let timeout_duration = Duration::from_secs(2);
    let address = format!("{ip}:{port}");
    let connect_future = TcpStream::connect(address);
    let resp:PortResponse;
    resp = match timeout(timeout_duration, connect_future).await {
        Ok(Ok(conn)) => {

            let sock = SockRef::from(&conn);
            sock.set_linger(Some(Duration::from_secs(0))).unwrap();
            if let Some(srv) = ServiceType::from_port(port) {
                match ServiceType::fetch_banner(&srv, conn, ip).await {
                    Some(str) => PortResponse {banner:Some(str),port,response: ConnectResponse::OK},
                    None => PortResponse {banner:None,port,response: ConnectResponse::OK}


                }
            } else {

              PortResponse {
                banner: None,
                port,
                response: ConnectResponse::OK
            }
        }
    }

        
            
        
        Ok(Err(e)) => {
            match e.kind() {
                ErrorKind::ConnectionRefused  => PortResponse::new(ConnectResponse::REJECTED,port),
                ErrorKind::HostUnreachable => PortResponse::new(ConnectResponse::CLOSED,port),
                _=> PortResponse::new(ConnectResponse::OTHER,port),
                

            }

        }
        Err(_) => {
             PortResponse::new(ConnectResponse::TIMEOUT,port)
        }
        };
        resp
    

}

pub async fn ping_host(addr:String) {
    event!(Level::DEBUG,"Starting ICMP Scan");
    let target = addr.parse::<IpAddr>().unwrap();
    let pinger = ping_async::IcmpEchoRequestor::new(target,None,None,Some(Duration::from_secs(3))).unwrap();
    let reply = pinger.send().await;
    match reply {
        Ok(val) => match val.status() {
            IcmpEchoStatus::Success => println!("Host: {} is {}",addr.blue().italic(),"up".green().bold()),
            _ => println!("Host: {} is {}",addr.blue().italic(),"down".red().bold())
        }
        Err(e) => println!("Couldnt connect to host:{}, reason:{}",addr.blue().italic(),e.fg::<Red>().bold())
    }

}

pub fn analyze_http_banner(banner:&str) -> String {
    let server_re = Regex::new(r"(?i)Server:\s*([^\r\n]+)").unwrap();
    if let Some(caps) = server_re.captures(banner) {
        let server_name = caps[1].trim();
        if !server_name.is_empty() {
            return format!("Server: {}", server_name);
        }
    }
    let title_re = Regex::new(r"(?i)<title>\s*(.*?)\s*</title>").unwrap();
    if let Some(caps) = title_re.captures(banner) {
        let title = caps[1].trim();
        if !title.is_empty() {
            return format!("Title: {}", title);
        }
    }

    if let Some(first_line) = banner.lines().next() {
        let trimmed = first_line.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    "Unknown HTTP Service".to_string()
}
