use futures_rustls::pki_types::ServerName;
use regex::Regex;
use tokio_rustls::{TlsConnector,  rustls::{ClientConfig, RootCertStore}};
use owo_colors::{OwoColorize,colors::*};
use ping_async::IcmpEchoStatus;
use socket2::SockRef;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{self, TcpStream, lookup_host}, time::timeout};
use std::{net::{IpAddr, SocketAddr}, str::FromStr, sync::Arc};
use serde::Serialize;
use tracing::*;
use std::{fmt,io::ErrorKind, time::Duration};
#[derive(Debug,PartialEq,Serialize)]
pub enum ConnectResponse {
    OK,
    Closed,
    Filtered,
    Unreachable,
   Unknown, 
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
    
    async fn fetch_banner(&self,mut conn:TcpStream,ip:SocketAddr) -> Option<String> {
        let mut buf: [u8;1024] = [0;1024];
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
        
        let servername = ServerName::from(ip.ip());
        let mut tls_stream = connector.connect(servername, conn).await.ok()?;
        let request = b"GET / HTTP/1.0\r\nHost:rust-scanner.com";
        let size = match timeout(Duration::from_secs(5), tls_stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };
    Some(String::from_utf8_lossy(&buf[..size]).to_string())
            }
            _ => {
                match timeout(Duration::from_secs(3), conn.read(&mut buf)).await {
                    Ok(Ok(size)) if size>0 => {
                        Some(analyze_http_banner(&String::from_utf8_lossy(&buf[..size])))
                    },
                    _ => None


            }
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
pub async fn scan_port(port:u16,ip:IpAddr) -> PortResponse {
    let timeout_duration = Duration::from_secs(2);
    let resp:PortResponse;
    let socket= SocketAddr::new(ip,port);
    let connect_future = TcpStream::connect(socket.clone());
    resp = match timeout(timeout_duration, connect_future).await {
        Ok(Ok(conn)) => {

            let sock = SockRef::from(&conn);
            sock.set_linger(Some(Duration::from_secs(0))).unwrap();
            if let Some(srv) = ServiceType::from_port(port) {
                match ServiceType::fetch_banner(&srv, conn, socket).await {
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
                ErrorKind::ConnectionRefused  => PortResponse::new(ConnectResponse::Closed,port),
                ErrorKind::HostUnreachable => PortResponse::new(ConnectResponse::Unreachable,port),
                _=> PortResponse::new(ConnectResponse::Unknown,port),
                

            }

        }
        Err(_) => {
             PortResponse::new(ConnectResponse::Filtered,port)
        }
        };
        resp
    

}

pub async fn ping_host(addr:String) {
    event!(Level::DEBUG,"Starting ICMP Scan");
    let query = if addr.contains(':') { addr.clone() } else { format!("{addr}:0") };
    let target = match lookup_host(query).await {
        Ok(mut val) => match val.next(){
            Some(val) => val,
            None => { println!("Failed to lookup host, make sure that host exists") ;
                return; }
        },
        Err(_) => {println!("Failed to lookup host, make sure that host exists");
            return; }
    };

    let pinger = ping_async::IcmpEchoRequestor::new(target.ip(),None,None,Some(Duration::from_secs(3))).unwrap();
    let reply = pinger.send().await;
    match reply {
        Ok(val) => match val.status() {
            IcmpEchoStatus::Success => println!("Host: {} is {}",target.ip().blue().italic(),"up".green().bold()),
            _ => println!("Host: {} is {}",target.ip().blue().italic(),"down".red().bold())
        }
        Err(e) => println!("Couldnt connect to host:{}, reason:{}",target.ip().blue().italic(),e.fg::<Red>().bold())
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

pub async fn parse_or_resolve(input:&str) -> Result<IpAddr,String> {
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(ip)
    }
    lookup_host(input)
        .await
        .map_err(|e| format!("DNS lookup failed: {e}"))?
        .next()
        .map(|sa| sa.ip())
        .ok_or_else(|| format!("No addresses for {input}"))
    
}
