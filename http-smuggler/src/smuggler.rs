use dns_lookup::lookup_host;

use std::{error::Error, net::IpAddr};





pub fn check_host(ip_addr: &str) -> Result<IpAddr,Box<dyn Error>> {
    let ip = lookup_host(ip_addr)?.next().ok_or("Couldnt find host address")?;
    Ok(ip)
    


}


pub fn create_http_request() -> String {
    let request = format!(r"
    POST /api/upload HTTP/1.1\r\n
Host: exampleapp.pl\r\n
Content-Type: application/json\r\n
Content-Length: 45\r\n
Connection: close\r\n
\r\n");
    request

}
