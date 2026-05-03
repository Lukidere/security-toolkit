

mod scanning;
use std::sync::Arc;
use scanning::*;
use clap::{Parser,};
use tokio::{sync::{Semaphore, mpsc}, task::JoinSet};
use owo_colors::{colors::*,OwoColorize};
use tracing::{event,Level};
#[derive(Parser)]
#[command(version="1",about="TCP Scanner",long_about = "Scans ports and grabs banner if it exists")]
struct Cli {
    ip: String,
    #[arg(short = 'i',long="isup",conflicts_with="ports")]
    isup:bool,
    #[arg(short,long,value_delimiter=',')]
    pub ports : Option<Vec<String>>,
    #[arg(short,long)]
    json:bool,
    #[arg(short,long)]
    debug:bool
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if cli.debug {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
    }

    match cli.ports {
        Some(ports) => { 
            let result = scan_ports(ports, cli.ip).await;
            if cli.json {
                let json_resp = serde_json::to_string(&result).unwrap();
                println!("{json_resp}");
            } else {
                result.iter().for_each(|item| println!("{}",item))
            }

        }
        None => ping_host(cli.ip).await,
    }
    event!(Level::DEBUG,"Scan has finished");
    
    


}
pub async fn scan_ports(ports:Vec<String>,addr:String) -> Vec<PortResponse> {
    event!(Level::DEBUG,"Starting port scan");
    let (tx,mut rx) = mpsc::channel::<(u16,PortResponse)>(256);
    let ports = get_all_ports(ports);
    let mut set = JoinSet::<()>::new();
    let semaphore = Arc::new(Semaphore::new(256));
    println!("Scanning ports for ip: {}",addr.fg::<Green>().bold());
    let collector = tokio::spawn(async move {
        let mut v: Vec<PortResponse> = Vec::new();
        while let Some((_port,resp)) = rx.recv().await {
            v.push(resp);
        }
        v
    });
    for &port in ports.iter() {
        let ip = addr.clone();
        event!(Level::DEBUG,"scanning port: {}",port);
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let tx2 = tx.clone();
        set.spawn(async move {
            match tx2.send((port,scan_port(port,&ip).await)).await {
                Ok(_) => (),
                Err(_) => tx2.closed().await
            }

                   
            drop(permit);
        });
    }
    drop(tx);
    while let Some(res) = set.join_next().await {
        if let Err(e) = res {
            eprintln!("blad wykonania: {e}")
        }
    
    }
    collector.await.unwrap()
    
}

fn get_all_ports(v:Vec<String>) -> Vec<u16> {
    let mut all_ports:Vec<u16> = v.into_iter().flat_map(|s| ports_in_range(&s).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    })).collect();
    all_ports.sort();
    all_ports.dedup();
    all_ports
    

}


fn ports_in_range(s:&str) -> Result<Vec<u16>,String> {
    if s.contains("-") {
        if let Some((start,end)) = s.split_once('-') {
            let start:u16 = start.parse::<u16>().map_err(|_| "start not a number")?;
            let end:u16= end.parse::<u16>().map_err(|_| "end not a number")?;
            if start > end {
                return Err("Start higher than end".into())
            }
            if start <= 0 {
                return Err("Start lower than 1".into())
            }
            return Ok((start..=end).collect())
        } else {
            return Err("failed to parse range usage: <StartingPortNumber>-<EndingPortNumber>".into())
        }

    } else if  s.contains(",") {
        let ports: Vec<u16> = s.split(',').filter_map(|s| s.parse::<u16>().ok()).collect();
        Ok(ports)
    }
    else  {
        let port:u16 = s.parse().map_err(|_| "port not a number")?;
        Ok(vec![port])
    }
}

#[cfg(test)]
mod tests
    {
        use super::*;
        #[test]
        fn parse_ports() {
            let input: Vec<&str> = vec!["1-3","4,5,6","7-8","10-15"];
            let input:Vec<String> = input.into_iter().map(|item| item.to_owned()).collect();
            let output = get_all_ports(input);
            assert_eq!(Vec::from([1,2,3,4,5,6,7,8,10,11,12,13,14,15]),output)
            

        }
    }
