use clap::Parser;
mod createrequest;
use owo_colors::{OwoColorize, colors::*};
use std::fs::File;
mod sender;
use crate::{
    createrequest::{InputType, SmuggleType, check_host, request_creator},
    sender::connect_to_remote,
};
#[derive(Clone, Parser)]
#[command(version = "1", about = "HTTP smuggling utility", long_about)]
struct Cli {
    ip: String,
    #[arg(short,long,value_parser=ParseSmuggleType)]
    mode: SmuggleType,
    #[arg(short, long, conflicts_with = "file")]
    request: Option<String>,
    #[arg(short, long)]
    https: Option<String>,
    #[arg(short, long)]
    file: Option<String>,
    #[arg(short, long)]
    debug: bool,
}
fn main() {
    let cli = Cli::parse();
    let input_type = if cli.file.is_some() {
        InputType::File
    } else {
        InputType::Stdio
    };
    let ishttps = if (cli.https.is_some()) { true } else { false };
    if let Ok(addr) = check_host(&cli.ip, ishttps) {
        if let Some(req) = request_creator(cli.mode, input_type) {
            match connect_to_remote(req, addr, cli.https) {
                Ok(val) => println!("{val}"),
                Err(e) => println!("Error connecting to remote: {e}"),
            }
        } else {
            eprintln!("Failed to send http smuggle due to previous errors");
        }
    } else {
        println!("Failed to lookup host:{}", cli.ip.fg::<Red>().bold());
    }
}

fn ParseSmuggleType(s: &str) -> Result<SmuggleType, String> {
    match s.to_lowercase().as_str() {
        "clte" => Ok(SmuggleType::CLTE),
        "tecl" => Ok(SmuggleType::TECL),
        _ => Err(format!(
            "Possible options are:\n{}\n{}",
            "clte".fg::<Green>().bold(),
            "tecl".fg::<Blue>().bold()
        )),
    }
}
