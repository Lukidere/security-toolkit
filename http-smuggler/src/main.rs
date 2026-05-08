use clap::Parser;
mod smuggler;
use owo_colors::{OwoColorize, colors::*};
use std::fs::File;

use crate::smuggler::{InputType, SmuggleType, check_host, request_creator};
#[derive(Clone, Parser)]
#[command(version = "1", about = "HTTP smuggling utility", long_about)]
struct Cli {
    ip: String,
    #[arg(short,long,value_parser=ParseSmuggleType)]
    mode: SmuggleType,
    #[arg(short, long, conflicts_with = "file")]
    request: String,
    #[arg(short, long)]
    file: Option<String>,
    #[arg(long)]
    https: bool,
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

    if let Ok(addr) = check_host(&cli.ip) {
        if let Some(req) = request_creator(cli.mode, input_type) {}
    } else {
        eprintln!("Failed to send http smuggle due to previous errors");
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
