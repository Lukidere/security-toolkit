use clap::{Parser, };
mod smuggler;
use std::fs::File;
use owo_colors::{OwoColorize,colors::*};

use crate::smuggler::check_host;
#[derive(Clone)]
enum SmuggleType {
    CLTE,
    TECL

}
#[derive(Parser)]
#[command(version="1",about="HTTP smuggling utility",long_about)]
struct Cli {
    ip: String,
    #[arg(short,long,value_parser=ParseSmuggleType)]
    mode: String,
    #[arg(short,long,conflicts_with="file")]
    request: String,
    #[arg(short,long)]
    file: Option<String>,
    #[arg(long)]
    https: bool,
    #[arg(short,long)]
    debug:bool
}
fn main() {
    let cli = Cli::parse();
    if let Ok(addr) = check_host(&cli.ip) {
        
    }
}



fn ParseSmuggleType(s:&str) -> Result<SmuggleType,String> {
    match s.to_lowercase().as_str() {
        "cl.te" => Ok(SmuggleType::CLTE),
        "te.cl" => Ok(SmuggleType::TECL),
        _ => Err(format!("Possible options are:\n{}\n{}","cl.te".fg::<Green>().bold(),"te.cl".fg::<Blue>().bold()))
    }

}
