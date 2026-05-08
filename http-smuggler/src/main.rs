use clap::{Parser, };
mod smuggler;
use std::fs::File;
use owo_colors::{OwoColorize,colors::*};

use crate::smuggler::{check_host, SmuggleType,InputType};
#[derive(Clone)]
#[derive(Parser)]
#[command(version="1",about="HTTP smuggling utility",long_about)]
struct Cli {
    ip: String,
    #[arg(short,long,value_parser=ParseSmuggleType)]
    mode: SmuggleType,
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
        println!("{:#?},",create_clte_request("/test/path".to_owned(), "vuln_host".to_owned(), "3".to_owned(),"GET /login/admin".to_owned()));
    }
}



fn ParseSmuggleType(s:&str) -> Result<SmuggleType,String> {
    match s.to_lowercase().as_str() {
        "clte" => Ok(SmuggleType::CLTE),
        "tecl" => Ok(SmuggleType::TECL),
        _ => Err(format!("Possible options are:\n{}\n{}","clte".fg::<Green>().bold(),"tecl".fg::<Blue>().bold()))
    }

}
