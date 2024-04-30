pub mod base64;
pub mod csv;
pub mod genpass;
pub mod http;
pub mod jwt;
pub mod text;

use anyhow::Result;
use clap::Parser;
use enum_dispatch::enum_dispatch;
use std::path::{Path, PathBuf};

pub use self::{base64::*, csv::*, genpass::*, http::*, jwt::*, text::*};

// rcli csv -i input.csv -o output.json --header -d ','
#[derive(Debug, Parser)]
#[command(name = "rcli", version, author = "Rust CLI", about, long_about =None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show CSV, or convert CSV to JSON")]
    Csv(CsvOpts),

    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),

    #[command(subcommand)]
    Base64(Base64SubCommand),

    #[command(subcommand)]
    Text(text::TextSubCommand),

    #[command(subcommand)]
    Http(HttpSubCommand),

    #[command(subcommand)]
    JWT(JWTSubCommand),
}

fn verify_file(filename: &str) -> Result<String, &'static str> {
    // if input is "-", it means read from stdin
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("File does not exist")
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    let path = Path::new(path);

    if Path::new(path).exists() && path.is_dir() {
        Ok(path.into())
    } else {
        Err("Path does not exist")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_input_file() {
        assert_eq!(verify_file("-"), Ok("-".into()));
        assert_eq!(verify_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(verify_file("non-existent.csv"), Err("File does not exist"));
    }
}
