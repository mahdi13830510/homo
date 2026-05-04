//! Binary entry point.

use clap::Parser;
use colored::Colorize;

mod cli;

fn main() {
    let parsed = cli::Cli::parse();
    if let Err(err) = cli::run(parsed) {
        eprintln!("{} {err}", "error:".red().bold());
        std::process::exit(1);
    }
}
