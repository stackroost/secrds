use clap::{Parser, Subcommand};
use serde_json;
use std::fs;
use std::path::PathBuf;

mod commands;

#[derive(Parser)]
#[command(name = "secrds")]
#[command(about = "secrds Security Monitor CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show recent alerts
    Alerts {
        /// Limit number of alerts to show
        #[arg(short, long, default_value_t = 50)]
        limit: usize,
    },
    /// Clean log files and optionally event storage
    Clean {
        /// Remove all data including event storage and kernel-level eBPF maps
        #[arg(short, long)]
        all: bool,
    },
    /// Show configuration
    Config,
    /// Restart the secrds service
    Restart,
    /// Start the secrds service
    Start,
    /// Show statistics
    Stats,
    /// Show service status
    Status,
    /// Stop the secrds service
    Stop,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Alerts { limit } => commands::alerts(limit),
        Commands::Clean { all } => commands::clean(all),
        Commands::Config => commands::config(),
        Commands::Restart => commands::restart(),
        Commands::Start => commands::start(),
        Commands::Stats => commands::stats(),
        Commands::Status => commands::status(),
        Commands::Stop => commands::stop(),
    }
}

