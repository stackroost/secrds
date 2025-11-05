use anyhow::Context;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

mod commands;
mod utils;

use commands::{alerts, config, stats, status, start, stop, restart};

#[derive(Parser)]
#[command(name = "ebpf-detector")]
#[command(about = "eBPF Security Monitor CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Status,
    Alerts {
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    Stats,
    Config,
    Start,
    Stop,
    Restart,
}

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            status::run().await?;
        }
        Commands::Alerts { limit } => {
            alerts::run(limit).await?;
        }
        Commands::Stats => {
            stats::run().await?;
        }
        Commands::Config => {
            config::run().await?;
        }
        Commands::Start => {
            start::run().await?;
        }
        Commands::Stop => {
            stop::run().await?;
        }
        Commands::Restart => {
            restart::run().await?;
        }
    }

    Ok(())
}

