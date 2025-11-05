use anyhow::Context;

pub async fn run() -> anyhow::Result<()> {
    println!("Restarting daemon...");
    
    crate::commands::stop::run().await?;
    
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    
    crate::commands::start::run().await?;
    
    println!("Daemon restarted successfully");
    Ok(())
}

