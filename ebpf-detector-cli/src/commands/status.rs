use anyhow::Context;
use std::fs;
use std::path::PathBuf;

const PID_FILE: &str = "/var/run/ebpf-detector.pid";

pub async fn run() -> anyhow::Result<()> {
    let pid_file = PathBuf::from(PID_FILE);

    if !pid_file.exists() {
        println!("Daemon is not running");
        return Ok(());
    }

    let pid_str = fs::read_to_string(&pid_file)
        .context("Failed to read PID file")?;
    
    let pid: u32 = pid_str.trim().parse()
        .context("Invalid PID in file")?;

    let proc_path = format!("/proc/{}", pid);
    if PathBuf::from(&proc_path).exists() {
        println!("Daemon is running (PID: {})", pid);
    } else {
        println!("Daemon PID file exists but process is not running");
        fs::remove_file(&pid_file).ok();
    }

    Ok(())
}

