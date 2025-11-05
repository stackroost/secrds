use anyhow::Context;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const SERVICE_NAME: &str = "ebpf-detector";
const PID_FILE: &str = "/var/run/ebpf-detector.pid";

pub async fn run() -> anyhow::Result<()> {
    if Command::new("systemctl").arg("--version").output().is_ok() {
        let output = Command::new("systemctl")
            .arg("stop")
            .arg(SERVICE_NAME)
            .output()
            .context("Failed to execute systemctl")?;

        if output.status.success() {
            println!("Stopped {} service", SERVICE_NAME);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not loaded") || stderr.contains("not found") {
                println!("Service is not running");
                return Ok(());
            }
            anyhow::bail!("Failed to stop service: {}", stderr);
        }
    } else {
        let pid_file = PathBuf::from(PID_FILE);
        
        if !pid_file.exists() {
            println!("Daemon is not running (no PID file found)");
            return Ok(());
        }

        let pid_str = fs::read_to_string(&pid_file)
            .context("Failed to read PID file")?;
        
        let pid: u32 = pid_str.trim().parse()
            .context("Invalid PID in file")?;

        let proc_path = format!("/proc/{}", pid);
        if !PathBuf::from(&proc_path).exists() {
            println!("Process with PID {} is not running", pid);
            fs::remove_file(&pid_file).ok();
            return Ok(());
        }

        let output = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .output()
            .context("Failed to send SIGTERM")?;

        if output.status.success() {
            println!("Sent SIGTERM to daemon (PID: {})", pid);
            
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            if PathBuf::from(&proc_path).exists() {
                println!("Process still running, sending SIGKILL...");
                Command::new("kill")
                    .arg("-KILL")
                    .arg(pid.to_string())
                    .output()
                    .ok();
            }
            
            fs::remove_file(&pid_file).ok();
        } else {
            anyhow::bail!("Failed to stop daemon");
        }
    }

    Ok(())
}

