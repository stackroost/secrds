use anyhow::Context;
use std::process::Command;

const SERVICE_NAME: &str = "ebpf-detector";

pub async fn run() -> anyhow::Result<()> {
    if Command::new("systemctl").arg("--version").output().is_ok() {
        let output = Command::new("systemctl")
            .arg("start")
            .arg(SERVICE_NAME)
            .output()
            .context("Failed to execute systemctl")?;
        
        if output.status.success() {
            println!(" Started {} service", SERVICE_NAME);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to start service: {}", stderr);
        }
    } else {
        let agent_path = "/usr/local/bin/ebpf-detector-agent";
        
        if !std::path::Path::new(agent_path).exists() {
            anyhow::bail!("Agent binary not found at {}. Please install first.", agent_path);
        }

        let pid_file = std::path::PathBuf::from("/var/run/ebpf-detector.pid");
        if pid_file.exists() {
            if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    let proc_path = format!("/proc/{}", pid);
                    if std::path::Path::new(&proc_path).exists() {
                        println!("  Daemon is already running (PID: {})", pid);
                        return Ok(());
                    }
                }
            }
        }

        let output = Command::new(agent_path)
            .spawn()
            .context("Failed to start agent")?;

        println!(" Started daemon (PID: {})", output.id());
    }

    Ok(())
}

