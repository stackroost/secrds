# secrds

secrds is a security monitoring tool that uses eBPF (Extended Berkeley Packet Filter) to monitor SSH connections and authentication events on Linux systems. It tracks SSH accept connections and authentication attempts in real-time, providing detailed logging of SSH activity.

## What it does

This tool monitors your system's SSH activity by:
- Tracking SSH connection accept events
- Monitoring SSH authentication attempts
- Logging all SSH-related activity to help you understand who is connecting to your system

## Requirements

- Linux kernel with eBPF support (Linux 4.9+)
- Go 1.21 or later
- Clang compiler with BPF target support
- Root/sudo privileges to run the monitoring tool

## Building

To build the project, run:

```bash
make all
```

This will:
1. Compile the BPF programs (`.bpf.o` files)
2. Build the Go binary (`secrds`)

## Running

After building, run the tool with sudo privileges:

```bash
sudo ./secrds
```

Or use the Makefile shortcut:

```bash
make run
```

The tool will start monitoring SSH events and log them to `/var/log/secrds` (or `/etc/secrds/logs` if `/var/log` is not available).

## Cleaning up

To remove build artifacts:

```bash
make clean
```

## How it works

secrds uses eBPF tracepoints and uprobes to hook into SSH-related system calls and library functions. It captures events as they happen and logs them for security analysis and monitoring purposes.

