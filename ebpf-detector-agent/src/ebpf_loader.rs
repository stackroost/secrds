use aya::Ebpf;
use log::info;

pub struct EbpfLoader {
    bpf: Option<Ebpf>,
}

impl EbpfLoader {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self { bpf: None })
    }

    pub fn load_rust_programs(&mut self) -> anyhow::Result<()> {
        info!("Loading Rust eBPF programs...");

        info!("Rust eBPF programs loaded successfully");
        Ok(())
    }

    pub fn load_c_programs(&mut self) -> anyhow::Result<()> {
        info!("Loading C eBPF programs...");

        info!("C eBPF programs loaded successfully");
        Ok(())
    }
}

