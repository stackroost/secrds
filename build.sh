#!/bin/bash
set -e

echo "Building eBPF Security Monitor..."

# Check if nightly toolchain is installed
if ! rustup toolchain list | grep -q nightly; then
    echo "Installing nightly Rust toolchain..."
    rustup toolchain install nightly
fi

# Install rust-src component (required for building std from source)
echo "Ensuring rust-src component is installed..."
rustup component add rust-src --toolchain nightly 2>/dev/null || true

# Install bpf-linker if not present (required for linking eBPF programs)
if ! command -v bpf-linker &> /dev/null; then
    echo "Installing bpf-linker (this may take a few minutes)..."
    cargo +nightly install bpf-linker --locked || {
        echo "Error: Failed to install bpf-linker. Please install it manually:"
        echo "  cargo +nightly install bpf-linker"
        exit 1
    }
fi

# Build Rust eBPF programs
echo "Building Rust eBPF programs..."
cd ebpf-detector-ebpf

# For eBPF, bpfel-unknown-none is a built-in target in rustc
# We don't need to install it via rustup - we build core from source
# The -Zbuild-std=core flag builds the core library from source for this target
echo "Building eBPF program with core library from source..."
cargo +nightly build -Zbuild-std=core --release --target bpfel-unknown-none
cd ..

# Build C eBPF programs
echo "Building C eBPF programs..."
cd ebpf-detector-ebpf-c
make
cd ..

# Build agent
echo "Building agent daemon..."
cargo build --release --bin ebpf-detector-agent

# Build CLI
echo "Building CLI tool..."
cargo build --release --bin ebpf-detector

echo "Build complete!"
echo ""
echo "Binaries:"
echo "  - Agent: target/release/ebpf-detector-agent"
echo "  - CLI: target/release/ebpf-detector"

