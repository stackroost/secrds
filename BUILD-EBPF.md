# Building Aya eBPF Programs

Aya eBPF programs require special compilation. Here are the options:

## Option 1: Use Aya Template (Recommended)

The easiest way is to use Aya's template system:

```bash
cargo install aya-toolchain
cd secrds-ebpf
cargo build --release
```

## Option 2: Manual Build with rustc + clang

Since `bpfel-unknown-none` target is not available in stable Rust, you can:

1. Compile Rust to LLVM IR:
```bash
cd secrds-ebpf
rustc --emit=llvm-ir --target bpfel-unknown-none src/lib.rs
```

2. Compile LLVM IR to eBPF with clang:
```bash
clang -target bpf -O2 -g -c output.ll -o secrds-ebpf.bpf.o
```

## Option 3: Use Pre-compiled eBPF

For now, you can use the original C eBPF program (`trace_ssh_guard.c`) 
and compile it with clang until the Rust eBPF build is set up:

```bash
cd secrds-programs  # if you still have the C version
clang -O2 -g -target bpf -c trace_ssh_guard.c -o trace_ssh_guard.bpf.o
```

## Current Status

The Rust eBPF code is written but needs proper build setup. The agent
can load pre-compiled eBPF programs from `/usr/local/lib/secrds/`.

For production, set up the Aya build system or use the C version temporarily.

