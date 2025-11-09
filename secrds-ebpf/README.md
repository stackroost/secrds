# secrds-ebpf - eBPF Program

## Status

The eBPF program code is written but requires proper Aya build system setup.

## Building

For Aya 0.12, eBPF programs need to be compiled using:
1. Aya's build system (recommended)
2. Manual compilation with clang

See `BUILD-EBPF.md` for detailed instructions.

## Note

The Rust eBPF code structure is correct, but compilation requires:
- Aya build system setup
- Or manual compilation from Rust → LLVM IR → eBPF bytecode

For production use, you can temporarily use the original C eBPF program
compiled with clang until the Rust build system is fully set up.

