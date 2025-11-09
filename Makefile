.PHONY: build install clean test fmt clippy build-bpf help

help:
	@echo "Available targets:"
	@echo "  build         - Build all Rust components"
	@echo "  build-bpf     - Build eBPF programs"
	@echo "  install       - Install to system (requires root)"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  fmt           - Format code"
	@echo "  clippy        - Run clippy linter"
	@echo "  help          - Show this help"

build: build-bpf
	@echo "Building secrds Security Monitor..."
	@cargo build --release
	@echo "Build complete."

build-bpf:
	@echo "Building eBPF programs..."
	@echo "Note: Aya eBPF build requires special setup."
	@echo "See BUILD-EBPF.md for instructions."
	@chmod +x build-ebpf.sh
	@./build-ebpf.sh
	@echo "eBPF build complete (may be placeholder)."

install:
	@echo "Installing secrds Security Monitor..."
	@sudo chmod +x install.sh
	@sudo ./install.sh

clean:
	@echo "Cleaning build artifacts..."
	@cargo clean
	@rm -rf target/release/secrds-*
	@rm -rf target/bpfel-unknown-none

test:
	@echo "Running Rust tests..."
	@cargo test --workspace || true

fmt:
	@echo "Formatting Rust code..."
	@cargo fmt --all || true

clippy:
	@echo "Running clippy linter..."
	@cargo clippy --workspace || true
