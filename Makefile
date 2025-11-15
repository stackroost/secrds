.PHONY: all bpf go clean

all: bpf go

bpf:
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/ssh_accept.bpf.c -o secrds.bpf.o
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/ssh_auth.bpf.c -o secrds_auth.bpf.o

go:
	go mod download
	go build -o secrds ./cmd/secrds

clean:
	rm -f secrds secrds.bpf.o secrds_auth.bpf.o

run: all
	sudo ./secrds

