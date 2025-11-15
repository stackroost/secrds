.PHONY: all bpf go clean

all: bpf go

bpf:
	clang -O2 -g -target bpf -c bpf/ssh_accept.bpf.c -o secrds.bpf.o

go:
	go mod download
	go build -o secrds ./cmd/secrds

clean:
	rm -f secrds secrds.bpf.o

run: all
	sudo ./secrds

