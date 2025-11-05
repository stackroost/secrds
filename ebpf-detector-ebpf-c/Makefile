CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -g -O2 -Wall
CFLAGS += -target bpf
CFLAGS += -D__TARGET_ARCH_$(ARCH)
CFLAGS += -I../include

CFLAGS += -I/usr/include

CFLAGS += -D__BPF__
CFLAGS += -D__BPF_TRACING__
CFLAGS += -Wno-address-of-packed-member
CFLAGS += -Wno-unknown-warning-option
CFLAGS += -Wno-unused-value
CFLAGS += -Wno-incompatible-pointer-types

all: ssh_kprobe.bpf.o tcp_trace.bpf.o

%.bpf.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f *.bpf.o

.PHONY: all clean

