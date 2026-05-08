CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/s390x/s390/')

BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH) -O2 -g \
	-Wall -Werror \
	$(shell pkg-config --cflags libbpf 2>/dev/null)

CFLAGS  := -O2 -Wall -Werror
LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

.PHONY: all clean

all: block-dirtyfrag

block_dirtyfrag.bpf.o: block_dirtyfrag.bpf.c block_dirtyfrag.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

block_dirtyfrag.skel.h: block_dirtyfrag.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

block-dirtyfrag: block_dirtyfrag.c block_dirtyfrag.h block_dirtyfrag.skel.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f block_dirtyfrag.bpf.o block_dirtyfrag.skel.h block-dirtyfrag
