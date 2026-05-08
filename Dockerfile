FROM registry.fedoraproject.org/fedora:latest AS builder

RUN dnf install -y \
    --setopt=install_weak_deps=0 \
    clang bpftool \
    libbpf-devel elfutils-libelf-devel zlib-devel \
    make pkg-config gcc \
    && dnf clean all

WORKDIR /build
COPY block_dirtyfrag.bpf.c block_dirtyfrag.h block_dirtyfrag.c Makefile ./
RUN make

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

RUN microdnf install -y libbpf elfutils-libelf zlib && microdnf clean all

COPY --from=builder /build/block-dirtyfrag /usr/local/bin/block-dirtyfrag

ENTRYPOINT ["/usr/local/bin/block-dirtyfrag"]
