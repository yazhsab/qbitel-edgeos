# Qbitel EdgeOS - Reproducible Build Environment
# Usage:
#   docker build -t qbitel-edgeos-builder .
#   docker run --rm -v $(pwd):/workspace qbitel-edgeos-builder make build
#   docker run --rm -v $(pwd):/workspace qbitel-edgeos-builder make test

FROM rust:1.82-bookworm AS builder

LABEL maintainer="Qbitel Inc."
LABEL description="Qbitel EdgeOS reproducible build environment"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    libnewlib-arm-none-eabi \
    gdb-multiarch \
    openocd \
    stlink-tools \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Install Rust targets for cross-compilation
RUN rustup target add \
    thumbv7em-none-eabihf \
    thumbv8m.main-none-eabihf \
    riscv32imac-unknown-none-elf

# Install Rust components
RUN rustup component add \
    rustfmt \
    clippy \
    llvm-tools-preview \
    rust-src

# Install cargo tools for CI
RUN cargo install \
    cargo-tarpaulin \
    cargo-deny \
    cargo-audit \
    cargo-geiger \
    cargo-fuzz \
    cargo-binutils \
    cargo-sbom \
    && rm -rf /usr/local/cargo/registry

# Set up Python virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python tool dependencies
RUN pip install --no-cache-dir \
    click>=8.1.0 \
    pycryptodome>=3.19.0 \
    pyserial>=3.5 \
    intelhex>=2.3.0 \
    cryptography>=41.0.0 \
    pyyaml>=6.0 \
    rich>=13.0.0 \
    pydantic>=2.0.0 \
    pytest>=7.0.0 \
    pytest-cov>=4.0.0 \
    mypy>=1.0.0 \
    ruff>=0.1.0 \
    black>=23.0.0

WORKDIR /workspace

# Copy dependency manifests first for layer caching
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo/ .cargo/
COPY crates/q-common/Cargo.toml crates/q-common/Cargo.toml
COPY crates/q-crypto/Cargo.toml crates/q-crypto/Cargo.toml
COPY crates/q-kernel/Cargo.toml crates/q-kernel/Cargo.toml
COPY crates/q-hal/Cargo.toml crates/q-hal/Cargo.toml
COPY crates/q-boot/Cargo.toml crates/q-boot/Cargo.toml
COPY crates/q-identity/Cargo.toml crates/q-identity/Cargo.toml
COPY crates/q-attest/Cargo.toml crates/q-attest/Cargo.toml
COPY crates/q-update/Cargo.toml crates/q-update/Cargo.toml
COPY crates/q-recover/Cargo.toml crates/q-recover/Cargo.toml
COPY crates/q-mesh/Cargo.toml crates/q-mesh/Cargo.toml

# Create stub source files for dependency caching
RUN for crate in q-common q-crypto q-kernel q-hal q-boot q-identity q-attest q-update q-recover q-mesh; do \
        mkdir -p crates/$crate/src && \
        echo '#![no_std]' > crates/$crate/src/lib.rs; \
    done && \
    echo '#![no_std]' > crates/q-boot/src/main.rs

# Pre-fetch and compile dependencies
RUN cargo fetch && \
    cargo check --workspace 2>/dev/null || true

# Remove stub sources (actual code will be mounted/copied)
RUN find crates -name "*.rs" -delete

# Copy full source
COPY . .

# Default command
CMD ["make", "check"]

# ---
# Multi-stage: minimal firmware output
FROM scratch AS firmware
COPY --from=builder /workspace/target/thumbv7em-none-eabihf/release/*.bin /firmware/
