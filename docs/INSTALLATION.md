# Qbitel EdgeOS - Installation Guide

Complete setup instructions for developing, building, testing, and flashing Qbitel EdgeOS firmware.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Rust Toolchain Setup](#rust-toolchain-setup)
- [Python Environment Setup](#python-environment-setup)
- [Hardware Debug Probes](#hardware-debug-probes)
- [Docker Environment](#docker-environment)
- [Development Container (VS Code)](#development-container-vs-code)
- [Verifying the Installation](#verifying-the-installation)
- [Platform-Specific Notes](#platform-specific-notes)

---

## System Requirements

### Host Machine

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Linux (x86_64), macOS (ARM/x86) | Ubuntu 22.04 LTS |
| RAM | 4GB | 8GB+ |
| Disk | 5GB free | 10GB+ |
| Rust | 1.82 (stable) | Latest stable |
| Python | 3.10 | 3.11+ |
| Docker | 24.0 (optional) | Latest |

### Target Hardware (for on-device testing)

| Platform | Board | Debug Probe |
|----------|-------|-------------|
| STM32H7 | NUCLEO-H743ZI, STM32H753I-EVAL | ST-Link V3 (built-in) |
| STM32U5 | B-U585I-IOT02A | ST-Link V3 (built-in) |
| RISC-V | HiFive1 Rev B | Segger J-Link |

> **No hardware?** All tests run on the host. Hardware is only needed for on-device testing and flashing.

---

## Rust Toolchain Setup

### 1. Install Rust

If you don't have Rust installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Verify the installation:

```bash
rustc --version   # Should be 1.82.0 or later
cargo --version
```

### 2. Add Embedded Targets

```bash
# ARM Cortex-M7 (STM32H743/753)
rustup target add thumbv7em-none-eabihf

# ARM Cortex-M33 (STM32U585)
rustup target add thumbv8m.main-none-eabihf

# RISC-V RV32IMAC (SiFive FE310)
rustup target add riscv32imac-unknown-none-elf
```

### 3. Install Rust Components

```bash
rustup component add rustfmt clippy llvm-tools-preview rust-src
```

### 4. Install Cargo Tools

```bash
# Code coverage
cargo install cargo-tarpaulin

# Dependency auditing
cargo install cargo-audit cargo-deny

# Unsafe code detection
cargo install cargo-geiger

# Binary utilities (size analysis)
cargo install cargo-binutils

# SBOM generation
cargo install cargo-sbom

# Fuzzing (optional)
cargo install cargo-fuzz
```

### 5. Install probe-rs (Hardware Flashing)

```bash
# Install probe-rs for flashing and debugging
cargo install probe-rs-tools

# Verify
probe-rs list
```

---

## Python Environment Setup

The Python tools (`q-sign` and `q-provision`) require Python 3.10+.

### 1. Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows
```

### 2. Install the Tools

```bash
# Firmware signing tool
pip install -e tools/q-sign

# Device provisioning tool
pip install -e tools/q-provision
```

### 3. Install Development Dependencies

```bash
# Formatter, linter, type checker
pip install black ruff mypy

# Testing
pip install pytest pytest-cov

# Pre-commit hooks
pip install pre-commit
pre-commit install
```

### 4. Verify

```bash
q-sign --help
q-provision --help
```

---

## Hardware Debug Probes

### ST-Link (STM32 Boards)

Most STM32 Nucleo and Discovery boards have an ST-Link debug probe built in. Connect via USB and verify:

```bash
probe-rs list
```

Expected output:
```
The following debug probes were found:
[0]: STLink V3 (VID: 0483, PID: 374E, Serial: ...)
```

**Linux udev rules** (required for non-root access):

```bash
# Create udev rules for ST-Link
sudo tee /etc/udev/rules.d/49-stlink.rules << 'EOF'
# STLink V2
ATTRS{idVendor}=="0483", ATTRS{idProduct}=="3748", MODE="0666"
# STLink V3
ATTRS{idVendor}=="0483", ATTRS{idProduct}=="374e", MODE="0666"
ATTRS{idVendor}=="0483", ATTRS{idProduct}=="374f", MODE="0666"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger
```

### J-Link (RISC-V Boards)

For SiFive HiFive1 boards:

1. Download J-Link Software from [segger.com](https://www.segger.com/downloads/jlink/)
2. Install the package for your OS
3. Verify:

```bash
probe-rs list
```

---

## Docker Environment

Docker provides a reproducible build environment with all toolchains pre-installed.

### 1. Install Docker

Follow the official instructions for your platform:
- [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)
- [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
- [Docker Engine for Linux](https://docs.docker.com/engine/install/)

### 2. Build the Docker Image

```bash
cd qbitel-edgeos
docker compose build
```

This builds an image with:
- Rust 1.82 + all embedded targets
- All cargo tools (tarpaulin, audit, deny, geiger, fuzz, sbom)
- Python 3.11 + all tool dependencies
- ARM and RISC-V cross-compilation toolchains

### 3. Available Services

```bash
# Full workspace build (all targets)
docker compose run builder

# Run the complete test suite
docker compose run test

# Format and lint check
docker compose run lint

# Security audit (cargo audit + deny + geiger)
docker compose run audit

# Code coverage report
docker compose run coverage

# Python tool tests
docker compose run python-test
```

### 4. Interactive Shell

```bash
docker compose run --entrypoint bash builder
```

---

## Development Container (VS Code)

If you use Visual Studio Code, a dev container configuration is provided:

### 1. Install the Extension

Install the **Dev Containers** extension (`ms-vscode-remote.remote-containers`).

### 2. Open in Container

1. Open the `qbitel-edgeos` folder in VS Code
2. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
3. Select **Dev Containers: Reopen in Container**

The container includes:
- Rust toolchain with all targets
- rust-analyzer extension
- Python environment with tools installed
- All cargo tools pre-installed

---

## Verifying the Installation

Run these commands to verify everything is set up correctly:

### 1. Compile Check

```bash
# Check that all crates compile (no output = success)
cargo check --workspace --all-features
```

### 2. Format Check

```bash
cargo fmt --all -- --check
```

### 3. Lint Check

```bash
cargo clippy --workspace --all-features -- -D warnings
```

### 4. Run Tests

```bash
cargo test --workspace --all-features
```

### 5. Build for Embedded Target

```bash
cargo build --release --target thumbv7em-none-eabihf --features stm32h7
```

### 6. Check Binary Size

```bash
cargo size --release --target thumbv7em-none-eabihf --features stm32h7 -- -A
```

### 7. Python Tools

```bash
q-sign keygen --algorithm dilithium3 --output /tmp/test-keys/
q-sign keyinfo --key /tmp/test-keys/firmware_signer.pub
rm -rf /tmp/test-keys/
```

### 8. Security Audit

```bash
cargo audit
cargo deny check
```

If all commands pass, your environment is ready.

---

## Platform-Specific Notes

### macOS (Apple Silicon)

Rust cross-compilation to ARM embedded targets works natively on Apple Silicon. No additional configuration needed.

```bash
# Rosetta is NOT required for embedded cross-compilation
rustup target add thumbv7em-none-eabihf  # Works natively
```

### macOS (Intel)

Same as Apple Silicon. All embedded targets compile via LLVM's cross-compilation backend.

### Ubuntu / Debian

Install system dependencies:

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  libudev-dev \
  libusb-1.0-0-dev \
  cmake
```

The `libudev-dev` and `libusb-1.0-0-dev` packages are required for probe-rs to communicate with debug probes.

### Fedora / RHEL

```bash
sudo dnf install -y \
  gcc \
  openssl-devel \
  systemd-devel \
  libusbx-devel \
  cmake
```

### Windows (WSL2)

Qbitel EdgeOS development is supported on Windows via WSL2:

1. Install WSL2 with Ubuntu 22.04
2. Follow the Ubuntu/Debian instructions above
3. For USB debug probe passthrough, use [usbipd-win](https://github.com/dorssel/usbipd-win)

Native Windows compilation is not officially supported due to the `no_std` embedded toolchain requirements.

---

## Troubleshooting

### `error[E0463]: can't find crate for std`

You're building for an embedded target but didn't disable std. Ensure your code uses `#![no_std]` and you're using the correct target triple.

### `probe-rs` can't find the debug probe

- **Linux:** Check udev rules (see [ST-Link section](#st-link-stm32-boards))
- **macOS:** No special permissions needed
- **WSL2:** Use usbipd-win to forward the USB device

### Cargo build out of memory

The post-quantum crypto algorithms use significant compile-time memory. Increase available RAM or reduce parallelism:

```bash
cargo build --release -j 2  # Limit to 2 parallel jobs
```

### `cargo deny` fails

Run `cargo deny check` to see which dependencies have advisories. Update affected dependencies:

```bash
cargo update
cargo deny check
```

---

## Next Steps

- **[QUICKSTART.md](QUICKSTART.md)** - Build and run your first application
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide
- **[../CONTRIBUTING.md](../CONTRIBUTING.md)** - Contributor guidelines
