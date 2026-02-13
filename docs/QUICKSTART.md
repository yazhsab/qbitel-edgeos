# Qbitel EdgeOS - Quickstart Guide

Get from zero to a running firmware image in under 10 minutes.

---

## Prerequisites

- **Rust 1.82+** (stable)
- **Python 3.10+** (for tools)
- **Git**

> Don't want to install anything? Skip to [Quickstart with Docker](#quickstart-with-docker).

---

## 1. Clone the Repository

```bash
git clone https://github.com/yazhsab/qbitel-edgeos.git
cd qbitel-edgeos
```

## 2. Install Embedded Targets

```bash
# ARM Cortex-M7 (STM32H7)
rustup target add thumbv7em-none-eabihf

# ARM Cortex-M33 (STM32U5)
rustup target add thumbv8m.main-none-eabihf

# RISC-V (SiFive FE310)
rustup target add riscv32imac-unknown-none-elf
```

## 3. Run the Test Suite

Verify everything works on your host machine:

```bash
cargo test --workspace --all-features
```

You should see all crates compile and tests pass:

```
running X tests
test q_crypto::kat::... ok
test q_kernel::scheduler::... ok
test q_boot::verify::... ok
...
test result: ok. X passed; 0 failed
```

## 4. Build for a Target Platform

```bash
# Build for STM32H7 (Cortex-M7)
cargo build --release --target thumbv7em-none-eabihf --features stm32h7

# Build for STM32U5 (Cortex-M33)
cargo build --release --target thumbv8m.main-none-eabihf --features stm32u5

# Build for RISC-V
cargo build --release --target riscv32imac-unknown-none-elf --features riscv
```

The output binary is at:
```
target/<target-triple>/release/qbitel-edgeos
```

## 5. Build an Example Application

```bash
# Smart meter example (STM32H7)
cargo build --release \
  --target thumbv7em-none-eabihf \
  --features stm32h7 \
  -p smart-meter

# Railway signaling example (STM32U5)
cargo build --release \
  --target thumbv8m.main-none-eabihf \
  --features stm32u5 \
  -p railway-signaling

# Border sensor example (RISC-V)
cargo build --release \
  --target riscv32imac-unknown-none-elf \
  --features riscv \
  -p border-sensor
```

## 6. Flash to Hardware

If you have a target board connected via ST-Link or J-Link:

```bash
# Install probe-rs (one-time)
cargo install probe-rs-tools

# Flash the firmware
probe-rs run --chip STM32H743ZITx \
  target/thumbv7em-none-eabihf/release/smart-meter
```

---

## Quickstart with Docker

No local Rust installation needed. The Docker environment includes all toolchains and tools.

```bash
# Clone the repo
git clone https://github.com/yazhsab/qbitel-edgeos.git
cd qbitel-edgeos

# Build everything
docker compose run builder

# Run tests
docker compose run test

# Lint check
docker compose run lint
```

---

## Install the Python Tools

The signing and provisioning tools are useful even without hardware:

```bash
# Install q-sign (firmware signing)
pip install -e tools/q-sign

# Install q-provision (device provisioning)
pip install -e tools/q-provision

# Verify installation
q-sign --help
q-provision --help
```

### Sign a Firmware Image

```bash
# Generate a signing keypair
q-sign keygen --algorithm dilithium3 --output keys/

# Sign a firmware binary
q-sign sign \
  --algorithm dilithium3 \
  --key keys/firmware_signer \
  --image target/thumbv7em-none-eabihf/release/smart-meter \
  --version 1

# Verify the signature
q-sign verify \
  --image target/thumbv7em-none-eabihf/release/smart-meter.signed
```

### Provision a Device Identity

```bash
# Generate device keys
q-provision keygen --key-type all --device-id DEVICE001

# Create an identity commitment
q-provision identity \
  --device-id DEVICE001 \
  --manufacturer-id MFG001 \
  --device-class sensor
```

---

## Run Individual Crate Tests

```bash
# Crypto Known Answer Tests (KAT)
cargo test -p q-crypto --all-features -- kat

# Kernel scheduler tests
cargo test -p q-kernel --all-features

# Boot verification tests
cargo test -p q-boot --all-features

# All crate tests
cargo test --workspace --all-features
```

---

## Explore the Code

```
qbitel-edgeos/
├── crates/
│   ├── q-boot/          # Start here: secure boot chain
│   ├── q-kernel/        # Scheduler, IPC, memory management
│   ├── q-crypto/        # Post-quantum algorithms
│   ├── q-hal/           # Hardware abstraction
│   ├── q-identity/      # Device identity
│   ├── q-attest/        # Remote attestation
│   ├── q-update/        # OTA updates
│   ├── q-recover/       # Key rotation
│   ├── q-mesh/          # Mesh networking
│   └── q-common/        # Shared types
├── examples/
│   ├── smart-meter/     # Energy metering demo
│   ├── railway-signaling/ # SIL4 signaling demo
│   └── border-sensor/   # Mesh sensor demo
└── tools/
    ├── q-sign/          # Firmware signing CLI
    └── q-provision/     # Device provisioning CLI
```

**Recommended reading order:**

1. `crates/q-common/src/lib.rs` - Understand shared types and errors
2. `crates/q-crypto/src/lib.rs` - See how PQC algorithms are structured
3. `crates/q-hal/src/lib.rs` - Learn the hardware abstraction
4. `crates/q-kernel/src/lib.rs` - Study the kernel architecture
5. `crates/q-boot/src/lib.rs` - Follow the secure boot flow
6. `examples/smart-meter/src/main.rs` - See a complete application

---

## Generate Documentation

```bash
# Generate and open rustdoc
cargo doc --workspace --all-features --no-deps --open
```

---

## Common Issues

### Build fails with "target not found"

You need to add the embedded target:
```bash
rustup target add thumbv7em-none-eabihf
```

### Tests fail with crypto errors

Ensure you have all features enabled:
```bash
cargo test --workspace --all-features
```

### Python tools won't install

Verify Python 3.10+:
```bash
python3 --version
pip install -e tools/q-sign
```

### Docker build is slow

The first build downloads the Rust toolchain image. Subsequent builds use Docker layer caching:
```bash
docker compose build  # Build the image once
docker compose run test  # Fast on subsequent runs
```

---

## Next Steps

- **[INSTALLATION.md](INSTALLATION.md)** - Full installation guide with all dependencies
- **[WALKTHROUGH.md](WALKTHROUGH.md)** - Detailed technical walkthrough
- **[API.md](API.md)** - Complete API reference
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide
