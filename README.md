<p align="center">
  <h1 align="center">Qbitel EdgeOS</h1>
  <p align="center">
    <strong>Post-quantum secure operating system for edge devices. Written in Rust.</strong>
  </p>
  <p align="center">
    <a href="https://github.com/yazhsab/qbitel-edgeos/actions/workflows/ci.yml"><img src="https://github.com/yazhsab/qbitel-edgeos/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.82%2B-orange.svg" alt="Rust"></a>
    <a href="#supported-hardware"><img src="https://img.shields.io/badge/platform-STM32%20%7C%20RISC--V-green.svg" alt="Platform"></a>
  </p>
</p>

---

Qbitel EdgeOS is a `no_std` Rust operating system purpose-built for securing critical infrastructure at the edge. It ships NIST-standardized post-quantum cryptography, hardware-bound device identity, secure boot, and mesh networking &mdash; everything needed to protect embedded systems against both classical and quantum-era threats.

> **Status:** `v0.1.0` &mdash; Active development. APIs may change before 1.0.

## Why Qbitel EdgeOS?

The quantum computing threat to embedded systems is not theoretical &mdash; it is a timeline problem. Devices deployed today in power grids, railways, and defense networks will still be operating when cryptographically-relevant quantum computers arrive. Qbitel EdgeOS solves this now.

- **Quantum-ready from day one.** ML-KEM-768, ML-DSA-65, FN-DSA-512, SHA3-256, AES-256-GCM &mdash; all NIST FIPS 203/204 compliant.
- **No heap, no std, no compromise.** Pure `no_std` Rust. All crypto runs in constant-time. Secrets are zeroized on drop. Integer overflow checks are on in release builds.
- **Hardware-rooted trust.** Device identity is anchored to PUF/eFUSE silicon roots. No certificates. No cloud dependency. No revocation servers.
- **Built for air-gapped environments.** Mesh networking over LoRa, 802.15.4, and BLE. OTA updates with A/B slots and rollback. Offline-first by design.
- **Runs on real hardware.** Primary targets: STM32H7 (Cortex-M7), STM32U5 (Cortex-M33), SiFive FE310 (RISC-V). 512KB flash, 128KB RAM minimum.

## Architecture

```
+---------------------------------------------------------------+
|  q-update   |  q-recover  |  q-attest   |      q-mesh         |
|  Secure OTA |  Key Rotation| Attestation |  Mesh Networking    |
+---------------------------------------------------------------+
|        q-identity          |          q-crypto                 |
|  Hardware-Bound Identity   |  Post-Quantum Crypto Engine       |
+---------------------------------------------------------------+
|                         q-kernel                               |
|  Preemptive Scheduler | IPC | MPU/PMP Isolation | Syscalls     |
+---------------------------------------------------------------+
|                          q-hal                                 |
|      STM32H7 (Cortex-M7) | STM32U5 (Cortex-M33) | RISC-V     |
+---------------------------------------------------------------+
|                         q-boot                                 |
|  Secure Boot | Signature Verification | Anti-Rollback          |
+---------------------------------------------------------------+
```

## Quick Start

```bash
# Clone
git clone https://github.com/yazhsab/qbitel-edgeos.git
cd qbitel-edgeos

# Install embedded targets
rustup target add thumbv7em-none-eabihf    # STM32H7
rustup target add thumbv8m.main-none-eabihf # STM32U5
rustup target add riscv32imac-unknown-none-elf # RISC-V

# Build for STM32H7
cargo build --release --target thumbv7em-none-eabihf --features stm32h7

# Run tests (host)
cargo test --workspace --all-features

# Or use Docker for reproducible builds
docker compose run builder
```

## Crates

| Crate | What it does |
|-------|-------------|
| **[q-boot](crates/q-boot)** | Secure bootloader &mdash; Dilithium-3 signature verification, anti-rollback counter, A/B slot selection |
| **[q-kernel](crates/q-kernel)** | Microkernel &mdash; preemptive round-robin scheduler, IPC channels, MPU/PMP task isolation, syscall interface |
| **[q-crypto](crates/q-crypto)** | Crypto engine &mdash; ML-KEM-768, ML-DSA-65, FN-DSA-512, SHA3-256, AES-256-GCM, HKDF, constant-time ops |
| **[q-hal](crates/q-hal)** | Hardware abstraction &mdash; GPIO, UART, SPI, I2C, RNG, flash for STM32H7/U5 and RISC-V |
| **[q-identity](crates/q-identity)** | Device identity &mdash; PUF/eFUSE hardware binding, certificate-less identity, key hierarchy |
| **[q-attest](crates/q-attest)** | Attestation &mdash; supply chain tracking with hash-linked ledger, runtime integrity verification |
| **[q-update](crates/q-update)** | OTA updates &mdash; A/B partition management, differential updates, air-gap support |
| **[q-recover](crates/q-recover)** | Key recovery &mdash; Shamir secret sharing over GF(2^8), threshold-based key rotation |
| **[q-mesh](crates/q-mesh)** | Mesh networking &mdash; post-quantum secured handshake, LoRa/802.15.4/BLE transport |
| **[q-common](crates/q-common)** | Shared primitives &mdash; error types, logging, time, configuration, constants |

## Supported Hardware

| Platform | MCU | Architecture | Flash / RAM | Status |
|----------|-----|-------------|-------------|--------|
| STM32H743/753 | Cortex-M7 @ 480MHz | `thumbv7em-none-eabihf` | 2MB / 1MB | Primary |
| STM32U585 | Cortex-M33 @ 160MHz | `thumbv8m.main-none-eabihf` | 2MB / 786KB | Primary |
| SiFive FE310 | RV32IMAC @ 320MHz | `riscv32imac-unknown-none-elf` | 16MB / 16KB | Secondary |

**Minimum requirements:** 512KB flash, 128KB RAM, hardware TRNG, OTP/eFUSE storage.

## Cryptographic Algorithms

| Algorithm | Standard | Use | Security Level |
|-----------|----------|-----|---------------|
| ML-KEM-768 (Kyber) | FIPS 203 | Key encapsulation | NIST Level 3 |
| ML-DSA-65 (Dilithium) | FIPS 204 | Digital signatures | NIST Level 3 |
| FN-DSA-512 (Falcon) | NIST Round 3 | Compact signatures | NIST Level 1 |
| SHA3-256 | FIPS 202 | Hashing | 128-bit |
| AES-256-GCM | FIPS 197 | Authenticated encryption | 256-bit |
| HKDF-SHA3-256 | RFC 5869 | Key derivation | 256-bit |

All cryptographic operations are constant-time. No secret-dependent branches or memory access patterns.

## Tools

| Tool | Description |
|------|-------------|
| **[q-sign](tools/q-sign)** | CLI for firmware signing, manifest creation, and package building |
| **[q-provision](tools/q-provision)** | Factory provisioning &mdash; identity generation, key injection, device flashing |

```bash
# Install tools
pip install -e tools/q-sign
pip install -e tools/q-provision

# Sign a firmware image
q-sign sign --algorithm dilithium3 --key keys/firmware_signer --image firmware.bin

# Provision a device
q-provision identity --manufacturer-id MFG001 --device-class smart-meter
```

## Examples

| Example | Description | Features |
|---------|-------------|----------|
| **[smart-meter](examples/smart-meter)** | Energy metering with secure telemetry | OTA updates, attestation |
| **[railway-signaling](examples/railway-signaling)** | SIL4 safety-critical signaling controller | Redundancy, fail-safe |
| **[border-sensor](examples/border-sensor)** | Mesh sensor grid with offline operation | Mesh networking, low power |

## Development

### Prerequisites

- Rust 1.82+ (stable)
- Python 3.10+ (for tools)
- [probe-rs](https://probe.rs/) or ST-Link (for flashing)

### Commands

```bash
# Format
cargo fmt --all

# Lint
cargo clippy --workspace --all-features -- -D warnings

# Test everything
cargo test --workspace --all-features

# Crypto KAT (Known Answer Tests)
cargo test -p q-crypto --all-features -- kat

# Security audit
cargo audit && cargo deny check

# Python tool tests
cd tools/q-sign && pytest tests/ -v
cd tools/q-provision && pytest tests/ -v
```

### Docker

```bash
docker compose run builder    # Full build
docker compose run test       # Run tests
docker compose run lint       # Lint check
docker compose run audit      # Security audit
docker compose run coverage   # Coverage report
```

## Project Structure

```
qbitel-edgeos/
├── crates/
│   ├── q-boot/          # Secure bootloader
│   ├── q-kernel/        # Microkernel
│   ├── q-crypto/        # Post-quantum crypto
│   ├── q-hal/           # Hardware abstraction
│   ├── q-identity/      # Device identity
│   ├── q-attest/        # Attestation
│   ├── q-update/        # OTA updates
│   ├── q-recover/       # Key recovery
│   ├── q-mesh/          # Mesh networking
│   └── q-common/        # Shared types
├── tools/
│   ├── q-sign/          # Firmware signing (Python)
│   └── q-provision/     # Device provisioning (Python)
├── examples/
│   ├── smart-meter/     # Energy metering demo
│   ├── railway-signaling/ # SIL4 signaling demo
│   └── border-sensor/   # Mesh sensor demo
├── deploy/
│   ├── terraform/       # AWS infrastructure
│   └── ansible/         # Fleet management playbooks
├── Cargo.toml           # Workspace root
├── Dockerfile           # Reproducible build env
└── docker-compose.yml   # Dev/CI services
```

## Compliance Targets

- **NIST FIPS 203/204/202/197** &mdash; Post-quantum cryptographic standards
- **Common Criteria EAL4+** &mdash; Security evaluation
- **IEC 62443** &mdash; Industrial cybersecurity
- **EN 50129 / EN 50159** &mdash; Railway safety & communication security
- **IEC 62351** &mdash; Power grid security

## Documentation

| Document | Description |
|----------|-------------|
| **[Product Overview](docs/PRODUCT_OVERVIEW.md)** | What Qbitel EdgeOS is, the problem it solves, and why it's different |
| **[Technical Walkthrough](docs/WALKTHROUGH.md)** | End-to-end walkthrough of boot, identity, mesh, attestation, and updates |
| **[API Reference](docs/API.md)** | Public API reference for all crates and CLI tools |
| **[Quickstart Guide](docs/QUICKSTART.md)** | Get from zero to running firmware in under 10 minutes |
| **[Installation Guide](docs/INSTALLATION.md)** | Full setup for Rust, Python, Docker, debug probes, and dev containers |
| **[Deployment Guide](docs/DEPLOYMENT.md)** | Production deployment with Terraform, Ansible, signing, and OTA |

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

**Quick version:**

1. Fork the repo and create a branch from `main`
2. Write code, add tests, run `cargo fmt && cargo clippy && cargo test`
3. Sign your commits with DCO (`git commit -s`)
4. Open a PR with a clear description

## Security

Found a vulnerability? **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

---

<p align="center">
  Built with Rust. Secured with post-quantum cryptography. Designed for critical infrastructure.
  <br><br>
  <a href="https://github.com/yazhsab/qbitel-edgeos">GitHub</a> &middot;
  <a href="https://github.com/yazhsab/qbitel-edgeos/issues">Issues</a> &middot;
  <a href="https://github.com/yazhsab/qbitel-edgeos/discussions">Discussions</a>
</p>
