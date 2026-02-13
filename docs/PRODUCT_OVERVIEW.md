# Qbitel EdgeOS - Product Overview

## What is Qbitel EdgeOS?

Qbitel EdgeOS is an open-source, post-quantum secure operating system purpose-built for embedded devices that protect critical infrastructure. Written entirely in Rust with `no_std` support, it delivers NIST-standardized post-quantum cryptography, hardware-bound device identity, secure boot, OTA updates, and mesh networking in a package that runs on microcontrollers with as little as 512KB flash and 128KB RAM.

## The Problem

Billions of embedded devices are deployed in power grids, railways, water systems, defense networks, and industrial plants. These devices:

- **Will outlive classical cryptography.** Devices deployed today will operate for 15-20 years. Cryptographically-relevant quantum computers are expected within that window. Every device using RSA or ECC is vulnerable to harvest-now-decrypt-later attacks.
- **Cannot be easily replaced.** A smart meter in a substation or a signaling controller on a rail line cannot be swapped out like a laptop. Firmware updates must be cryptographically verified, atomic, and rollback-safe.
- **Operate in hostile environments.** Edge devices are physically accessible to attackers, run on constrained hardware, and often operate in air-gapped networks with no cloud connectivity.
- **Lack defense-in-depth.** Most embedded systems rely on a single layer of security (if any). Once breached, there is no isolation, no attestation, no recovery path.

## The Solution

Qbitel EdgeOS addresses every layer of the embedded security stack:

### Post-Quantum Cryptography (q-crypto)

All cryptographic operations use NIST-standardized post-quantum algorithms:

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| ML-KEM-768 (Kyber) | FIPS 203 | Key encapsulation |
| ML-DSA-65 (Dilithium) | FIPS 204 | Digital signatures |
| FN-DSA-512 (Falcon) | NIST Round 3 | Compact signatures |
| SHA3-256/384/512 | FIPS 202 | Hashing |
| AES-256-GCM | FIPS 197 | Authenticated encryption |
| ChaCha20-Poly1305 | RFC 8439 | Authenticated encryption |
| HKDF-SHA3-256 | RFC 5869 | Key derivation |

Every operation is constant-time. No secret-dependent branches. No secret-dependent memory access patterns. Secrets are automatically zeroized on drop.

### Hardware-Rooted Identity (q-identity)

Device identity is cryptographically bound to silicon:

- **PUF/eFUSE anchoring** ties identity to physical hardware characteristics that cannot be cloned or extracted.
- **Certificate-less architecture** eliminates dependency on PKI infrastructure, certificate authorities, and revocation servers.
- **Offline verification** means identity can be validated without network connectivity.

### Secure Boot Chain (q-boot)

Every boot is verified from the first instruction:

- **Post-quantum signature verification** of kernel images using Dilithium3.
- **Anti-rollback counters** prevent downgrade attacks via monotonic version enforcement.
- **A/B slot selection** ensures a known-good firmware is always available.
- **Recovery mode** automatically activates on repeated boot failures.

### Microkernel Architecture (q-kernel)

A minimal, auditable kernel provides strong isolation:

- **Preemptive scheduler** with priority-based task management.
- **MPU/PMP enforcement** isolates tasks in hardware-protected memory regions.
- **IPC channels** provide controlled inter-task communication.
- **Syscall interface** enforces privilege separation.

### Mesh Networking (q-mesh)

Secure communication without infrastructure:

- **Post-quantum handshake** using ML-KEM for session key establishment.
- **Multi-hop routing** with automatic peer discovery.
- **Transport support** for LoRa, IEEE 802.15.4, and BLE.
- **Group trust policies** for fleet-level access control.

### Remote Attestation (q-attest)

Prove device integrity to remote verifiers:

- **Boot measurement chain** captures hashes at every boot stage.
- **Runtime integrity monitoring** detects unauthorized modifications.
- **Supply chain tracking** via hash-linked provenance ledger.
- **Anomaly detection** flags deviations from expected behavior.

### Secure OTA Updates (q-update)

Field-update firmware safely, even in air-gapped environments:

- **Signed manifests** with post-quantum signatures.
- **A/B partitioning** with atomic slot switching.
- **Rollback protection** via monotonic version counters.
- **Air-gap support** for environments without network connectivity.

### Key Recovery (q-recover)

Rotate and recover keys without recalling devices:

- **Shamir secret sharing** over GF(2^8) for threshold-based recovery.
- **Field-updateable keys** without physical access.
- **Batch revocation** for compromised device groups.

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

## Supported Hardware

| Platform | MCU | Architecture | Flash / RAM | Status |
|----------|-----|-------------|-------------|--------|
| STM32H743/753 | Cortex-M7 @ 480MHz | ARMv7E-M | 2MB / 1MB | Primary |
| STM32U585 | Cortex-M33 @ 160MHz | ARMv8-M | 2MB / 786KB | Primary |
| SiFive FE310 | RV32IMAC @ 320MHz | RISC-V | 16MB / 16KB | Secondary |

**Minimum requirements:** 512KB flash, 128KB RAM, hardware TRNG, OTP/eFUSE storage.

## Target Industries

| Industry | Use Case | Key Features |
|----------|----------|-------------|
| **Energy** | Smart meters, grid controllers, substation gateways | OTA updates, attestation, mesh telemetry |
| **Rail** | Signaling controllers, trackside equipment, ETCS | SIL4 safety, fail-safe defaults, redundancy |
| **Defense** | Tactical edge nodes, sensor arrays, communications | Air-gapped updates, mesh networking, attestation |
| **Industrial** | PLCs, RTUs, safety controllers | IEC 62443 compliance, key recovery, secure boot |
| **Water** | SCADA endpoints, pump controllers, quality sensors | Offline operation, low-power mesh, tamper detection |

## Compliance Targets

| Standard | Domain | Status |
|----------|--------|--------|
| NIST FIPS 203/204/202/197 | Post-quantum cryptography | Implemented |
| Common Criteria EAL4+ | Security evaluation | In progress |
| IEC 62443 | Industrial cybersecurity | In progress |
| EN 50129 / EN 50159 | Railway safety & communication | In progress |
| IEC 62351 | Power grid security | In progress |

## What Makes It Different

1. **Quantum-ready from day one.** Not a bolt-on. Post-quantum cryptography is the foundation, not an afterthought.
2. **No heap, no std, no compromise.** Pure `no_std` Rust with zero heap allocations. Predictable memory usage. No garbage collector. No runtime panics in production code.
3. **Hardware-rooted trust.** Device identity is anchored to silicon. No certificates. No cloud dependency. No single point of failure.
4. **Built for disconnected operations.** Mesh networking, air-gapped updates, offline attestation. Designed for environments where "just connect to the cloud" is not an option.
5. **Open source.** Apache 2.0 licensed. Audit the code. Contribute improvements. Build on the platform.

## Project Status

**Current version:** 0.1.0 (Active Development)

The core architecture is implemented and functional. APIs may change before 1.0. Contributions are welcome. See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0. See [LICENSE](../LICENSE) for full text.
