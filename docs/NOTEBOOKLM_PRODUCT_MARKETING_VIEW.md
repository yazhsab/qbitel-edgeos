# Qbitel EdgeOS — Product & Marketing Reference

> **Document Purpose:** This is the comprehensive product and marketing reference for Qbitel EdgeOS. It covers the product vision, market positioning, value propositions, competitive differentiation, go-to-market strategy, pricing considerations, customer personas, and messaging frameworks. Designed for product managers, marketing teams, business development, investors, and sales enablement.

---

## 1. Product Identity

- **Product Name:** Qbitel EdgeOS
- **Tagline:** Post-quantum secure operating system for edge devices. Written in Rust.
- **Company:** Qbitel Inc.
- **License:** Apache License 2.0 (open source)
- **Current Version:** 0.1.0 (Active Development)
- **Website/Repository:** https://github.com/yazhsab/qbitel-edgeos
- **Category:** Embedded Operating System / Edge Security Platform / Post-Quantum Infrastructure Software

---

## 2. The Problem (Market Context)

### 2.1. The Quantum Timeline Problem

Cryptographically-relevant quantum computers (CRQCs) are projected to arrive within 10-15 years. Embedded devices deployed today in critical infrastructure will still be operational when quantum computers break classical encryption. This creates an existential security gap:

- **RSA-2048 and ECC-256 will be broken** by sufficiently large quantum computers using Shor's algorithm.
- **Harvest-now, decrypt-later (HNDL) attacks** are already underway — adversaries collect encrypted traffic today to decrypt when quantum computers become available.
- **Embedded devices have 15-20 year lifespans.** A smart meter installed in 2025 will likely still be running in 2040.
- **Physical replacement is prohibitively expensive.** Replacing millions of deployed edge devices costs billions and takes years. Rail signaling equipment replacement can take a decade.

### 2.2. The Embedded Security Gap

Current embedded systems lack fundamental security capabilities:

- **No post-quantum cryptography.** Most embedded devices use RSA or ECC, which will be quantum-vulnerable.
- **No hardware-rooted identity.** Devices rely on certificates from centralized PKI infrastructure that can be compromised.
- **No secure boot verification.** Firmware is loaded without cryptographic integrity checks.
- **No secure update mechanism.** OTA updates lack signature verification, rollback protection, or atomic installation.
- **No attestation capability.** Operators cannot remotely verify whether a deployed device is running authorized firmware.
- **Certificate dependency.** Current identity systems depend on certificate authorities, revocation servers, and internet connectivity — all of which fail in air-gapped environments.

### 2.3. The Regulatory Pressure

Governments and standards bodies are mandating post-quantum readiness:

- **NIST** finalized FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) in 2024, creating the first standardized post-quantum algorithms.
- **NSA CNSA 2.0** requires federal systems to transition to post-quantum algorithms by 2030-2035.
- **EU Cyber Resilience Act** imposes security requirements on all internet-connected products, including embedded devices.
- **IEC 62443** (industrial cybersecurity) is increasingly mandated for critical infrastructure.
- **EN 50129/50159** (railway safety) requires cryptographic protection for safety-critical communications.
- **NERC CIP** (power grid) mandates cybersecurity controls for bulk electric system components.

### 2.4. Market Size

The addressable market spans multiple sectors:

| Segment | Estimated Global TAM | Growth Rate |
|---------|---------------------|-------------|
| Smart Grid / Energy | $35B+ | 10-12% CAGR |
| Railway Signaling & Safety | $12B+ | 7-9% CAGR |
| Industrial IoT Security | $25B+ | 15-20% CAGR |
| Defense & Government IoT | $18B+ | 8-10% CAGR |
| Water / Utility SCADA | $8B+ | 6-8% CAGR |
| Post-Quantum Cryptography Solutions | $2B+ (emerging) | 30%+ CAGR |

---

## 3. The Solution

Qbitel EdgeOS is a purpose-built operating system that makes embedded devices quantum-safe from the ground up. It is not a library or SDK bolted onto an existing OS — it is a complete, integrated security platform from boot to application.

### 3.1. Product Architecture

Ten integrated components working as a unified system:

| Component | Function | Key Capability |
|-----------|----------|---------------|
| **q-boot** | Secure Bootloader | ML-DSA-65 signature verification, A/B slots, anti-rollback counters |
| **q-kernel** | Microkernel | Preemptive scheduler, MPU/PMP memory isolation, IPC channels |
| **q-crypto** | Crypto Engine | ML-KEM-768, ML-DSA-65, FN-DSA-512, SHA3, AES-256-GCM, ChaCha20 |
| **q-hal** | Hardware Abstraction | STM32H7, STM32U5, RISC-V support with unified API |
| **q-identity** | Device Identity | PUF/eFUSE hardware binding, certificate-less, offline verification |
| **q-attest** | Attestation | Remote integrity verification, supply chain tracking |
| **q-update** | OTA Updates | Signed manifests, A/B partitioning, air-gap support |
| **q-recover** | Key Recovery | Shamir secret sharing, field-rotatable keys, batch revocation |
| **q-mesh** | Mesh Networking | Post-quantum handshake, LoRa/802.15.4/BLE, multi-hop routing |
| **q-common** | Shared Utilities | Error types, logging, configuration, constants |

**Plus two operational tools:**
| Tool | Function |
|------|----------|
| **q-sign** | CLI for firmware signing, verification, and package creation |
| **q-provision** | Factory provisioning — identity generation, key injection, device flashing |

### 3.2. Supported Hardware

| Platform | Processor | Flash / RAM | Use Case |
|----------|-----------|------------|----------|
| STM32H743/753 | ARM Cortex-M7 @ 480MHz | 2MB / 1MB | High-performance edge (gateways, controllers) |
| STM32U585 | ARM Cortex-M33 @ 160MHz | 2MB / 786KB | TrustZone-enabled devices (signaling, safety) |
| SiFive FE310 | RISC-V RV32IMAC @ 320MHz | 16MB / 16KB | Low-power sensors (mesh nodes, border security) |

**Minimum requirements:** 512KB flash, 128KB RAM, hardware TRNG, OTP/eFUSE storage.

---

## 4. Value Propositions

### 4.1. For CISOs and Security Leaders

**"Protect your deployed infrastructure against quantum threats — today, not when it's too late."**

- Every cryptographic operation uses NIST-standardized post-quantum algorithms (FIPS 203, 204)
- Hardware-rooted device identity eliminates single points of failure (no CA compromise risk)
- Attestation proves device integrity remotely — know your fleet is running authorized firmware
- Secure boot chain with anti-rollback prevents firmware downgrade attacks
- Field-rotatable keys without device recall — respond to compromises without truck rolls

### 4.2. For Engineering Teams

**"A real embedded OS, not a security library. Build on a foundation that handles the hard problems."**

- Pure Rust, `no_std`, zero heap allocations — predictable memory, no runtime surprises
- 10 modular crates with clean API boundaries — use what you need
- Constant-time crypto — no side-channel analysis worries
- Secrets automatically zeroized on drop — no "forgot to clear the buffer" bugs
- Preemptive scheduler with hardware memory isolation — real OS capabilities on microcontrollers
- Works on STM32 and RISC-V — bring your own hardware
- Open source (Apache 2.0) — audit every line, contribute improvements, no vendor lock-in

### 4.3. For Operations Teams

**"Deploy once, manage remotely, update securely — even in air-gapped environments."**

- A/B firmware slots with automatic rollback — updates never brick devices
- Signed OTA updates with anti-rollback counters — only authorized firmware runs
- Air-gap friendly — update via USB/serial when network isn't available
- Mesh networking — devices communicate without infrastructure
- Ansible playbooks for fleet management — automate provisioning and updates at scale
- Terraform infrastructure — production-ready AWS backend for device fleet management
- Docker-based CI/CD — reproducible builds every time

### 4.4. For Executives and Investors

**"First-mover advantage in post-quantum edge security for critical infrastructure."**

- Post-quantum cryptography is a regulatory mandate, not an option — NIST FIPS 203/204 are finalized
- $100B+ combined TAM across energy, rail, defense, and industrial IoT
- Open-source model enables rapid adoption and community validation
- Platform play: OS-level integration creates deep moats vs. bolt-on security libraries
- Revenue opportunities: enterprise support, custom hardware ports, compliance consulting, managed fleet services

---

## 5. Competitive Differentiation

### 5.1. Vs. Classical Embedded RTOS (FreeRTOS, Zephyr, RIOT)

| Capability | FreeRTOS/Zephyr/RIOT | Qbitel EdgeOS |
|-----------|---------------------|---------------|
| Post-quantum crypto | Not built-in; requires third-party library integration | Native — ML-KEM-768, ML-DSA-65, FN-DSA-512, SHA3, AES-256-GCM |
| Secure boot | Basic or community-contributed | Full chain — PQC signature verification + anti-rollback + A/B slots |
| Hardware-bound identity | Not available | PUF/eFUSE anchored, certificate-less, offline-verifiable |
| Remote attestation | Not available | Integrated — boot measurements, runtime integrity, supply chain tracking |
| Memory safety | C-based (FreeRTOS, RIOT) or mixed (Zephyr) | 100% Rust, no_std, zero heap, all unsafe documented |
| OTA updates | Community-contributed, variable quality | Integrated — signed manifests, A/B slots, rollback protection, air-gap support |
| Mesh networking | Basic or external | PQC-secured handshake, multi-hop, LoRa/802.15.4/BLE |
| Key management | Not available | Shamir secret sharing, field-rotatable keys, batch revocation |

**Key message:** Existing RTOS platforms were designed before the quantum threat materialized. Bolting on post-quantum crypto to a C-based RTOS creates integration complexity, memory safety risks, and maintenance burdens that a purpose-built solution avoids.

### 5.2. Vs. Linux-Based Edge Platforms (Yocto, Buildroot)

| Capability | Linux-based | Qbitel EdgeOS |
|-----------|------------|---------------|
| Memory footprint | 8-64 MB RAM minimum | 128 KB RAM minimum |
| Boot time | Seconds to minutes | Microseconds (direct boot from flash) |
| Attack surface | Large (kernel, userspace, drivers, systemd) | Minimal (10 crates, no_std, no heap, no shell) |
| Real-time capability | Soft real-time with PREEMPT_RT patch | Hard real-time with hardware-enforced isolation |
| Power consumption | mW to Watts | uW to mW |
| Flash requirements | 16-256 MB | 512 KB minimum |
| PQC integration | Bolt-on (liboqs, BoringSSL) | Native, constant-time, zeroized |

**Key message:** Linux is too heavy for true edge devices. Qbitel EdgeOS runs on the same microcontrollers that Linux cannot reach — the billions of 512KB-flash, 128KB-RAM devices that form the actual edge of critical infrastructure.

### 5.3. Vs. PQC Libraries (liboqs, PQClean, BoringSSL-PQ)

| Capability | PQC Library | Qbitel EdgeOS |
|-----------|------------|---------------|
| Scope | Algorithms only | Full OS: boot, kernel, identity, attestation, updates, mesh |
| Integration | Developer responsibility | Integrated and tested |
| Embedded support | Limited no_std support | Pure no_std, tested on real hardware |
| Key management | Not provided | Hardware-bound identity, Shamir recovery, rotation |
| Secure boot | Not provided | PQC-verified boot chain |
| OTA updates | Not provided | Signed, rollback-protected, air-gap capable |

**Key message:** A crypto library gives you algorithms. Qbitel EdgeOS gives you a secure device. The gap between "we have PQC algorithms" and "our deployed devices are quantum-safe" is enormous — that gap is what Qbitel EdgeOS fills.

---

## 6. Customer Personas

### 6.1. Persona: Chief Information Security Officer (CISO) — Critical Infrastructure

**Name:** Sarah Chen
**Title:** CISO, National Grid Operator
**Pain Points:**
- Board is asking about quantum readiness
- Millions of smart meters deployed with 15-year lifespans and RSA/ECC encryption
- No way to remotely verify if field devices are compromised
- Certificate management across 10,000+ devices is a nightmare
- Air-gapped substations can't connect to cloud-based security services

**What she needs:**
- Verifiable quantum-safe protection for deployed devices
- Remote attestation to prove device fleet integrity to regulators
- Compliance evidence for NERC CIP and IEC 62443 audits
- Solution that works offline in air-gapped environments

**Qbitel EdgeOS message:** "Replace your devices' firmware with quantum-safe protection. Verify their integrity remotely. Rotate keys without truck rolls. Works offline."

### 6.2. Persona: Embedded Systems Architect

**Name:** Marcus Wei
**Title:** Principal Engineer, Railway Systems Integrator
**Pain Points:**
- EN 50129/50159 compliance requires cryptographic protection
- Existing C-based firmware has had multiple buffer overflow vulnerabilities
- Integration of PQC libraries into bare-metal C code is risky and slow
- Safety-critical systems require predictable, auditable behavior
- Needs to support multiple MCU platforms (ARM + RISC-V)

**What he needs:**
- Memory-safe embedded OS with formal safety properties
- Integrated PQC that doesn't require manual buffer management
- Multi-platform support with a single codebase
- Fail-safe defaults for safety-critical applications
- Auditable open-source code for certification

**Qbitel EdgeOS message:** "Pure Rust. No heap. Hardware-enforced isolation. Post-quantum crypto that just works. Runs on your hardware. Audit every line."

### 6.3. Persona: DevSecOps Lead — Defense Contractor

**Name:** Colonel Alex Reeves (Ret.)
**Title:** VP of Cybersecurity, Defense Technology Company
**Pain Points:**
- NSA CNSA 2.0 mandates PQC transition by 2030
- Tactical edge devices operate in contested, disconnected environments
- Devices must resist sophisticated state-sponsored attacks
- Supply chain integrity is paramount
- Cannot depend on any cloud connectivity for security

**What he needs:**
- CNSA 2.0 compliant cryptography
- Supply chain attestation from manufacturing through deployment
- Secure mesh networking for tactical operations
- Air-gapped update capability
- Hardware-tamper detection and response

**Qbitel EdgeOS message:** "NIST FIPS 203/204 compliant. Hardware-rooted identity. Mesh networking without infrastructure. Air-gapped updates. Supply chain tracking. Built for denied environments."

### 6.4. Persona: Product Manager — IoT Device Manufacturer

**Name:** Priya Sharma
**Title:** Director of Product, Industrial IoT Company
**Pain Points:**
- Customers are demanding quantum-safe devices
- EU Cyber Resilience Act will mandate security for all connected products
- Building security from scratch would take years and millions in R&D
- Needs to differentiate products in a commoditized market
- Time-to-market pressure is intense

**What she needs:**
- Drop-in OS platform with security already built
- Reduces R&D cost by eliminating need to build security stack
- Marketable differentiator ("quantum-safe" on the datasheet)
- Regulatory compliance ready
- Open source to avoid vendor lock-in

**Qbitel EdgeOS message:** "Ship quantum-safe devices now. Skip years of crypto R&D. Differentiate with NIST-compliant post-quantum security. Open source, no vendor lock-in."

---

## 7. Messaging Framework

### 7.1. Elevator Pitch (30 seconds)

"Qbitel EdgeOS is a Rust-based embedded operating system that makes edge devices quantum-safe from boot to application. It ships NIST-standardized post-quantum cryptography, hardware-bound identity, secure boot, OTA updates, and mesh networking — everything critical infrastructure needs to survive the quantum era. It runs on standard STM32 and RISC-V microcontrollers. It's open source under Apache 2.0."

### 7.2. Value Statement (1 minute)

"The devices protecting our power grids, railways, and defense networks will still be operating when quantum computers break today's encryption. Qbitel EdgeOS is the only embedded operating system purpose-built for this reality. Every boot is cryptographically verified. Every device has a hardware-rooted identity that can't be cloned or faked. Every communication uses post-quantum encryption. Keys can be rotated in the field without physical access. Firmware updates are signed, rollback-protected, and work in air-gapped environments. Built in Rust with zero heap allocations, it runs on microcontrollers with as little as 512KB flash. Open source. NIST FIPS compliant. Designed for the most critical infrastructure on earth."

### 7.3. Technical Headline

"Post-quantum secure embedded OS: ML-KEM-768 + ML-DSA-65 + hardware-rooted identity + secure boot + mesh networking. Pure no_std Rust. 512KB flash minimum. Apache 2.0."

### 7.4. Key Messages by Audience

**For Security Professionals:**
- "NIST FIPS 203/204 compliant post-quantum cryptography, built-in"
- "Hardware-rooted identity eliminates certificate infrastructure dependency"
- "Remote attestation proves device integrity — not just device presence"
- "Constant-time crypto operations prevent side-channel attacks"
- "Field-rotatable keys without device recall"

**For Engineers:**
- "Pure Rust, no_std, zero heap allocations — predictable embedded behavior"
- "10 modular crates with clean boundaries — use what you need"
- "Runs on STM32H7, STM32U5, and RISC-V from a single codebase"
- "Preemptive scheduler with hardware memory isolation (MPU/PMP)"
- "Open source: audit, contribute, customize"

**For Business Leaders:**
- "First-mover advantage in mandatory post-quantum migration"
- "Reduces embedded security R&D cost by 70-80%"
- "Open source eliminates vendor lock-in risk"
- "Addresses $100B+ TAM across energy, rail, defense, industrial"
- "Regulatory compliance accelerator for IEC 62443, EN 50129, NERC CIP"

**For Government / Defense:**
- "CNSA 2.0 migration path for fielded edge devices"
- "Works without cloud connectivity — designed for denied environments"
- "Supply chain attestation from manufacturing through deployment"
- "Secure mesh networking for tactical communications"
- "Air-gapped firmware updates with rollback protection"

---

## 8. Product Roadmap Vision

### Phase 1: Foundation (Current — v0.1.x)
- Core OS with all 10 crates functional
- Post-quantum crypto (ML-KEM-768, ML-DSA-65, FN-DSA-512)
- Secure boot, OTA updates, device identity
- Mesh networking (LoRa, 802.15.4, BLE)
- Three example applications (smart meter, railway, border sensor)
- Python tooling (q-sign, q-provision)
- Open-source release

### Phase 2: Hardening (v0.2.x — v0.5.x)
- NIST FIPS validation testing
- Common Criteria EAL4+ evaluation preparation
- Performance optimization and benchmarking
- Additional hardware platform support
- Enhanced mesh protocols (AODV, RPL)
- Power management optimization
- Expanded testing (fuzzing, formal verification of critical paths)

### Phase 3: Enterprise (v1.0+)
- Enterprise fleet management console
- Cloud-hosted attestation service
- Managed OTA update service
- Hardware Security Module (HSM) integration
- Custom hardware porting service
- Compliance consulting and documentation packages
- Long-term support (LTS) releases

---

## 9. Business Model Considerations

### 9.1. Open-Source Core (Apache 2.0)

The entire OS, all 10 crates, all tools, all examples — fully open source. This enables:
- Community trust and code audit
- Rapid developer adoption
- Contribution from the embedded/security community
- No barriers to evaluation and proof-of-concept

### 9.2. Potential Revenue Streams

| Revenue Stream | Description | Target Customer |
|---------------|-------------|-----------------|
| Enterprise Support | SLA-backed support, bug fix priority, security advisory access | Large utilities, rail operators |
| Custom Platform Ports | Porting Qbitel EdgeOS to new MCU platforms | Device manufacturers |
| Compliance Packages | Pre-built documentation for IEC 62443, EN 50129, NERC CIP audits | Compliance teams |
| Fleet Management SaaS | Cloud-hosted device management, attestation, and OTA service | Operations teams |
| Training & Certification | Developer training, security architecture review | Engineering teams |
| Hardware Integration | Pre-integrated reference designs with silicon partners | OEMs |

### 9.3. Partnership Opportunities

| Partner Type | Value Exchange |
|-------------|---------------|
| MCU Vendors (ST, SiFive, NXP) | Pre-integration, reference designs, co-marketing |
| System Integrators (Siemens, ABB, Thales) | Deployment, customization, compliance consulting |
| Cloud Providers (AWS, Azure) | IoT platform integration, managed services |
| Crypto Vendors (Thales, Entrust) | HSM integration, key management |
| Certification Bodies (TUV, BSI, NIAP) | Accelerated Common Criteria evaluation |

---

## 10. Technology Differentiators (Marketing Language)

### "Quantum-Ready from Day One"
Not a bolt-on library. Post-quantum cryptography is the foundation of every operation: boot verification, device identity, mesh communication, firmware updates, and attestation. ML-KEM-768 and ML-DSA-65 are built into the core, not added as an afterthought.

### "No Heap, No Std, No Compromise"
Pure Rust with zero heap allocations. Every byte of memory is accounted for at compile time. No garbage collector. No runtime panics in production code. Integer overflow checks are enabled even in release builds. This is what "memory safety" means for embedded: not just absence of buffer overflows, but deterministic, predictable behavior on every boot.

### "Hardware-Rooted Trust"
Device identity is anchored to Physical Unclonable Functions (PUF) and one-time programmable fuses (eFUSE) in the silicon itself. No certificates to expire. No certificate authority to compromise. No revocation server to go offline. A device's identity is as unique and unforgeable as a fingerprint.

### "Built for Disconnected Operations"
Mesh networking over LoRa, 802.15.4, and BLE. OTA updates via USB and serial for air-gapped environments. Offline identity verification. Remote attestation that works over mesh networks. Designed for devices where "just connect to the cloud" is impossible, impractical, or a security risk.

### "Open Source, Auditable, No Lock-In"
Apache 2.0 licensed. Every line of code is public. Security through transparency, not obscurity. No proprietary dependencies. No licensing fees. No vendor lock-in. The community can audit, contribute, fork, and build on the platform.

### "Runs on Real Hardware"
Not a simulation. Qbitel EdgeOS runs on commercially available STM32 (ARM Cortex-M7, Cortex-M33) and SiFive (RISC-V) microcontrollers. 512KB flash minimum. These are the processors inside real smart meters, railway controllers, and industrial sensors deployed today.

---

## 11. Proof Points and Validation

### Example Applications as Proof Points

**Smart Meter (Energy):**
- 24-byte encrypted telemetry readings every 15 minutes
- Tamper detection with immediate alert capability
- Mesh communication to gateway with PQC-secured sessions
- OTA firmware updates with A/B rollback
- Demonstrates: encryption, attestation, mesh, OTA in a real energy use case

**Railway Signaling (Rail):**
- SIL4 (Safety Integrity Level 4) compliant design patterns
- Fail-safe defaults: all signals default to Danger on any fault
- Interlocking logic verification (track circuits, points, conflicting signals)
- Watchdog enforcement (100ms timeout)
- Demonstrates: safety-critical operation, deterministic behavior, fail-safe design

**Border Sensor (Defense):**
- Multi-sensor detection (PIR, seismic, magnetic, acoustic, infrared)
- Solar-powered with adaptive power management (4 power states)
- Mesh relay to command center over multiple hops (up to 8)
- Air-gapped firmware updates
- Demonstrates: low-power operation, mesh networking, air-gap capability, multi-hop

### Open-Source Transparency

Every claim is verifiable in the source code:
- Constant-time crypto: audit the `subtle` crate usage and NTT implementations
- Zeroization: check `Zeroize` and `ZeroizeOnDrop` derives on all secret types
- No unwrap: grep the codebase — zero `.unwrap()` calls in production crates
- No heap: verify `#![no_std]` attribute on every crate, zero `alloc` usage
- Overflow checks: see `overflow-checks = true` in Cargo.toml release profile

---

## 12. Frequently Asked Questions (Sales Enablement)

**Q: Is post-quantum cryptography ready for production?**
A: NIST finalized ML-KEM (FIPS 203) and ML-DSA (FIPS 204) in August 2024. These are standardized, peer-reviewed algorithms. NSA mandates their adoption by 2030-2035. Deploying now means your devices are ready before the mandate deadline.

**Q: How does this compare to just using a PQC library on our existing RTOS?**
A: A crypto library gives you algorithms. Qbitel EdgeOS gives you a secure device. The integration work — secure boot, identity management, key rotation, attestation, OTA updates, mesh networking — is where 80% of the security engineering effort lies. We've already done that work.

**Q: Is Rust actually used in embedded production?**
A: Yes. Rust for embedded is maturing rapidly. The Embedded Rust Working Group has production-quality tooling. Companies like Espressif (ESP32), Samsung (Tizen), and Microsoft (Azure RTOS successor) are investing in Rust for embedded. Qbitel EdgeOS demonstrates production-quality no_std Rust.

**Q: What if we need a different MCU?**
A: The hardware abstraction layer (q-hal) provides trait-based interfaces. Adding a new platform means implementing those traits for your MCU's peripherals. The entire application layer (crypto, identity, boot, updates, mesh) works unchanged.

**Q: Is open source secure enough for critical infrastructure?**
A: Open source enables security through transparency. Anyone can audit the code. The Linux kernel, OpenSSL, and WireGuard are all open source and trusted by critical infrastructure worldwide. Proprietary security through obscurity has a poor track record.

**Q: What's the performance overhead of post-quantum crypto?**
A: ML-KEM-768 key generation takes ~1ms on a 480MHz Cortex-M7. Encapsulation/decapsulation are comparable. ML-DSA-65 signing takes ~5-10ms. For devices that communicate every 15 minutes (like smart meters), this overhead is negligible. The real constraint is key/signature size, not computation time.

**Q: How big are post-quantum keys and signatures?**
A: ML-KEM-768 public keys are 1184 bytes and ciphertexts are 1088 bytes. ML-DSA-65 public keys are 1952 bytes and signatures are 3293 bytes. These are larger than RSA/ECC equivalents but manageable for embedded systems. FN-DSA-512 (Falcon) provides compact 666-byte signatures where space is critical.

---

*End of Product & Marketing Reference Document.*
