export const SITE_CONFIG = {
  name: 'Qbitel EdgeOS',
  tagline: 'Post-Quantum Secure OS for Edge Devices',
  description: 'NIST-standardized post-quantum cryptography, hardware-rooted identity, secure boot, and mesh networking — purpose-built for critical infrastructure. Written in Rust.',
  version: '0.1.0',
  github: 'https://github.com/yazhsab/qbitel-edgeos',
  license: 'Apache-2.0',
}

export const NAV_LINKS = [
  { label: 'Why', href: '#why' },
  { label: 'Architecture', href: '#architecture' },
  { label: 'Crates', href: '#crates' },
  { label: 'Crypto', href: '#crypto' },
  { label: 'Hardware', href: '#hardware' },
  { label: 'Use Cases', href: '#usecases' },
  { label: 'Quick Start', href: '#quickstart' },
]

export const WHY_ITEMS = [
  {
    icon: '🛡️',
    title: 'Quantum-Ready from Day One',
    description: 'ML-KEM-768, ML-DSA-65, FN-DSA-512 — all NIST FIPS 203/204 compliant. Not bolted on. Built in.',
  },
  {
    icon: '⚡',
    title: 'No Heap, No Std, No Compromise',
    description: 'Pure no_std Rust. Zero heap allocations. Constant-time crypto. Secrets zeroized on drop. Overflow checks in release.',
  },
  {
    icon: '🔒',
    title: 'Hardware-Rooted Trust',
    description: 'Device identity anchored to PUF/eFUSE silicon. No certificates. No cloud dependency. No revocation servers.',
  },
  {
    icon: '📡',
    title: 'Built for Air-Gapped Environments',
    description: 'Mesh networking over LoRa, 802.15.4, BLE. OTA updates via USB for disconnected deployments. Offline-first.',
  },
  {
    icon: '🔧',
    title: 'Runs on Real Hardware',
    description: 'STM32H7 (Cortex-M7), STM32U5 (Cortex-M33), SiFive FE310 (RISC-V). 512KB flash, 128KB RAM minimum.',
  },
  {
    icon: '🌐',
    title: 'Open Source',
    description: 'Apache 2.0 licensed. Audit every line. Contribute improvements. No vendor lock-in. Security through transparency.',
  },
]

export const ARCHITECTURE_LAYERS = [
  {
    label: 'q-boot',
    description: 'Secure Boot | Signature Verification | Anti-Rollback',
    color: 'purple',
  },
  {
    label: 'q-hal',
    description: 'STM32H7 (Cortex-M7) | STM32U5 (Cortex-M33) | RISC-V',
    color: 'cyan',
  },
  {
    label: 'q-kernel',
    description: 'Preemptive Scheduler | IPC | MPU/PMP Isolation | Syscalls',
    color: 'purple',
  },
  {
    label: 'q-identity + q-crypto',
    description: 'Hardware-Bound Identity | Post-Quantum Crypto Engine',
    color: 'cyan',
  },
  {
    label: 'q-update | q-recover | q-attest | q-mesh',
    description: 'Secure OTA | Key Rotation | Attestation | Mesh Networking',
    color: 'purple',
  },
]

export const CRATES = [
  { name: 'q-boot', description: 'Secure bootloader — Dilithium-3 signature verification, anti-rollback counter, A/B slot selection' },
  { name: 'q-kernel', description: 'Microkernel — preemptive round-robin scheduler, IPC channels, MPU/PMP task isolation' },
  { name: 'q-crypto', description: 'Crypto engine — ML-KEM-768, ML-DSA-65, FN-DSA-512, SHA3-256, AES-256-GCM, constant-time ops' },
  { name: 'q-hal', description: 'Hardware abstraction — GPIO, UART, SPI, I2C, RNG, flash for STM32H7/U5 and RISC-V' },
  { name: 'q-identity', description: 'Device identity — PUF/eFUSE hardware binding, certificate-less identity, offline verification' },
  { name: 'q-attest', description: 'Attestation — supply chain tracking with hash-linked ledger, runtime integrity verification' },
  { name: 'q-update', description: 'OTA updates — A/B partition management, signed manifests, air-gap support, rollback protection' },
  { name: 'q-recover', description: 'Key recovery — Shamir secret sharing over GF(2^8), threshold-based key rotation' },
  { name: 'q-mesh', description: 'Mesh networking — post-quantum handshake, LoRa/802.15.4/BLE transport, multi-hop routing' },
  { name: 'q-common', description: 'Shared primitives — error types, logging, time, configuration, constants' },
]

export const CRYPTO_ALGORITHMS = [
  { name: 'ML-KEM-768 (Kyber)', standard: 'FIPS 203', use: 'Key Encapsulation', level: 'NIST Level 3', keySize: '1184 B', outputSize: '1088 B' },
  { name: 'ML-DSA-65 (Dilithium)', standard: 'FIPS 204', use: 'Digital Signatures', level: 'NIST Level 3', keySize: '1952 B', outputSize: '3293 B' },
  { name: 'FN-DSA-512 (Falcon)', standard: 'NIST R3', use: 'Compact Signatures', level: 'NIST Level 1', keySize: '897 B', outputSize: '666 B' },
  { name: 'SHA3-256', standard: 'FIPS 202', use: 'Hashing', level: '128-bit', keySize: '—', outputSize: '32 B' },
  { name: 'AES-256-GCM', standard: 'FIPS 197', use: 'Authenticated Encryption', level: '256-bit', keySize: '32 B', outputSize: '16 B tag' },
  { name: 'HKDF-SHA3-256', standard: 'RFC 5869', use: 'Key Derivation', level: '256-bit', keySize: '—', outputSize: 'Variable' },
]

export const HARDWARE_PLATFORMS = [
  {
    name: 'STM32H743/753',
    mcu: 'Cortex-M7 @ 480 MHz',
    arch: 'ARMv7E-M',
    target: 'thumbv7em-none-eabihf',
    flash: '2 MB',
    ram: '1 MB',
    status: 'Primary',
    features: ['Hardware TRNG', 'Crypto accelerator', 'Dual-bank flash'],
  },
  {
    name: 'STM32U585',
    mcu: 'Cortex-M33 @ 160 MHz',
    arch: 'ARMv8-M',
    target: 'thumbv8m.main-none-eabihf',
    flash: '2 MB',
    ram: '786 KB',
    status: 'Primary',
    features: ['TrustZone-M', 'Hardware TRNG', 'Secure storage'],
  },
  {
    name: 'SiFive FE310',
    mcu: 'RV32IMAC @ 320 MHz',
    arch: 'RISC-V',
    target: 'riscv32imac-unknown-none-elf',
    flash: '16 MB',
    ram: '16 KB',
    status: 'Secondary',
    features: ['PMP protection', 'Low power', 'Open ISA'],
  },
]

export const USE_CASES = [
  {
    icon: '⚡',
    title: 'Energy & Smart Grid',
    description: 'Smart meters, substation gateways, DER controllers with quantum-safe telemetry and OTA.',
    standards: ['IEC 62351', 'NERC CIP'],
  },
  {
    icon: '🚄',
    title: 'Railway & Transit',
    description: 'SIL4 signaling controllers, ETCS onboard units, trackside equipment with fail-safe defaults.',
    standards: ['EN 50129', 'EN 50159'],
  },
  {
    icon: '🛡️',
    title: 'Defense & Intelligence',
    description: 'Tactical edge nodes, border sensors, comms equipment for denied and contested environments.',
    standards: ['CNSA 2.0', 'MIL-STD'],
  },
  {
    icon: '🏭',
    title: 'Industrial Manufacturing',
    description: 'Secure PLCs, safety instrumented systems, IoT gateways with IEC 62443 compliance.',
    standards: ['IEC 62443', 'ISA-99'],
  },
  {
    icon: '💧',
    title: 'Water & Utilities',
    description: 'Remote pump stations, SCADA endpoints, water quality sensors with mesh networking.',
    standards: ['NIST CSF', 'AWWA'],
  },
  {
    icon: '📡',
    title: 'Border & Perimeter',
    description: 'Unattended ground sensors, surveillance mesh networks with solar power and air-gapped ops.',
    standards: ['Gov specific'],
  },
]

export const EXAMPLES = [
  {
    name: 'smart-meter',
    title: 'Smart Energy Meter',
    description: 'Secure energy metering with 15-minute encrypted readings, tamper detection, and mesh communication to gateway.',
    features: ['OTA updates', 'Attestation', 'Mesh telemetry'],
    command: 'cargo build --release --target thumbv7em-none-eabihf --features stm32h7 -p smart-meter',
  },
  {
    name: 'railway-signaling',
    title: 'Railway Signaling Controller',
    description: 'SIL4 safety-critical signaling with interlocking logic, fail-safe defaults, and 100ms watchdog.',
    features: ['Fail-safe', 'Redundancy', 'SIL4'],
    command: 'cargo build --release --target thumbv8m.main-none-eabihf --features stm32u5 -p railway-signaling',
  },
  {
    name: 'border-sensor',
    title: 'Border Surveillance Sensor',
    description: 'Multi-sensor detection with solar power management, 8-hop mesh relay, and air-gapped firmware updates.',
    features: ['Mesh networking', 'Low power', 'Air-gapped'],
    command: 'cargo build --release --target riscv32imac-unknown-none-elf --features riscv -p border-sensor',
  },
]

export const TOOLS = [
  {
    name: 'q-sign',
    description: 'CLI for firmware signing, manifest creation, and update package building.',
    commands: [
      { label: 'Generate signing keys', cmd: 'q-sign keygen --algorithm dilithium3 --output keys/' },
      { label: 'Sign firmware', cmd: 'q-sign sign --algorithm dilithium3 --key keys/firmware_signer --image firmware.bin --version 1' },
      { label: 'Verify signature', cmd: 'q-sign verify --image firmware.signed --strict' },
    ],
  },
  {
    name: 'q-provision',
    description: 'Factory provisioning — identity generation, key injection, device flashing and verification.',
    commands: [
      { label: 'Generate device keys', cmd: 'q-provision keygen --key-type all --device-id DEVICE001' },
      { label: 'Create identity', cmd: 'q-provision identity --device-id DEVICE001 --device-class sensor' },
      { label: 'Flash device', cmd: 'q-provision flash --target stm32h7 --bootloader boot.signed --kernel app.signed' },
    ],
  },
]

export const QUICKSTART_STEPS = [
  { label: 'Clone', cmd: 'git clone https://github.com/yazhsab/qbitel-edgeos.git && cd qbitel-edgeos' },
  { label: 'Add targets', cmd: 'rustup target add thumbv7em-none-eabihf thumbv8m.main-none-eabihf riscv32imac-unknown-none-elf' },
  { label: 'Build', cmd: 'cargo build --release --target thumbv7em-none-eabihf --features stm32h7' },
  { label: 'Test', cmd: 'cargo test --workspace --all-features' },
  { label: 'Docker', cmd: 'docker compose run builder  # Or use Docker for reproducible builds' },
]

export const COMPLIANCE = [
  { name: 'NIST FIPS 203/204', domain: 'Post-Quantum Crypto', status: 'implemented' as const },
  { name: 'NIST FIPS 202/197', domain: 'SHA-3 / AES', status: 'implemented' as const },
  { name: 'Common Criteria EAL4+', domain: 'Security Evaluation', status: 'in-progress' as const },
  { name: 'IEC 62443', domain: 'Industrial Cybersecurity', status: 'in-progress' as const },
  { name: 'EN 50129 / EN 50159', domain: 'Railway Safety', status: 'in-progress' as const },
  { name: 'IEC 62351', domain: 'Power Grid Security', status: 'in-progress' as const },
]
