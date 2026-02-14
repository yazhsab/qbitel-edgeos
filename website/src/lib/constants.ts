export const BASE_PATH = process.env.NODE_ENV === 'production' ? '/qbitel-edgeos' : ''

export const SITE_CONFIG = {
  name: 'Qbitel EdgeOS',
  version: '0.9.0',
  github: 'https://github.com/yazhsab/qbitel-edgeos',
  tagline: 'Post-quantum secure OS for critical infrastructure edge devices.',
}

export const NAV_LINKS = [
  { label: 'Threat', href: '#why' },
  { label: 'Framework', href: '#architecture' },
  { label: 'Crypto', href: '#crypto' },
  { label: 'Domains', href: '#usecases' },
  { label: 'Compliance', href: '#compliance' },
]

export const WHY_ITEMS = [
  {
    title: 'Harvest-now decrypt-later is active today',
    description:
      'Adversaries can capture encrypted telemetry now and decrypt it when cryptographically relevant quantum computers mature.',
    metric: 'Data shelf-life: 15+ years',
  },
  {
    title: 'Infrastructure outlives classical cryptography',
    description:
      'Field devices in energy, rail, water, and defense remain deployed for decades, while RSA and ECC timelines keep shrinking.',
    metric: 'Operational lifespan: 15-30 years',
  },
  {
    title: 'Regulatory deadlines are already defined',
    description:
      'Migration programs are aligned to NIST FIPS 203/204 and NSA CNSA 2.0 requirements across 2030-2035 windows.',
    metric: 'Transition window: 2030-2035',
  },
]

export const ARCHITECTURE_LAYERS = [
  {
    label: 'q-boot',
    description: 'Secure bootloader with anti-rollback OTP counters and measured startup chain.',
    signal: 'Boot trust chain',
  },
  {
    label: 'q-kernel',
    description: 'Deterministic microkernel designed for no-heap, resource-constrained operation.',
    signal: 'Deterministic runtime',
  },
  {
    label: 'q-crypto',
    description: 'Built-in NIST-standardized PQC primitives with constant-time implementations.',
    signal: 'Native post-quantum cryptography',
  },
  {
    label: 'q-hal',
    description: 'Hardware abstraction for MCU families and board-level secure peripherals.',
    signal: 'Portable hardware layer',
  },
  {
    label: 'q-identity',
    description: 'Physical unclonable function identity for certificate-less device trust.',
    signal: 'Hardware-rooted identity',
  },
  {
    label: 'q-attest',
    description: 'Remote attestation and signed posture proofs for fleet verification.',
    signal: 'Continuous verification',
  },
  {
    label: 'q-update',
    description: 'OTA and air-gapped update channels with policy-gated key rotation.',
    signal: 'Resilient lifecycle updates',
  },
  {
    label: 'q-mesh',
    description: 'Secure mesh networking optimized for constrained links and hostile environments.',
    signal: 'Trusted edge connectivity',
  },
  {
    label: 'q-recover',
    description: 'Cryptographic key recovery and rotation flows for incident containment.',
    signal: 'Recovery-ready controls',
  },
  {
    label: 'q-common',
    description: 'Shared primitives, errors, and contract types across all crates.',
    signal: 'Shared trusted core',
  },
]

export const CRATES = [
  {
    name: 'q-boot',
    description: 'Measured boot sequence and immutable trust anchors for device startup.',
    focus: 'Secure startup',
  },
  {
    name: 'q-kernel',
    description: 'Minimal microkernel scheduler tuned for hard realtime behavior and safety.',
    focus: 'Realtime control',
  },
  {
    name: 'q-crypto',
    description: 'PQC algorithms and key-exchange APIs for handshake and firmware security.',
    focus: 'Cryptographic core',
  },
  {
    name: 'q-identity',
    description: 'PUF and eFUSE identity primitives for unique device-level trust roots.',
    focus: 'Identity anchoring',
  },
  {
    name: 'q-attest',
    description: 'Remote attestation proofs for control plane policy validation.',
    focus: 'Attestation',
  },
  {
    name: 'q-update',
    description: 'Signed update workflow with anti-rollback and staged release capability.',
    focus: 'Update safety',
  },
  {
    name: 'q-mesh',
    description: 'Secure mesh packet handling and link-level authenticated transport.',
    focus: 'Edge networking',
  },
  {
    name: 'q-recover',
    description: 'Compromised-key response workflow with deterministic recovery playbooks.',
    focus: 'Incident recovery',
  },
  {
    name: 'q-hal',
    description: 'Board and silicon adaptation interfaces for industrial hardware targets.',
    focus: 'Hardware adapters',
  },
  {
    name: 'q-common',
    description: 'Common types, defensive utilities, and low-level shared runtime helpers.',
    focus: 'Shared primitives',
  },
]

export const CRYPTO_ALGORITHMS = [
  {
    name: 'ML-KEM-768',
    standard: 'FIPS 203',
    purpose: 'Key encapsulation',
    level: 'NIST Level 3',
    perf: 'Balanced for edge',
  },
  {
    name: 'ML-DSA-65',
    standard: 'FIPS 204',
    purpose: 'Digital signatures',
    level: 'NIST Level 3',
    perf: 'Fleet signing ready',
  },
  {
    name: 'FN-DSA-512',
    standard: 'Falcon family',
    purpose: 'Compact signatures',
    level: 'NIST Level 1+',
    perf: 'Latency-optimized',
  },
]

export const HARDWARE_PLATFORMS = [
  {
    name: 'Pure no_std Rust',
    detail: 'Entire runtime is written in Rust with deterministic memory behavior.',
    tags: ['No heap allocation', 'Memory-safe', 'Zero-cost abstractions'],
  },
  {
    name: 'Hardware-bound identity',
    detail: 'Device trust is anchored in PUF/eFUSE roots rather than external certificate chains.',
    tags: ['Certificate-less trust', 'PUF anchored', 'Clone resistance'],
  },
  {
    name: 'Secure lifecycle controls',
    detail: 'Anti-rollback counters and signed firmware pipelines protect long-lived infrastructure fleets.',
    tags: ['OTP counters', 'Signed OTA', 'Key rotation'],
  },
]

export const USE_CASES = [
  {
    title: 'Energy and Smart Grid',
    description: 'Protect smart meters, DER controllers, and substation gateways against delayed decryption attacks.',
    systems: ['Smart energy meters', 'Substation gateways', 'DER controllers'],
  },
  {
    title: 'Railway and Transit',
    description: 'Secure signaling controllers and trackside equipment with attestable software supply chains.',
    systems: ['Signaling controllers', 'Trackside equipment', 'ETCS onboard units'],
  },
  {
    title: 'Defense and Intelligence',
    description: 'Establish resilient identity and encrypted telemetry for high-assurance field nodes.',
    systems: ['Border sensors', 'Tactical comms nodes', 'Supply chain tracking'],
  },
  {
    title: 'Industrial Manufacturing',
    description: 'Harden PLC-connected systems and industrial gateways with deterministic secure runtimes.',
    systems: ['Secure PLCs', 'Safety instrumented systems', 'Industrial IoT gateways'],
  },
  {
    title: 'Water and Utilities',
    description: 'Protect remote utility endpoints with cryptographic agility and air-gapped updates.',
    systems: ['Pump stations', 'Telemetry endpoints', 'Remote valve controllers'],
  },
]

export const EXAMPLES = [
  {
    title: 'Grid Substation Attestation',
    name: 'grid-attestation',
    description: 'Provision identity, attest firmware, and enforce policy before control messages are accepted.',
    outcome: 'Blocks unauthorized firmware from joining the substation network.',
    command: 'cargo run --example grid-attestation --release',
    metrics: ['Identity proof < 280 ms', 'Verified policy gates', 'Signed event logs'],
  },
  {
    title: 'Rail Signal Secure Update',
    name: 'rail-secure-update',
    description: 'Demonstrates signed firmware rollout with rollback resistance for rail signaling nodes.',
    outcome: 'Maintains deterministic timing while applying staged secure updates.',
    command: 'cargo run --example rail-secure-update --release',
    metrics: ['Rollback protected', 'No service interruption', 'Dual-bank validation'],
  },
  {
    title: 'Air-Gapped Utility Patch Flow',
    name: 'airgap-patch-flow',
    description: 'Uses offline artifact signing and physically transferred bundles for isolated utility zones.',
    outcome: 'Supports compliant patching without persistent internet connectivity.',
    command: 'cargo run --example airgap-patch-flow --release',
    metrics: ['Offline signature verify', 'Chain-of-custody audit', 'Tamper-evident bundle'],
  },
]

export const TOOLS = [
  {
    name: 'q-sign',
    description: 'Firmware signing toolchain for release artifacts, SBOM binding, and key policy enforcement.',
    commands: [
      { label: 'Install', cmd: 'pip install q-sign' },
      { label: 'Sign firmware', cmd: 'q-sign sign --in firmware.bin --profile prod-grid' },
      { label: 'Verify package', cmd: 'q-sign verify --in firmware.bin.signed' },
    ],
  },
  {
    name: 'q-provision',
    description: 'Factory and field provisioning CLI for identity enrollment and secure manufacturing workflows.',
    commands: [
      { label: 'Install', cmd: 'pip install q-provision' },
      { label: 'Enroll PUF identity', cmd: 'q-provision enroll --device /dev/ttyUSB0 --mode puf' },
      { label: 'Issue policy bundle', cmd: 'q-provision bundle --tier critical --out device.bundle' },
    ],
  },
]

export const QUICKSTART_STEPS = [
  {
    label: 'Clone repository',
    cmd: 'git clone https://github.com/yazhsab/qbitel-edgeos.git',
    note: 'Start from the reference implementation and docs.',
  },
  {
    label: 'Build secure runtime',
    cmd: 'cargo build --release --target thumbv7em-none-eabihf',
    note: 'Compiles no_std Rust runtime and core security crates.',
  },
  {
    label: 'Run host validation tests',
    cmd: 'cargo test -p q-crypto -p q-identity --release',
    note: 'Checks PQC and identity flows before flashing hardware.',
  },
  {
    label: 'Provision and flash',
    cmd: 'q-provision enroll --device /dev/ttyUSB0 && q-sign sign --in firmware.bin',
    note: 'Binds hardware identity and signs firmware for deployment.',
  },
]

export const COMPLIANCE = [
  {
    name: 'NIST FIPS 203',
    domain: 'ML-KEM key encapsulation',
    status: 'implemented',
    window: 'Active now',
  },
  {
    name: 'NIST FIPS 204',
    domain: 'ML-DSA digital signatures',
    status: 'implemented',
    window: 'Active now',
  },
  {
    name: 'NSA CNSA 2.0',
    domain: 'National security transition profile',
    status: 'in-progress',
    window: '2030 target alignment',
  },
  {
    name: 'IEC 62443',
    domain: 'Industrial control systems security',
    status: 'in-progress',
    window: 'Roadmap integration',
  },
  {
    name: 'EN 50129 / EN 51159',
    domain: 'Railway safety and communication',
    status: 'in-progress',
    window: 'Domain validation phase',
  },
  {
    name: 'Air-Gapped Ops Profile',
    domain: 'Offline secure update compliance',
    status: 'implemented',
    window: 'Operationally deployed',
  },
]
