# Qbitel EdgeOS - API Reference

This document provides a reference for the public API of each Qbitel EdgeOS crate. All crates are `no_std` compatible and use no heap allocations.

> **Generating rustdoc:** For the most up-to-date API documentation with full type signatures, run:
> ```bash
> cargo doc --workspace --all-features --no-deps --open
> ```

---

## Table of Contents

- [q-crypto](#q-crypto)
- [q-kernel](#q-kernel)
- [q-boot](#q-boot)
- [q-hal](#q-hal)
- [q-identity](#q-identity)
- [q-attest](#q-attest)
- [q-update](#q-update)
- [q-recover](#q-recover)
- [q-mesh](#q-mesh)
- [q-common](#q-common)
- [Tools CLI Reference](#tools-cli-reference)

---

## q-crypto

**Post-quantum cryptographic engine.**

### Traits

| Trait | Purpose | Methods |
|-------|---------|---------|
| `Kem` | Key encapsulation mechanism | `keygen()`, `encapsulate()`, `decapsulate()` |
| `Signer` | Digital signature | `keygen()`, `sign()`, `verify()` |
| `Hash` | Cryptographic hashing | `new()`, `update()`, `finalize()` |
| `Aead` | Authenticated encryption | `encrypt()`, `decrypt()` |
| `Xof` | Extendable output function | `new()`, `update()`, `squeeze()` |
| `CryptoRng` | Cryptographic RNG | `fill_bytes()` |

### Key Encapsulation (KEM)

```rust
use q_crypto::{Kyber768, Kem};

// Generate a keypair
let (public_key, secret_key) = Kyber768::keygen(&mut rng)?;

// Encapsulate: sender creates ciphertext + shared secret
let (ciphertext, shared_secret_sender) = Kyber768::encapsulate(&public_key, &mut rng)?;

// Decapsulate: receiver recovers the same shared secret
let shared_secret_receiver = Kyber768::decapsulate(&ciphertext, &secret_key)?;

assert_eq!(shared_secret_sender, shared_secret_receiver);
```

**Supported parameter sets:** `Kyber512`, `Kyber768`, `Kyber1024`

### Digital Signatures

```rust
use q_crypto::{Dilithium3, Signer};

// Generate a signing keypair
let (public_key, secret_key) = Dilithium3::keygen(&mut rng)?;

// Sign a message
let signature = Dilithium3::sign(&message, &secret_key)?;

// Verify the signature
let valid = Dilithium3::verify(&message, &signature, &public_key)?;
assert!(valid);
```

**Supported schemes:**
- `Dilithium2`, `Dilithium3`, `Dilithium5` (ML-DSA)
- `Falcon512`, `Falcon1024` (FN-DSA)

### Hashing

```rust
use q_crypto::{Sha3_256, Hash};

let mut hasher = Sha3_256::new();
hasher.update(b"Qbitel EdgeOS");
let digest = hasher.finalize();
```

**Supported functions:** `Sha3_256`, `Sha3_384`, `Sha3_512`, `Shake128`, `Shake256`

### Authenticated Encryption

```rust
use q_crypto::{Aes256Gcm, Aead};

let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, &aad)?;
let plaintext = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, &aad)?;
```

**Supported ciphers:** `Aes256Gcm`, `ChaCha20Poly1305Impl`

### Error Type

```rust
pub enum CryptoError {
    InvalidKey,
    InvalidSignature,
    DecapsulationFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidLength,
    RngError,
    // ...
}
```

### Feature Flags

| Feature | Description |
|---------|-------------|
| `default` | Core PQC algorithms |
| `hybrid` | Hybrid classical+PQC modes |
| `classical` | Classical algorithm fallbacks |
| `all-algorithms` | All supported algorithms |

---

## q-kernel

**Microkernel with preemptive scheduling and memory isolation.**

### Initialization

```rust
use q_kernel;

// Configure kernel timing (CPU frequency, tick rate)
q_kernel::configure(480_000_000, 1000); // 480MHz, 1kHz tick

// Initialize all subsystems
q_kernel::init();

// Register tasks
q_kernel::add_task(
    task_main,          // Entry point function
    &mut TASK_STACK,    // Stack memory
    4096,               // Stack size in bytes
    TaskPriority::Normal,
    "main_task",
);

// Start scheduler (never returns)
q_kernel::start();
```

### Task Management

```rust
use q_kernel::{TaskId, TaskPriority, TaskState};

// Get current task ID
let id: TaskId = q_kernel::current_task();

// Voluntary yield
q_kernel::yield_now();

// Sleep for ticks or milliseconds
q_kernel::sleep(100);      // 100 ticks
q_kernel::sleep_ms(500);   // 500 milliseconds

// Get current tick count
let ticks: u64 = q_kernel::ticks();
```

### Task Priorities

```rust
pub enum TaskPriority {
    High,    // Real-time critical
    Normal,  // Default application tasks
    Low,     // Background processing
    Idle,    // Only runs when nothing else is ready
}
```

### IPC Channels

```rust
use q_kernel::ipc;

// Create a channel (static allocation)
static CHANNEL: ipc::Channel<SensorReading, 8> = ipc::Channel::new();

// Producer task
CHANNEL.send(reading)?;

// Consumer task
let reading = CHANNEL.recv()?;       // Blocking
let reading = CHANNEL.try_recv()?;   // Non-blocking
```

### Constants

```rust
q_kernel::VERSION    // Kernel version string
q_kernel::BUILD_INFO // Build metadata
```

---

## q-boot

**Secure bootloader with post-quantum verification.**

### Boot Verification

```rust
use q_boot;

// Verify kernel image signature
let result = q_boot::verify_kernel();

// Verify entire boot chain
let result = q_boot::verify_boot_chain();

// Load verified kernel into execution memory
q_boot::load_kernel()?;
```

### Recovery Mode

```rust
use q_boot::{BootDecision, RecoveryReason};

// Check if recovery mode should be entered
if q_boot::should_enter_recovery() {
    q_boot::enter_recovery_mode();
}
```

### Boot Log

```rust
use q_boot::{BootLog, BootLogEntry, BootStage, ErrorCategory};

// Boot log is persistent across resets
let log = BootLog::read()?;
for entry in log.entries() {
    // entry.stage: BootStage
    // entry.category: ErrorCategory
    // entry.timestamp: u64
}
```

### Types

```rust
pub enum BootDecision { Boot, Recovery }
pub enum RecoveryReason { SignatureFailure, RollbackDetected, RepeatedBootFailure, ManualTrigger }
pub enum BootStage { HardwareInit, BootloaderVerify, KernelLoad, KernelVerify, KernelStart }
pub enum ErrorCategory { Crypto, Storage, Memory, Hardware, Timeout }
```

---

## q-hal

**Hardware abstraction for multi-platform support.**

### Platform Detection

```rust
use q_hal::Platform;

let platform = Platform::current();
match platform {
    Platform::Stm32H7 => { /* Cortex-M7 specific */ },
    Platform::Stm32U5 => { /* Cortex-M33 specific */ },
    Platform::RiscV   => { /* RISC-V specific */ },
    Platform::Unknown => { /* Host / testing */ },
}

platform.has_trustzone();  // true for STM32U5
platform.has_pmp();        // true for RISC-V
platform.flash_base();     // 0x0800_0000 for STM32
platform.ram_base();       // 0x2000_0000 for STM32
```

### Feature Flags

| Feature | Target |
|---------|--------|
| `stm32h7` | STM32H743/753 (Cortex-M7) |
| `stm32u5` | STM32U585 (Cortex-M33) |
| `riscv` | SiFive FE310 (RV32IMAC) |

### Trait Interfaces

All platforms implement these traits:

```rust
pub trait GpioPin { fn set_high(&mut self); fn set_low(&mut self); fn is_high(&self) -> bool; }
pub trait UartPort { fn write(&mut self, data: &[u8]) -> Result<usize>; fn read(&mut self, buf: &mut [u8]) -> Result<usize>; }
pub trait SpiDevice { fn transfer(&mut self, data: &mut [u8]) -> Result<()>; }
pub trait I2cDevice { fn write_read(&mut self, addr: u8, write: &[u8], read: &mut [u8]) -> Result<()>; }
pub trait FlashStorage { fn read(&self, addr: u32, buf: &mut [u8]) -> Result<()>; fn write(&mut self, addr: u32, data: &[u8]) -> Result<()>; fn erase_sector(&mut self, sector: u32) -> Result<()>; }
pub trait Rng { fn fill_bytes(&mut self, buf: &mut [u8]) -> Result<()>; }
```

---

## q-identity

**Hardware-bound device identity.**

### Types

```rust
pub struct IdentityCommitment {
    pub device_id: [u8; 32],
    pub kem_public_key: KemPublicKey,
    pub signing_public_key: SigningPublicKey,
    pub device_class: DeviceClass,
    pub manufacturer_id: [u8; 16],
    // self_signature, metadata, hardware_binding
}

pub struct IdentitySecrets {
    // Private key material (Zeroize on drop)
}

pub enum DeviceClass { Gateway, Sensor, Actuator, Controller }

pub enum VerificationResult { Valid, InvalidSignature, HardwareBindingMismatch, Expired, Revoked }
```

### Verification

```rust
use q_identity;

let result = q_identity::verify_identity()?;
match result {
    VerificationResult::Valid => { /* Proceed */ },
    VerificationResult::HardwareBindingMismatch => { /* Possible clone */ },
    _ => { /* Identity compromised */ },
}
```

---

## q-attest

**Remote attestation protocol.**

### Evidence Collection

```rust
use q_attest::{EvidenceCollector, AttestationEvidence, AttestationScope};

let collector = EvidenceCollector::new();
let evidence: AttestationEvidence = collector.collect(AttestationScope::Full)?;
```

### Protocol Handler

```rust
use q_attest::{AttestationHandler, AttestationRequest, AttestationResponse};

// Device-side handler
let handler = AttestationHandler::new(&identity, &signing_key);
let response: AttestationResponse = handler.handle_request(&request)?;

// Verifier-side
let verifier = AttestationVerifier::new(&policy);
let result = verifier.verify(&response)?;
```

### Types

```rust
pub struct AttestationEvidence { /* boot measurements, identity, runtime state */ }
pub struct AttestationRequest { pub scope: AttestationScope, pub nonce: [u8; 32] }
pub struct AttestationResponse { pub evidence: AttestationEvidence, pub signature: Signature }
pub enum AttestationScope { Boot, Runtime, Full }
pub enum AttestationResult { Trusted, Untrusted, Unknown }
```

---

## q-update

**Secure OTA update manager.**

### Manifest Verification

```rust
use q_update::{UpdateManifest, MonotonicVersion};

let manifest = UpdateManifest::parse(&manifest_bytes)?;
manifest.verify_signature(&public_key)?;
manifest.check_version(&current_version)?;
```

### Slot Management

```rust
use q_update::{SlotManager, Slot, SlotState};

let manager = SlotManager::new();

let active = manager.active_slot();          // Slot::A or Slot::B
let inactive = manager.inactive_slot();

let status = manager.slot_status(Slot::A);
// status.state: Active | Inactive | Testing | Invalid
// status.version: MonotonicVersion
// status.hash: [u8; 32]

// After successful update
manager.mark_active(Slot::B)?;
manager.update_rollback_counter(new_version)?;
```

### Types

```rust
pub struct UpdateManifest { pub version: MonotonicVersion, pub firmware_hash: [u8; 32], pub signature: Signature, /* ... */ }
pub struct MonotonicVersion(u32);
pub enum Slot { A, B }
pub enum SlotState { Active, Inactive, Testing, Invalid }
```

---

## q-recover

**Key rotation and threshold recovery.**

### Key Rotation

```rust
use q_recover::KeyRotation;

let rotation = KeyRotation::new(&current_identity);
let new_keys = rotation.generate_new_keys(&mut rng)?;
rotation.create_transition_record(&old_signing_key)?;
rotation.apply(&new_keys)?;
```

### Shamir Secret Sharing

```rust
use q_recover::ThresholdScheme;

// Split a secret into 5 shares, requiring 3 to reconstruct
let shares = ThresholdScheme::split(&secret, 5, 3, &mut rng)?;

// Reconstruct from any 3 shares
let recovered = ThresholdScheme::reconstruct(&shares[0..3])?;
assert_eq!(secret, recovered);
```

---

## q-mesh

**Post-quantum secure mesh networking.**

### Session Management

```rust
use q_mesh::{Handshake, Session, SessionState};

// Initiator
let mut handshake = Handshake::new_initiator(&identity, &mut rng)?;
let client_hello = handshake.create_client_hello()?;

// After receiving server_hello
let session = handshake.process_server_hello(&server_hello)?;

// Encrypt/decrypt frames
let encrypted = session.encrypt(&plaintext)?;
let plaintext = session.decrypt(&encrypted)?;
```

### Radio Configuration

```rust
use q_mesh::radio::{LoRaRadio, LoRaConfig, SpreadingFactor, Bandwidth, FrequencyBand};

let config = LoRaConfig {
    spreading_factor: SpreadingFactor::SF7,
    bandwidth: Bandwidth::Bw125kHz,
    coding_rate: CodingRate::Cr4_5,
    frequency_band: FrequencyBand::Eu868,
    tx_power: 14,
};

let radio = LoRaRadio::new(spi, config)?;
```

### Peer Discovery

```rust
use q_mesh::{PeerDiscovery, Peer, PeerState};

let discovery = PeerDiscovery::new(&identity);

// Broadcast beacon
let beacon = discovery.create_beacon()?;
radio.transmit(&beacon)?;

// Process received beacon
discovery.process_beacon(&received_beacon)?;

// Get known peers
let peers: &[Peer] = discovery.peers();
```

### Routing

```rust
use q_mesh::{Router, NeighborTable, RoutingTable};

let router = Router::new(device_id);

// Route a message to a destination
let next_hop = router.route(&destination_id)?;

// Get routing table
let table: &RoutingTable = router.routing_table();
```

### Group Management

```rust
use q_mesh::group::{GroupManager, TrustLevel, GroupRole};

let mut groups = GroupManager::new();
groups.add_member(peer_id, TrustLevel::Full, GroupRole::Member)?;
groups.verify_membership(&peer_id)?;
```

### Transport & Frames

```rust
use q_mesh::transport::{Transport, Frame, FrameType, Priority};

let frame = Frame {
    frame_type: FrameType::Data,
    priority: Priority::Normal,
    source: my_id,
    destination: peer_id,
    payload: &encrypted_data,
};

transport.send(frame)?;
```

---

## q-common

**Shared types and utilities.**

```rust
use q_common::{Error, Result, SystemConfig, Version};

// Common error type used across crates
pub enum Error {
    Crypto(CryptoError),
    Hal(HalError),
    Identity(IdentityError),
    Attestation(AttestError),
    Update(UpdateError),
    Network(MeshError),
    InvalidArgument,
    BufferTooSmall,
    NotInitialized,
    // ...
}

// System configuration
let config = SystemConfig::default();

// Version information
let version = Version::new(0, 1, 0);
```

### Modules

| Module | Exports |
|--------|---------|
| `types` | Common type definitions |
| `errors` | `Error`, `Result` |
| `config` | `SystemConfig` |
| `log` | Logging macros and utilities |
| `constants` | System-wide constants |
| `time` | Tick-based time utilities |
| `version` | `Version` type |

---

## Tools CLI Reference

### q-sign

Firmware signing and package creation tool.

```
q-sign keygen     Generate a post-quantum signing keypair
q-sign sign       Sign a firmware image
q-sign verify     Verify a signed firmware image
q-sign package    Create an update package
q-sign keyinfo    Display key information
q-sign export-public  Export public key from private key
```

**keygen options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--algorithm` | `dilithium3`, `falcon512`, `falcon1024` | `dilithium3` |
| `--output` | Output path for key files | `./keys/` |
| `--purpose` | `firmware`, `update`, `attestation` | `firmware` |

**sign options:**

| Option | Description |
|--------|-------------|
| `--algorithm` | Signing algorithm |
| `--key` | Path to private key |
| `--image` | Path to firmware binary |
| `--image-type` | `bootloader`, `kernel`, `application` |
| `--version` | Firmware version |
| `--hw-version` | Hardware compatibility version |
| `--output` | Output path for signed image |

**verify options:**

| Option | Description |
|--------|-------------|
| `--image` | Path to signed firmware |
| `--key` | Path to public key (optional if embedded) |
| `--strict` | Fail on warnings |

**package options:**

| Option | Description |
|--------|-------------|
| `--bootloader` | Path to bootloader binary |
| `--kernel` | Path to kernel binary |
| `--application` | Path to application binary |
| `--key` | Signing key |
| `--target` | `stm32h7`, `stm32u5`, `riscv` |
| `--output` | Output package path |

### q-provision

Factory provisioning and device identity tool.

```
q-provision keygen       Generate PQC keys for a device
q-provision identity     Create device identity commitment
q-provision flash        Flash firmware to device via probe
q-provision verify       Verify a provisioned device
q-provision init-config  Generate default configuration
q-provision list-devices List connected debug probes
```

**keygen options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--key-type` | `kyber768`, `dilithium3`, `falcon512`, `all` | `all` |
| `--device-id` | Unique device identifier | Auto-generated |
| `--output` | Output directory | `./keys/` |

**identity options:**

| Option | Description |
|--------|-------------|
| `--device-id` | Device identifier |
| `--manufacturer-id` | Manufacturer identifier |
| `--device-class` | `gateway`, `sensor`, `actuator`, `controller` |
| `--puf-data` | Path to PUF challenge-response data |
| `--output` | Output path for identity files |

**flash options:**

| Option | Description |
|--------|-------------|
| `--target` | `stm32h7`, `stm32u5`, `riscv` |
| `--bootloader` | Bootloader binary |
| `--kernel` | Kernel binary |
| `--identity` | Identity data file |
| `--port` | Debug probe port |
| `--lock` | Lock flash after programming (production) |

**verify options:**

| Option | Description |
|--------|-------------|
| `--target` | Target platform |
| `--port` | Debug probe port |
| `--full` | Run full verification (crypto + flash) |

---

## Generating Full Documentation

For the complete, auto-generated API documentation with full type signatures and inline examples:

```bash
# Generate rustdoc for all crates
cargo doc --workspace --all-features --no-deps --open

# Generate docs for a specific crate
cargo doc -p q-crypto --all-features --no-deps --open

# Generate with private items (for contributors)
cargo doc --workspace --all-features --document-private-items --open
```
