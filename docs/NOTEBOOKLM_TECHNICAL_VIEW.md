# Qbitel EdgeOS — Complete Technical Reference

> **Document Purpose:** This document is the single, comprehensive technical reference for Qbitel EdgeOS. It covers every architectural layer, every crate, every algorithm, every data structure, every protocol, and every infrastructure component in complete detail. Intended for engineering review, security audit, and technical due diligence.

---

## 1. System Identity

- **Product Name:** Qbitel EdgeOS
- **Version:** 0.1.0 (Active Development, pre-1.0)
- **Language:** Rust (100% of OS), Python (tooling only)
- **Rust Edition:** 2021, Minimum Rust Version: 1.82 (stable)
- **License:** Apache License 2.0
- **Authors:** Qbitel Inc.
- **Repository:** https://github.com/yazhsab/qbitel-edgeos
- **Core Constraint:** `no_std` — no standard library, no heap allocations, no dynamic memory in production code
- **Safety Guarantees:** No `.unwrap()` in production code; all `unsafe` blocks require `// SAFETY:` comments; all secrets derive `Zeroize` and `ZeroizeOnDrop`; all secret comparisons use the `subtle` crate for constant-time equality

---

## 2. Architecture Overview

Qbitel EdgeOS is a layered, modular embedded operating system composed of 10 Rust crates organized in a strict dependency hierarchy:

```
Layer 5 (Applications):
+---------------------------------------------------------------+
|  q-update   |  q-recover  |  q-attest   |      q-mesh         |
|  Secure OTA |  Key Rotation| Attestation |  Mesh Networking    |
+---------------------------------------------------------------+

Layer 4 (Identity + Crypto):
+---------------------------------------------------------------+
|        q-identity          |          q-crypto                 |
|  Hardware-Bound Identity   |  Post-Quantum Crypto Engine       |
+---------------------------------------------------------------+

Layer 3 (Kernel):
+---------------------------------------------------------------+
|                         q-kernel                               |
|  Preemptive Scheduler | IPC | MPU/PMP Isolation | Syscalls     |
+---------------------------------------------------------------+

Layer 2 (Hardware Abstraction):
+---------------------------------------------------------------+
|                          q-hal                                 |
|      STM32H7 (Cortex-M7) | STM32U5 (Cortex-M33) | RISC-V     |
+---------------------------------------------------------------+

Layer 1 (Bootloader):
+---------------------------------------------------------------+
|                         q-boot                                 |
|  Secure Boot | Signature Verification | Anti-Rollback          |
+---------------------------------------------------------------+

Layer 0 (Shared):
+---------------------------------------------------------------+
|                        q-common                                |
|  Error Types | Logging | Time | Configuration | Constants      |
+---------------------------------------------------------------+
```

Each layer depends only on layers below it. No circular dependencies exist. All crates compile independently and can be tested on a host machine without hardware.

---

## 3. Crate-by-Crate Technical Specification

### 3.1. q-common — Shared Primitives

**Crate path:** `crates/q-common/`

Provides types, errors, and utilities shared across all other crates. No dependencies on any other Qbitel crate.

**Modules:**
- `types` — Core data types: `DeviceId` ([u8; 32]), `ManufacturerId` ([u8; 16]), `Timestamp` (u64), `AlgorithmId` (u8), `SecurityLevel` (enum)
- `errors` — Unified error enum with 40+ variants covering crypto, HAL, identity, attestation, update, network, and system errors
- `config` — `SystemConfig` struct for system-wide configuration
- `log` — Logging macros compatible with `defmt` for embedded debug output
- `constants` — System-wide constants (max task count, buffer sizes, timeout values)
- `time` — Tick-based time utilities for scheduling
- `version` — `Version` struct with `major.minor.patch` comparison and parsing

**Error Type (complete):**
```
Error enum variants:
  InvalidKey, InvalidSignature, RngFailure, BufferTooSmall,
  UnsupportedAlgorithm, DecapsulationFailed, UpdateCorrupted,
  RollbackAttempted, BootVerificationFailed, HardwareFingerprintMismatch,
  TaskCreationFailed, InvalidState, Timeout, NotInitialized,
  AlreadyInitialized, PermissionDenied, ResourceExhausted,
  InvalidArgument, CommunicationError, StorageError,
  AttestationFailed, IdentityInvalid, MeshError, ...
```

---

### 3.2. q-crypto — Post-Quantum Cryptographic Engine

**Crate path:** `crates/q-crypto/`

The cryptographic foundation of the entire system. Implements NIST-standardized post-quantum algorithms with constant-time execution, secure memory handling, and algorithm agility via traits.

**Dependencies:**
- `zeroize` 1.7 (with derive feature) for secret erasure
- `sha3` 0.10 for SHA3/SHAKE hash functions
- `aes-gcm` 0.10 for AES-256-GCM authenticated encryption
- `chacha20poly1305` 0.10 for ChaCha20-Poly1305 AEAD
- `subtle` 2.5 for constant-time operations
- `fn-dsa` 0.3 for Falcon (FN-DSA) signatures
- `rand_core` 0.6 for RNG trait compatibility

**Modules:**
- `error` — `CryptoError` enum: InvalidKey, InvalidSignature, SigningFailed, DecapsulationFailed, EncryptionFailed, DecryptionFailed, InvalidLength, RngFailure, BufferTooSmall, InvalidNonce, HashError, KdfError, UnsupportedAlgorithm
- `traits` — Abstract cryptographic interfaces
- `field` — Finite field arithmetic for lattice-based schemes
- `ntt` — Number Theoretic Transform for polynomial multiplication
- `rng` — `SystemRng` wrapping hardware TRNG
- `hash` — SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 implementations
- `aead` — AES-256-GCM and ChaCha20-Poly1305 implementations
- `kyber` — ML-KEM-768 (Kyber) implementation
- `dilithium` — ML-DSA-65 (Dilithium-3) implementation
- `falcon` — FN-DSA-512 (Falcon) implementation
- `kat` — Known Answer Tests for NIST compliance validation
- `zeroize_utils` — Helpers for secure memory cleanup
- `hybrid` (optional feature) — Hybrid classical+PQC modes
- `classical` (optional feature) — Classical algorithm fallbacks

**Feature Flags:** `default` (core PQC), `hybrid`, `classical`, `all-algorithms`

#### 3.2.1. Trait System

All cryptographic algorithms implement abstract traits for algorithm agility:

**`Kem` trait** — Key Encapsulation Mechanism:
- `type PublicKey`, `type SecretKey`, `type Ciphertext`, `type SharedSecret`
- `keygen(rng) -> (PublicKey, SecretKey)` — Generate keypair
- `encapsulate(pk, rng) -> (Ciphertext, SharedSecret)` — Create ciphertext + shared secret
- `decapsulate(ct, sk) -> SharedSecret` — Recover shared secret

**`Signer` trait** — Digital Signatures:
- `type PublicKey`, `type SecretKey`, `type Signature`
- `keygen(rng) -> (PublicKey, SecretKey)` — Generate signing keypair
- `sign(message, sk) -> Signature` — Sign a message
- `verify(message, signature, pk) -> bool` — Verify a signature

**`Hash` trait** — Cryptographic Hashing:
- `new() -> Self` — Create new hasher instance
- `update(data)` — Feed data incrementally
- `finalize() -> Digest` — Produce final hash
- `one_shot(data) -> Digest` — Hash in a single call

**`Aead` trait** — Authenticated Encryption:
- `encrypt(key, nonce, plaintext, aad) -> Ciphertext` — Encrypt with authenticated associated data
- `decrypt(key, nonce, ciphertext, aad) -> Plaintext` — Decrypt and verify

**`Xof` trait** — Extendable Output Function:
- `new() -> Self`, `update(data)`, `squeeze(output_len) -> Bytes`

**`CryptoRng` trait** — Cryptographic RNG:
- `fill_bytes(buf)` — Fill buffer with cryptographically secure random bytes

**`Kdf` trait** — Key Derivation Function:
- `derive(ikm, salt, info, output_len) -> DerivedKey`

All traits enforce: constant-time execution, mandatory zeroization of secret types, type safety preventing algorithm confusion.

#### 3.2.2. ML-KEM-768 (Kyber) — Key Encapsulation

**Standard:** NIST FIPS 203
**Security Level:** NIST Level 3 (equivalent to AES-192 classical security)

**Parameters:**
- Polynomial degree (n): 256
- Module dimension (k): 3
- Modulus (q): 3329
- Noise parameters: eta1 = 2, eta2 = 2
- Compression bits: du = 10, dv = 4
- Shared secret size: 32 bytes

**Key and Ciphertext Sizes:**
- Public key: 1184 bytes (3 compressed polynomials + 32-byte seed rho)
- Secret key: 2400 bytes (secret vector s + public key + hash(pk) + rejection secret z)
- Ciphertext: 1088 bytes (compressed u vector + compressed v)
- Shared secret: 32 bytes

**Data Structures:**
- `Kyber768PublicKey` — Contains: t (public vector in NTT domain, 3 x 256 coefficients), rho (32-byte seed for generating matrix A)
- `Kyber768SecretKey` — Contains: s (secret vector), t (public vector), rho (seed), h_pk (SHA3-256 hash of public key), z (32-byte implicit rejection secret). Derives Zeroize + ZeroizeOnDrop.
- `Kyber768Ciphertext` — Contains: compressed u (polynomial vector) and v (polynomial)
- `Kyber768SharedSecret` — 32-byte shared secret. Derives Zeroize + ZeroizeOnDrop.

**Key Functions:**
- `generate_keypair_from_seed(seed: [u8; 64])` — Deterministic keypair generation from 64-byte seed
- `encapsulate_with_randomness(pk, randomness: [u8; 32])` — Deterministic encapsulation for testing
- `decapsulate_internal(ct, sk)` — Core decapsulation with implicit rejection (returns random-looking output on failure instead of error, preventing timing attacks)

**Security Properties:**
- Constant-time polynomial arithmetic via NTT
- Implicit rejection: invalid ciphertexts produce random-looking shared secrets rather than errors
- No secret-dependent branching in any operation
- All intermediate values zeroized after use

#### 3.2.3. ML-DSA-65 (Dilithium-3) — Digital Signatures

**Standard:** NIST FIPS 204
**Security Level:** NIST Level 3

**Parameters:**
- Polynomial degree (n): 256
- Modulus (q): 8,380,417
- Module dimensions: k = 6 (public key), l = 5 (secret key)
- Noise bound (eta): 4
- Gamma1: 2^19 (masking vector range)
- Gamma2: (q-1)/32 = 261,888
- Challenge weight (tau): 49
- Beta: 196 (rejection bound)
- Omega: 55 (max hint ones)

**Key and Signature Sizes:**
- Public key: 1952 bytes
- Secret key: 4000 bytes
- Signature: 3293 bytes

**Data Structures:**
- `Dilithium3PublicKey` — Contains: rho (32-byte seed for matrix A), t1 (high bits of t = A*s1 + s2)
- `Dilithium3SecretKey` — Contains: rho, key (32-byte secret seed), tr (SHA3-512 hash of pk), s1 (secret vector, l=5 polynomials), s2 (secret vector, k=6 polynomials), t0 (low bits of t). All secret fields zeroized on drop.
- `Dilithium3Signature` — 3293 bytes: c_tilde (challenge hash, 32 bytes) + z (response vector) + hint (h)

**Signing Algorithm (detailed):**
1. Regenerate matrix A from seed rho using SHAKE-128
2. Transform s1, s2, t0 to NTT domain
3. Compute mu = CRH(tr || message) where CRH is SHA3-512
4. Initialize rejection sampling counter (max 1000 attempts)
5. For each attempt:
   a. Sample masking vector y uniformly from [-gamma1+1, gamma1]
   b. Compute w = A * NTT(y) in NTT domain
   c. Decompose w into high bits w1 and low bits w0
   d. Compute c_tilde = H(mu || w1) using SHAKE-256
   e. Sample challenge polynomial c from c_tilde (tau non-zero coefficients in {-1, +1})
   f. Compute z = y + c * s1
   g. Check if infinity norm of z < gamma1 - beta (reject if not)
   h. Compute r0 = w0 - c * s2
   i. Check if infinity norm of r0 < gamma2 - beta (reject if not)
   j. Compute ct0 = c * t0
   k. Check if infinity norm of ct0 < gamma2 (reject if not)
   l. Compute hint h = MakeHint(-ct0, w - cs2 + ct0)
   m. Check if number of ones in h <= omega (reject if not)
   n. Pack signature: (c_tilde, z, h)
6. Return signature or error if max attempts exceeded

**Verification Algorithm:**
1. Expand matrix A from public key seed rho
2. Unpack signature: (c_tilde, z, h)
3. Check: infinity norm of z < gamma1 - beta
4. Compute w' = A * NTT(z) - c * NTT(t1) * 2^d
5. Use hints h to recover w1' = UseHint(h, w')
6. Compute c_tilde' = H(mu || w1')
7. Accept if c_tilde == c_tilde'

#### 3.2.4. FN-DSA-512 (Falcon) — Compact Signatures

**Standard:** NIST Round 3 finalist
**Security Level:** NIST Level 1 (equivalent to AES-128)
**Implementation:** Uses `fn-dsa` crate (v0.3)

**Key and Signature Sizes:**
- Public key: 897 bytes
- Secret key: ~1281 bytes
- Signature: ~666 bytes (compact, variable length)

Falcon is used where signature size is critical (e.g., constrained mesh network frames).

#### 3.2.5. Hash Functions

**SHA3-256** (FIPS 202): 32-byte output, 128-bit security. Used for image hashes, identity commitments, PUF fingerprints.

**SHA3-384** (FIPS 202): 48-byte output, 192-bit security. Used for extended hashing requirements.

**SHA3-512** (FIPS 202): 64-byte output, 256-bit security. Used for key derivation input and transcript hashing.

**SHAKE128** (FIPS 202): XOF with 128-bit security. Used for matrix generation in Kyber/Dilithium.

**SHAKE256** (FIPS 202): XOF with 256-bit security. Used for challenge generation in Dilithium.

#### 3.2.6. Authenticated Encryption

**AES-256-GCM** (FIPS 197): 256-bit key, 96-bit nonce, 128-bit authentication tag. Primary AEAD cipher for stored data and standard communications.

**ChaCha20-Poly1305** (RFC 8439): 256-bit key, 96-bit nonce, 128-bit authentication tag. Used for mesh session encryption (more suitable for software-only implementations on resource-constrained devices).

#### 3.2.7. Key Derivation

**HKDF-SHA3-256** (RFC 5869 with SHA3): Used to derive session keys from shared secrets during mesh handshake. Extract-then-expand paradigm with domain separation labels.

---

### 3.3. q-hal — Hardware Abstraction Layer

**Crate path:** `crates/q-hal/`

Provides platform-agnostic trait interfaces for hardware peripherals. Compile-time platform selection via feature flags.

**Platform Enumeration:**
```
Platform::Stm32H7  — ARM Cortex-M7 @ 480 MHz, 2MB flash, 1MB RAM, TrustZone-M
Platform::Stm32U5  — ARM Cortex-M33 @ 160 MHz, 2MB flash, 786KB RAM, TrustZone-M
Platform::RiscV    — SiFive FE310 RV32IMAC @ 320 MHz, 16MB flash, 16KB RAM, PMP
Platform::Unknown  — Host/testing
```

**Feature Flags:** `stm32h7`, `stm32u5`, `riscv` (mutually exclusive)

**Hardware Trait Interfaces:**
- `Gpio` — Digital I/O: set_high(), set_low(), is_high(), configure(mode)
- `Uart` — Serial: write(data) -> usize, read(buf) -> usize, configure(baud, parity, stop_bits)
- `Spi` — SPI bus: transfer(data), write(data), read(buf)
- `I2c` — I2C bus: write_read(addr, write_buf, read_buf)
- `Flash` — Flash memory: read(addr, buf), write(addr, data), erase_sector(sector), is_busy()
- `Rng` — Hardware TRNG: fill_bytes(buf)
- `SecureStorage` — OTP/eFUSE: read_otp(block, buf), write_otp(block, data)
- `Watchdog` — Watchdog timer: start(timeout_ms), feed(), is_expired()
- `Puf` — Physical Unclonable Function: challenge(input) -> response

**Memory Maps:**
| Platform | Flash Base | RAM Base | OTP Base | UID Base |
|----------|-----------|---------|---------|---------|
| STM32H7 | 0x0800_0000 | 0x2000_0000 | 0x1FF0_F000 | 0x1FF1_E800 |
| STM32U5 | 0x0800_0000 | 0x2000_0000 | 0x0BFA_0000 | 0x0BFA_0700 |
| RISC-V | 0x2000_0000 | 0x8000_0000 | 0x1000_0000 | 0x1000_0004 |

**STM32H7 Peripheral Drivers:**
- `gpio.rs` — GPIO pin control (ports A-K)
- `uart.rs` — UART1-8 serial communication
- `spi.rs` — SPI1-6 bus master/slave
- `i2c.rs` — I2C1-4 bus communication
- `flash.rs` — Dual-bank flash controller (Bank 1: 0x0800_0000, Bank 2: 0x0810_0000), sector erase, write with ECC
- `rng.rs` — Hardware True Random Number Generator peripheral
- `secure_storage.rs` — OTP memory blocks and eFUSE access
- `watchdog.rs` — Independent Watchdog (IWDG)
- `timer.rs` — TIM1-17 general purpose timers
- `puf.rs` — SRAM PUF implementation using power-on SRAM state
- `crypto.rs` — Hardware CRYP and HASH accelerator peripheral access
- `system_rng.rs` — System RNG wrapper implementing q-crypto's CryptoRng trait

---

### 3.4. q-boot — Secure Bootloader

**Crate path:** `crates/q-boot/`

First code to execute on device power-on. Verifies firmware integrity using post-quantum signatures before transferring control.

**Modules:** `verify`, `load`, `rollback`, `recovery`, `boot_log`

**Dependencies:** q-crypto (for Dilithium3, SHA3-256), q-hal (for flash, OTP)

#### 3.4.1. Image Header Format

The firmware image header is a packed C-compatible structure (3421 bytes total):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | magic | "QEDG" (0x47444551) for kernel, "QBTL" for bootloader |
| 0x04 | 2 | format_version | Header format version (currently 1) |
| 0x06 | 1 | image_type | 0=Bootloader, 1=Kernel, 2=Application |
| 0x07 | 1 | flags_low | Lower 8 bits of flags |
| 0x08 | 4 | flags | ENCRYPTED(bit0), SECURE_BOOT_REQUIRED(bit1), DEBUGGABLE(bit2), HW_BOUND(bit3), HYBRID_SIGNATURE(bit4) |
| 0x0C | 4 | version | Encoded as major.minor.patch.build |
| 0x10 | 4 | image_size | Size of firmware image (excluding header) |
| 0x14 | 4 | load_address | Memory address to load the image |
| 0x18 | 4 | entry_offset | Entry point offset from load_address |
| 0x1C | 4 | rollback_counter | Monotonic anti-rollback counter |
| 0x20 | 32 | image_hash | SHA3-256 hash of the firmware image |
| 0x40 | 32 | hw_binding | SHA3-256(root_key || PUF_fingerprint) |
| 0x60 | 32 | reserved | Reserved for future use |
| 0x80 | 3293 | signature | ML-DSA-65 (Dilithium-3) signature |

#### 3.4.2. Verification Sequence

Full verification of a firmware image:

1. **Address validation** — Verify the flash address is within valid range
2. **Magic number check** — First 4 bytes must be KERNEL_MAGIC (0x47444551) or BOOTLOADER_MAGIC
3. **Format version check** — Must be <= current supported version (1)
4. **Image size validation** — Must be > 0 and <= 4MB
5. **Rollback counter check** — Header counter must be >= stored OTP counter
6. **Hardware binding check** (if HW_BOUND flag set):
   - Read PUF fingerprint from hardware
   - Compute SHA3-256(root_key || PUF_fingerprint)
   - Compare with header's hw_binding field (constant-time comparison)
7. **Image hash computation** — Read firmware image data, compute SHA3-256, compare with header's image_hash
8. **Signature verification** — Verify Dilithium-3 signature over all header fields (excluding the signature field itself) using the root public key

If any step fails, the bootloader moves to the fallback slot or recovery mode.

#### 3.4.3. Boot Chain Decision

```
verify_boot_chain() returns:
  Boot { entry_point, slot }        — Primary slot verified, boot it
  Fallback { entry_point, slot, error } — Primary failed, fallback verified
  Halt { primary_error, fallback_error } — Both failed, enter recovery
```

#### 3.4.4. Anti-Rollback Protection

Monotonic counters stored in OTP memory using unary encoding (count set bits):

**OTP Layout (STM32H7):**
| Block Range | Size | Purpose |
|------------|------|---------|
| 0-3 | 128 bytes | Bootloader version counter (up to 1024 versions) |
| 4-7 | 128 bytes | Kernel version counter |
| 8-11 | 128 bytes | Application version counter |

Counter can only increment (OTP bits can only go from 0 to 1, never back). Reading counts set bits. Writing sets the next unset bit.

#### 3.4.5. PUF Providers

**SRAM PUF Provider:**
- Reads 256 bytes from SRAM1 base (0x2000_0000) before SRAM initialization
- Applies fuzzy extraction with 64-byte helper data (enrolled during provisioning)
- Error correction tolerates up to 15% bit flips between power cycles
- Output: SHA3-256 of corrected PUF response

**eFUSE Fingerprint Provider:**
- Reads 12-byte unique device ID from STM32 UID registers at 0x1FF1_E800
- Applies domain separation: SHA3-256("qbitel-efuse-v1" || device_uid)
- Output: 32-byte fingerprint

#### 3.4.6. Boot Logging

Persistent boot log stored in dedicated flash sector:

```
BootLogEntry:
  - timestamp: u64 (tick count at event)
  - stage: BootStage (HardwareInit | BootloaderVerify | KernelLoad | KernelVerify | KernelStart)
  - category: ErrorCategory (Crypto | Storage | Memory | Hardware | Timeout)
  - error_code: u32
  - details: [u8; 16]
```

The boot log survives across resets and is used to detect repeated boot failures (triggering recovery mode after a configurable threshold, default 3 consecutive failures).

#### 3.4.7. Recovery Mode

Recovery mode is entered when:
- Primary and fallback slots both fail verification
- Boot failure counter exceeds threshold
- Manual trigger via hardware pin (GPIO held low during reset)

In recovery mode, the device:
- Disables normal boot path
- Activates UART/SWD debug interface
- Accepts firmware re-flashing via debug probe
- Does NOT execute any application code

#### 3.4.8. Incremental Verifier

For systems where verification must be interleaved with other operations:

```
States: Idle -> ReadingHeader -> ValidatingFields -> CheckingRollback ->
        ComputingHash -> VerifyingSignature -> Complete
```

`step()` method advances one state per call. `verify()` runs to completion.

---

### 3.5. q-kernel — Microkernel

**Crate path:** `crates/q-kernel/`

Minimal microkernel providing preemptive task scheduling, hardware-enforced memory isolation, inter-process communication, and a syscall interface.

**Modules:** `scheduler`, `memory`, `ipc`, `syscall`, `task`, `panic`, `arch`

**Dependencies:** q-crypto, q-identity, q-update, q-recover, q-mesh, q-attest, q-hal, q-common, cortex-m (optional), cortex-m-rt (optional), heapless 0.8

#### 3.5.1. Scheduler

**Algorithm:** Priority-based preemptive scheduling with round-robin within the same priority level.

**Configuration:**
- Maximum concurrent tasks: 16 (compile-time constant MAX_TASKS)
- Configurable CPU frequency (default 480 MHz for STM32H7)
- Configurable tick rate (default 1000 Hz = 1ms tick)
- Time slice per task: configurable

**Task Priority Levels (descending):**
```
Critical — Interrupt-level urgency (safety-critical operations)
High     — Real-time tasks (sensor reading, communication)
Normal   — Standard application tasks
Low      — Background processing (logging, telemetry buffering)
Idle     — Only runs when no other task is ready
```

**Task States:**
```
Ready       — Task is ready to run
Running     — Task is currently executing
Sleeping(wake_at: u64) — Task sleeping until tick count reaches wake_at
Blocked     — Task waiting on IPC or resource
Terminated  — Task has finished execution
```

**Task Control Block:**
```
Task {
  id: TaskId (u8),
  entry: fn() -> ! (task entry point, never returns),
  priority: TaskPriority,
  state: TaskState,
  context: TaskContext (saved CPU registers),
  stack_base: *mut u8 (pointer to stack memory),
  stack_size: usize,
  time_slice: u32 (ticks per scheduling quantum),
  mpu_regions: [Option<MpuRegion>; 2] (ARM MPU regions for this task),
  pmp_entries: [Option<PmpEntry>; 2] (RISC-V PMP entries for this task),
  stats: TaskStats { total_ticks, context_switches, created_at },
  name: [u8; 16] (human-readable task name),
}
```

**Scheduler Statistics:**
```
SchedulerStats {
  total_ticks: u64,
  context_switches: u64,
  idle_ticks: u64,
  task_count: u8,
}
```

**Scheduling Algorithm:**
1. On each SysTick interrupt (every 1ms by default):
   a. Increment global tick counter
   b. Wake any sleeping tasks whose wake_at <= current tick
   c. Check if current task has exhausted its time slice
   d. If time slice expired or task yielded: select next task
2. Task selection:
   a. Find highest priority level with any Ready tasks
   b. Among Ready tasks at that priority: round-robin (advance index)
   c. If no Ready tasks: run idle task
3. If selected task differs from current task: perform context switch

**Priority Inheritance:**
- `boost_priority(task_id, new_priority)` — Temporarily elevate a task's priority (used when a high-priority task is blocked waiting for a resource held by a lower-priority task)
- `restore_priority(task_id)` — Restore original priority after resource is released

#### 3.5.2. Context Switching

**ARM Cortex-M (PendSV handler):**
1. Exception entry automatically saves: R0-R3, R12, LR, PC, xPSR
2. PendSV handler manually saves: R4-R11, FPU registers (if used)
3. Save current stack pointer to task control block
4. Switch MPU regions to new task's memory protection configuration
5. Load new task's stack pointer
6. Restore R4-R11, FPU registers
7. Exception return restores R0-R3, R12, LR, PC, xPSR

**RISC-V (software interrupt):**
1. Save all general-purpose registers (x1-x31) to current task's context
2. Save mepc (return address) and mstatus
3. Switch PMP entries to new task's configuration
4. Load new task's context registers
5. Set mepc to new task's saved PC
6. mret to resume new task

#### 3.5.3. Memory Protection

**ARM MPU Configuration:**
- Each task gets up to 2 MPU regions: one for code/rodata (read-only), one for data/stack (read-write)
- Kernel memory is always accessible only in privileged mode
- Peripheral access is restricted to kernel-mode only
- Stack guard: 32-byte no-access region at bottom of each task's stack (detects overflow)

**RISC-V PMP Configuration:**
- Each task gets up to 2 PMP entries
- Similar read/write/execute permission model
- TOR (Top of Range) addressing mode for flexible region sizes

#### 3.5.4. IPC Channels

Static, type-safe, bounded channels for inter-task communication:

```
Channel<T, N> where T: Copy, N: usize (buffer capacity)
  send(item: T) -> Result    // Blocks if full
  try_send(item: T) -> Result // Non-blocking, returns error if full
  recv() -> Result<T>         // Blocks if empty
  try_recv() -> Result<T>     // Non-blocking, returns error if empty
  is_full() -> bool
  is_empty() -> bool
  len() -> usize
```

Channels are statically allocated (no heap). Buffer size N is a const generic parameter. Sending to a full channel or receiving from an empty channel blocks the calling task (sets state to Blocked).

#### 3.5.5. Syscall Interface

System calls provide safe entry from unprivileged task code to privileged kernel code:

| Syscall | Number | Purpose |
|---------|--------|---------|
| SYS_YIELD | 0 | Yield current time slice |
| SYS_SLEEP | 1 | Sleep for specified ticks |
| SYS_SEND | 2 | Send on IPC channel |
| SYS_RECV | 3 | Receive from IPC channel |
| SYS_GET_TICK | 4 | Get current tick count |
| SYS_GET_TASK_ID | 5 | Get current task's ID |

Implemented via SVC (Supervisor Call) instruction on ARM Cortex-M, or ecall instruction on RISC-V.

#### 3.5.6. Kernel Public API

```
configure(cpu_freq_hz: u32, tick_rate_hz: u32)  // Set kernel timing parameters
init()                                            // Initialize all subsystems
start() -> !                                      // Start scheduler (never returns)
add_task(entry, stack, stack_size, priority, name) -> TaskId
yield_now()                                       // Voluntary yield
sleep(ticks: u64)                                 // Sleep for tick count
sleep_ms(ms: u32)                                 // Sleep for milliseconds
ticks() -> u64                                    // Current tick count
current_task() -> TaskId                          // Current task's ID

Constants:
  VERSION: &str                                   // Kernel version string
  BUILD_INFO: &str                                // Build metadata
```

---

### 3.6. q-identity — Device Identity Management

**Crate path:** `crates/q-identity/`

Hardware-bound device identity system. No certificates. No PKI. No cloud dependency. Identity is cryptographically anchored to physical hardware characteristics.

**Modules:** `commitment`, `hardware_binding`, `verification`, `storage`, `lifecycle`

#### 3.6.1. Identity Commitment Structure

The core data structure (approximately 6.6 KB):

| Field | Size | Description |
|-------|------|-------------|
| version | 1 byte | Commitment format version |
| device_id | 32 bytes | Globally unique device identifier |
| manufacturer_id | 16 bytes | Factory/manufacturer identifier |
| device_class | 1 byte | Gateway (0x01) / Sensor (0x02) / Actuator (0x03) / Controller (0x04) |
| created_at | 8 bytes | Unix timestamp of identity creation |
| kem_algorithm | 1 byte | Algorithm ID for KEM key (Kyber768) |
| sig_algorithm | 1 byte | Algorithm ID for signing key (Dilithium3) |
| kem_public_key | 1184 bytes | ML-KEM-768 public key |
| signing_public_key | 1952 bytes | ML-DSA-65 public key |
| hardware_fingerprint_hash | 32 bytes | SHA3-256 of PUF/eFUSE response |
| metadata | 256 bytes | Custom metadata (variable length, padded) |
| metadata_len | 2 bytes | Actual metadata length |
| self_signature | 3293 bytes | Dilithium3 signature over all preceding fields |

**Identity Secrets** (never leaves the device):
| Field | Size | Description |
|-------|------|-------------|
| kem_secret_key | 2400 bytes | ML-KEM-768 secret key |
| signing_secret_key | 4000 bytes | ML-DSA-65 secret key |
| hardware_binding_key | 32 bytes | Derived from PUF response |
| master_seed | 64 bytes | Root seed for all key derivations |

All secret fields implement `Zeroize` and `ZeroizeOnDrop`.

#### 3.6.2. Identity Verification

Offline verification (no network required):

1. Read `IdentityCommitment` from secure flash storage
2. Read current hardware fingerprint (PUF challenge or eFUSE UID)
3. Compute SHA3-256 of hardware fingerprint
4. Compare computed fingerprint hash with stored `hardware_fingerprint_hash` (constant-time)
5. Verify `self_signature` over all commitment fields using embedded `signing_public_key`
6. Return: `Valid`, `InvalidSignature`, `HardwareBindingMismatch`, `Expired`, or `Revoked`

**Result enum:**
```
VerificationResult:
  Valid                     — Identity is authentic and hardware-bound
  InvalidSignature          — Self-signature verification failed (tampering detected)
  HardwareBindingMismatch   — PUF/eFUSE doesn't match (cloning detected)
  Expired                   — Identity past its validity period
  Revoked                   — Identity appears on revocation list
```

#### 3.6.3. Identity Lifecycle

| State | Description |
|-------|-------------|
| Provisioned | Identity created at factory, keys generated, PUF enrolled |
| Active | Device deployed, identity verified on each boot |
| Rotated | Keys rotated via q-recover, new commitment created |
| Suspended | Temporarily disabled (can be reactivated) |
| Revoked | Permanently disabled (cannot be reactivated) |

---

### 3.7. q-attest — Attestation Protocol

**Crate path:** `crates/q-attest/`

Remote attestation system for proving device integrity and tracking supply chain provenance.

**Modules:** `evidence`, `verification`, `protocol`, `supply_chain`, `runtime`, `anomaly`

#### 3.7.1. Attestation Evidence

```
AttestationEvidence:
  boot_measurements:
    bootloader_hash: [u8; 32]   — SHA3-256 of bootloader image
    kernel_hash: [u8; 32]       — SHA3-256 of kernel image
    config_hash: [u8; 32]       — SHA3-256 of configuration data
  runtime_measurements:
    task_list_hash: [u8; 32]    — Hash of current task configurations
    memory_integrity: [u8; 32]  — Hash of kernel memory regions
    uptime: u64                 — Ticks since boot
  hardware_fingerprint: [u8; 32] — Current PUF/eFUSE fingerprint
  firmware_version: Version
  timestamp: u64
  nonce: [u8; 32]               — Freshness nonce from verifier
```

#### 3.7.2. Protocol Flow

```
Verifier                                Device
   |                                       |
   |  AttestationRequest                   |
   |  { scope, nonce, policy }             |
   |-------------------------------------> |
   |                                       |  Collect evidence
   |                                       |  Sign with device key
   |              AttestationResponse      |
   |  { evidence, signature[3293 bytes] }  |
   | <-------------------------------------|
   |                                       |
   Verify signature                        |
   Compare measurements                   |
   Check policy compliance                |
   |                                       |
   Result: Trusted / Untrusted / Unknown   |
```

#### 3.7.3. Supply Chain Tracking

Hash-linked provenance ledger recording manufacturing and deployment events:

```
SupplyChainEntry:
  event_type: Manufacturing | Testing | Shipping | Deployment | Maintenance
  timestamp: u64
  actor_id: [u8; 32]        — Who performed the action
  location: [u8; 16]        — Where (facility code)
  previous_hash: [u8; 32]   — Hash of previous entry (chain linkage)
  data: [u8; 128]           — Event-specific data
  signature: [u8; 3293]     — Signed by actor's key
```

#### 3.7.4. Anomaly Detection

Runtime monitoring for:
- Unexpected boot measurement changes
- Abnormal task creation or termination patterns
- Memory access violations
- Communication pattern deviations
- Firmware version inconsistencies

---

### 3.8. q-update — Secure OTA Updates

**Crate path:** `crates/q-update/`

Secure firmware update system with A/B partitioning, signed manifests, and air-gap support.

**Modules:** `manifest`, `verification`, `version`, `rollback`, `apply`, `staged`, `airgap`, `slots`

#### 3.8.1. Update Manifest

```
UpdateManifest:
  magic: u32 (0x51555044 = "QUPD")
  version: Version (major.minor.patch)
  rollback_version: u32 (monotonic counter value)
  target_platform: Platform (Stm32H7 | Stm32U5 | RiscV)
  image_hash: [u8; 32] (SHA3-256 of firmware image)
  image_size: u32
  dependencies: Vec<Dependency, 8> (max 8 crate version requirements)
  created_at: u64 (Unix timestamp)
  signature: [u8; 3293] (ML-DSA-65 signature over all preceding fields)
```

#### 3.8.2. A/B Slot Management

```
Slot A (Primary):  Flash address 0x0802_0000 (after bootloader)
Slot B (Fallback): Flash address 0x0810_0000 (Bank 2 on STM32H7)

SlotState flow:
  Empty -> Staged (firmware written) -> Valid (signature verified)
  Valid -> Active (currently booting from this slot)
  Valid -> Invalid (verification failed or corruption detected)

SlotManager:
  active_slot() -> Slot
  inactive_slot() -> Slot
  slot_status(slot) -> SlotStatus { state, version, hash, size }
  mark_staged(slot)
  mark_valid(slot)
  mark_active(slot)
  mark_invalid(slot)
  update_rollback_counter(version)
```

#### 3.8.3. Update Flow (Complete)

1. **Notification** received via mesh network, AWS IoT MQTT, or local trigger
2. **Download** manifest from update source (S3, USB, UART)
3. **Verify manifest** signature using ML-DSA-65 and the update signing public key
4. **Check version** against current monotonic rollback counter (reject if <=)
5. **Check platform** compatibility (target must match current platform)
6. **Write firmware** to inactive slot (A or B, whichever is not currently active)
7. **Verify written data** by computing SHA3-256 and comparing with manifest hash
8. **Mark slot as Staged**, then Tested
9. **Set boot preference** to new slot
10. **Reboot**
11. **q-boot verifies** new slot (full signature verification)
12. **On success:** Application confirms, slot marked Active, rollback counter updated in OTP
13. **On failure:** q-boot automatically reverts to previous slot (the old Active slot)

**Air-Gap Mode:** Same flow, but firmware is read from UART/SPI/external flash instead of network download. Manifest verification is identical.

---

### 3.9. q-recover — Key Recovery and Rotation

**Crate path:** `crates/q-recover/`

Field-serviceable key lifecycle management without requiring physical access to devices.

**Modules:** `rotation`, `threshold`, `recovery`, `revocation`, `offline`

#### 3.9.1. Shamir Secret Sharing (GF(2^8))

Threshold scheme operating over the Galois Field GF(2^8) with the irreducible polynomial x^8 + x^4 + x^3 + x + 1.

```
ThresholdScheme:
  split_secret(secret: &[u8], n: u8, t: u8) -> Vec<Share, 16>
    — Split secret into n shares; any t shares can reconstruct
  reconstruct(shares: &[Share]) -> Result<Secret>
    — Reconstruct secret from >= t shares using Lagrange interpolation
```

- Maximum 16 shares (n <= 16)
- Threshold 2 <= t <= n
- Each share is secret_length + 1 bytes (1 byte for x-coordinate)
- Byte-by-byte Lagrange interpolation over GF(2^8)

#### 3.9.2. Key Rotation Protocol

1. **Generate** new ML-KEM-768 + ML-DSA-65 keypair
2. **Create** new `IdentityCommitment` with new public keys
3. **Sign** transition record with the OLD signing key (proves continuity)
4. **Store** new keys in secure storage
5. **Update** self-signature with new signing key
6. **Broadcast** new public keys to mesh peers
7. **Zeroize** old private key material

#### 3.9.3. Batch Revocation

```
RevocationList:
  version: u32
  entries: Vec<DeviceId, 256>     — Up to 256 revoked devices per list
  issued_at: u64
  expires_at: u64
  issuer_id: [u8; 32]
  signature: [u8; 3293]          — Signed by fleet authority key
```

Distributed via mesh network or cloud. Devices check incoming connections against the revocation list and refuse communication with revoked peers.

---

### 3.10. q-mesh — Secure Mesh Networking

**Crate path:** `crates/q-mesh/`

Post-quantum secured mesh networking for air-gapped and infrastructure-free deployments.

**Modules:** `discovery`, `handshake`, `session`, `routing`, `group`, `transport`, `radio`

#### 3.10.1. Protocol Stack

```
+------------------------------+
| Application Data             |
+------------------------------+
| Session Layer (encryption)   |  ChaCha20-Poly1305 or AES-256-GCM
+------------------------------+
| Routing Layer (multi-hop)    |  Source routing + neighbor tables
+------------------------------+
| Transport Layer (framing)    |  Frame type, priority, addressing
+------------------------------+
| Radio Layer (physical)       |  LoRa / 802.15.4 / BLE
+------------------------------+
```

#### 3.10.2. Handshake Protocol (Detailed)

**Message Structures:**

ClientHello (total ~1252 bytes):
```
version: u8 (protocol version, currently 1)
client_random: [u8; 32] (fresh random nonce)
kem_public_key: [u8; 1184] (ephemeral ML-KEM-768 public key)
client_id: [u8; 32] (device identity)
```

ServerHello (total ~4414 bytes):
```
version: u8
server_random: [u8; 32]
kem_ciphertext: [u8; 1088] (ML-KEM-768 ciphertext encapsulating shared secret)
server_id: [u8; 32]
signature: [u8; 3293] (ML-DSA-65 signature over: client_random || server_random || kem_ciphertext)
```

ClientFinished (total ~3325 bytes):
```
signature: [u8; 3293] (ML-DSA-65 signature over: transcript_hash)
verify_data: [u8; 32] (HKDF-SHA3-256 derived verification value)
```

**Session Key Derivation:**
```
shared_secret = ML-KEM-768.Decapsulate(kem_ciphertext, ephemeral_secret_key)
master_secret = HKDF-Extract(salt=client_random||server_random, ikm=shared_secret)
client_write_key = HKDF-Expand(master_secret, "client_write_key", 32)
server_write_key = HKDF-Expand(master_secret, "server_write_key", 32)
client_write_mac = HKDF-Expand(master_secret, "client_write_mac", 32)
server_write_mac = HKDF-Expand(master_secret, "server_write_mac", 32)
```

All 4 keys are 32 bytes. Session uses ChaCha20-Poly1305 for frame encryption with the appropriate directional key.

#### 3.10.3. Frame Structure

```
FrameHeader (16 bytes):
  frame_type: u8 (Data=0x01, Beacon=0x02, Handshake=0x03, Ack=0x04, Control=0x05)
  priority: u8 (Critical=0, High=1, Normal=2, Low=3)
  source: [u8; 4] (truncated device ID)
  destination: [u8; 4] (truncated device ID, 0xFFFFFFFF for broadcast)
  sequence: u16 (frame sequence number)
  hop_count: u8 (TTL, decremented at each hop)
  payload_len: u16

EncryptedFrame:
  header: FrameHeader (16 bytes, authenticated but not encrypted)
  ciphertext: [u8; payload_len] (encrypted payload)
  auth_tag: [u8; 16] (Poly1305 authentication tag)
  nonce: [u8; 12] (derived from sequence number + direction)
```

#### 3.10.4. Peer Discovery

Beacon messages broadcast periodically (configurable interval, default 30 seconds):

```
BeaconMessage:
  device_id: [u8; 32]
  capabilities: u16 (bitfield: LoRa, 802.15.4, BLE, relay_capable, gateway)
  group_ids: Vec<u16, 4> (up to 4 group memberships)
  signal_strength: i8 (dBm)
  battery_level: u8 (percentage)
  hop_count: u8 (how far this beacon has traveled)
  timestamp: u32 (relative time)
```

Neighbor table updated on beacon receipt. Stale entries removed after 5x beacon interval.

#### 3.10.5. Routing

**Routing Table:**
```
RoutingEntry:
  destination: [u8; 4] (truncated device ID)
  next_hop: [u8; 4] (next device to relay through)
  metric: u8 (hop count to destination)
  last_updated: u32 (timestamp)
  expires: u32 (timestamp)
```

Routing algorithm: distance-vector with split horizon. Maximum hop count: 8. Route expiry: 5 minutes (configurable).

#### 3.10.6. LoRa Radio Configuration

```
LoRaConfig:
  frequency: FrequencyBand
    EU868 — 863-870 MHz (EU, 14 dBm max EIRP)
    US915 — 902-928 MHz (US, 30 dBm max EIRP)
    AS923 — 920-923 MHz (Asia)
    AU915 — 915-928 MHz (Australia)
  spreading_factor: SpreadingFactor
    SF7 (highest data rate, shortest range)
    SF8, SF9, SF10, SF11
    SF12 (lowest data rate, longest range)
  bandwidth: Bandwidth
    Bw125kHz (standard)
    Bw250kHz (higher data rate)
    Bw500kHz (highest data rate)
  coding_rate: CodingRate
    Cr4_5 (least overhead, minimum error correction)
    Cr4_6, Cr4_7
    Cr4_8 (most overhead, maximum error correction)
  tx_power: i8 (-17 to +22 dBm)
  preamble_length: u16 (default 8 symbols)
```

#### 3.10.7. Group Management

```
GroupManager:
  create_group(group_id, policy) -> Result
  add_member(group_id, peer_id, trust_level, role) -> Result
  remove_member(group_id, peer_id) -> Result
  verify_membership(group_id, peer_id) -> Result
  get_policy(group_id) -> GroupPolicy

TrustLevel: Full | Relay | ReadOnly | Untrusted
GroupRole: Admin | Member | Guest
```

---

## 4. Example Applications

### 4.1. Smart Meter

**Path:** `examples/smart-meter/`
**Target:** STM32H7 (primary), all platforms supported

**Purpose:** Secure smart energy meter with quantum-resistant telemetry, tamper detection, and mesh communication.

**Core Data Structure:**
```
MeterReading (24 bytes serialized):
  timestamp: u64           — Unix timestamp
  active_import_wh: u32    — Active energy import (watt-hours)
  active_export_wh: u32    — Active energy export (watt-hours)
  reactive_varh: u32       — Reactive energy (VAR-hours)
  instant_power_w: u16     — Instantaneous power (watts)
  voltage_dv: u16          — Voltage in decivolts (e.g., 2300 = 230.0V)
  current_ma: u16          — Current in milliamps
  power_factor: u8         — Power factor (0-100, representing 0.00-1.00)
  tamper_flags: u8         — Bitfield for tamper conditions
```

**Message Types:** Reading (0x01), TamperAlert (0x02), Attestation (0x03), CommandAck (0x04)

**Operational Parameters:**
- Reading interval: 900 seconds (15 minutes)
- Buffer capacity: 96 readings (24 hours)
- Mesh beacon interval: 30 seconds
- Tamper check: every reading cycle
- Attestation: on request from gateway

### 4.2. Railway Signaling Controller

**Path:** `examples/railway-signaling/`
**Target:** STM32U5 (TrustZone), all platforms supported

**Purpose:** SIL4 (Safety Integrity Level 4) railway signaling controller with fail-safe defaults, interlocking logic, and redundant communication.

**Signal Aspects:**
```
Danger = 0x00              — Red (Stop)
Caution = 0x01             — Yellow (Prepare to stop)
PreliminaryCaution = 0x02  — Double Yellow (Distant warning)
Clear = 0x03               — Green (Proceed)
FlashingYellow = 0x04      — Flashing (Special indication)
LampFailure = 0xFF         — Fail to Danger (safety default)
```

**Safety State Machine:**
```
Normal -> Degraded (on partial failure)
Normal -> Emergency (on safety violation)
Degraded -> Emergency (on additional failure)
Degraded -> Normal (on fault clearance)
Emergency -> Maintenance (manual intervention)
Maintenance -> Normal (after repair and verification)
```

**Interlocking Rules:**
```
InterlockingRule:
  signal_id: u8
  required_clear_tracks: Vec<u8, 8>     — Track circuits that must be clear
  required_points: Vec<(u8, PointPosition), 4> — Points that must be in position
  conflicting_signals: Vec<u8, 4>       — Signals that must show Danger
```

**Safety Timing:**
- Watchdog timeout: 100ms
- Heartbeat interval: 500ms
- Communication timeout: 2000ms (triggers Emergency)
- Default on any failure: All signals to Danger

### 4.3. Border Sensor

**Path:** `examples/border-sensor/`
**Target:** RISC-V (low power), all platforms supported

**Purpose:** Remote surveillance sensor for perimeter security with multi-sensor detection, mesh networking, and solar-powered operation.

**Detection Types:**
```
Motion = 0x01       — PIR / radar motion detection
Seismic = 0x02      — Ground vibration / footstep detection
Magnetic = 0x03     — Vehicle / metallic object detection
Acoustic = 0x04     — Sound-based detection
Infrared = 0x05     — Thermal signature detection
MultiSensor = 0x0F  — Multiple sensors triggered simultaneously
Tamper = 0xFF       — Physical tampering detected
```

**Power Management:**
```
PowerState:
  Active          — Full operation, 100ms scan interval
  LowPower        — Reduced scanning, 500ms interval (5x)
  UltraLowPower   — Minimal operation, 2s interval (20x)
  Sleep           — Wake on interrupt only

Thresholds:
  Active -> LowPower: battery < 3.3V
  LowPower -> UltraLowPower: battery < 3.0V
  UltraLowPower -> Sleep: battery < 2.7V
  Solar charging detected: transition toward Active
```

**Operational Parameters:**
- Mesh beacon interval: 30 seconds
- Heartbeat to command center: 5 minutes
- Detection confidence threshold: 70%
- Multi-hop relay: up to 8 hops
- GPS coordinates: fixed (configured at deployment)

---

## 5. Python Tooling

### 5.1. q-sign — Firmware Signing Tool

**Path:** `tools/q-sign/`
**Framework:** Click (CLI), Pydantic (validation)
**Python:** 3.10+, formatted with Black, linted with Ruff, typed with mypy --strict

**Commands and Options:**

`q-sign keygen`
- `--algorithm`: dilithium3 (default), falcon512, falcon1024
- `--output`: Output directory for key files
- `--purpose`: firmware, update, attestation
- `--key-id`: Unique key identifier

`q-sign sign`
- `--algorithm`: Signing algorithm
- `--key`: Path to private key file
- `--image`: Path to firmware binary
- `--image-type`: bootloader, kernel, application
- `--version`: Firmware version (major.minor.patch)
- `--rollback-version`: Monotonic rollback counter value
- `--hw-version`: Hardware compatibility version
- `--output`: Output path for signed image

`q-sign verify`
- `--image`: Path to signed firmware
- `--key`: Public key path (optional if embedded in image)
- `--strict`: Fail on warnings

`q-sign package`
- `--bootloader`: Signed bootloader binary
- `--kernel`: Signed kernel binary
- `--application`: Signed application binary
- `--key`: Update signing key
- `--target`: stm32h7, stm32u5, riscv
- `--version`: Package version
- `--output`: Output package path

`q-sign keyinfo` — Display key metadata (algorithm, ID, purpose, creation date, public key hash)

`q-sign export-public` — Export public key from private key file

### 5.2. q-provision — Factory Provisioning Tool

**Path:** `tools/q-provision/`
**Framework:** Click (CLI), Pydantic (validation), PySerial (debug probe)

**Commands and Options:**

`q-provision keygen`
- `--key-type`: kyber768, dilithium3, falcon512, all (default: all)
- `--device-id`: Unique device identifier
- `--manufacturer-id`: Factory identifier
- `--output`: Output directory

`q-provision identity`
- `--device-id`: Device identifier
- `--manufacturer-id`: Manufacturer ID
- `--device-class`: gateway, sensor, actuator, controller
- `--puf-data`: Path to PUF challenge-response data
- `--output`: Output directory

`q-provision flash`
- `--target`: stm32h7, stm32u5, riscv
- `--bootloader`: Signed bootloader binary
- `--kernel`: Signed kernel binary
- `--identity`: Identity data file
- `--port`: Debug probe serial port
- `--verify`: Verify after flashing
- `--lock`: Enable flash read-out protection (production)

`q-provision verify`
- `--target`: Target platform
- `--port`: Debug probe port
- `--full`: Full verification (crypto self-tests + flash integrity)

`q-provision list-devices` — List connected debug probes and serial ports

`q-provision init-config` — Generate default YAML/JSON configuration template

---

## 6. Build System and Configuration

### 6.1. Cargo Workspace

**Members:** q-kernel, q-crypto, q-identity, q-update, q-recover, q-mesh, q-attest, q-hal, q-boot, q-common

**Workspace Dependencies (shared):**
- `cortex-m` — ARM Cortex-M register access
- `cortex-m-rt` — Cortex-M runtime and startup
- `embedded-hal` — Embedded hardware abstraction traits
- `heapless` 0.8 — Static data structures (no heap)
- `zeroize` 1.7 — Secure secret erasure
- `sha3` 0.10 — SHA3 hash functions
- `aes-gcm` 0.10 — AES-GCM authenticated encryption
- `chacha20poly1305` 0.10 — ChaCha20-Poly1305 AEAD
- `subtle` 2.5 — Constant-time operations
- `fn-dsa` 0.3 — Falcon signature scheme
- `cfg-if` — Conditional compilation
- `static_assertions` — Compile-time checks
- `bitflags` — Bitfield types

### 6.2. Build Profiles

**Release Profile:**
```
opt-level = "z"        — Optimize for binary size
lto = true             — Link-time optimization
codegen-units = 1      — Single codegen unit (better optimization)
panic = "abort"        — No unwinding (saves flash)
overflow-checks = true — Integer overflow detection in release (security critical)
strip = "symbols"      — Strip debug symbols
```

**Production Profile (inherits release):**
```
lto = "fat"            — Full cross-crate LTO
overflow-checks = true — Security: always check overflows
```

**Dev Profile:**
```
opt-level = 1          — Basic optimization for faster incremental builds
overflow-checks = true — Overflow checks even in debug
[q-crypto] opt-level = 2  — Crypto needs optimization even in dev
```

### 6.3. Target Architectures

| Target Triple | Platform | Architecture | Instruction Set |
|--------------|----------|-------------|----------------|
| `thumbv7em-none-eabihf` | STM32H743/753 | ARMv7E-M | Thumb-2 + FPv5 |
| `thumbv8m.main-none-eabihf` | STM32U585 | ARMv8-M Mainline | Thumb-2 + FPv5 + TrustZone |
| `riscv32imac-unknown-none-elf` | SiFive FE310 | RV32IMAC | Integer + Multiply + Atomic + Compressed |

### 6.4. Linker Script

`crates/q-boot/link.x` defines the memory layout:

```
MEMORY {
  FLASH : ORIGIN = 0x08000000, LENGTH = 64K   /* Bootloader region */
  RAM   : ORIGIN = 0x20000000, LENGTH = 128K   /* Kernel + stack */
}

SECTIONS {
  .vector_table ORIGIN(FLASH) : { ... }
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  .data : AT(ADDR(.text) + SIZEOF(.text) + SIZEOF(.rodata)) { ... }
  .bss : { ... }
  ._stack_start = ORIGIN(RAM) + LENGTH(RAM);
}
```

---

## 7. Infrastructure and Deployment

### 7.1. AWS Infrastructure (Terraform)

**Path:** `deploy/terraform/`

**Resources provisioned:**

| Resource | Service | Purpose |
|----------|---------|---------|
| firmware_updates | S3 | Versioned, AES-256 encrypted firmware storage |
| telemetry | S3 | Device telemetry with lifecycle (30d Standard -> IA -> Glacier -> Delete@365d) |
| device_registry | DynamoDB | Fleet registry with GSIs on fleet_id and device_class |
| attestation_records | DynamoDB | Attestation logs with TTL-based expiry |
| IoT Thing Group | AWS IoT | Fleet organization for MQTT topic routing |
| Device Policy | AWS IoT | Least-privilege MQTT pub/sub rules |
| ota_orchestrator | Lambda | Python 3.11 function for OTA coordination (512MB, 5min timeout) |
| fleet_dashboard | CloudWatch | Monitoring: ActiveDevices, OTA success/failure, Attestation results |

**IoT Topic Structure:**
```
q-edge/{device_id}/telemetry     — Device telemetry data
q-edge/{device_id}/update        — OTA update notifications
q-edge/{device_id}/attestation   — Attestation requests/responses
q-edge/{device_id}/command       — Device commands
q-edge/fleet/{fleet_name}/update — Fleet-wide update notifications
q-edge/fleet/{fleet_name}/status — Fleet status aggregation
```

**Terraform Variables:**
- `project_name` (default: "qbitel-edgeos")
- `vpc_cidr` (default: "10.0.0.0/16")
- `enable_hsm` (default: false) — Enable CloudHSM for key management
- `enable_waf` (default: true) — Enable WAF for API protection
- `retention_days` (default: 90) — Log retention
- `alarm_email` — CloudWatch alarm notifications
- `max_devices` (default: 10000) — Maximum fleet size
- `firmware_signing_key_arn` — KMS key for firmware signing

### 7.2. Ansible Playbooks

**Path:** `deploy/ansible/`

**build.yml** — Firmware build automation:
- Clones repository to /opt/qbitel/
- Installs Rust toolchain
- Builds firmware for specified targets
- Runs test suite
- Archives build artifacts

**provision.yml** — Factory provisioning:
- Installs q-provision tool in virtualenv (/opt/qbitel/)
- Copies provisioning configuration
- Generates manufacturer keys (if not exists)
- Provisions devices in batch (configurable batch_size)
- Flashes firmware via debug probe
- Verifies provisioned devices
- Logs all operations

**update.yml** — OTA update deployment:
- Validates update packages
- Uploads to S3 firmware bucket
- Triggers OTA notifications via AWS IoT
- Monitors update progress
- Reports success/failure

**Inventory structure:**
- `provisioning_stations` — Factory workstations
- `build_servers` — CI/CD build machines
- `edge_devices` — Device fleet (smart_meters, railway_controllers, border_sensors)

### 7.3. Docker Environment

**Dockerfile** (multi-stage):
- **Build stage:** Rust 1.82 on Debian Bookworm with all embedded targets, cargo tools (tarpaulin, deny, audit, geiger, fuzz, binutils, sbom), Python 3.11 with all tool dependencies
- **Output stage:** Minimal image with firmware binaries only

**docker-compose.yml services:**
| Service | Command | Purpose |
|---------|---------|---------|
| builder | make build | Full workspace build |
| test | make test | Complete test suite |
| lint | cargo fmt --check + cargo clippy + cargo deny | Code quality |
| audit | cargo audit + cargo deny advisories + cargo geiger | Security audit |
| coverage | cargo tarpaulin --workspace | Code coverage (XML + HTML) |
| python-test | pytest for q-sign and q-provision | Python tool tests |

### 7.4. CI/CD (GitHub Actions)

**ci.yml** — On push/PR to main:
- Format check (cargo fmt)
- Lint check (cargo clippy -D warnings)
- Test suite (cargo test --workspace --all-features)
- Security audit (cargo audit, cargo deny)
- Build for all 3 targets

**sbom.yml** — SBOM generation:
- Generates CycloneDX SBOM for Rust dependencies
- Generates SBOM for Python tool dependencies (q-sign, q-provision)
- Combines into summary
- Attaches to GitHub releases

**release.yml** — On version tags (v*):
- Builds production firmware for all platforms
- Creates signed packages
- Creates GitHub release with artifacts
- Archive naming: qbitel-edgeos-{version}-{platform}.tar.gz

---

## 8. Security Properties Summary

| Property | Implementation |
|----------|---------------|
| Post-quantum key exchange | ML-KEM-768 (NIST Level 3) |
| Post-quantum signatures | ML-DSA-65 (NIST Level 3), FN-DSA-512 (Level 1) |
| Constant-time execution | All crypto operations; no secret-dependent branches or memory access |
| Secret zeroization | Zeroize + ZeroizeOnDrop on all secret types; intermediate values cleared |
| No heap allocations | 100% static allocation; `heapless` crate for bounded collections |
| Integer overflow protection | overflow-checks = true even in release builds |
| No unwrap in production | All errors handled via Result; no panic paths in production code |
| Memory isolation | MPU (ARM) or PMP (RISC-V) per-task regions |
| Secure boot | ML-DSA-65 verified boot chain with anti-rollback OTP counters |
| Hardware-rooted identity | PUF/eFUSE binding; certificate-less; offline-verifiable |
| Forward secrecy | Ephemeral ML-KEM keys per mesh session |
| Implicit rejection (KEM) | Invalid Kyber ciphertexts return random-looking secret |
| Fail-safe defaults | Railway signals default to Danger; boot defaults to recovery |

---

## 9. Compliance and Standards

| Standard | Domain | Relevance |
|----------|--------|-----------|
| NIST FIPS 203 | ML-KEM | Key encapsulation algorithm standard |
| NIST FIPS 204 | ML-DSA | Digital signature algorithm standard |
| NIST FIPS 202 | SHA-3 | Hash function standard |
| NIST FIPS 197 | AES | Block cipher standard |
| RFC 8439 | ChaCha20-Poly1305 | AEAD cipher specification |
| RFC 5869 | HKDF | Key derivation specification |
| Common Criteria EAL4+ | Security evaluation | Target certification level |
| IEC 62443 | Industrial cybersecurity | IACS security requirements |
| EN 50129 | Railway safety | Safety-related electronic systems |
| EN 50159 | Railway communication | Communication security for signaling |
| IEC 62351 | Power grid security | Security for energy systems |

---

*End of Technical Reference Document.*
