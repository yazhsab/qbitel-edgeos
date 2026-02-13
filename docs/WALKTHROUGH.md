# Qbitel EdgeOS - Technical Walkthrough

This document walks through the complete lifecycle of a Qbitel EdgeOS device, from first boot to field operation, explaining how each component interacts.

---

## 1. Boot Sequence

When power is applied to a Qbitel EdgeOS device, the secure boot chain executes before any application code runs.

### Stage 1: Hardware Initialization (q-hal)

The hardware abstraction layer initializes platform-specific peripherals:

```
Power On
  |
  v
q-hal detects platform (STM32H7 / STM32U5 / RISC-V)
  |
  v
Initialize: Clock tree, GPIO, UART, SPI, I2C, TRNG, Flash controller
  |
  v
Configure MPU (ARM) or PMP (RISC-V) memory protection regions
  |
  v
Hand off to q-boot
```

Platform detection is automatic at compile time via feature flags (`stm32h7`, `stm32u5`, `riscv`). Each platform provides the same trait interfaces (`GpioPin`, `UartPort`, `SpiDevice`, `FlashStorage`, `Rng`) but implements them for the target silicon.

### Stage 2: Secure Boot (q-boot)

The bootloader verifies firmware integrity before execution:

```
q-boot starts
  |
  v
Read boot log (persistent across resets)
  |
  +--> Boot failure count >= threshold? --> Enter Recovery Mode
  |
  v
Select firmware slot (A or B)
  |
  v
Read firmware image from flash
  |
  v
Compute SHA3-256 hash of firmware image
  |
  v
Read embedded manifest (magic bytes, version, signature)
  |
  v
Verify ML-DSA-65 (Dilithium3) signature against known public key
  |
  +--> Signature invalid? --> Try alternate slot or enter recovery
  |
  v
Check monotonic version counter (anti-rollback)
  |
  +--> Version <= stored counter? --> Reject (downgrade attack)
  |
  v
Update boot log: record successful verification
  |
  v
Load kernel into execution memory
  |
  v
Jump to kernel entry point
```

**Key security properties:**
- The bootloader itself resides in write-protected flash.
- Signature verification uses post-quantum ML-DSA-65, resistant to quantum attacks.
- Anti-rollback counters are stored in OTP (one-time programmable) memory and can only increment.
- Recovery mode provides a minimal environment for re-flashing via debug probe.

### Stage 3: Kernel Initialization (q-kernel)

```
Kernel entry point
  |
  v
Initialize memory manager
  - Configure MPU/PMP regions for kernel and task isolation
  - Set up stack guards
  |
  v
Initialize scheduler
  - Create idle task (lowest priority)
  - Configure SysTick timer for preemption
  |
  v
Initialize IPC subsystem
  - Allocate static channel buffers
  |
  v
Register application tasks
  - Each task gets: entry point, stack, priority, name
  - Tasks are isolated in separate MPU regions
  |
  v
Start scheduler (never returns)
  - Highest priority ready task executes first
  - SysTick interrupt triggers preemptive context switches
```

**Scheduler behavior:**
- Priority levels: `High`, `Normal`, `Low`, `Idle`
- Equal-priority tasks are scheduled round-robin
- Tasks can yield voluntarily (`yield_now()`) or sleep (`sleep_ms()`)
- Context switches save/restore full register state including FPU

---

## 2. Device Identity

After the kernel starts, the identity subsystem validates the device.

### Identity Structure

Every Qbitel EdgeOS device has an `IdentityCommitment` anchored to hardware:

```
IdentityCommitment
  |
  +-- device_id: [u8; 32]        // Unique device identifier
  +-- kem_public_key              // ML-KEM-768 public key for key exchange
  +-- signing_public_key          // ML-DSA-65 public key for signatures
  +-- device_class                // Gateway | Sensor | Actuator | Controller
  +-- manufacturer_id             // Factory identifier
  +-- metadata                    // Additional attributes
  +-- self_signature              // Commitment signed by device's own key
       |
       v
  Hardware Fingerprint
  +-- PUF response                // Physical Unclonable Function
  +-- eFUSE values                // One-time programmable silicon ID
```

### Identity Verification Flow

```
Application requests identity verification
  |
  v
q-identity reads stored IdentityCommitment from secure flash
  |
  v
Read hardware fingerprint (PUF challenge-response / eFUSE)
  |
  v
Verify self-signature using embedded signing public key
  |
  +--> Invalid signature? --> Identity compromised
  |
  v
Verify hardware binding (commitment matches current PUF/eFUSE)
  |
  +--> Mismatch? --> Device cloning detected
  |
  v
Return VerificationResult::Valid
```

No network access is required. No certificate authority. No revocation list. Identity is verified locally against the hardware itself.

---

## 3. Establishing Secure Communications (q-mesh)

Once identity is confirmed, the device can join a mesh network.

### Peer Discovery

```
Device powers up mesh radio (LoRa / 802.15.4 / BLE)
  |
  v
Broadcast beacon message
  +-- device_id
  +-- capabilities (radio type, supported protocols)
  +-- group membership
  |
  v
Listen for beacons from nearby devices
  |
  v
Populate neighbor table with discovered peers
  |
  v
Build routing table for multi-hop paths
```

### Post-Quantum Handshake

When two devices need to communicate, they perform a post-quantum key exchange:

```
Initiator                                  Responder
    |                                          |
    |  ClientHello                             |
    |  +-- initiator_id                        |
    |  +-- ML-KEM ephemeral public key         |
    |  +-- supported cipher suites             |
    |----------------------------------------->|
    |                                          |
    |                               ServerHello|
    |              +-- responder_id            |
    |              +-- ML-KEM ciphertext       |
    |              +-- selected cipher suite   |
    |<-----------------------------------------|
    |                                          |
    |  Both sides derive shared secret         |
    |  via ML-KEM decapsulation                |
    |                                          |
    |  ClientFinished                          |
    |  +-- authentication tag                  |
    |  +-- signed with ML-DSA-65               |
    |----------------------------------------->|
    |                                          |
    |  Session established                     |
    |  Encrypted with ChaCha20-Poly1305        |
    |<========================================>|
```

**Security properties:**
- Forward secrecy: ephemeral ML-KEM keys are generated per session.
- Quantum resistance: ML-KEM-768 provides NIST Level 3 security.
- Mutual authentication: both sides verify identity via ML-DSA-65 signatures.
- Session keys are zeroized when the session ends.

### Message Routing

For devices not in direct radio range, messages are routed through intermediate hops:

```
Sensor A --[LoRa]--> Relay B --[LoRa]--> Relay C --[LoRa]--> Gateway D
```

Each hop re-encrypts the frame. The routing table is maintained via periodic beacon exchanges. Group trust policies control which devices can relay for which groups.

---

## 4. Remote Attestation (q-attest)

Attestation proves a device's integrity to a remote verifier.

### Evidence Collection

```
Verifier sends AttestationRequest
  |
  v
q-attest EvidenceCollector gathers:
  +-- Boot measurements
  |   +-- Bootloader hash (measured at boot)
  |   +-- Kernel hash (measured at boot)
  |   +-- Application hash (measured at boot)
  |
  +-- Identity commitment
  |   +-- Device ID
  |   +-- Public keys
  |   +-- Hardware binding proof
  |
  +-- Runtime state
  |   +-- Current firmware version
  |   +-- Uptime
  |   +-- Memory integrity check
  |   +-- Task list and states
  |
  v
Sign evidence bundle with device signing key (ML-DSA-65)
  |
  v
Return AttestationResponse to verifier
```

### Verification

```
Verifier receives AttestationResponse
  |
  v
Check signature on evidence bundle
  |
  v
Compare boot measurements against known-good values
  |
  v
Verify identity commitment matches registered device
  |
  v
Check runtime state for anomalies
  |
  v
Result: Trusted / Untrusted / Unknown
```

Attestation can be performed over the mesh network or via a cloud backend. The evidence format is self-contained and can be verified offline.

---

## 5. OTA Firmware Updates (q-update)

Firmware can be updated securely without physical access.

### Update Package Structure

```
UpdatePackage
  +-- manifest
  |   +-- magic: 0x51454447 ("QEDG")
  |   +-- version: MonotonicVersion
  |   +-- target_platform: stm32h7 | stm32u5 | riscv
  |   +-- firmware_hash: SHA3-256
  |   +-- signature: ML-DSA-65
  |
  +-- firmware_image
      +-- bootloader (optional)
      +-- kernel
      +-- application
```

### Update Flow

```
Update available (via mesh, USB, or cloud)
  |
  v
q-update downloads manifest
  |
  v
Verify manifest signature (ML-DSA-65)
  |
  +--> Invalid? --> Reject update
  |
  v
Check version > current monotonic counter
  |
  +--> Version too old? --> Reject (rollback attack)
  |
  v
Determine inactive slot (if A is active, write to B)
  |
  v
Write firmware to inactive slot
  |
  v
Verify written data (hash check)
  |
  v
Mark inactive slot as "Testing"
  |
  v
Set next boot to use the new slot
  |
  v
Reboot
  |
  v
q-boot verifies new firmware (Stage 2 above)
  |
  +--> Verification fails? --> Revert to previous slot
  |
  v
Application confirms update successful
  |
  v
Mark new slot as "Active", update monotonic counter
```

**Air-gapped updates:** For devices without network connectivity, update packages can be delivered via USB or removable media. The verification flow is identical; only the transport changes.

---

## 6. Key Recovery and Rotation (q-recover)

Keys can be rotated in the field without recalling devices.

### Shamir Secret Sharing

Device master keys are split using Shamir's scheme over GF(2^8):

```
Master Key K
  |
  v
Split into N shares with threshold T
  (any T-of-N shares can reconstruct K)
  |
  +-- Share 1 --> Stored on device
  +-- Share 2 --> Stored at factory
  +-- Share 3 --> Stored with fleet operator
  +-- Share 4 --> Stored in escrow
  ...
```

### Key Rotation Flow

```
Rotation command issued (fleet operator)
  |
  v
Generate new key pair (ML-KEM + ML-DSA)
  |
  v
Create new IdentityCommitment with new keys
  |
  v
Sign transition record with old key
  |
  v
Update device identity in secure storage
  |
  v
Distribute new public key to peers
  |
  v
Zeroize old private key material
```

### Batch Revocation

If a group of devices is compromised:

```
Fleet operator issues revocation list
  |
  v
Revocation list signed by fleet authority key
  |
  v
Distributed to all devices via mesh or cloud
  |
  v
Each device updates its trust store
  |
  v
Revoked devices are excluded from mesh routing and attestation
```

---

## 7. Example Application Flow: Smart Meter

Putting it all together with the smart meter example:

```
Power On
  |
  v
[q-boot] Secure boot --> verify kernel --> load
  |
  v
[q-kernel] Initialize --> start scheduler
  |
  v
[q-identity] Verify device identity against PUF
  |
  v
[q-mesh] Discover neighbor meters and gateways
  |
  v
[q-mesh] Establish post-quantum encrypted session with gateway
  |
  v
Main loop (every 15 minutes):
  |
  +-- Read energy sensors (voltage, current, power factor)
  |
  +-- Create MeterReading with timestamp
  |
  +-- Buffer reading locally (24-hour buffer)
  |
  +-- Check for tamper conditions (enclosure, magnetic, voltage)
  |   |
  |   +--> Tamper detected? --> Send immediate TamperAlert
  |
  +-- Encrypt reading with session key (ChaCha20-Poly1305)
  |
  +-- Transmit via mesh to gateway
  |
  +-- Check for pending OTA updates
  |   |
  |   +--> Update available? --> [q-update] Apply update flow
  |
  +-- Respond to attestation requests
  |   |
  |   +--> Request received? --> [q-attest] Collect and send evidence
  |
  +-- Send periodic mesh beacon
  |
  v
  Loop
```

---

## System Interactions Summary

```
                    +-------------------+
                    |   Fleet Operator  |
                    +-------------------+
                       |           |
              Attestation    OTA Updates
              Requests       via Cloud/Mesh
                       |           |
                       v           v
  +----------+    +----------+    +----------+
  | q-attest |<-->| q-update |<-->|  q-mesh  |
  +----------+    +----------+    +----------+
       |               |               |
       v               v               v
  +----------+    +----------+    +----------+
  |q-identity|    |  q-boot  |    | q-crypto |
  +----------+    +----------+    +----------+
       |               |               |
       +-------+-------+-------+-------+
               |               |
               v               v
          +----------+   +----------+
          | q-kernel |   |  q-hal   |
          +----------+   +----------+
               |               |
               v               v
          +---------+   +-----------+
          | Tasks   |   | Hardware  |
          +---------+   +-----------+
```

Every arrow represents a dependency. Lower layers have no knowledge of higher layers. Communication flows through well-defined APIs.

---

## Next Steps

- **[QUICKSTART.md](QUICKSTART.md)** - Build and run your first application
- **[API.md](API.md)** - Complete API reference for all crates
- **[INSTALLATION.md](INSTALLATION.md)** - Detailed setup instructions
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide
