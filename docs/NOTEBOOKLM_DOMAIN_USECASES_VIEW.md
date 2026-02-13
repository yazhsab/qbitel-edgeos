# Qbitel EdgeOS — Domain Use Cases Reference

> **Document Purpose:** This is the comprehensive domain and use-case reference for Qbitel EdgeOS. It covers every target industry, every deployment scenario, every operational workflow, and every real-world application in complete detail. Designed for solution architects, domain specialists, pre-sales engineers, customer success teams, and technical evaluators.

---

## 1. Overview of Target Domains

Qbitel EdgeOS targets embedded devices in critical infrastructure — systems where security failure has physical, safety, or national security consequences. These devices share common characteristics:

- **Long operational lifespans** (15-25 years)
- **Physical accessibility** to attackers (deployed in the field)
- **Resource constraints** (512KB-2MB flash, 128KB-1MB RAM)
- **Air-gapped or intermittently connected** environments
- **Safety-critical or high-availability** requirements
- **Regulatory compliance** mandates for cybersecurity

The six primary domains are:

| Domain | Primary Device Types | Key Standards |
|--------|---------------------|--------------|
| Energy & Smart Grid | Smart meters, RTUs, substation gateways, DERs | IEC 62351, NERC CIP, IEC 62443 |
| Railway & Transit | Signaling controllers, trackside equipment, ETCS | EN 50129, EN 50159, IEC 62280 |
| Defense & Intelligence | Tactical edge nodes, sensor arrays, comms equipment | CNSA 2.0, NSA CSfC, MIL-STD |
| Industrial Manufacturing | PLCs, safety controllers, HMIs, RTUs | IEC 62443, ISA/IEC 62443-4-1 |
| Water & Utilities | SCADA endpoints, pump controllers, quality sensors | NIST Cybersecurity Framework, AWWA |
| Border & Perimeter Security | Ground sensors, surveillance nodes, relay stations | Government-specific standards |

---

## 2. Energy & Smart Grid

### 2.1. Industry Context

The global power grid is undergoing a fundamental transformation. Distributed Energy Resources (DERs), smart meters, and advanced metering infrastructure (AMI) are creating millions of new network-connected endpoints. These devices are critical attack surfaces — compromising a smart meter doesn't just expose billing data; it can destabilize grid operations, enable energy theft at scale, or serve as a pivot point for attacks on substation control systems.

**Scale of deployment:** A single national utility may operate 10-50 million smart meters, each with a 15-20 year field life.

**Quantum threat:** Harvest-now-decrypt-later attacks on smart meter traffic could expose grid topology, consumption patterns, and control commands that remain sensitive for decades.

### 2.2. Use Case: Smart Energy Meter

**Qbitel EdgeOS Component:** Complete example implementation at `examples/smart-meter/`

**Device Profile:**
- MCU: STM32H7 (Cortex-M7 @ 480MHz) or STM32U5 (Cortex-M33)
- Flash: 2MB, RAM: 1MB
- Communication: LoRa mesh to neighborhood gateway, or 802.15.4
- Power: Mains powered with supercapacitor backup
- Lifetime: 15-20 years

**Operational Flow:**

```
Every 15 minutes:
  1. Read energy sensors (voltage, current, power factor, active/reactive energy)
  2. Create MeterReading struct (24 bytes)
     - active_import_wh, active_export_wh, reactive_varh
     - instant_power_w, voltage_dv, current_ma, power_factor
     - tamper_flags (enclosure open, magnetic field, voltage anomaly)
  3. Buffer reading locally (96-reading circular buffer = 24 hours)
  4. Check tamper conditions
     - If tamper detected: send immediate TamperAlert via mesh
  5. Encrypt reading with session key (ChaCha20-Poly1305)
  6. Transmit encrypted SecureMeterMessage to gateway via q-mesh
  7. Check for pending OTA firmware updates
  8. Respond to attestation requests from utility backend

On boot:
  1. q-boot verifies firmware signature (ML-DSA-65)
  2. q-kernel initializes with MPU isolation
  3. q-identity verifies hardware-bound device identity (PUF/eFUSE)
  4. q-mesh discovers neighbor meters and establishes PQC-secured session to gateway

On OTA update:
  1. Gateway pushes update notification via mesh
  2. q-update downloads and verifies signed manifest
  3. Firmware written to inactive A/B slot
  4. Reboot; q-boot verifies new slot
  5. On failure: automatic rollback to previous slot
```

**Security Properties Addressing Energy-Specific Threats:**

| Threat | Qbitel EdgeOS Mitigation |
|--------|-------------------------|
| Meter data interception | Post-quantum encrypted mesh (ML-KEM-768 handshake + ChaCha20-Poly1305) |
| Firmware tampering | ML-DSA-65 signed boot chain with anti-rollback OTP counters |
| Device cloning/impersonation | PUF/eFUSE hardware-bound identity (physically unclonable) |
| Energy theft via meter manipulation | Tamper detection flags + remote attestation verification |
| Man-in-the-middle on mesh | Mutual authentication during PQC handshake (both sides verify identity) |
| Harvest-now-decrypt-later | All traffic encrypted with post-quantum algorithms from day one |
| Grid topology reconnaissance | Encrypted mesh hides meter-to-meter communication patterns |
| Unauthorized firmware rollback | Monotonic OTP counters prevent loading older firmware versions |

**Regulatory Alignment:**
- **IEC 62351** (Power systems security): Post-quantum key management and authenticated communication
- **NERC CIP** (Critical Infrastructure Protection): Secure firmware updates, access control, audit logging
- **IEC 62443** (Industrial cybersecurity): Defense-in-depth, security lifecycle management

### 2.3. Use Case: Substation Gateway

**Device Profile:**
- MCU: STM32H7 (highest performance)
- Role: Aggregation point for 100-500 smart meters in a neighborhood
- Connectivity: LoRa mesh (downlink to meters) + Ethernet/4G (uplink to utility backend)
- Additional requirements: Higher throughput, more concurrent mesh sessions

**Operational Flow:**
- Maintains post-quantum secured sessions with each connected meter
- Aggregates meter readings and forwards to utility SCADA/MDMS
- Relays OTA update packages from utility backend to meters
- Performs attestation verification on behalf of utility backend
- Reports anomalous meter behavior (unexpected readings, tamper alerts)
- Manages mesh routing table for neighborhood coverage

**Qbitel EdgeOS capabilities used:**
- q-mesh: Multi-session management (up to hundreds of concurrent PQC sessions)
- q-attest: Verifier role — checking meter attestation evidence
- q-update: Relay — forwarding firmware packages to meters
- q-identity: Gateway identity for utility backend authentication
- q-kernel: Higher task count for concurrent meter handling

### 2.4. Use Case: Distributed Energy Resource (DER) Controller

**Device Profile:**
- Controls: Solar inverter, battery storage, EV charger
- MCU: STM32U5 (TrustZone for secure/non-secure separation)
- Communication: 802.15.4 or BLE to home gateway, mesh to utility

**Operational Scenario:**
- Receives grid frequency/voltage signals
- Adjusts DER output based on utility commands
- Reports generation/consumption data
- Must authenticate utility commands (prevent unauthorized grid manipulation)
- PQC-signed command verification prevents spoofed control messages

**Critical security requirement:** A compromised DER controller could inject power at wrong frequency/voltage, destabilizing the grid. Post-quantum command authentication prevents this even against quantum-capable adversaries.

---

## 3. Railway & Transit

### 3.1. Industry Context

Railway signaling systems are among the most safety-critical systems in existence. A single signaling error can cause collisions with catastrophic consequences. These systems are governed by EN 50129 (Safety Integrity Level 4, the highest), EN 50159 (communication security), and IEC 62280 (data communication).

Modern railways are transitioning from standalone relay-based interlocking to networked digital systems (ETCS Level 2/3, CBTC). This digitization creates new attack surfaces that require cryptographic protection.

**Quantum threat:** Railway signaling equipment has 25-30 year lifecycle. Equipment being specified today must withstand threats that will exist in 2050.

### 3.2. Use Case: Signaling Controller

**Qbitel EdgeOS Component:** Complete example implementation at `examples/railway-signaling/`

**Device Profile:**
- MCU: STM32U5 (Cortex-M33 with TrustZone) — preferred for safety-critical separation
- Flash: 2MB, RAM: 786KB
- Communication: Dedicated signaling network (Ethernet or serial)
- Safety level: SIL4 (Safety Integrity Level 4 per EN 50129)
- Lifetime: 25-30 years

**Operational Flow:**

```
Main safety loop (every 100ms):
  1. Read track circuit states (Clear / Occupied / Unknown)
  2. Read point (switch) positions (Normal / Reverse / Moving)
  3. Execute interlocking logic:
     For each signal:
       a. Check all required track circuits are clear
       b. Check all required points are in correct position
       c. Check no conflicting signals showing permissive aspect
       d. If ALL conditions met: allow signal to show requested aspect
       e. If ANY condition fails: force signal to Danger (Red)
  4. Send heartbeat to adjacent controllers
  5. Check communication timeouts
     - If any peer timeout > 2000ms: transition to Emergency state
  6. Feed hardware watchdog (100ms timeout)
     - If watchdog not fed: hardware forces system reset -> all signals to Danger
  7. Respond to attestation requests
  8. Log all state transitions for audit trail

Safety state machine:
  Normal:
    - All systems operational
    - Interlocking rules evaluated normally
    - Permissive aspects allowed when conditions met

  Degraded:
    - Some non-critical function unavailable
    - Reduced operational capability
    - Additional caution signaling

  Emergency:
    - ALL signals forced to Danger (Red)
    - Triggered by: communication timeout, safety violation, hardware fault
    - Cannot auto-recover; requires manual intervention

  Maintenance:
    - All signals forced to Danger
    - Debug interfaces enabled
    - Entered only via manual trigger (physical switch)
```

**Signal Aspects (EN standard compliant):**
```
Danger (Red)                — Stop. Do not proceed.
Caution (Yellow)            — Prepare to stop at next signal.
Preliminary Caution (YY)    — Two signals ahead is Danger.
Clear (Green)               — Proceed at line speed.
Flashing Yellow             — Special indication (junction diverging route).
Lamp Failure                — Automatically defaults to Danger.
```

**Interlocking Rule Structure:**
```
Each rule specifies:
  - Signal being controlled (signal_id)
  - Track circuits that must be clear (up to 8)
  - Points that must be in a specific position (up to 4 point/position pairs)
  - Conflicting signals that must show Danger (up to 4)

Example:
  Signal S1 may show Clear ONLY IF:
    Track sections T1, T2, T3 are all Clear
    AND Point P1 is in Normal position
    AND Signal S2 is showing Danger
    AND Signal S5 is showing Danger
```

**Safety Properties Provided by Qbitel EdgeOS:**

| Safety Requirement | Implementation |
|-------------------|---------------|
| Fail-safe default | All signals default to Danger on any fault, timeout, or unexpected state |
| Deterministic execution | Preemptive scheduler with fixed priorities; safety loop at highest priority |
| Memory isolation | MPU/PMP regions prevent application code from corrupting safety-critical data |
| Firmware integrity | ML-DSA-65 signed boot chain; tampered firmware cannot execute |
| Communication authentication | Post-quantum signed and encrypted controller-to-controller messages |
| Anti-rollback | OTP monotonic counters prevent loading older (potentially vulnerable) firmware |
| Watchdog enforcement | 100ms hardware watchdog; if safety loop fails to execute, system resets to safe state |
| Audit trail | Boot log and operational log stored in dedicated flash sectors |
| Attestation | Remote verification that controller is running authorized, unmodified firmware |

**Regulatory Alignment:**
- **EN 50129** (SIL4): Fail-safe design, fault tolerance, diagnostic coverage
- **EN 50159** (Communication): Authenticated and encrypted messages between safety-critical systems
- **IEC 62280** (Data communication): Message authentication for railway communication
- **IEC 62443** (Cybersecurity): Defense-in-depth, security lifecycle

### 3.3. Use Case: Trackside Equipment (Axle Counters, Level Crossings)

**Device Profile:**
- MCU: STM32H7 (for sensor processing) or RISC-V (for cost optimization)
- Sensors: Wheel detectors, barrier position sensors, warning light controllers
- Communication: Mesh to nearest signaling controller
- Safety level: SIL4 for axle counters, SIL2-SIL3 for level crossings

**Operational Scenario:**
- Axle counter detects train wheel passages, transmits authenticated count to interlocking
- Level crossing controller activates barriers and warning lights based on train approach
- All messages signed with ML-DSA-65 to prevent spoofing
- Device attestation ensures trackside equipment hasn't been tampered with
- Air-gapped firmware updates for trackside equipment in remote locations

### 3.4. Use Case: ETCS (European Train Control System) Onboard Unit

**Device Profile:**
- MCU: STM32U5 (TrustZone for security/safety separation)
- Communication: GSM-R/FRMCS to Radio Block Centre (RBC)
- Safety level: SIL4

**Operational Scenario:**
- Receives Movement Authority from RBC
- Computes safe braking curves
- Enforces speed limits and stopping points
- All RBC-to-train messages must be authenticated with post-quantum signatures
- Device identity prevents unauthorized train impersonation
- Key rotation capability for long-service trains (30+ year lifecycle)

---

## 4. Defense & Intelligence

### 4.1. Industry Context

Military and intelligence organizations deploy edge devices in the most hostile environments: contested battlefields, foreign territory, electromagnetic warfare zones, and areas with no connectivity. These devices face nation-state adversaries with quantum computing programs.

The NSA's CNSA 2.0 guidance mandates transition to post-quantum cryptography for all national security systems by 2030-2035. Devices being developed now must be quantum-safe from initial deployment.

### 4.2. Use Case: Border/Perimeter Sensor

**Qbitel EdgeOS Component:** Complete example implementation at `examples/border-sensor/`

**Device Profile:**
- MCU: SiFive FE310 (RISC-V) for lowest power consumption, or STM32U5
- Power: Solar panel + lithium battery (designed for months of autonomous operation)
- Sensors: PIR (motion), geophone (seismic), magnetometer (vehicles), acoustic, IR
- Communication: LoRa mesh (range: 2-15 km depending on terrain)
- Deployment: Concealed, unattended ground sensors in remote terrain
- Lifetime: 5-10 years per deployment

**Operational Flow:**

```
Main detection loop:
  1. Scan sensors at interval based on power state:
     - Active: 100ms (full sensitivity)
     - LowPower: 500ms (reduced, battery < 3.3V)
     - UltraLowPower: 2000ms (minimal, battery < 3.0V)
     - Sleep: interrupt-only (battery < 2.7V)

  2. Process sensor readings:
     - PIR: Detect motion (human, animal, vehicle differentiation)
     - Seismic: Detect footsteps, vehicle vibration (frequency analysis)
     - Magnetic: Detect metallic objects (vehicles, weapons)
     - Acoustic: Detect sounds (engine noise, speech, gunfire)
     - IR: Detect thermal signatures

  3. If detection confidence > 70%:
     Create DetectionEvent:
       - detection_type: Motion/Seismic/Magnetic/Acoustic/Infrared/MultiSensor/Tamper
       - confidence: 0-100%
       - sensor_readings: raw data snapshot
       - gps_coordinates: fixed deployment position
       - timestamp: synchronized via mesh
       - power_state: current power level

  4. Encrypt detection report with session key
  5. Transmit via mesh to command center (up to 8 hops)
  6. Send periodic heartbeat (every 5 minutes)
  7. Send mesh beacon (every 30 seconds)
  8. Monitor battery voltage and solar charging
  9. Adjust power state based on energy budget
```

**Multi-Hop Mesh Topology:**
```
Sensor A ─[LoRa 2km]─> Relay B ─[LoRa 5km]─> Relay C ─[LoRa 3km]─> Gateway D
                                                                          |
                                                                    [Satellite/4G]
                                                                          |
                                                                   Command Center
```

Each hop:
- Re-encrypts frame with hop-specific session key
- Decrements TTL (hop_count)
- Checks group membership of next hop (trust policy enforcement)
- Routes based on distance-vector routing table

**Power Management (Detailed):**
```
Active State:
  - All sensors active at full rate
  - Radio always on
  - CPU running at full clock
  - Power draw: ~50mA @ 3.3V

LowPower State (battery < 3.3V):
  - Scan interval 5x longer
  - Radio duty-cycled (listen windows)
  - CPU clock reduced
  - Power draw: ~15mA

UltraLowPower State (battery < 3.0V):
  - Scan interval 20x longer
  - Only PIR and seismic active
  - Radio transmit-only (no relay)
  - Power draw: ~5mA

Sleep State (battery < 2.7V):
  - All sensors off except PIR (interrupt-driven)
  - No radio activity
  - Wake only on PIR trigger or timer
  - Power draw: ~0.5mA

Solar Charging:
  - Monitors solar panel voltage
  - Transitions toward Active as battery recovers
  - Hysteresis to prevent rapid state oscillation
```

**Security Properties for Defense Use:**

| Requirement | Implementation |
|------------|---------------|
| Quantum-safe communications | ML-KEM-768 handshake + ChaCha20-Poly1305 session encryption |
| Device authentication | Hardware-bound identity (PUF); cannot clone sensor identity |
| Anti-tamper | Physical tamper detection (case open, accelerometer shock) triggers immediate alert + key zeroization |
| Covert operation | Encrypted mesh traffic is indistinguishable from noise; no plaintext metadata |
| Air-gapped updates | Firmware updates via USB/serial; no network required |
| Supply chain integrity | Attestation records track manufacturing, testing, shipping, deployment |
| Forward secrecy | Ephemeral KEM keys per session; compromise of one session doesn't expose others |
| Denial of service resistance | Mesh routing adapts around disabled/destroyed nodes |

### 4.3. Use Case: Tactical Communications Node

**Device Profile:**
- MCU: STM32H7 (high performance for multi-radio operation)
- Radios: LoRa + 802.15.4 + BLE (multi-band mesh)
- Role: Communications relay for tactical units
- Deployment: Vehicle-mounted or man-portable

**Operational Scenario:**
- Forms mesh network between dismounted soldiers, vehicles, and command post
- Routes messages through multiple hops using best available radio
- Post-quantum handshake ensures session keys are quantum-safe
- Group management controls which units can communicate with which networks
- Device attestation prevents compromised nodes from joining the network
- Key rotation can be performed in the field without returning to base

### 4.4. Use Case: Supply Chain Tracking Device

**Device Profile:**
- MCU: STM32U5 or RISC-V (low power)
- Sensors: GPS, accelerometer, temperature, humidity, light (tamper)
- Communication: BLE to handler's mobile, or LoRa to fixed infrastructure
- Power: Long-life battery (2-5 year operation)

**Operational Scenario:**
- Attached to high-value shipments (weapons, electronics, classified materials)
- Records a hash-linked provenance ledger at each custody transfer:
  ```
  Manufacturing -> Testing -> Packaging -> Shipping -> Customs -> Delivery -> Installation
  ```
- Each event is signed by the handler's device identity
- Tamper detection (shock, temperature, light exposure) triggers immediate alert
- At destination, supply chain integrity can be cryptographically verified
- Post-quantum signatures ensure provenance records cannot be forged even by future quantum computers

---

## 5. Industrial Manufacturing

### 5.1. Industry Context

Industrial Control Systems (ICS) — including PLCs, RTUs, DCS, and safety controllers — are the nervous system of manufacturing, chemical processing, oil and gas, and critical infrastructure. The IEC 62443 standard mandates cybersecurity for Industrial Automation and Control Systems (IACS).

Industrial devices are high-value targets because compromising them can cause physical damage, environmental disasters, or production shutdowns. The Stuxnet, TRITON/TRISIS, and Industroyer attacks demonstrated that nation-state adversaries actively target ICS.

### 5.2. Use Case: Secure PLC (Programmable Logic Controller)

**Device Profile:**
- MCU: STM32H7 (for real-time I/O processing)
- I/O: Digital and analog inputs/outputs for sensor/actuator control
- Communication: Industrial Ethernet (Modbus TCP, OPC-UA) or serial (Modbus RTU)
- Safety: SIL2-SIL3 for safety-instrumented functions
- Lifetime: 15-25 years

**Operational Scenario:**
- Executes control logic (ladder, structured text, function block)
- Reads sensor inputs (temperature, pressure, flow, level)
- Drives actuator outputs (valves, motors, heaters)
- Communicates with SCADA/HMI for supervisory control

**Qbitel EdgeOS Security Capabilities Applied:**

| ICS Threat | Mitigation |
|-----------|-----------|
| Unauthorized firmware modification (e.g., Stuxnet) | ML-DSA-65 signed boot chain; only authorized firmware executes |
| Control logic manipulation | Memory isolation (MPU) separates control logic from communication stack |
| Man-in-the-middle on industrial protocols | Post-quantum authenticated and encrypted communication |
| PLC impersonation | Hardware-bound identity; device cannot be cloned or spoofed |
| Unauthorized configuration changes | Attestation verifies device is running expected firmware and configuration |
| Insider threat (malicious firmware update) | Signed update manifests; rollback protection prevents downgrade attacks |
| Long-term data exfiltration (HNDL) | Post-quantum encryption protects process data against future decryption |

**IEC 62443 Alignment:**

| IEC 62443 Requirement | Qbitel EdgeOS Capability |
|----------------------|-------------------------|
| FR 1: Identification and Authentication | Hardware-bound device identity (q-identity) |
| FR 2: Use Control | MPU/PMP-enforced task isolation (q-kernel) |
| FR 3: System Integrity | Secure boot (q-boot) + attestation (q-attest) |
| FR 4: Data Confidentiality | Post-quantum encryption (q-crypto + q-mesh) |
| FR 5: Restricted Data Flow | Mesh group trust policies (q-mesh) |
| FR 6: Timely Response to Events | Runtime integrity monitoring + anomaly detection (q-attest) |
| FR 7: Resource Availability | Watchdog timer, fail-safe defaults, A/B firmware slots |

### 5.3. Use Case: Safety Instrumented System (SIS)

**Device Profile:**
- MCU: STM32U5 (TrustZone for safety/security domain separation)
- Role: Emergency shutdown controller
- Safety: SIL3-SIL4
- Independence requirement: Must operate independently of the Basic Process Control System (BPCS)

**Operational Scenario:**
- Monitors critical process parameters (overpressure, overtemperature, gas detection)
- Triggers emergency shutdown sequence when safety limits exceeded
- Must execute shutdown even if the control network is compromised
- TrustZone separation ensures safety functions cannot be influenced by non-safety code
- Post-quantum signed commands for remote safety system management
- Attestation proves SIS integrity to safety regulators

### 5.4. Use Case: Industrial IoT Gateway

**Device Profile:**
- MCU: STM32H7
- Role: Bridge between OT (Operational Technology) and IT (Information Technology) networks
- Communication: Industrial Ethernet (downlink) + Ethernet/4G (uplink)

**Operational Scenario:**
- Protocol translation (Modbus to MQTT, OPC-UA to REST)
- Data aggregation and edge analytics
- Security boundary between OT and IT networks
- Post-quantum encrypted uplink to cloud/SCADA
- Device attestation for all connected OT devices
- OTA update relay for downstream devices

---

## 6. Water & Utilities

### 6.1. Industry Context

Water treatment and distribution systems rely on SCADA (Supervisory Control and Data Acquisition) networks to monitor and control pumps, valves, chemical dosing, and quality sensors across geographically distributed infrastructure. The 2021 Oldsmar water treatment attack demonstrated that these systems are actively targeted.

Water utilities face unique challenges: extreme geographic distribution, remote locations without reliable connectivity, limited cybersecurity budgets, and regulatory pressure from EPA/AWWA guidelines.

### 6.2. Use Case: Remote Pump Station Controller

**Device Profile:**
- MCU: STM32H7 or STM32U5
- Sensors: Pressure transducers, flow meters, level sensors, vibration monitors
- Actuators: Pump motor controllers, valve actuators
- Communication: LoRa mesh (primary, when no cellular available) or cellular
- Power: Mains with solar/battery backup
- Location: Often remote, physically accessible, limited physical security

**Operational Scenario:**
- Controls water pumps based on pressure and flow setpoints
- Monitors pump health (vibration, temperature, current draw)
- Adjusts chemical dosing based on water quality readings
- Reports telemetry to central SCADA
- Receives setpoint changes from operator (must be authenticated)
- Operates autonomously during communication outages

**Security Requirements:**
| Threat | Risk | Mitigation |
|--------|------|-----------|
| Unauthorized setpoint changes | Water pressure excursion, pipe burst | PQC-authenticated commands; only signed commands from verified operators |
| Chemical dosing manipulation | Public health emergency | Hardware-isolated control loop; tamper-evident command verification |
| Telemetry falsification | Masking attack or creating false alarms | Signed telemetry with device attestation |
| Physical access exploitation | Firmware extraction, device cloning | Flash read-out protection, PUF-bound identity |
| Long-range communication interception | Infrastructure reconnaissance | Post-quantum encrypted mesh communication |

### 6.3. Use Case: Water Quality Monitoring Sensor

**Device Profile:**
- MCU: RISC-V (low power, solar-powered)
- Sensors: pH, turbidity, chlorine residual, temperature, conductivity
- Communication: LoRa mesh to nearest gateway
- Deployment: In-pipe or reservoir-mounted, extremely remote

**Operational Scenario:**
- Takes water quality readings every 5-30 minutes
- Detects excursions from safe parameters
- Sends encrypted readings via mesh
- Ultra-low-power operation for years of battery life
- Air-gapped firmware updates (physical access only for remote sensors)
- Device attestation ensures sensor hasn't been tampered with to produce false readings

---

## 7. Border & Perimeter Security

### 7.1. Industry Context

National border protection and critical facility perimeter security require unattended sensor networks that operate reliably in extreme environments without infrastructure. These systems must detect, classify, and report intrusions while being resilient to electronic warfare, physical tampering, and adversarial interference.

### 7.2. Use Case: Unattended Ground Sensor (UGS) Network

**Reference Implementation:** `examples/border-sensor/` (see Section 4.2 for detailed technical breakdown)

**Deployment Scenario:**

A 50-km border section is monitored by a network of 200 ground sensors forming a self-healing mesh:

```
Topology:
  - 180 sensor nodes (RISC-V, solar+battery, buried/concealed)
  - 15 relay nodes (STM32U5, elevated position, larger solar panel)
  - 5 gateway nodes (STM32H7, connected to command center via satellite)

Coverage:
  - Sensor spacing: 200-500m (overlapping detection zones)
  - Relay spacing: 3-5km
  - Gateway spacing: 10-15km
  - Detection types: human movement, vehicle, animal (classification)

Communication:
  - Sensor-to-relay: LoRa SF10, 868 MHz, 500mW
  - Relay-to-gateway: LoRa SF7, 868 MHz, 1W
  - Gateway-to-command: Satellite or 4G backhaul
  - All links: PQC-encrypted (ML-KEM-768 + ChaCha20-Poly1305)
  - Mesh: Self-healing, automatic re-routing around destroyed/disabled nodes
```

**Operational Capabilities:**

| Capability | Implementation |
|-----------|---------------|
| Multi-sensor detection | PIR (motion), geophone (seismic), magnetometer (vehicle), acoustic, IR |
| Classification | Signal processing differentiates human/vehicle/animal |
| Low probability of intercept | Encrypted LoRa with frequency hopping; no plaintext headers |
| Tamper response | Accelerometer detects disturbance; triggers alert + key zeroization |
| Power autonomy | Solar charging with 4-level adaptive power management |
| Self-healing mesh | Distance-vector routing re-converges around lost nodes |
| Air-gapped updates | Firmware updates via physical access (USB/debug probe) |
| Supply chain integrity | Each sensor's manufacturing and deployment history is attestable |

### 7.3. Use Case: Critical Facility Perimeter

**Deployment Scenario:**
- Nuclear plant, military base, or data center perimeter
- Combination of ground sensors + fence-mounted sensors + camera integration points
- Higher density deployment (50-100m spacing)
- Redundant mesh paths for high availability
- Integration with access control systems

**Additional Requirements:**
- Faster alert latency (<1 second from detection to command center)
- Higher reliability (redundant sensors per zone)
- Integration APIs for existing security management systems
- Compliance with site-specific security regulations

---

## 8. Cross-Domain Capabilities

### 8.1. Air-Gapped Operations

Many critical infrastructure environments prohibit or cannot support network connectivity:

**Applicable domains:** Military installations, nuclear facilities, air-gapped substations, remote railway trackside equipment, classified environments.

**Qbitel EdgeOS Capabilities:**
- **Mesh networking** operates without any external infrastructure (no routers, no servers, no internet)
- **OTA updates** can be delivered via USB or serial port
- **Identity verification** requires no network (hardware-bound, self-signed)
- **Attestation** works over mesh without cloud backend
- **Key rotation** can be performed locally using Shamir shares from authorized personnel

### 8.2. Fleet Management at Scale

Managing thousands to millions of devices requires automated tooling:

**Provisioning (q-provision):**
- Batch device provisioning at factory (configurable batch_size)
- Automated key generation for each device
- Identity commitment creation with manufacturer binding
- Flash programming with optional read-out protection
- Verification after provisioning

**OTA Updates (q-update + Ansible + Terraform):**
- Firmware signing pipeline (q-sign)
- Upload to S3 firmware storage (versioned, encrypted)
- Fleet-wide update notifications via AWS IoT MQTT
- Staged rollouts (by fleet segment: smart_meters, railway_controllers, etc.)
- Automatic rollback on failure
- Progress monitoring via CloudWatch dashboard

**Monitoring and Observability:**
- CloudWatch metrics: ActiveDevices, OTASuccess, OTAFailure, AttestationSuccess, AttestationFailure
- Telemetry storage with lifecycle policies (30d Standard -> IA -> Glacier -> delete@365d)
- DynamoDB device registry with fleet and class-based querying
- Attestation records with TTL-based expiry

### 8.3. Supply Chain Security

From silicon to field deployment, every step is tracked:

```
Manufacturing Stage:
  1. MCU arrives from silicon vendor
  2. Factory provisioning station generates device keys (q-provision keygen)
  3. Identity commitment created with PUF enrollment (q-provision identity)
  4. Firmware flashed and verified (q-provision flash --verify)
  5. Supply chain entry signed: "Manufactured at Factory X, Date Y, by Operator Z"

Testing Stage:
  6. Functional test executed
  7. Crypto self-test (KAT) verified
  8. Attestation evidence collected and baseline recorded
  9. Supply chain entry signed: "Tested at Lab A, All tests passed"

Shipping Stage:
  10. Device packaged with tamper-evident seal
  11. Supply chain entry signed: "Shipped from Factory X to Deployment Site Y"

Deployment Stage:
  12. Device received, tamper seal verified
  13. Attestation check: does evidence match manufacturing baseline?
  14. Supply chain entry signed: "Deployed at Location Z by Installer W"
  15. Device enters operational state

Maintenance Stage:
  16. Any firmware update is recorded
  17. Any key rotation is recorded
  18. Supply chain entry signed for each maintenance action
```

Each supply chain entry includes:
- Event type (Manufacturing, Testing, Shipping, Deployment, Maintenance)
- Timestamp
- Actor identity (who performed the action)
- Previous entry hash (chain linkage — tamper evident)
- Digital signature (ML-DSA-65 by the actor's key)

### 8.4. Multi-Platform Deployment

Single firmware codebase targets all supported platforms:

```
                    Shared Application Code
                    (examples/smart-meter)
                            |
                    +-------+-------+
                    |               |
              Qbitel EdgeOS Crates    Platform Feature Flags
              (q-boot, q-kernel,      (--features stm32h7)
               q-crypto, q-mesh...)   (--features stm32u5)
                    |                 (--features riscv)
                    |
              +-----+------+------+
              |            |      |
          STM32H7      STM32U5  RISC-V
        Cortex-M7    Cortex-M33  RV32IMAC
         480MHz       160MHz     320MHz
```

The same `smart-meter` application code compiles for all three platforms. Only the q-hal implementation changes (via feature-gated modules). Application developers write platform-agnostic code using q-hal traits.

### 8.5. Compliance Mapping

| Standard | Domain | Qbitel EdgeOS Coverage |
|----------|--------|----------------------|
| **NIST FIPS 203** | PQC Key Encapsulation | ML-KEM-768 implemented in q-crypto |
| **NIST FIPS 204** | PQC Digital Signatures | ML-DSA-65 implemented in q-crypto |
| **NIST FIPS 202** | SHA-3 Hash Functions | SHA3-256/384/512, SHAKE128/256 in q-crypto |
| **NIST FIPS 197** | AES Block Cipher | AES-256-GCM in q-crypto |
| **NSA CNSA 2.0** | National Security Systems PQC | ML-KEM-768 + ML-DSA-65 satisfy requirements |
| **Common Criteria EAL4+** | Security Evaluation | Architecture designed for EAL4+ evaluation |
| **IEC 62443** | Industrial Cybersecurity | All 7 Foundational Requirements addressed |
| **EN 50129** | Railway Safety | SIL4 design patterns in railway example |
| **EN 50159** | Railway Communication | Authenticated messaging via PQC signatures |
| **IEC 62280** | Railway Data Communication | Message authentication codes |
| **IEC 62351** | Power Grid Security | Key management, authenticated communication |
| **NERC CIP** | Power Grid Infrastructure | Firmware integrity, access control, audit |
| **NIST CSF** | Cybersecurity Framework | Identify, Protect, Detect, Respond, Recover |
| **EU CRA** | Cyber Resilience Act | Security by design, vulnerability management |

---

## 9. Deployment Scenarios Summary

### 9.1. Scenario Matrix

| Scenario | Domain | Device Count | Connectivity | Update Method | Key Management |
|----------|--------|-------------|-------------|---------------|---------------|
| National smart meter rollout | Energy | 1M-50M | Mesh + gateway | OTA via cloud | Centralized fleet authority |
| Railway line signaling | Rail | 100-1000 | Dedicated network | Staged OTA or physical | Safety authority controlled |
| Border surveillance network | Defense | 200-2000 | LoRa mesh only | Physical (USB) | Threshold shares (3-of-5) |
| Factory floor automation | Industrial | 50-500 | Industrial Ethernet | OTA via factory server | Plant-level authority |
| Water distribution SCADA | Water | 100-5000 | LoRa + cellular | Staged OTA or physical | Utility IT department |
| Military tactical comms | Defense | 20-200 | Multi-band mesh | Air-gapped USB | Unit commander authority |
| Nuclear facility perimeter | Defense | 50-200 | Redundant mesh | Physical only | Multi-person authorization |

### 9.2. Time-to-Deploy Estimates

| Phase | Duration | Activities |
|-------|----------|-----------|
| Evaluation | 2-4 weeks | Build from source, run tests, evaluate on dev board |
| Proof of Concept | 4-8 weeks | Custom application on target hardware, mesh testing |
| Platform Port (if needed) | 4-12 weeks | Implement q-hal traits for new MCU |
| Factory Provisioning Setup | 2-4 weeks | Provisioning station, key management, workflow |
| Pilot Deployment | 4-8 weeks | 10-100 devices in field, operational validation |
| Production Rollout | Ongoing | Batch provisioning, staged deployment, fleet management |

---

## 10. Integration Points

### 10.1. Cloud Integration

| Service | Integration | Purpose |
|---------|------------|---------|
| AWS IoT Core | MQTT pub/sub | Device telemetry and commands |
| AWS S3 | Firmware storage | Versioned, encrypted firmware hosting |
| AWS DynamoDB | Device registry | Fleet management and attestation records |
| AWS Lambda | OTA orchestrator | Update coordination and monitoring |
| AWS CloudWatch | Monitoring | Fleet health metrics and alerting |
| Azure IoT Hub | Alternative cloud | Equivalent functionality on Azure |

### 10.2. SCADA/Industrial Integration

| Protocol | Support | Use Case |
|----------|---------|----------|
| Modbus TCP/RTU | Via application layer | PLC communication |
| OPC-UA | Via application layer | Industrial data exchange |
| MQTT | Via q-mesh + gateway | Telemetry to cloud |
| DLMS/COSEM | Via application layer | Smart metering |
| IEC 61850 | Via application layer | Substation automation |

### 10.3. Hardware Integration

| Interface | q-hal Trait | Supported Peripherals |
|-----------|-----------|---------------------|
| GPIO | `Gpio` | Digital I/O, interrupt, alternate function |
| UART | `Uart` | Debug console, sensor interfaces, Modbus RTU |
| SPI | `Spi` | LoRa radio (SX1276/1262), flash, displays |
| I2C | `I2c` | Sensors, EEPROMs, crypto co-processors |
| Flash | `Flash` | Internal flash for firmware and configuration |
| TRNG | `Rng` | Hardware true random number generation |
| OTP/eFUSE | `SecureStorage` | Rollback counters, device UID |
| PUF | `Puf` | Hardware-bound identity anchoring |
| Watchdog | `Watchdog` | Safety watchdog timer |

---

*End of Domain Use Cases Reference Document.*
