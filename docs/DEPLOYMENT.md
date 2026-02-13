# Qbitel EdgeOS - Deployment Guide

This guide covers production deployment of Qbitel EdgeOS, from building firmware to fleet management at scale.

---

## Table of Contents

- [Deployment Overview](#deployment-overview)
- [Building Release Firmware](#building-release-firmware)
- [Firmware Signing](#firmware-signing)
- [Device Provisioning](#device-provisioning)
- [Flashing Devices](#flashing-devices)
- [Cloud Infrastructure (Terraform)](#cloud-infrastructure-terraform)
- [Fleet Management (Ansible)](#fleet-management-ansible)
- [OTA Updates](#ota-updates)
- [Monitoring and Observability](#monitoring-and-observability)
- [CI/CD Pipeline](#cicd-pipeline)
- [Air-Gapped Deployments](#air-gapped-deployments)
- [Production Checklist](#production-checklist)

---

## Deployment Overview

A typical Qbitel EdgeOS deployment follows this pipeline:

```
Source Code
    |
    v
CI/CD Build (Docker / GitHub Actions)
    |
    v
Firmware Signing (q-sign + ML-DSA-65)
    |
    v
Factory Provisioning (q-provision + debug probe)
    |
    v
Fleet Registration (AWS IoT / DynamoDB)
    |
    v
Field Deployment
    |
    v
OTA Updates (q-update + S3 + Lambda)
    |
    v
Monitoring (CloudWatch + Attestation)
```

---

## Building Release Firmware

### Local Build

```bash
# Production-optimized build for STM32H7
cargo build --profile production --target thumbv7em-none-eabihf --features stm32h7

# Production build for STM32U5
cargo build --profile production --target thumbv8m.main-none-eabihf --features stm32u5

# Production build for RISC-V
cargo build --profile production --target riscv32imac-unknown-none-elf --features riscv
```

The `production` profile enables:
- Full LTO (Link-Time Optimization)
- Size optimization (`opt-level = "z"`)
- Panic = abort (no unwinding overhead)
- Integer overflow checks (security-critical)
- Symbol stripping

### Docker Build (Reproducible)

For reproducible builds that produce identical binaries regardless of the host:

```bash
docker compose run builder
```

This builds all targets in a controlled environment with pinned toolchain versions.

### Check Binary Size

Embedded targets have strict flash constraints. Verify your binary fits:

```bash
# ARM targets
cargo size --profile production --target thumbv7em-none-eabihf --features stm32h7 -- -A

# Check section breakdown
cargo objdump --profile production --target thumbv7em-none-eabihf --features stm32h7 -- -h
```

**Size budget:**

| Section | STM32H7 Budget | STM32U5 Budget | RISC-V Budget |
|---------|---------------|---------------|--------------|
| .text (code) | < 1.5MB | < 1.5MB | < 12MB |
| .rodata (constants) | < 256KB | < 256KB | < 2MB |
| .data + .bss (RAM) | < 768KB | < 512KB | < 12KB |

---

## Firmware Signing

Every production firmware image must be signed before deployment.

### 1. Generate Signing Keys

```bash
# Create a directory for production keys
mkdir -p keys/production

# Generate firmware signing keypair (Dilithium3 / ML-DSA-65)
q-sign keygen \
  --algorithm dilithium3 \
  --purpose firmware \
  --output keys/production/

# Generate update signing keypair (for OTA packages)
q-sign keygen \
  --algorithm dilithium3 \
  --purpose update \
  --output keys/production/
```

**Key management best practices:**
- Store private keys in an HSM or hardware security module
- Never commit private keys to version control
- Maintain offline backups of signing keys
- Rotate keys annually or after any suspected compromise
- The `.gitignore` already excludes `*.pem`, `*.key`, and `*_private.json`

### 2. Sign Firmware Images

```bash
# Sign the kernel image
q-sign sign \
  --algorithm dilithium3 \
  --key keys/production/firmware_signer \
  --image target/thumbv7em-none-eabihf/production/qbitel-edgeos \
  --image-type kernel \
  --version 1 \
  --hw-version 1

# Sign the bootloader
q-sign sign \
  --algorithm dilithium3 \
  --key keys/production/firmware_signer \
  --image target/thumbv7em-none-eabihf/production/q-boot \
  --image-type bootloader \
  --version 1
```

### 3. Create Update Package

Bundle all components into a signed update package:

```bash
q-sign package \
  --bootloader target/thumbv7em-none-eabihf/production/q-boot.signed \
  --kernel target/thumbv7em-none-eabihf/production/qbitel-edgeos.signed \
  --application target/thumbv7em-none-eabihf/production/smart-meter.signed \
  --key keys/production/update_signer \
  --target stm32h7 \
  --output dist/qbitel-edgeos-v0.1.0-stm32h7.pkg
```

### 4. Verify Before Distribution

```bash
q-sign verify \
  --image dist/qbitel-edgeos-v0.1.0-stm32h7.pkg \
  --key keys/production/update_signer.pub \
  --strict
```

---

## Device Provisioning

Each device must be provisioned with a unique identity before deployment.

### 1. Set Up Provisioning Station

A provisioning station is a workstation connected to a debug probe (ST-Link or J-Link):

```bash
# Install provisioning tools
pip install -e tools/q-provision

# Generate default configuration
q-provision init-config --output provision-config.yml

# Verify connected debug probes
q-provision list-devices
```

### 2. Generate Device Keys

```bash
# Generate all key types for a device
q-provision keygen \
  --key-type all \
  --device-id DEVICE-001 \
  --output provisioning_output/DEVICE-001/
```

This generates:
- ML-KEM-768 keypair (for key encapsulation)
- ML-DSA-65 keypair (for digital signatures)
- FN-DSA-512 keypair (for compact signatures)

### 3. Create Device Identity

```bash
q-provision identity \
  --device-id DEVICE-001 \
  --manufacturer-id MFG-QBITEL \
  --device-class sensor \
  --output provisioning_output/DEVICE-001/
```

If the device supports PUF (Physical Unclonable Function):

```bash
q-provision identity \
  --device-id DEVICE-001 \
  --manufacturer-id MFG-QBITEL \
  --device-class sensor \
  --puf-data provisioning_output/DEVICE-001/puf_response.bin \
  --output provisioning_output/DEVICE-001/
```

### 4. Flash to Device

```bash
q-provision flash \
  --target stm32h7 \
  --bootloader target/thumbv7em-none-eabihf/production/q-boot.signed \
  --kernel target/thumbv7em-none-eabihf/production/smart-meter.signed \
  --identity provisioning_output/DEVICE-001/identity.bin \
  --port /dev/ttyACM0
```

For production, lock the flash to prevent readout:

```bash
q-provision flash \
  --target stm32h7 \
  --bootloader q-boot.signed \
  --kernel smart-meter.signed \
  --identity identity.bin \
  --port /dev/ttyACM0 \
  --lock    # Enable read-out protection
```

### 5. Verify Provisioned Device

```bash
q-provision verify \
  --target stm32h7 \
  --port /dev/ttyACM0 \
  --full    # Run crypto self-tests + flash integrity check
```

---

## Cloud Infrastructure (Terraform)

The `deploy/terraform/` directory contains AWS infrastructure for fleet management.

### Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform 1.5+

### Infrastructure Components

| Resource | Purpose |
|----------|---------|
| S3 (firmware_updates) | Versioned, encrypted firmware storage |
| S3 (telemetry) | Device telemetry with lifecycle policies |
| DynamoDB (device_registry) | Fleet registry with GSIs |
| DynamoDB (attestation_records) | Attestation logs with TTL |
| AWS IoT | Device connectivity (MQTT) |
| Lambda (ota_orchestrator) | OTA update coordination |
| CloudWatch | Fleet monitoring dashboard |

### Deploy Infrastructure

```bash
cd deploy/terraform

# Initialize Terraform
terraform init

# Review the plan
terraform plan \
  -var="alarm_email=ops@example.com" \
  -var="max_devices=10000"

# Apply
terraform apply \
  -var="alarm_email=ops@example.com" \
  -var="max_devices=10000"
```

### Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `project_name` | Resource naming prefix | `qbitel-edgeos` |
| `vpc_cidr` | VPC CIDR block | `10.0.0.0/16` |
| `enable_hsm` | Enable CloudHSM for key management | `false` |
| `enable_waf` | Enable WAF for API protection | `true` |
| `retention_days` | Log retention period | `90` |
| `alarm_email` | CloudWatch alarm notifications | `""` |
| `max_devices` | Maximum fleet size | `10000` |
| `firmware_signing_key_arn` | KMS key ARN for firmware signing | `""` |

### Outputs

After deployment, Terraform outputs:

```bash
terraform output

# firmware_bucket      = "qbitel-edgeos-firmware-..."
# device_registry      = "qbitel-edgeos-device-registry"
# iot_policy           = "qbitel-edgeos-device-policy"
# dashboard_url        = "https://..."
```

---

## Fleet Management (Ansible)

The `deploy/ansible/` directory contains playbooks for device fleet operations.

### Inventory Structure

```yaml
# deploy/ansible/inventory/hosts.yml
all:
  vars:
    qbitel_version: "0.1.0"
    firmware_base_url: "https://firmware.qbitel.example.com"
  children:
    provisioning_stations:
      hosts:
        provision-station-01:
          ansible_host: 192.168.1.10
    build_servers:
      hosts:
        build-server-01:
          ansible_host: 192.168.1.20
    edge_devices:
      children:
        smart_meters:
          vars:
            device_class: smart-meter
        railway_controllers:
          vars:
            device_class: railway-signaling
            safety_level: SIL4
        border_sensors:
          vars:
            device_class: border-sensor
            mesh_enabled: true
```

### Available Playbooks

**Build firmware:**
```bash
ansible-playbook deploy/ansible/playbooks/build.yml \
  -i deploy/ansible/inventory/hosts.yml \
  -e "qbitel_version=0.1.0"
```

**Provision devices:**
```bash
ansible-playbook deploy/ansible/playbooks/provision.yml \
  -i deploy/ansible/inventory/hosts.yml \
  -e "manufacturer_id=MFG001" \
  -e "device_class=sensor" \
  -e "target_platform=stm32h7" \
  -e "batch_size=10"
```

**Deploy OTA updates:**
```bash
ansible-playbook deploy/ansible/playbooks/update.yml \
  -i deploy/ansible/inventory/hosts.yml \
  -e "firmware_version=0.2.0" \
  -e "target_fleet=smart_meters"
```

---

## OTA Updates

### Upload Firmware to S3

```bash
# Get the firmware bucket name from Terraform
BUCKET=$(terraform -chdir=deploy/terraform output -raw firmware_bucket)

# Upload signed firmware package
aws s3 cp \
  dist/qbitel-edgeos-v0.2.0-stm32h7.pkg \
  s3://$BUCKET/firmware/v0.2.0/stm32h7/

# Upload the manifest
aws s3 cp \
  dist/manifest-v0.2.0.json \
  s3://$BUCKET/manifests/v0.2.0/
```

### Trigger OTA via AWS IoT

```bash
# Publish update notification to a fleet
aws iot-data publish \
  --topic "q-edge/fleet/smart-meters/update" \
  --payload '{"version":"0.2.0","url":"s3://bucket/firmware/v0.2.0/stm32h7/"}'
```

### Update Flow on Device

1. Device receives MQTT notification on `q-edge/{device_id}/update`
2. `q-update` downloads the manifest from the URL
3. Manifest is verified (ML-DSA-65 signature, monotonic version)
4. Firmware is written to the inactive A/B slot
5. Device reboots; `q-boot` verifies the new slot
6. On success: slot is marked active, rollback counter updated
7. On failure: automatic rollback to the previous slot

---

## Monitoring and Observability

### CloudWatch Dashboard

The Terraform deployment creates a fleet monitoring dashboard with:

| Metric | Description |
|--------|-------------|
| ActiveDevices | Number of devices reporting in |
| OTASuccess / OTAFailure | Update success/failure counts |
| AttestationSuccess / AttestationFailure | Attestation verification results |

Access the dashboard URL from Terraform outputs:
```bash
terraform -chdir=deploy/terraform output dashboard_url
```

### Device Telemetry

Devices publish telemetry to the S3 telemetry bucket via AWS IoT rules. Data lifecycle:

| Age | Storage Tier |
|-----|-------------|
| 0-30 days | S3 Standard |
| 30-90 days | S3 Infrequent Access |
| 90-365 days | S3 Glacier |
| > 365 days | Deleted |

### Attestation Monitoring

Attestation records are stored in DynamoDB with TTL. Monitor for:
- Devices that stop attesting (potential compromise or connectivity loss)
- Attestation failures (firmware tampering, identity mismatch)
- Anomalous measurement values

---

## CI/CD Pipeline

### GitHub Actions

The repository includes CI workflows:

**CI (`.github/workflows/ci.yml`):**
- Format check (`cargo fmt`)
- Lint check (`cargo clippy`)
- Test suite (`cargo test --workspace --all-features`)
- Security audit (`cargo audit`, `cargo deny`)
- Build for all targets

**SBOM (`.github/workflows/sbom.yml`):**
- Generates CycloneDX SBOM for Rust dependencies
- Generates SBOM for Python tool dependencies
- Attaches SBOM to releases

**Release (`.github/workflows/release.yml`):**
- Triggered by version tags (`v*`)
- Builds firmware for all platforms
- Signs firmware packages
- Creates GitHub release with artifacts

### Triggering a Release

```bash
# Tag and push
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

The CI pipeline will:
1. Run all tests
2. Build firmware for STM32H7, STM32U5, and RISC-V
3. Generate SBOM
4. Create a GitHub release with signed firmware packages

---

## Air-Gapped Deployments

For environments without internet connectivity:

### 1. Build Offline Update Package

```bash
# Build and sign firmware on a connected machine
q-sign package \
  --bootloader q-boot.signed \
  --kernel smart-meter.signed \
  --key keys/production/update_signer \
  --target stm32h7 \
  --output update-v0.2.0-stm32h7.pkg
```

### 2. Transfer via Removable Media

Copy the signed package to a USB drive or secure transfer medium.

### 3. Apply on Device

The `q-update` crate supports air-gapped update application. The device reads the update package from a local source (UART, SPI flash, or external storage) instead of downloading it over the network.

The verification flow is identical to a network-delivered update:
- Manifest signature verification
- Monotonic version check
- A/B slot management
- Automatic rollback on failure

---

## Production Checklist

Before deploying to production, verify:

### Build

- [ ] Built with `--profile production` (full LTO, size optimized)
- [ ] Binary size fits within target flash constraints
- [ ] Overflow checks enabled (`overflow-checks = true`)
- [ ] Panic = abort (no unwinding)
- [ ] Symbols stripped

### Security

- [ ] Firmware signed with ML-DSA-65 (Dilithium3)
- [ ] Signing keys stored in HSM or secure offline storage
- [ ] Private keys not in version control
- [ ] `cargo audit` passes with no known vulnerabilities
- [ ] `cargo deny check` passes
- [ ] `cargo geiger` reviewed for unsafe code usage

### Device

- [ ] Device identity provisioned and verified
- [ ] PUF/eFUSE binding confirmed
- [ ] Flash read-out protection enabled (`--lock`)
- [ ] Debug port disabled in production firmware
- [ ] Anti-rollback counter initialized

### Infrastructure

- [ ] Terraform applied successfully
- [ ] S3 buckets encrypted (AES-256)
- [ ] DynamoDB tables with point-in-time recovery
- [ ] IoT policies follow least-privilege
- [ ] CloudWatch alarms configured
- [ ] WAF enabled for API endpoints

### Testing

- [ ] All host tests pass (`cargo test --workspace --all-features`)
- [ ] Crypto Known Answer Tests (KAT) pass
- [ ] On-device boot test completed
- [ ] OTA update cycle tested (apply + rollback)
- [ ] Attestation flow verified
- [ ] Mesh communication tested with multiple devices

### Documentation

- [ ] Firmware version documented
- [ ] SBOM generated and archived
- [ ] Deployment records maintained
- [ ] Incident response plan in place

---

## Next Steps

- **[PRODUCT_OVERVIEW.md](PRODUCT_OVERVIEW.md)** - Product overview
- **[WALKTHROUGH.md](WALKTHROUGH.md)** - Technical walkthrough
- **[API.md](API.md)** - API reference
- **[../SECURITY.md](../SECURITY.md)** - Security vulnerability reporting
