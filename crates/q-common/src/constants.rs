// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! System-wide constants for Qbitel EdgeOS
//!
//! This module defines compile-time constants used throughout the system.
//! All sizes and limits are carefully chosen for embedded constraints.

// =============================================================================
// Cryptographic Constants
// =============================================================================

/// Kyber-768 public key size in bytes
pub const KYBER768_PUBLIC_KEY_SIZE: usize = 1184;

/// Kyber-768 secret key size in bytes
pub const KYBER768_SECRET_KEY_SIZE: usize = 2400;

/// Kyber-768 ciphertext size in bytes
pub const KYBER768_CIPHERTEXT_SIZE: usize = 1088;

/// Kyber-768 shared secret size in bytes
pub const KYBER768_SHARED_SECRET_SIZE: usize = 32;

/// Dilithium3 public key size in bytes
pub const DILITHIUM3_PUBLIC_KEY_SIZE: usize = 1952;

/// Dilithium3 secret key size in bytes
pub const DILITHIUM3_SECRET_KEY_SIZE: usize = 4000;

/// Dilithium3 signature size in bytes
pub const DILITHIUM3_SIGNATURE_SIZE: usize = 3293;

/// Falcon-512 public key size in bytes
pub const FALCON512_PUBLIC_KEY_SIZE: usize = 897;

/// Falcon-512 secret key size in bytes
pub const FALCON512_SECRET_KEY_SIZE: usize = 1281;

/// Falcon-512 signature size in bytes (max)
pub const FALCON512_SIGNATURE_SIZE: usize = 690;

/// SHA3-256 output size in bytes
pub const SHA3_256_OUTPUT_SIZE: usize = 32;

/// SHA3-512 output size in bytes
pub const SHA3_512_OUTPUT_SIZE: usize = 64;

/// AES-256-GCM key size in bytes
pub const AES256_KEY_SIZE: usize = 32;

/// AES-GCM nonce size in bytes
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// AES-GCM tag size in bytes
pub const AES_GCM_TAG_SIZE: usize = 16;

/// ChaCha20-Poly1305 key size in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size in bytes
pub const CHACHA20_NONCE_SIZE: usize = 12;

// =============================================================================
// Identity Constants
// =============================================================================

/// Device ID size in bytes
pub const DEVICE_ID_SIZE: usize = 32;

/// Manufacturer ID size in bytes
pub const MANUFACTURER_ID_SIZE: usize = 16;

/// Maximum metadata size in bytes
pub const MAX_METADATA_SIZE: usize = 256;

/// Hardware fingerprint size in bytes
pub const HARDWARE_FINGERPRINT_SIZE: usize = 32;

/// PUF response size in bytes
pub const PUF_RESPONSE_SIZE: usize = 256;

/// PUF helper data size in bytes
pub const PUF_HELPER_DATA_SIZE: usize = 128;

/// Identity commitment version
pub const IDENTITY_COMMITMENT_VERSION: u8 = 1;

// =============================================================================
// Update Constants
// =============================================================================

/// Update manifest magic number: "QUPD"
pub const UPDATE_MANIFEST_MAGIC: u32 = 0x5155_5044;

/// Maximum update image size (1MB)
pub const MAX_UPDATE_IMAGE_SIZE: usize = 1024 * 1024;

/// Update manifest header size
pub const UPDATE_MANIFEST_HEADER_SIZE: usize = 256;

/// Maximum number of update slots
pub const MAX_UPDATE_SLOTS: usize = 2;

// =============================================================================
// Mesh Networking Constants
// =============================================================================

/// Maximum number of mesh peers
pub const MAX_MESH_PEERS: usize = 32;

/// Maximum message payload size
pub const MAX_MESSAGE_PAYLOAD_SIZE: usize = 4096;

/// Session ID size in bytes
pub const SESSION_ID_SIZE: usize = 16;

/// Nonce size for mesh messages
pub const MESH_NONCE_SIZE: usize = 12;

/// Maximum routing hops
pub const MAX_ROUTING_HOPS: u8 = 8;

// =============================================================================
// Attestation Constants
// =============================================================================

/// Maximum attestation evidence size
pub const MAX_ATTESTATION_EVIDENCE_SIZE: usize = 2048;

/// Supply chain record size
pub const SUPPLY_CHAIN_RECORD_SIZE: usize = 512;

/// Maximum number of supply chain records
pub const MAX_SUPPLY_CHAIN_RECORDS: usize = 16;

// =============================================================================
// Recovery Constants
// =============================================================================

/// Default threshold for key recovery (k of n)
pub const DEFAULT_RECOVERY_THRESHOLD: u8 = 3;

/// Default total shares for key recovery
pub const DEFAULT_RECOVERY_SHARES: u8 = 5;

/// Recovery token size in bytes
pub const RECOVERY_TOKEN_SIZE: usize = 256;

/// Maximum key rotation history
pub const MAX_KEY_ROTATION_HISTORY: usize = 8;

// =============================================================================
// Kernel Constants
// =============================================================================

/// Maximum number of tasks
pub const MAX_TASKS: usize = 16;

/// Default task stack size
pub const DEFAULT_TASK_STACK_SIZE: usize = 2048;

/// Maximum task name length
pub const MAX_TASK_NAME_LEN: usize = 16;

/// IPC message buffer size
pub const IPC_MESSAGE_SIZE: usize = 256;

/// Maximum IPC channels
pub const MAX_IPC_CHANNELS: usize = 8;

// =============================================================================
// Boot Constants
// =============================================================================

/// Boot magic number: "QEDG"
pub const BOOT_MAGIC: u32 = 0x5145_4447;

/// Kernel header size
pub const KERNEL_HEADER_SIZE: usize = 4096;

/// Maximum boot time in milliseconds
pub const MAX_BOOT_TIME_MS: u32 = 100;

// =============================================================================
// Performance Budgets (in microseconds unless noted)
// =============================================================================

/// Maximum Kyber key generation time (ms)
pub const KYBER_KEYGEN_BUDGET_MS: u32 = 5;

/// Maximum Kyber encapsulation time (ms)
pub const KYBER_ENCAPS_BUDGET_MS: u32 = 6;

/// Maximum Kyber decapsulation time (ms)
pub const KYBER_DECAPS_BUDGET_MS: u32 = 7;

/// Maximum Dilithium sign time (ms)
pub const DILITHIUM_SIGN_BUDGET_MS: u32 = 12;

/// Maximum Dilithium verify time (ms)
pub const DILITHIUM_VERIFY_BUDGET_MS: u32 = 6;

/// Maximum hybrid handshake time (ms)
pub const HYBRID_HANDSHAKE_BUDGET_MS: u32 = 150;

/// Maximum attestation time (ms)
pub const ATTESTATION_BUDGET_MS: u32 = 20;

/// Maximum key rotation time (ms)
pub const KEY_ROTATION_BUDGET_MS: u32 = 200;

// =============================================================================
// Memory Budgets (in bytes)
// =============================================================================

/// Kyber key generation memory budget
pub const KYBER_KEYGEN_MEMORY_BUDGET: usize = 12 * 1024;

/// Dilithium sign memory budget
pub const DILITHIUM_SIGN_MEMORY_BUDGET: usize = 16 * 1024;

/// Hybrid handshake memory budget
pub const HYBRID_HANDSHAKE_MEMORY_BUDGET: usize = 20 * 1024;

/// Attestation memory budget
pub const ATTESTATION_MEMORY_BUDGET: usize = 8 * 1024;

/// Boot process memory budget
pub const BOOT_MEMORY_BUDGET: usize = 32 * 1024;

/// Key rotation memory budget
pub const KEY_ROTATION_MEMORY_BUDGET: usize = 24 * 1024;
