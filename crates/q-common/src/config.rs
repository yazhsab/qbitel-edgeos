// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! System configuration for Qbitel EdgeOS
//!
//! This module defines configuration structures that control system behavior.
//! All configuration is compile-time or provisioned at factory - no runtime
//! configuration changes are allowed for security.

use crate::types::{AlgorithmId, DeviceClass, SecurityLevel};

/// System-wide configuration
#[derive(Debug, Clone, Copy)]
pub struct SystemConfig {
    /// Device class for this device
    pub device_class: DeviceClass,
    /// Minimum required security level
    pub min_security_level: SecurityLevel,
    /// Default KEM algorithm
    pub default_kem: AlgorithmId,
    /// Default signature algorithm
    pub default_signature: AlgorithmId,
    /// Default hash algorithm
    pub default_hash: AlgorithmId,
    /// Default AEAD algorithm
    pub default_aead: AlgorithmId,
    /// Enable hybrid mode (PQC + classical)
    pub hybrid_mode: bool,
    /// Crypto configuration
    pub crypto: CryptoConfig,
    /// Identity configuration
    pub identity: IdentityConfig,
    /// Update configuration
    pub update: UpdateConfig,
    /// Mesh configuration
    pub mesh: MeshConfig,
    /// Boot configuration
    pub boot: BootConfig,
}

impl SystemConfig {
    /// Create a default configuration for a given device class
    #[must_use]
    pub const fn for_device_class(device_class: DeviceClass) -> Self {
        let min_security = SecurityLevel::minimum_for_device_class(device_class);

        Self {
            device_class,
            min_security_level: min_security,
            default_kem: AlgorithmId::Kyber768,
            default_signature: AlgorithmId::Dilithium3,
            default_hash: AlgorithmId::Sha3_256,
            default_aead: AlgorithmId::Aes256Gcm,
            hybrid_mode: device_class.requires_enhanced_security(),
            crypto: CryptoConfig::default_for_level(min_security),
            identity: IdentityConfig::DEFAULT,
            update: UpdateConfig::DEFAULT,
            mesh: MeshConfig::DEFAULT,
            boot: BootConfig::DEFAULT,
        }
    }

    /// Default configuration (Level 3 security, generic device)
    pub const DEFAULT: Self = Self {
        device_class: DeviceClass::Generic,
        min_security_level: SecurityLevel::Level3,
        default_kem: AlgorithmId::Kyber768,
        default_signature: AlgorithmId::Dilithium3,
        default_hash: AlgorithmId::Sha3_256,
        default_aead: AlgorithmId::Aes256Gcm,
        hybrid_mode: false,
        crypto: CryptoConfig::DEFAULT,
        identity: IdentityConfig::DEFAULT,
        update: UpdateConfig::DEFAULT,
        mesh: MeshConfig::DEFAULT,
        boot: BootConfig::DEFAULT,
    };
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Cryptographic configuration
#[derive(Debug, Clone, Copy)]
pub struct CryptoConfig {
    /// Enable constant-time operations (always true for production)
    pub constant_time: bool,
    /// Enable hardware acceleration if available
    pub hw_acceleration: bool,
    /// Zeroize sensitive memory after use
    pub zeroize_on_drop: bool,
    /// Maximum key derivation iterations
    pub max_kdf_iterations: u32,
    /// Session key lifetime in seconds
    pub session_key_lifetime_secs: u32,
}

impl CryptoConfig {
    /// Default crypto configuration
    pub const DEFAULT: Self = Self {
        constant_time: true,
        hw_acceleration: true,
        zeroize_on_drop: true,
        max_kdf_iterations: 100_000,
        session_key_lifetime_secs: 3600, // 1 hour
    };

    /// Create configuration for a security level
    #[must_use]
    pub const fn default_for_level(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::Level5 => Self {
                constant_time: true,
                hw_acceleration: true,
                zeroize_on_drop: true,
                max_kdf_iterations: 200_000,
                session_key_lifetime_secs: 1800, // 30 minutes
            },
            SecurityLevel::Level3 => Self::DEFAULT,
            SecurityLevel::Level1 => Self {
                constant_time: true,
                hw_acceleration: true,
                zeroize_on_drop: true,
                max_kdf_iterations: 50_000,
                session_key_lifetime_secs: 7200, // 2 hours
            },
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Identity configuration
#[derive(Debug, Clone, Copy)]
pub struct IdentityConfig {
    /// Maximum identity age in seconds (0 = no limit)
    pub max_identity_age_secs: u64,
    /// Require hardware binding (PUF/eFUSE)
    pub require_hardware_binding: bool,
    /// Allow identity re-provisioning
    pub allow_reprovisioning: bool,
    /// Identity commitment version
    pub commitment_version: u8,
}

impl IdentityConfig {
    /// Default identity configuration
    pub const DEFAULT: Self = Self {
        max_identity_age_secs: 0, // No expiration by default
        require_hardware_binding: true,
        allow_reprovisioning: false,
        commitment_version: 1,
    };
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Update configuration
#[derive(Debug, Clone, Copy)]
pub struct UpdateConfig {
    /// Enable A/B partitioning
    pub ab_partitioning: bool,
    /// Maximum rollback count (0 = no rollback allowed)
    pub max_rollback_count: u8,
    /// Require signed updates
    pub require_signature: bool,
    /// Minimum version delta for updates
    pub min_version_delta: u16,
    /// Update timeout in seconds
    pub update_timeout_secs: u32,
    /// Verify update after application
    pub verify_after_apply: bool,
}

impl UpdateConfig {
    /// Default update configuration
    pub const DEFAULT: Self = Self {
        ab_partitioning: true,
        max_rollback_count: 0, // No rollback allowed
        require_signature: true,
        min_version_delta: 1,
        update_timeout_secs: 300, // 5 minutes
        verify_after_apply: true,
    };
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Mesh networking configuration
#[derive(Debug, Clone, Copy)]
pub struct MeshConfig {
    /// Maximum number of peers
    pub max_peers: u16,
    /// Discovery interval in seconds
    pub discovery_interval_secs: u32,
    /// Session timeout in seconds
    pub session_timeout_secs: u32,
    /// Enable offline mode
    pub offline_mode: bool,
    /// Maximum message size
    pub max_message_size: usize,
    /// Require mutual authentication
    pub require_mutual_auth: bool,
}

impl MeshConfig {
    /// Default mesh configuration
    pub const DEFAULT: Self = Self {
        max_peers: 32,
        discovery_interval_secs: 60,
        session_timeout_secs: 3600,
        offline_mode: true,
        max_message_size: 4096,
        require_mutual_auth: true,
    };
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Boot configuration
#[derive(Debug, Clone, Copy)]
pub struct BootConfig {
    /// Boot timeout in milliseconds
    pub boot_timeout_ms: u32,
    /// Require signature verification
    pub verify_signature: bool,
    /// Enable secure boot chain
    pub secure_boot: bool,
    /// Lock debug interface after boot
    pub lock_debug: bool,
    /// Maximum boot attempts before recovery
    pub max_boot_attempts: u8,
}

impl BootConfig {
    /// Default boot configuration
    pub const DEFAULT: Self = Self {
        boot_timeout_ms: 100, // 100ms max boot time
        verify_signature: true,
        secure_boot: true,
        lock_debug: true,
        max_boot_attempts: 3,
    };

    /// Development boot configuration (less restrictive)
    pub const DEVELOPMENT: Self = Self {
        boot_timeout_ms: 1000,
        verify_signature: true,
        secure_boot: true,
        lock_debug: false,
        max_boot_attempts: 10,
    };
}

impl Default for BootConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Memory layout configuration for different platforms
#[derive(Debug, Clone, Copy)]
pub struct MemoryLayout {
    /// Flash base address
    pub flash_base: u32,
    /// Flash size in bytes
    pub flash_size: u32,
    /// RAM base address
    pub ram_base: u32,
    /// RAM size in bytes
    pub ram_size: u32,
    /// Secure RAM base address (0 if not available)
    pub secure_ram_base: u32,
    /// Secure RAM size in bytes
    pub secure_ram_size: u32,
    /// Bootloader region size
    pub bootloader_size: u32,
    /// Kernel region size (per slot for A/B)
    pub kernel_size: u32,
    /// Application region size (per slot for A/B)
    pub app_size: u32,
}

impl MemoryLayout {
    /// STM32H7 memory layout
    pub const STM32H7: Self = Self {
        flash_base: 0x0800_0000,
        flash_size: 2 * 1024 * 1024, // 2MB
        ram_base: 0x2000_0000,
        ram_size: 512 * 1024, // 512KB
        secure_ram_base: 0x3000_0000,
        secure_ram_size: 64 * 1024, // 64KB
        bootloader_size: 32 * 1024, // 32KB
        kernel_size: 256 * 1024, // 256KB
        app_size: 256 * 1024, // 256KB
    };

    /// STM32U5 memory layout
    pub const STM32U5: Self = Self {
        flash_base: 0x0800_0000,
        flash_size: 2 * 1024 * 1024, // 2MB
        ram_base: 0x2000_0000,
        ram_size: 786 * 1024, // 786KB
        secure_ram_base: 0x0C00_0000,
        secure_ram_size: 64 * 1024, // 64KB
        bootloader_size: 32 * 1024,
        kernel_size: 256 * 1024,
        app_size: 256 * 1024,
    };

    /// RISC-V (SiFive) memory layout
    pub const RISCV_SIFIVE: Self = Self {
        flash_base: 0x2000_0000,
        flash_size: 512 * 1024, // 512KB
        ram_base: 0x8000_0000,
        ram_size: 256 * 1024, // 256KB
        secure_ram_base: 0,
        secure_ram_size: 0,
        bootloader_size: 32 * 1024,
        kernel_size: 128 * 1024,
        app_size: 128 * 1024,
    };

    /// Get the bootloader start address
    #[must_use]
    pub const fn bootloader_start(&self) -> u32 {
        self.flash_base
    }

    /// Get the bootloader end address
    #[must_use]
    pub const fn bootloader_end(&self) -> u32 {
        self.flash_base + self.bootloader_size
    }

    /// Get kernel slot A start address
    #[must_use]
    pub const fn kernel_a_start(&self) -> u32 {
        self.bootloader_end()
    }

    /// Get kernel slot B start address
    #[must_use]
    pub const fn kernel_b_start(&self) -> u32 {
        self.kernel_a_start() + self.kernel_size
    }

    /// Get application slot A start address
    #[must_use]
    pub const fn app_a_start(&self) -> u32 {
        self.kernel_b_start() + self.kernel_size
    }

    /// Get application slot B start address
    #[must_use]
    pub const fn app_b_start(&self) -> u32 {
        self.app_a_start() + self.app_size
    }
}
