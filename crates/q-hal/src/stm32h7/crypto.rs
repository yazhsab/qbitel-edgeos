// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32H7 Hardware Crypto Accelerator Driver
//!
//! This module provides drivers for the STM32H7 cryptographic hardware:
//!
//! - **CRYP**: AES encryption/decryption with ECB, CBC, CTR, GCM modes
//! - **HASH**: SHA-1, SHA-224, SHA-256, MD5 hardware acceleration
//!
//! # Reference
//! STM32H7 Reference Manual RM0433, Sections:
//! - 27: Cryptographic processor (CRYP)
//! - 28: Hash processor (HASH)
//!
//! # Security
//!
//! - Keys are loaded directly into hardware and never stored in memory
//! - DMA is disabled to prevent memory exposure
//! - Processor is disabled when not in use

use super::registers::{read_reg, write_reg};
use crate::error::{HalError, HalResult};

// ============================================================================
// CRYP Peripheral Register Definitions (RM0433 Section 27.6)
// ============================================================================

/// CRYP base address (AHB2)
const CRYP_BASE: u32 = 0x4802_1000;

// CRYP Register offsets
const CRYP_CR: u32 = CRYP_BASE + 0x00;       // Control register
const CRYP_SR: u32 = CRYP_BASE + 0x04;       // Status register
const CRYP_DIN: u32 = CRYP_BASE + 0x08;      // Data input register
const CRYP_DOUT: u32 = CRYP_BASE + 0x0C;     // Data output register
const CRYP_DMACR: u32 = CRYP_BASE + 0x10;    // DMA control register
const CRYP_IMSCR: u32 = CRYP_BASE + 0x14;    // Interrupt mask set/clear register
#[allow(dead_code)]
const CRYP_RISR: u32 = CRYP_BASE + 0x18;     // Raw interrupt status register
#[allow(dead_code)]
const CRYP_MISR: u32 = CRYP_BASE + 0x1C;     // Masked interrupt status register
const CRYP_K0LR: u32 = CRYP_BASE + 0x20;     // Key register 0 left
const CRYP_K0RR: u32 = CRYP_BASE + 0x24;     // Key register 0 right
const CRYP_K1LR: u32 = CRYP_BASE + 0x28;     // Key register 1 left
const CRYP_K1RR: u32 = CRYP_BASE + 0x2C;     // Key register 1 right
const CRYP_K2LR: u32 = CRYP_BASE + 0x30;     // Key register 2 left
const CRYP_K2RR: u32 = CRYP_BASE + 0x34;     // Key register 2 right
const CRYP_K3LR: u32 = CRYP_BASE + 0x38;     // Key register 3 left
const CRYP_K3RR: u32 = CRYP_BASE + 0x3C;     // Key register 3 right
const CRYP_IV0LR: u32 = CRYP_BASE + 0x40;    // Initialization vector 0 left
const CRYP_IV0RR: u32 = CRYP_BASE + 0x44;    // Initialization vector 0 right
const CRYP_IV1LR: u32 = CRYP_BASE + 0x48;    // Initialization vector 1 left
const CRYP_IV1RR: u32 = CRYP_BASE + 0x4C;    // Initialization vector 1 right

// GCM-specific registers (context swap)
#[allow(dead_code)]
const CRYP_CSGCMCCM0R: u32 = CRYP_BASE + 0x50;  // GCM/CCM context swap 0
#[allow(dead_code)]
const CRYP_CSGCM0R: u32 = CRYP_BASE + 0x70;     // GCM context swap 0

// CRYP_CR bit definitions
const CR_ALGODIR: u32 = 1 << 2;          // Algorithm direction: 0=encrypt, 1=decrypt
#[allow(dead_code)]
const CR_ALGOMODE_MASK: u32 = 0x7 << 3;  // Algorithm mode bits [5:3]
const CR_ALGOMODE_AES_ECB: u32 = 0x2 << 3;
const CR_ALGOMODE_AES_CBC: u32 = 0x3 << 3;
const CR_ALGOMODE_AES_CTR: u32 = 0x4 << 3;
const CR_ALGOMODE_AES_KEY: u32 = 0x7 << 3;  // Key preparation for decryption
const CR_ALGOMODE_AES_GCM: u32 = 0x0 << 3;  // GCM mode (with GCM bit set)
#[allow(dead_code)]
const CR_DATATYPE_MASK: u32 = 0x3 << 6;  // Data type bits [7:6]
#[allow(dead_code)]
const CR_DATATYPE_32B: u32 = 0x0 << 6;   // 32-bit data, no swap
#[allow(dead_code)]
const CR_DATATYPE_16B: u32 = 0x1 << 6;   // 16-bit data, half-word swap
const CR_DATATYPE_8B: u32 = 0x2 << 6;    // 8-bit data, byte swap
#[allow(dead_code)]
const CR_DATATYPE_1B: u32 = 0x3 << 6;    // 1-bit data, bit swap
#[allow(dead_code)]
const CR_KEYSIZE_MASK: u32 = 0x3 << 8;   // Key size bits [9:8]
const CR_KEYSIZE_128: u32 = 0x0 << 8;
const CR_KEYSIZE_192: u32 = 0x1 << 8;
const CR_KEYSIZE_256: u32 = 0x2 << 8;
const CR_FFLUSH: u32 = 1 << 14;          // FIFO flush
const CR_CRYPEN: u32 = 1 << 15;          // Crypto processor enable
#[allow(dead_code)]
const CR_GCM_CCMPH_MASK: u32 = 0x3 << 16; // GCM/CCM phase bits [17:16]
const CR_GCM_CCMPH_INIT: u32 = 0x0 << 16;
const CR_GCM_CCMPH_HEADER: u32 = 0x1 << 16;
const CR_GCM_CCMPH_PAYLOAD: u32 = 0x2 << 16;
const CR_GCM_CCMPH_FINAL: u32 = 0x3 << 16;
const CR_ALGOMODE3: u32 = 1 << 19;       // Algorithm mode bit 3 (for GCM/CCM)

// CRYP_SR bit definitions
#[allow(dead_code)]
const SR_IFEM: u32 = 1 << 0;   // Input FIFO empty
const SR_IFNF: u32 = 1 << 1;   // Input FIFO not full
const SR_OFNE: u32 = 1 << 2;   // Output FIFO not empty
#[allow(dead_code)]
const SR_OFFU: u32 = 1 << 3;   // Output FIFO full
const SR_BUSY: u32 = 1 << 4;   // Busy flag

// ============================================================================
// HASH Peripheral Register Definitions (RM0433 Section 28.6)
// ============================================================================

/// HASH base address (AHB2)
const HASH_BASE: u32 = 0x4802_1400;

// HASH Register offsets
const HASH_CR: u32 = HASH_BASE + 0x00;       // Control register
const HASH_DIN: u32 = HASH_BASE + 0x04;      // Data input register
const HASH_STR: u32 = HASH_BASE + 0x08;      // Start register
const HASH_HR0: u32 = HASH_BASE + 0x0C;      // Hash register 0
const HASH_HR1: u32 = HASH_BASE + 0x10;      // Hash register 1
const HASH_HR2: u32 = HASH_BASE + 0x14;      // Hash register 2
const HASH_HR3: u32 = HASH_BASE + 0x18;      // Hash register 3
const HASH_HR4: u32 = HASH_BASE + 0x1C;      // Hash register 4
#[allow(dead_code)]
const HASH_IMR: u32 = HASH_BASE + 0x20;      // Interrupt enable register
const HASH_SR: u32 = HASH_BASE + 0x24;       // Status register
// Context swap registers for hash state save/restore
#[allow(dead_code)]
const HASH_CSR0: u32 = HASH_BASE + 0xF8;     // Context swap register 0
// Additional hash result registers for SHA-256
const HASH_HR5: u32 = HASH_BASE + 0x310;     // Hash register 5
const HASH_HR6: u32 = HASH_BASE + 0x314;     // Hash register 6
const HASH_HR7: u32 = HASH_BASE + 0x318;     // Hash register 7

// HASH_CR bit definitions
const HASH_CR_INIT: u32 = 1 << 2;           // Initialize message digest
#[allow(dead_code)]
const HASH_CR_DMAE: u32 = 1 << 3;           // DMA enable
#[allow(dead_code)]
const HASH_CR_DATATYPE_MASK: u32 = 0x3 << 4; // Data type bits [5:4]
#[allow(dead_code)]
const HASH_CR_DATATYPE_32B: u32 = 0x0 << 4;
#[allow(dead_code)]
const HASH_CR_DATATYPE_16B: u32 = 0x1 << 4;
const HASH_CR_DATATYPE_8B: u32 = 0x2 << 4;
#[allow(dead_code)]
const HASH_CR_DATATYPE_1B: u32 = 0x3 << 4;
const HASH_CR_MODE: u32 = 1 << 6;           // Mode: 0=hash, 1=HMAC
#[allow(dead_code)]
const HASH_CR_ALGO_MASK: u32 = 0x1 << 7 | 0x1 << 18; // Algorithm bits [7] and [18]
const HASH_CR_ALGO_SHA1: u32 = 0x0;
const HASH_CR_ALGO_MD5: u32 = 0x1 << 7;
const HASH_CR_ALGO_SHA224: u32 = 0x1 << 18;
const HASH_CR_ALGO_SHA256: u32 = 0x1 << 18 | 0x1 << 7;
#[allow(dead_code)]
const HASH_CR_NBW_MASK: u32 = 0xF << 8;      // Number of words already pushed
#[allow(dead_code)]
const HASH_CR_DINNE: u32 = 1 << 12;          // DIN not empty
#[allow(dead_code)]
const HASH_CR_MDMAT: u32 = 1 << 13;          // Multiple DMA transfers
const HASH_CR_LKEY: u32 = 1 << 16;           // Long key (>64 bytes)

// HASH_STR bit definitions
const HASH_STR_NBLW_MASK: u32 = 0x1F;        // Number of valid bits in last word
const HASH_STR_DCAL: u32 = 1 << 8;           // Digest calculation

// HASH_SR bit definitions
const HASH_SR_DINIS: u32 = 1 << 0;           // Data input interrupt status
const HASH_SR_DCIS: u32 = 1 << 1;            // Digest calculation interrupt status
#[allow(dead_code)]
const HASH_SR_DMAS: u32 = 1 << 2;            // DMA status
const HASH_SR_BUSY: u32 = 1 << 3;            // Busy

// ============================================================================
// RCC Enable for Crypto Peripherals
// ============================================================================

const RCC_BASE: u32 = 0x5802_4400;
const RCC_AHB2ENR: u32 = RCC_BASE + 0x0DC;   // AHB2 peripheral clock enable register
const RCC_AHB2ENR_CRYPEN: u32 = 1 << 4;      // CRYP enable bit
const RCC_AHB2ENR_HASHEN: u32 = 1 << 5;      // HASH enable bit

// ============================================================================
// Type Definitions
// ============================================================================

/// AES key size
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeySize {
    /// 128-bit key (16 bytes)
    Aes128,
    /// 192-bit key (24 bytes)
    Aes192,
    /// 256-bit key (32 bytes)
    Aes256,
}

impl AesKeySize {
    /// Get key size in bytes
    #[must_use]
    pub const fn bytes(&self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    /// Get register value for CR register
    #[allow(dead_code)]
    const fn to_cr_bits(&self) -> u32 {
        match self {
            Self::Aes128 => CR_KEYSIZE_128,
            Self::Aes192 => CR_KEYSIZE_192,
            Self::Aes256 => CR_KEYSIZE_256,
        }
    }
}

/// Cipher mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    /// Electronic Codebook mode
    Ecb,
    /// Cipher Block Chaining mode
    Cbc,
    /// Counter mode
    Ctr,
    /// Galois/Counter Mode (authenticated encryption)
    Gcm,
}

impl CipherMode {
    /// Get register value for CR register
    #[allow(dead_code)]
    const fn to_cr_bits(&self) -> u32 {
        match self {
            Self::Ecb => CR_ALGOMODE_AES_ECB,
            Self::Cbc => CR_ALGOMODE_AES_CBC,
            Self::Ctr => CR_ALGOMODE_AES_CTR,
            Self::Gcm => CR_ALGOMODE_AES_GCM | CR_ALGOMODE3,
        }
    }

    /// Check if mode requires IV
    #[must_use]
    pub const fn requires_iv(&self) -> bool {
        !matches!(self, Self::Ecb)
    }
}

/// Cipher direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherDirection {
    /// Encryption
    Encrypt,
    /// Decryption
    Decrypt,
}

/// Hash algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-1 (160 bits) - NOT RECOMMENDED for security
    Sha1,
    /// SHA-224 (224 bits)
    Sha224,
    /// SHA-256 (256 bits)
    Sha256,
    /// MD5 (128 bits) - NOT RECOMMENDED for security
    Md5,
}

impl HashAlgorithm {
    /// Get digest size in bytes
    #[must_use]
    pub const fn digest_size(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Md5 => 16,
        }
    }

    /// Get register value for CR register
    const fn to_cr_bits(&self) -> u32 {
        match self {
            Self::Sha1 => HASH_CR_ALGO_SHA1,
            Self::Md5 => HASH_CR_ALGO_MD5,
            Self::Sha224 => HASH_CR_ALGO_SHA224,
            Self::Sha256 => HASH_CR_ALGO_SHA256,
        }
    }
}

/// GCM context for authenticated encryption
#[derive(Debug)]
pub struct GcmContext {
    /// Initialization vector (96 bits)
    pub iv: [u8; 12],
    /// Additional authenticated data length in bits
    pub aad_len_bits: u64,
    /// Payload length in bits
    pub payload_len_bits: u64,
    /// Current phase
    phase: GcmPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GcmPhase {
    Init,
    Header,
    Payload,
    Final,
}

impl GcmContext {
    /// Create a new GCM context with IV
    #[must_use]
    pub fn new(iv: [u8; 12]) -> Self {
        Self {
            iv,
            aad_len_bits: 0,
            payload_len_bits: 0,
            phase: GcmPhase::Init,
        }
    }
}

// ============================================================================
// CRYP Hardware Accelerator Driver
// ============================================================================

/// STM32H7 CRYP (Cryptographic Processor) driver
pub struct Stm32h7Cryp {
    /// Initialization state
    initialized: bool,
    /// Current key size
    key_size: AesKeySize,
    /// Timeout in CPU cycles
    timeout_cycles: u32,
}

impl Stm32h7Cryp {
    /// Create a new uninitialized CRYP driver
    #[must_use]
    pub const fn new() -> Self {
        Self {
            initialized: false,
            key_size: AesKeySize::Aes256,
            timeout_cycles: 1_000_000, // ~2ms at 480MHz
        }
    }

    /// Initialize the CRYP peripheral
    pub fn init(&mut self) -> HalResult<()> {
        // Enable CRYP clock
        // SAFETY: RCC_AHB2ENR is an architecturally-defined STM32H7 register at 0x5802_44DC.
        // Volatile read-modify-write is required to enable the CRYP peripheral clock.
        unsafe {
            let enr = read_reg(RCC_AHB2ENR);
            write_reg(RCC_AHB2ENR, enr | RCC_AHB2ENR_CRYPEN);
        }

        // Small delay for clock stabilization
        for _ in 0..100 {
            core::hint::spin_loop();
        }

        // Disable CRYP and reset configuration
        // SAFETY: CRYP_CR, CRYP_DMACR, CRYP_IMSCR are architecturally-defined CRYP registers.
        // Volatile writes reset the peripheral to a known safe state.
        unsafe {
            write_reg(CRYP_CR, 0);
            write_reg(CRYP_DMACR, 0); // Disable DMA
            write_reg(CRYP_IMSCR, 0); // Disable interrupts
        }

        // Flush FIFOs
        self.flush_fifos();

        self.initialized = true;
        Ok(())
    }

    /// Check if CRYP is initialized
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Flush input and output FIFOs
    fn flush_fifos(&self) {
        // SAFETY: CRYP_CR is an architecturally-defined register. Volatile read-modify-write
        // sets the FFLUSH bit to flush the CRYP FIFOs.
        unsafe {
            let cr = read_reg(CRYP_CR);
            write_reg(CRYP_CR, cr | CR_FFLUSH);
        }
    }

    /// Wait for CRYP to become ready (not busy)
    fn wait_ready(&self) -> HalResult<()> {
        let mut timeout = self.timeout_cycles;

        while timeout > 0 {
            // SAFETY: CRYP_SR is an architecturally-defined read-only status register.
            // Volatile read required to poll hardware busy state.
            let sr = unsafe { read_reg(CRYP_SR) };
            if sr & SR_BUSY == 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }

        Err(HalError::Timeout)
    }

    /// Wait for input FIFO to have space
    fn wait_input_ready(&self) -> HalResult<()> {
        let mut timeout = self.timeout_cycles;

        while timeout > 0 {
            // SAFETY: CRYP_SR is an architecturally-defined read-only status register.
            // Volatile read required to poll input FIFO not-full flag.
            let sr = unsafe { read_reg(CRYP_SR) };
            if sr & SR_IFNF != 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }

        Err(HalError::Timeout)
    }

    /// Wait for output FIFO to have data
    fn wait_output_ready(&self) -> HalResult<()> {
        let mut timeout = self.timeout_cycles;

        while timeout > 0 {
            // SAFETY: CRYP_SR is an architecturally-defined read-only status register.
            // Volatile read required to poll output FIFO not-empty flag.
            let sr = unsafe { read_reg(CRYP_SR) };
            if sr & SR_OFNE != 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }

        Err(HalError::Timeout)
    }

    /// Load an AES key into the CRYP peripheral
    ///
    /// # Arguments
    /// * `key` - Key bytes (16, 24, or 32 bytes)
    pub fn load_key(&mut self, key: &[u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let key_size = match key.len() {
            16 => AesKeySize::Aes128,
            24 => AesKeySize::Aes192,
            32 => AesKeySize::Aes256,
            _ => return Err(HalError::InvalidParameter),
        };

        self.key_size = key_size;

        // Disable CRYP before loading key
        // SAFETY: CRYP_CR is an architecturally-defined register. Must disable CRYP
        // before modifying key registers per STM32H7 reference manual.
        unsafe {
            let cr = read_reg(CRYP_CR);
            write_reg(CRYP_CR, cr & !CR_CRYPEN);
        }

        self.wait_ready()?;

        // Load key registers (big-endian format)
        // For AES-256: K0LR, K0RR, K1LR, K1RR, K2LR, K2RR, K3LR, K3RR
        // For AES-192: K1LR, K1RR, K2LR, K2RR, K3LR, K3RR
        // For AES-128: K2LR, K2RR, K3LR, K3RR

        // SAFETY: CRYP key registers (K0LR..K3RR) are architecturally-defined MMIO registers.
        // Volatile writes load AES key material into hardware. Key length was validated above.
        unsafe {
            match key_size {
                AesKeySize::Aes256 => {
                    write_reg(CRYP_K0LR, u32::from_be_bytes([key[0], key[1], key[2], key[3]]));
                    write_reg(CRYP_K0RR, u32::from_be_bytes([key[4], key[5], key[6], key[7]]));
                    write_reg(CRYP_K1LR, u32::from_be_bytes([key[8], key[9], key[10], key[11]]));
                    write_reg(CRYP_K1RR, u32::from_be_bytes([key[12], key[13], key[14], key[15]]));
                    write_reg(CRYP_K2LR, u32::from_be_bytes([key[16], key[17], key[18], key[19]]));
                    write_reg(CRYP_K2RR, u32::from_be_bytes([key[20], key[21], key[22], key[23]]));
                    write_reg(CRYP_K3LR, u32::from_be_bytes([key[24], key[25], key[26], key[27]]));
                    write_reg(CRYP_K3RR, u32::from_be_bytes([key[28], key[29], key[30], key[31]]));
                }
                AesKeySize::Aes192 => {
                    write_reg(CRYP_K1LR, u32::from_be_bytes([key[0], key[1], key[2], key[3]]));
                    write_reg(CRYP_K1RR, u32::from_be_bytes([key[4], key[5], key[6], key[7]]));
                    write_reg(CRYP_K2LR, u32::from_be_bytes([key[8], key[9], key[10], key[11]]));
                    write_reg(CRYP_K2RR, u32::from_be_bytes([key[12], key[13], key[14], key[15]]));
                    write_reg(CRYP_K3LR, u32::from_be_bytes([key[16], key[17], key[18], key[19]]));
                    write_reg(CRYP_K3RR, u32::from_be_bytes([key[20], key[21], key[22], key[23]]));
                }
                AesKeySize::Aes128 => {
                    write_reg(CRYP_K2LR, u32::from_be_bytes([key[0], key[1], key[2], key[3]]));
                    write_reg(CRYP_K2RR, u32::from_be_bytes([key[4], key[5], key[6], key[7]]));
                    write_reg(CRYP_K3LR, u32::from_be_bytes([key[8], key[9], key[10], key[11]]));
                    write_reg(CRYP_K3RR, u32::from_be_bytes([key[12], key[13], key[14], key[15]]));
                }
            }
        }

        Ok(())
    }

    /// Load an initialization vector
    ///
    /// # Arguments
    /// * `iv` - 16-byte IV (for CBC, CTR) or 12-byte nonce + 4-byte counter (for GCM)
    fn load_iv(&self, iv: &[u8]) -> HalResult<()> {
        if iv.len() != 16 {
            return Err(HalError::InvalidParameter);
        }

        // SAFETY: CRYP IV registers (IV0LR..IV1RR) are architecturally-defined MMIO registers.
        // Volatile writes load the initialization vector. IV length validated above.
        unsafe {
            write_reg(CRYP_IV0LR, u32::from_be_bytes([iv[0], iv[1], iv[2], iv[3]]));
            write_reg(CRYP_IV0RR, u32::from_be_bytes([iv[4], iv[5], iv[6], iv[7]]));
            write_reg(CRYP_IV1LR, u32::from_be_bytes([iv[8], iv[9], iv[10], iv[11]]));
            write_reg(CRYP_IV1RR, u32::from_be_bytes([iv[12], iv[13], iv[14], iv[15]]));
        }

        Ok(())
    }

    /// Prepare key for AES decryption (CBC/ECB modes require key schedule)
    fn prepare_decrypt_key(&mut self) -> HalResult<()> {
        // SAFETY: CRYP_CR is an architecturally-defined register. Volatile writes configure
        // the CRYP for AES key preparation mode and enable the peripheral for key derivation.
        unsafe {
            // Configure for key preparation
            let cr = self.key_size.to_cr_bits() | CR_ALGOMODE_AES_KEY | CR_DATATYPE_8B;
            write_reg(CRYP_CR, cr);

            // Enable CRYP for key derivation
            write_reg(CRYP_CR, cr | CR_CRYPEN);
        }

        // Wait for key preparation to complete
        self.wait_ready()?;

        // SAFETY: CRYP_CR is an architecturally-defined register. Volatile read-modify-write
        // disables the CRYP peripheral after key preparation completes.
        unsafe {
            // Disable CRYP
            let cr = read_reg(CRYP_CR);
            write_reg(CRYP_CR, cr & !CR_CRYPEN);
        }

        Ok(())
    }

    /// Encrypt or decrypt data using AES-ECB mode
    ///
    /// # Arguments
    /// * `input` - Input data (must be multiple of 16 bytes)
    /// * `output` - Output buffer (same size as input)
    /// * `direction` - Encrypt or decrypt
    pub fn aes_ecb(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        direction: CipherDirection,
    ) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        if input.len() % 16 != 0 || output.len() < input.len() {
            return Err(HalError::InvalidParameter);
        }

        // Prepare decryption key if needed
        if matches!(direction, CipherDirection::Decrypt) {
            self.prepare_decrypt_key()?;
        }

        // Configure CRYP
        let mut cr = self.key_size.to_cr_bits() | CR_ALGOMODE_AES_ECB | CR_DATATYPE_8B;

        if matches!(direction, CipherDirection::Decrypt) {
            cr |= CR_ALGODIR;
        }

        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile write configures AES-ECB mode, key size, and data type.
        unsafe {
            write_reg(CRYP_CR, cr);
        }

        self.flush_fifos();

        // Enable CRYP
        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile write enables the crypto processor for ECB operation.
        unsafe {
            write_reg(CRYP_CR, cr | CR_CRYPEN);
        }

        // Process data in 16-byte blocks
        self.process_blocks(input, output)?;

        // Disable CRYP
        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile read-modify-write disables the crypto processor after operation.
        unsafe {
            let cr = read_reg(CRYP_CR);
            write_reg(CRYP_CR, cr & !CR_CRYPEN);
        }

        Ok(())
    }

    /// Encrypt or decrypt data using AES-CBC mode
    ///
    /// # Arguments
    /// * `input` - Input data (must be multiple of 16 bytes)
    /// * `output` - Output buffer (same size as input)
    /// * `iv` - 16-byte initialization vector
    /// * `direction` - Encrypt or decrypt
    pub fn aes_cbc(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        iv: &[u8; 16],
        direction: CipherDirection,
    ) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        if input.len() % 16 != 0 || output.len() < input.len() {
            return Err(HalError::InvalidParameter);
        }

        // Prepare decryption key if needed
        if matches!(direction, CipherDirection::Decrypt) {
            self.prepare_decrypt_key()?;
        }

        // Load IV
        self.load_iv(iv)?;

        // Configure CRYP
        let mut cr = self.key_size.to_cr_bits() | CR_ALGOMODE_AES_CBC | CR_DATATYPE_8B;

        if matches!(direction, CipherDirection::Decrypt) {
            cr |= CR_ALGODIR;
        }

        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile write configures AES-CBC mode, key size, and data type.
        unsafe {
            write_reg(CRYP_CR, cr);
        }

        self.flush_fifos();

        // Enable CRYP
        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile write enables the crypto processor for CBC operation.
        unsafe {
            write_reg(CRYP_CR, cr | CR_CRYPEN);
        }

        // Process data
        self.process_blocks(input, output)?;

        // Disable CRYP
        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile read-modify-write disables the crypto processor after operation.
        unsafe {
            let cr = read_reg(CRYP_CR);
            write_reg(CRYP_CR, cr & !CR_CRYPEN);
        }

        Ok(())
    }

    /// Encrypt or decrypt data using AES-CTR mode
    ///
    /// # Arguments
    /// * `input` - Input data (any length)
    /// * `output` - Output buffer (same size as input)
    /// * `nonce_counter` - 16-byte nonce + counter (counter in last 4 bytes, big-endian)
    pub fn aes_ctr(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        nonce_counter: &[u8; 16],
    ) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        if output.len() < input.len() {
            return Err(HalError::InvalidParameter);
        }

        // Load nonce/counter as IV
        self.load_iv(nonce_counter)?;

        // Configure CRYP (CTR mode is same for encrypt/decrypt)
        let cr = self.key_size.to_cr_bits() | CR_ALGOMODE_AES_CTR | CR_DATATYPE_8B;

        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile write configures AES-CTR mode, key size, and data type.
        unsafe {
            write_reg(CRYP_CR, cr);
        }

        self.flush_fifos();

        // Enable CRYP
        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile write enables the crypto processor for CTR operation.
        unsafe {
            write_reg(CRYP_CR, cr | CR_CRYPEN);
        }

        // Process complete 16-byte blocks
        let full_blocks = input.len() / 16;
        let remaining = input.len() % 16;

        if full_blocks > 0 {
            let block_len = full_blocks * 16;
            self.process_blocks(&input[..block_len], &mut output[..block_len])?;
        }

        // Handle remaining bytes (partial block)
        if remaining > 0 {
            let offset = full_blocks * 16;
            let mut last_block = [0u8; 16];
            let mut out_block = [0u8; 16];

            last_block[..remaining].copy_from_slice(&input[offset..]);
            self.process_blocks(&last_block, &mut out_block)?;
            output[offset..offset + remaining].copy_from_slice(&out_block[..remaining]);
        }

        // Disable CRYP
        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile read-modify-write disables the crypto processor after CTR operation.
        unsafe {
            let cr = read_reg(CRYP_CR);
            write_reg(CRYP_CR, cr & !CR_CRYPEN);
        }

        Ok(())
    }

    /// Initialize AES-GCM operation
    ///
    /// # Arguments
    /// * `nonce` - 12-byte nonce
    /// * `direction` - Encrypt or decrypt
    pub fn aes_gcm_init(
        &mut self,
        nonce: &[u8; 12],
        direction: CipherDirection,
    ) -> HalResult<GcmContext> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        // Create IV from nonce (12 bytes) + counter (4 bytes starting at 1)
        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(nonce);
        iv[15] = 1; // Initial counter value

        self.load_iv(&iv)?;

        // Configure for GCM init phase
        let mut cr = self.key_size.to_cr_bits()
            | CR_ALGOMODE_AES_GCM
            | CR_ALGOMODE3
            | CR_DATATYPE_8B
            | CR_GCM_CCMPH_INIT;

        if matches!(direction, CipherDirection::Decrypt) {
            cr |= CR_ALGODIR;
        }

        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile write configures GCM init phase with key size and data type.
        unsafe {
            write_reg(CRYP_CR, cr);
        }

        self.flush_fifos();

        // Enable CRYP for init phase
        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile write enables the crypto processor for GCM initialization.
        unsafe {
            write_reg(CRYP_CR, cr | CR_CRYPEN);
        }

        self.wait_ready()?;

        let mut ctx = GcmContext::new(*nonce);
        ctx.phase = GcmPhase::Init;

        Ok(ctx)
    }

    /// Process additional authenticated data (AAD) for AES-GCM
    ///
    /// # Arguments
    /// * `ctx` - GCM context
    /// * `aad` - Additional authenticated data
    /// * `direction` - Encrypt or decrypt
    pub fn aes_gcm_update_aad(
        &mut self,
        ctx: &mut GcmContext,
        aad: &[u8],
        direction: CipherDirection,
    ) -> HalResult<()> {
        if ctx.phase != GcmPhase::Init && ctx.phase != GcmPhase::Header {
            return Err(HalError::InvalidState);
        }

        if aad.is_empty() {
            ctx.phase = GcmPhase::Header;
            return Ok(());
        }

        // Switch to header phase
        let mut cr = self.key_size.to_cr_bits()
            | CR_ALGOMODE_AES_GCM
            | CR_ALGOMODE3
            | CR_DATATYPE_8B
            | CR_GCM_CCMPH_HEADER;

        if matches!(direction, CipherDirection::Decrypt) {
            cr |= CR_ALGODIR;
        }

        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile write switches to GCM header phase and enables processing.
        unsafe {
            write_reg(CRYP_CR, cr | CR_CRYPEN);
        }

        // Feed AAD (must be 16-byte aligned, pad with zeros if needed)
        let full_blocks = aad.len() / 16;
        let remaining = aad.len() % 16;

        // Process full blocks
        for i in 0..full_blocks {
            let block = &aad[i * 16..(i + 1) * 16];
            self.write_block(block)?;

            // Wait for processing (no output in header phase)
            self.wait_ready()?;
        }

        // Process final partial block with padding
        if remaining > 0 {
            let mut last_block = [0u8; 16];
            last_block[..remaining].copy_from_slice(&aad[full_blocks * 16..]);
            self.write_block(&last_block)?;
            self.wait_ready()?;
        }

        ctx.aad_len_bits = (aad.len() as u64) * 8;
        ctx.phase = GcmPhase::Header;

        Ok(())
    }

    /// Process payload data for AES-GCM
    ///
    /// # Arguments
    /// * `ctx` - GCM context
    /// * `input` - Input plaintext (encrypt) or ciphertext (decrypt)
    /// * `output` - Output ciphertext (encrypt) or plaintext (decrypt)
    /// * `direction` - Encrypt or decrypt
    pub fn aes_gcm_update(
        &mut self,
        ctx: &mut GcmContext,
        input: &[u8],
        output: &mut [u8],
        direction: CipherDirection,
    ) -> HalResult<()> {
        if ctx.phase != GcmPhase::Header && ctx.phase != GcmPhase::Payload {
            return Err(HalError::InvalidState);
        }

        if output.len() < input.len() {
            return Err(HalError::InvalidParameter);
        }

        if input.is_empty() {
            ctx.phase = GcmPhase::Payload;
            return Ok(());
        }

        // Switch to payload phase
        let mut cr = self.key_size.to_cr_bits()
            | CR_ALGOMODE_AES_GCM
            | CR_ALGOMODE3
            | CR_DATATYPE_8B
            | CR_GCM_CCMPH_PAYLOAD;

        if matches!(direction, CipherDirection::Decrypt) {
            cr |= CR_ALGODIR;
        }

        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile write switches to GCM payload phase and enables processing.
        unsafe {
            write_reg(CRYP_CR, cr | CR_CRYPEN);
        }

        // Process full blocks
        let full_blocks = input.len() / 16;
        let remaining = input.len() % 16;

        for i in 0..full_blocks {
            let in_block = &input[i * 16..(i + 1) * 16];
            self.write_block(in_block)?;
            self.read_block(&mut output[i * 16..(i + 1) * 16])?;
        }

        // Process final partial block
        if remaining > 0 {
            let offset = full_blocks * 16;
            let mut last_in = [0u8; 16];
            let mut last_out = [0u8; 16];

            last_in[..remaining].copy_from_slice(&input[offset..]);
            self.write_block(&last_in)?;
            self.read_block(&mut last_out)?;
            output[offset..offset + remaining].copy_from_slice(&last_out[..remaining]);
        }

        ctx.payload_len_bits = (input.len() as u64) * 8;
        ctx.phase = GcmPhase::Payload;

        Ok(())
    }

    /// Finalize AES-GCM and compute authentication tag
    ///
    /// # Arguments
    /// * `ctx` - GCM context
    /// * `tag` - Output buffer for 16-byte authentication tag
    /// * `direction` - Encrypt or decrypt
    pub fn aes_gcm_finalize(
        &mut self,
        ctx: &mut GcmContext,
        tag: &mut [u8; 16],
        direction: CipherDirection,
    ) -> HalResult<()> {
        if ctx.phase != GcmPhase::Header && ctx.phase != GcmPhase::Payload {
            return Err(HalError::InvalidState);
        }

        // Switch to final phase
        let mut cr = self.key_size.to_cr_bits()
            | CR_ALGOMODE_AES_GCM
            | CR_ALGOMODE3
            | CR_DATATYPE_8B
            | CR_GCM_CCMPH_FINAL;

        if matches!(direction, CipherDirection::Decrypt) {
            cr |= CR_ALGODIR;
        }

        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile write switches to GCM final phase for tag computation.
        unsafe {
            write_reg(CRYP_CR, cr | CR_CRYPEN);
        }

        // Write length block: [AAD length in bits (64-bit BE)] [Payload length in bits (64-bit BE)]
        let aad_bits = ctx.aad_len_bits;
        let payload_bits = ctx.payload_len_bits;

        let len_block: [u8; 16] = [
            (aad_bits >> 56) as u8,
            (aad_bits >> 48) as u8,
            (aad_bits >> 40) as u8,
            (aad_bits >> 32) as u8,
            (aad_bits >> 24) as u8,
            (aad_bits >> 16) as u8,
            (aad_bits >> 8) as u8,
            aad_bits as u8,
            (payload_bits >> 56) as u8,
            (payload_bits >> 48) as u8,
            (payload_bits >> 40) as u8,
            (payload_bits >> 32) as u8,
            (payload_bits >> 24) as u8,
            (payload_bits >> 16) as u8,
            (payload_bits >> 8) as u8,
            payload_bits as u8,
        ];

        self.write_block(&len_block)?;
        self.read_block(tag)?;

        // Disable CRYP
        // SAFETY: CRYP_CR is an architecturally-defined register.
        // Volatile read-modify-write disables the crypto processor after GCM finalization.
        unsafe {
            let cr = read_reg(CRYP_CR);
            write_reg(CRYP_CR, cr & !CR_CRYPEN);
        }

        ctx.phase = GcmPhase::Final;

        Ok(())
    }

    /// Write a 16-byte block to CRYP input FIFO
    fn write_block(&self, block: &[u8]) -> HalResult<()> {
        if block.len() != 16 {
            return Err(HalError::InvalidParameter);
        }

        // Write 4 words (16 bytes) to input FIFO
        for i in 0..4 {
            self.wait_input_ready()?;
            let word = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
            // SAFETY: CRYP_DIN is an architecturally-defined data input register.
            // Volatile write feeds one 32-bit word into the CRYP input FIFO.
            unsafe {
                write_reg(CRYP_DIN, word);
            }
        }

        Ok(())
    }

    /// Read a 16-byte block from CRYP output FIFO
    fn read_block(&self, block: &mut [u8]) -> HalResult<()> {
        if block.len() != 16 {
            return Err(HalError::InvalidParameter);
        }

        // Read 4 words (16 bytes) from output FIFO
        for i in 0..4 {
            self.wait_output_ready()?;
            // SAFETY: CRYP_DOUT is an architecturally-defined data output register.
            // Volatile read retrieves one 32-bit word from the CRYP output FIFO.
            let word = unsafe { read_reg(CRYP_DOUT) };
            let bytes = word.to_be_bytes();
            block[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }

        Ok(())
    }

    /// Process multiple 16-byte blocks
    fn process_blocks(&self, input: &[u8], output: &mut [u8]) -> HalResult<()> {
        let blocks = input.len() / 16;

        for i in 0..blocks {
            let in_block = &input[i * 16..(i + 1) * 16];
            let out_block = &mut output[i * 16..(i + 1) * 16];

            self.write_block(in_block)?;
            self.read_block(out_block)?;
        }

        Ok(())
    }

    /// Disable and reset the CRYP peripheral
    pub fn deinit(&mut self) {
        // SAFETY: All registers below are architecturally-defined CRYP and RCC MMIO registers.
        // Volatile writes disable the peripheral, zeroize key/IV registers to prevent
        // key leakage, and disable the CRYP clock to save power.
        unsafe {
            // Disable CRYP
            write_reg(CRYP_CR, 0);

            // Clear all key registers (security: don't leave keys in hardware)
            write_reg(CRYP_K0LR, 0);
            write_reg(CRYP_K0RR, 0);
            write_reg(CRYP_K1LR, 0);
            write_reg(CRYP_K1RR, 0);
            write_reg(CRYP_K2LR, 0);
            write_reg(CRYP_K2RR, 0);
            write_reg(CRYP_K3LR, 0);
            write_reg(CRYP_K3RR, 0);

            // Clear IV registers
            write_reg(CRYP_IV0LR, 0);
            write_reg(CRYP_IV0RR, 0);
            write_reg(CRYP_IV1LR, 0);
            write_reg(CRYP_IV1RR, 0);

            // Disable clock (optional - saves power)
            let enr = read_reg(RCC_AHB2ENR);
            write_reg(RCC_AHB2ENR, enr & !RCC_AHB2ENR_CRYPEN);
        }

        self.initialized = false;
    }
}

impl Default for Stm32h7Cryp {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// HASH Hardware Accelerator Driver
// ============================================================================

/// STM32H7 HASH (Hash Processor) driver
pub struct Stm32h7Hash {
    /// Initialization state
    initialized: bool,
    /// Current algorithm
    algorithm: HashAlgorithm,
    /// Bytes processed (for final padding)
    bytes_processed: usize,
    /// Timeout in CPU cycles
    timeout_cycles: u32,
}

impl Stm32h7Hash {
    /// Create a new uninitialized HASH driver
    #[must_use]
    pub const fn new() -> Self {
        Self {
            initialized: false,
            algorithm: HashAlgorithm::Sha256,
            bytes_processed: 0,
            timeout_cycles: 1_000_000,
        }
    }

    /// Initialize the HASH peripheral
    pub fn init(&mut self) -> HalResult<()> {
        // Enable HASH clock
        // SAFETY: RCC_AHB2ENR is an architecturally-defined STM32H7 register.
        // Volatile read-modify-write enables the HASH peripheral clock.
        unsafe {
            let enr = read_reg(RCC_AHB2ENR);
            write_reg(RCC_AHB2ENR, enr | RCC_AHB2ENR_HASHEN);
        }

        // Small delay for clock stabilization
        for _ in 0..100 {
            core::hint::spin_loop();
        }

        self.initialized = true;
        Ok(())
    }

    /// Check if HASH is initialized
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Wait for HASH to complete
    fn wait_ready(&self) -> HalResult<()> {
        let mut timeout = self.timeout_cycles;

        while timeout > 0 {
            // SAFETY: HASH_SR is an architecturally-defined read-only status register.
            // Volatile read required to poll hash processor busy state.
            let sr = unsafe { read_reg(HASH_SR) };
            if sr & HASH_SR_BUSY == 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }

        Err(HalError::Timeout)
    }

    /// Wait for digest calculation to complete
    fn wait_digest_ready(&self) -> HalResult<()> {
        let mut timeout = self.timeout_cycles;

        while timeout > 0 {
            // SAFETY: HASH_SR is an architecturally-defined read-only status register.
            // Volatile read required to poll digest calculation completion flag.
            let sr = unsafe { read_reg(HASH_SR) };
            if sr & HASH_SR_DCIS != 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }

        Err(HalError::Timeout)
    }

    /// Start a new hash operation
    ///
    /// # Arguments
    /// * `algorithm` - Hash algorithm to use
    pub fn start(&mut self, algorithm: HashAlgorithm) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        self.algorithm = algorithm;
        self.bytes_processed = 0;

        // Configure HASH
        let cr = algorithm.to_cr_bits() | HASH_CR_DATATYPE_8B | HASH_CR_INIT;

        // SAFETY: HASH_CR is an architecturally-defined register. Volatile write
        // configures the hash algorithm, data type, and initializes the hash processor.
        unsafe {
            write_reg(HASH_CR, cr);
        }

        Ok(())
    }

    /// Update hash with data
    ///
    /// # Arguments
    /// * `data` - Data to hash
    pub fn update(&mut self, data: &[u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        // Process full 32-bit words
        let mut offset = 0;

        while offset + 4 <= data.len() {
            let word = u32::from_ne_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);

            // SAFETY: HASH_DIN is an architecturally-defined data input register.
            // Volatile write feeds one 32-bit word into the hash processor.
            unsafe {
                write_reg(HASH_DIN, word);
            }

            offset += 4;
        }

        // Handle remaining bytes (will be processed in finalize)
        // For simplicity, we process remaining bytes here with proper handling
        if offset < data.len() {
            let remaining = data.len() - offset;
            let mut last_word = [0u8; 4];
            last_word[..remaining].copy_from_slice(&data[offset..]);

            let word = u32::from_ne_bytes(last_word);
            // SAFETY: HASH_DIN is an architecturally-defined data input register.
            // Volatile write feeds the final partial word (zero-padded) into the hash processor.
            unsafe {
                write_reg(HASH_DIN, word);
            }
        }

        self.bytes_processed += data.len();

        Ok(())
    }

    /// Finalize hash and get digest
    ///
    /// # Arguments
    /// * `digest` - Output buffer for digest (size depends on algorithm)
    pub fn finalize(&mut self, digest: &mut [u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let expected_size = self.algorithm.digest_size();
        if digest.len() < expected_size {
            return Err(HalError::InvalidParameter);
        }

        // Calculate number of valid bits in last word
        let nblw = ((self.bytes_processed % 4) * 8) as u32;

        // Start digest calculation
        // SAFETY: HASH_STR is an architecturally-defined register. Volatile write sets
        // the number of valid bits in the last word and triggers digest calculation.
        unsafe {
            write_reg(HASH_STR, (nblw & HASH_STR_NBLW_MASK) | HASH_STR_DCAL);
        }

        // Wait for digest to be ready
        self.wait_digest_ready()?;

        // Read digest from hash registers
        self.read_digest(digest)?;

        Ok(())
    }

    /// Read digest from hash registers
    fn read_digest(&self, digest: &mut [u8]) -> HalResult<()> {
        let words_needed = (self.algorithm.digest_size() + 3) / 4;

        for i in 0..words_needed {
            let hr_addr = match i {
                0 => HASH_HR0,
                1 => HASH_HR1,
                2 => HASH_HR2,
                3 => HASH_HR3,
                4 => HASH_HR4,
                5 => HASH_HR5,
                6 => HASH_HR6,
                7 => HASH_HR7,
                _ => return Err(HalError::InvalidParameter),
            };

            // SAFETY: HASH_HRx registers are architecturally-defined read-only digest output registers.
            // Volatile read retrieves the computed hash word. hr_addr is validated by the match above.
            let word = unsafe { read_reg(hr_addr) };
            let bytes = word.to_be_bytes();

            let offset = i * 4;
            let remaining = digest.len() - offset;
            let copy_len = remaining.min(4);

            digest[offset..offset + copy_len].copy_from_slice(&bytes[..copy_len]);
        }

        Ok(())
    }

    /// Compute hash of data in one shot
    ///
    /// # Arguments
    /// * `algorithm` - Hash algorithm
    /// * `data` - Data to hash
    /// * `digest` - Output buffer for digest
    pub fn hash(
        &mut self,
        algorithm: HashAlgorithm,
        data: &[u8],
        digest: &mut [u8],
    ) -> HalResult<()> {
        self.start(algorithm)?;
        self.update(data)?;
        self.finalize(digest)
    }

    /// Compute HMAC
    ///
    /// # Arguments
    /// * `algorithm` - Hash algorithm
    /// * `key` - HMAC key
    /// * `data` - Data to authenticate
    /// * `mac` - Output buffer for MAC
    pub fn hmac(
        &mut self,
        algorithm: HashAlgorithm,
        key: &[u8],
        data: &[u8],
        mac: &mut [u8],
    ) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let expected_size = algorithm.digest_size();
        if mac.len() < expected_size {
            return Err(HalError::InvalidParameter);
        }

        self.algorithm = algorithm;
        self.bytes_processed = 0;

        // Determine if long key handling is needed (key > 64 bytes)
        let long_key = key.len() > 64;

        // Configure HASH for HMAC mode
        let mut cr = algorithm.to_cr_bits() | HASH_CR_DATATYPE_8B | HASH_CR_MODE | HASH_CR_INIT;

        if long_key {
            cr |= HASH_CR_LKEY;
        }

        // SAFETY: HASH_CR is an architecturally-defined register. Volatile write configures
        // the hash processor for HMAC mode with the selected algorithm and key length.
        unsafe {
            write_reg(HASH_CR, cr);
        }

        // Feed key (first HMAC phase)
        self.feed_data(key)?;

        // Indicate key is complete by starting digest (internally)
        let nblw = ((key.len() % 4) * 8) as u32;
        // SAFETY: HASH_STR is an architecturally-defined register. Volatile write sets
        // valid bits in last word and triggers internal digest for HMAC key phase.
        unsafe {
            write_reg(HASH_STR, nblw & HASH_STR_NBLW_MASK | HASH_STR_DCAL);
        }

        self.wait_ready()?;

        // Feed data (second HMAC phase)
        self.feed_data(data)?;

        // Indicate data is complete
        let nblw = ((data.len() % 4) * 8) as u32;
        // SAFETY: HASH_STR is an architecturally-defined register. Volatile write sets
        // valid bits in last word and triggers internal digest for HMAC data phase.
        unsafe {
            write_reg(HASH_STR, nblw & HASH_STR_NBLW_MASK | HASH_STR_DCAL);
        }

        self.wait_ready()?;

        // Feed key again (third HMAC phase)
        self.feed_data(key)?;

        // Final digest calculation
        let nblw = ((key.len() % 4) * 8) as u32;
        // SAFETY: HASH_STR is an architecturally-defined register. Volatile write triggers
        // the final HMAC digest calculation after the second key feed.
        unsafe {
            write_reg(HASH_STR, nblw & HASH_STR_NBLW_MASK | HASH_STR_DCAL);
        }

        self.wait_digest_ready()?;

        // Read MAC
        self.read_digest(mac)
    }

    /// Feed data to hash processor
    fn feed_data(&self, data: &[u8]) -> HalResult<()> {
        let mut offset = 0;

        // Process full 32-bit words
        while offset + 4 <= data.len() {
            let word = u32::from_ne_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);

            // Wait for input ready
            self.wait_input_ready()?;

            // SAFETY: HASH_DIN is an architecturally-defined data input register.
            // Volatile write feeds one 32-bit word into the hash processor.
            unsafe {
                write_reg(HASH_DIN, word);
            }

            offset += 4;
        }

        // Handle remaining bytes
        if offset < data.len() {
            let remaining = data.len() - offset;
            let mut last_word = [0u8; 4];
            last_word[..remaining].copy_from_slice(&data[offset..]);

            let word = u32::from_ne_bytes(last_word);

            self.wait_input_ready()?;

            // SAFETY: HASH_DIN is an architecturally-defined data input register.
            // Volatile write feeds the final partial word (zero-padded) into the hash processor.
            unsafe {
                write_reg(HASH_DIN, word);
            }
        }

        Ok(())
    }

    /// Wait for input ready
    fn wait_input_ready(&self) -> HalResult<()> {
        let mut timeout = self.timeout_cycles;

        while timeout > 0 {
            // SAFETY: HASH_SR is an architecturally-defined read-only status register.
            // Volatile read required to poll the data input ready flag.
            let sr = unsafe { read_reg(HASH_SR) };
            if sr & HASH_SR_DINIS != 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }

        Err(HalError::Timeout)
    }

    /// Disable and reset the HASH peripheral
    pub fn deinit(&mut self) {
        // SAFETY: HASH_CR and RCC_AHB2ENR are architecturally-defined MMIO registers.
        // Volatile writes reset the hash processor and disable its clock.
        unsafe {
            // Reset HASH
            write_reg(HASH_CR, 0);

            // Disable clock
            let enr = read_reg(RCC_AHB2ENR);
            write_reg(RCC_AHB2ENR, enr & !RCC_AHB2ENR_HASHEN);
        }

        self.initialized = false;
    }
}

impl Default for Stm32h7Hash {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Combined Crypto Accelerator
// ============================================================================

/// Combined STM32H7 crypto accelerator (CRYP + HASH)
pub struct Stm32h7CryptoAccel {
    /// CRYP driver
    pub cryp: Stm32h7Cryp,
    /// HASH driver
    pub hash: Stm32h7Hash,
    /// Initialization state
    initialized: bool,
}

impl Stm32h7CryptoAccel {
    /// Create a new uninitialized crypto accelerator
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cryp: Stm32h7Cryp::new(),
            hash: Stm32h7Hash::new(),
            initialized: false,
        }
    }

    /// Initialize both CRYP and HASH peripherals
    pub fn init(&mut self) -> HalResult<()> {
        self.cryp.init()?;
        self.hash.init()?;
        self.initialized = true;
        Ok(())
    }

    /// Check if crypto accelerator is initialized
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Deinitialize both peripherals
    pub fn deinit(&mut self) {
        self.cryp.deinit();
        self.hash.deinit();
        self.initialized = false;
    }
}

impl Default for Stm32h7CryptoAccel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Crypto Accelerator Trait Implementation
// ============================================================================

/// Hardware crypto accelerator interface
pub trait CryptoAcceleratorInterface {
    /// Check if hardware acceleration is available
    fn is_available(&self) -> bool;

    /// Encrypt data using AES-256-GCM
    fn aes_256_gcm_encrypt(
        &mut self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> HalResult<()>;

    /// Decrypt data using AES-256-GCM
    fn aes_256_gcm_decrypt(
        &mut self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 16],
    ) -> HalResult<bool>;

    /// Compute SHA-256 hash
    fn sha256(&mut self, data: &[u8], hash: &mut [u8; 32]) -> HalResult<()>;
}

impl CryptoAcceleratorInterface for Stm32h7CryptoAccel {
    fn is_available(&self) -> bool {
        self.initialized
    }

    fn aes_256_gcm_encrypt(
        &mut self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> HalResult<()> {
        if ciphertext.len() < plaintext.len() {
            return Err(HalError::InvalidParameter);
        }

        self.cryp.load_key(key)?;

        let mut ctx = self.cryp.aes_gcm_init(nonce, CipherDirection::Encrypt)?;
        self.cryp.aes_gcm_update_aad(&mut ctx, aad, CipherDirection::Encrypt)?;
        self.cryp.aes_gcm_update(&mut ctx, plaintext, ciphertext, CipherDirection::Encrypt)?;
        self.cryp.aes_gcm_finalize(&mut ctx, tag, CipherDirection::Encrypt)?;

        Ok(())
    }

    fn aes_256_gcm_decrypt(
        &mut self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 16],
    ) -> HalResult<bool> {
        if plaintext.len() < ciphertext.len() {
            return Err(HalError::InvalidParameter);
        }

        self.cryp.load_key(key)?;

        let mut ctx = self.cryp.aes_gcm_init(nonce, CipherDirection::Decrypt)?;
        self.cryp.aes_gcm_update_aad(&mut ctx, aad, CipherDirection::Decrypt)?;
        self.cryp.aes_gcm_update(&mut ctx, ciphertext, plaintext, CipherDirection::Decrypt)?;

        let mut computed_tag = [0u8; 16];
        self.cryp.aes_gcm_finalize(&mut ctx, &mut computed_tag, CipherDirection::Decrypt)?;

        // Constant-time tag comparison
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= computed_tag[i] ^ tag[i];
        }

        Ok(diff == 0)
    }

    fn sha256(&mut self, data: &[u8], hash: &mut [u8; 32]) -> HalResult<()> {
        self.hash.hash(HashAlgorithm::Sha256, data, hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_size_bytes() {
        assert_eq!(AesKeySize::Aes128.bytes(), 16);
        assert_eq!(AesKeySize::Aes192.bytes(), 24);
        assert_eq!(AesKeySize::Aes256.bytes(), 32);
    }

    #[test]
    fn test_hash_digest_size() {
        assert_eq!(HashAlgorithm::Md5.digest_size(), 16);
        assert_eq!(HashAlgorithm::Sha1.digest_size(), 20);
        assert_eq!(HashAlgorithm::Sha224.digest_size(), 28);
        assert_eq!(HashAlgorithm::Sha256.digest_size(), 32);
    }

    #[test]
    fn test_cipher_mode_requires_iv() {
        assert!(!CipherMode::Ecb.requires_iv());
        assert!(CipherMode::Cbc.requires_iv());
        assert!(CipherMode::Ctr.requires_iv());
        assert!(CipherMode::Gcm.requires_iv());
    }
}
