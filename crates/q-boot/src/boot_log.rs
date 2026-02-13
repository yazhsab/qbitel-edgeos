// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Persistent Boot Failure Logging
//!
//! This module provides persistent logging of boot failures that survives
//! across reboots. It stores detailed diagnostic information in backup RAM
//! or a dedicated flash region to help diagnose boot issues.
//!
//! # Storage Layout (Backup SRAM)
//!
//! The boot log uses a dedicated region of backup SRAM:
//!
//! ```text
//! Offset  Size    Description
//! 0x100   4       Magic number (0x424F_4F54 "BOOT")
//! 0x104   4       Log version
//! 0x108   4       Total entries written
//! 0x10C   4       Current write index (circular buffer)
//! 0x110   4       CRC32 of header
//! 0x114   N*64    Log entries (N entries, 64 bytes each)
//! ```
//!
//! # Entry Format
//!
//! Each log entry contains:
//! - Timestamp (if RTC available)
//! - Boot stage where failure occurred
//! - Error code
//! - Register dump (PC, LR, SP)
//! - Additional context

use core::ptr;
use q_common::Error;

// ============================================================================
// Constants
// ============================================================================

/// Boot log magic number
const BOOT_LOG_MAGIC: u32 = 0x424F_4F54; // "BOOT"

/// Log version
const BOOT_LOG_VERSION: u32 = 1;

/// Maximum number of log entries (circular buffer)
pub const MAX_LOG_ENTRIES: usize = 16;

/// Size of each log entry in bytes
pub const LOG_ENTRY_SIZE: usize = 64;

/// Backup SRAM base address
const BKPSRAM_BASE: u32 = 0x3800_0000;

/// Boot log region offset in backup SRAM
const BOOT_LOG_OFFSET: u32 = 0x100;

/// Boot log base address
const BOOT_LOG_BASE: u32 = BKPSRAM_BASE + BOOT_LOG_OFFSET;

/// Header offsets
const HEADER_MAGIC: u32 = BOOT_LOG_BASE;
const HEADER_VERSION: u32 = BOOT_LOG_BASE + 4;
const HEADER_TOTAL_ENTRIES: u32 = BOOT_LOG_BASE + 8;
const HEADER_WRITE_INDEX: u32 = BOOT_LOG_BASE + 12;
const HEADER_CRC: u32 = BOOT_LOG_BASE + 16;
const ENTRIES_BASE: u32 = BOOT_LOG_BASE + 32;

// ============================================================================
// Boot Stage
// ============================================================================

/// Boot stage where failure occurred
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootStage {
    /// Early initialization (before peripherals)
    EarlyInit = 0,
    /// Clock initialization
    ClockInit = 1,
    /// Memory initialization (MPU, caches)
    MemoryInit = 2,
    /// Security initialization (TrustZone, SAU)
    SecurityInit = 3,
    /// Peripheral initialization
    PeripheralInit = 4,
    /// RNG/PUF initialization
    CryptoInit = 5,
    /// Bootloader verification
    BootloaderVerify = 6,
    /// Kernel slot selection
    SlotSelection = 7,
    /// Kernel verification
    KernelVerify = 8,
    /// Kernel loading
    KernelLoad = 9,
    /// Kernel jump
    KernelJump = 10,
    /// Watchdog timeout
    WatchdogTimeout = 11,
    /// Unknown stage
    Unknown = 255,
}

impl From<u8> for BootStage {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::EarlyInit,
            1 => Self::ClockInit,
            2 => Self::MemoryInit,
            3 => Self::SecurityInit,
            4 => Self::PeripheralInit,
            5 => Self::CryptoInit,
            6 => Self::BootloaderVerify,
            7 => Self::SlotSelection,
            8 => Self::KernelVerify,
            9 => Self::KernelLoad,
            10 => Self::KernelJump,
            11 => Self::WatchdogTimeout,
            _ => Self::Unknown,
        }
    }
}

// ============================================================================
// Error Category
// ============================================================================

/// Boot error category
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCategory {
    /// No error
    None = 0,
    /// Hardware initialization failure
    HardwareInit = 1,
    /// Memory/flash error
    Memory = 2,
    /// Cryptographic error (RNG, hash, signature)
    Crypto = 3,
    /// Verification/signature failure
    Verification = 4,
    /// Rollback protection triggered
    Rollback = 5,
    /// Configuration error
    Config = 6,
    /// Timeout
    Timeout = 7,
    /// Security violation
    Security = 8,
    /// Corruption detected
    Corruption = 9,
    /// Unknown error
    Unknown = 255,
}

impl From<u8> for ErrorCategory {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::None,
            1 => Self::HardwareInit,
            2 => Self::Memory,
            3 => Self::Crypto,
            4 => Self::Verification,
            5 => Self::Rollback,
            6 => Self::Config,
            7 => Self::Timeout,
            8 => Self::Security,
            9 => Self::Corruption,
            _ => Self::Unknown,
        }
    }
}

// ============================================================================
// Boot Log Entry
// ============================================================================

/// A single boot log entry (64 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BootLogEntry {
    /// Entry magic (for validation)
    pub magic: u32,
    /// Boot attempt counter (monotonic)
    pub boot_attempt: u32,
    /// Timestamp (RTC value or uptime in ms)
    pub timestamp: u32,
    /// Boot stage where failure occurred
    pub stage: BootStage,
    /// Error category
    pub category: ErrorCategory,
    /// Specific error code (from q_common::Error)
    pub error_code: u16,
    /// Program counter at failure
    pub pc: u32,
    /// Link register at failure
    pub lr: u32,
    /// Stack pointer at failure
    pub sp: u32,
    /// Exception/fault status register (if applicable)
    pub fault_status: u32,
    /// Faulting address (if applicable)
    pub fault_address: u32,
    /// Active firmware slot (0=A, 1=B)
    pub active_slot: u8,
    /// Previous boot result
    pub prev_result: u8,
    /// Reset reason
    pub reset_reason: u8,
    /// Reserved/flags
    pub flags: u8,
    /// Additional context (firmware version, etc.)
    pub context: [u8; 16],
    /// CRC32 of this entry
    pub crc: u32,
}

impl BootLogEntry {
    /// Entry magic value
    const ENTRY_MAGIC: u32 = 0x4C4F_4745; // "LOGE"

    /// Create a new empty log entry
    pub const fn new() -> Self {
        Self {
            magic: 0,
            boot_attempt: 0,
            timestamp: 0,
            stage: BootStage::Unknown,
            category: ErrorCategory::None,
            error_code: 0,
            pc: 0,
            lr: 0,
            sp: 0,
            fault_status: 0,
            fault_address: 0,
            active_slot: 0,
            prev_result: 0,
            reset_reason: 0,
            flags: 0,
            context: [0; 16],
            crc: 0,
        }
    }

    /// Create a log entry for a boot failure
    pub fn for_failure(
        boot_attempt: u32,
        stage: BootStage,
        category: ErrorCategory,
        error_code: u16,
    ) -> Self {
        let mut entry = Self::new();
        entry.magic = Self::ENTRY_MAGIC;
        entry.boot_attempt = boot_attempt;
        entry.timestamp = get_timestamp();
        entry.stage = stage;
        entry.category = category;
        entry.error_code = error_code;
        entry.reset_reason = get_reset_reason();

        // Capture current execution context
        entry.capture_context();

        // Calculate CRC
        entry.crc = entry.calculate_crc();

        entry
    }

    /// Capture current execution context (registers)
    fn capture_context(&mut self) {
        #[cfg(target_arch = "arm")]
        {
            // Capture PC, LR, SP from current context
            // Note: These are the values at time of logging, not necessarily
            // the exact failure point
            let pc: u32;
            let lr: u32;
            let sp: u32;

            // SAFETY: Inline assembly reads PC, LR, and SP registers which are
            // always valid on ARM. Options `nomem, nostack` indicate no memory or
            // stack side effects, making this a pure register read.
            unsafe {
                core::arch::asm!(
                    "mov {pc}, pc",
                    "mov {lr}, lr",
                    "mov {sp}, sp",
                    pc = out(reg) pc,
                    lr = out(reg) lr,
                    sp = out(reg) sp,
                    options(nomem, nostack)
                );
            }

            self.pc = pc;
            self.lr = lr;
            self.sp = sp;

            // Capture fault status registers if in fault handler
            const SCB_CFSR: u32 = 0xE000_ED28;
            const SCB_HFSR: u32 = 0xE000_ED2C;
            const SCB_MMFAR: u32 = 0xE000_ED34;
            const SCB_BFAR: u32 = 0xE000_ED38;

            // SAFETY: SCB_CFSR (0xE000_ED28), SCB_HFSR (0xE000_ED2C), SCB_MMFAR
            // (0xE000_ED34), and SCB_BFAR (0xE000_ED38) are ARM Cortex-M System
            // Control Block registers, always mapped and readable in privileged mode.
            // Volatile reads are required because hardware may update these at any time.
            unsafe {
                self.fault_status = ptr::read_volatile(SCB_CFSR as *const u32);

                // Get faulting address if valid
                let _hfsr = ptr::read_volatile(SCB_HFSR as *const u32);
                if self.fault_status & 0x80 != 0 {
                    // MMARVALID - MemManage fault address valid
                    self.fault_address = ptr::read_volatile(SCB_MMFAR as *const u32);
                } else if self.fault_status & 0x8000 != 0 {
                    // BFARVALID - BusFault address valid
                    self.fault_address = ptr::read_volatile(SCB_BFAR as *const u32);
                }
            }
        }

        #[cfg(not(target_arch = "arm"))]
        {
            // Simulated values for testing
            self.pc = 0;
            self.lr = 0;
            self.sp = 0;
        }
    }

    /// Calculate CRC32 of entry (excluding CRC field)
    fn calculate_crc(&self) -> u32 {
        // SAFETY: `self` is a valid, initialized `BootLogEntry` reference.
        // The slice covers LOG_ENTRY_SIZE - 4 bytes (excluding the trailing CRC
        // field), which is within the struct's layout since size_of::<BootLogEntry>()
        // equals LOG_ENTRY_SIZE.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                LOG_ENTRY_SIZE - 4, // Exclude CRC field
            )
        };

        crc32(bytes)
    }

    /// Validate entry CRC and magic
    pub fn is_valid(&self) -> bool {
        self.magic == Self::ENTRY_MAGIC && self.crc == self.calculate_crc()
    }

    /// Read entry from backup RAM at given index
    pub fn read(index: usize) -> Option<Self> {
        if index >= MAX_LOG_ENTRIES {
            return None;
        }

        let addr = ENTRIES_BASE + (index as u32 * LOG_ENTRY_SIZE as u32);

        let mut entry = Self::new();
        // SAFETY: `addr` points into the backup SRAM log entries region
        // (ENTRIES_BASE + index * LOG_ENTRY_SIZE). The index bounds check above
        // ensures we stay within the allocated MAX_LOG_ENTRIES area. The
        // destination is a stack-local BootLogEntry of exactly LOG_ENTRY_SIZE bytes.
        unsafe {
            let src = addr as *const u8;
            let dst = &mut entry as *mut Self as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, LOG_ENTRY_SIZE);
        }

        if entry.is_valid() {
            Some(entry)
        } else {
            None
        }
    }

    /// Write entry to backup RAM at given index
    pub fn write(&self, index: usize) -> Result<(), Error> {
        if index >= MAX_LOG_ENTRIES {
            return Err(Error::InvalidParameter);
        }

        let addr = ENTRIES_BASE + (index as u32 * LOG_ENTRY_SIZE as u32);

        // SAFETY: `self` is a valid BootLogEntry reference providing LOG_ENTRY_SIZE
        // bytes. `addr` points into the backup SRAM log entries region, bounded by
        // the index check above. Backup SRAM is always mapped and writable after
        // enable_backup_sram() has been called during init.
        unsafe {
            let src = self as *const Self as *const u8;
            let dst = addr as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, LOG_ENTRY_SIZE);
        }

        Ok(())
    }
}

impl Default for BootLogEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Boot Log Manager
// ============================================================================

/// Boot log manager
pub struct BootLog {
    /// Total entries ever written
    total_entries: u32,
    /// Current write index (circular buffer)
    write_index: usize,
    /// Initialized flag
    initialized: bool,
}

impl BootLog {
    /// Create a new boot log manager
    pub const fn new() -> Self {
        Self {
            total_entries: 0,
            write_index: 0,
            initialized: false,
        }
    }

    /// Initialize the boot log
    ///
    /// Reads the log header from backup RAM and validates it.
    /// If invalid, initializes a fresh log.
    pub fn init(&mut self) -> Result<(), Error> {
        // Enable backup SRAM clock and power if needed
        self.enable_backup_sram();

        // Check for valid log header
        // SAFETY: HEADER_MAGIC and HEADER_VERSION are fixed addresses within
        // backup SRAM (0x3800_0100 and 0x3800_0104), which is mapped and
        // accessible after enable_backup_sram() above. Volatile reads are
        // required because the values persist across reboots.
        let magic = unsafe { ptr::read_volatile(HEADER_MAGIC as *const u32) };
        let version = unsafe { ptr::read_volatile(HEADER_VERSION as *const u32) };

        if magic == BOOT_LOG_MAGIC && version == BOOT_LOG_VERSION {
            // Valid header, load state
            // SAFETY: HEADER_TOTAL_ENTRIES (0x3800_0108) and HEADER_WRITE_INDEX
            // (0x3800_010C) are within backup SRAM, validated accessible by the
            // magic/version check above. Volatile reads ensure we see the persisted
            // values from prior boot cycles.
            self.total_entries = unsafe { ptr::read_volatile(HEADER_TOTAL_ENTRIES as *const u32) };
            self.write_index = unsafe { ptr::read_volatile(HEADER_WRITE_INDEX as *const u32) } as usize;

            // Validate header CRC
            // SAFETY: HEADER_CRC (0x3800_0110) is within backup SRAM, accessible
            // after enable_backup_sram(). Volatile read required for persistent data.
            let stored_crc = unsafe { ptr::read_volatile(HEADER_CRC as *const u32) };
            let calculated_crc = self.calculate_header_crc();

            if stored_crc != calculated_crc {
                // Header corrupted, reinitialize
                self.format()?;
            }
        } else {
            // No valid log, initialize fresh
            self.format()?;
        }

        self.initialized = true;
        Ok(())
    }

    /// Enable backup SRAM access (STM32H7)
    fn enable_backup_sram(&self) {
        #[cfg(target_arch = "arm")]
        {
            // Enable PWR clock
            const RCC_APB1ENR1: u32 = 0x5802_4400 + 0x58;
            const RCC_APB1ENR1_PWREN: u32 = 1 << 28;

            // SAFETY: RCC_APB1ENR1 (0x5802_4458) is a memory-mapped RCC peripheral
            // register on STM32H7, always accessible in privileged mode. We
            // read-modify-write to set only the PWREN bit without disturbing
            // other clock enables. Volatile access is required for MMIO.
            unsafe {
                let enr = ptr::read_volatile(RCC_APB1ENR1 as *const u32);
                ptr::write_volatile(RCC_APB1ENR1 as *mut u32, enr | RCC_APB1ENR1_PWREN);
            }

            // Enable backup domain access
            const PWR_CR1: u32 = 0x5802_4800;
            const PWR_CR1_DBP: u32 = 1 << 8;

            // SAFETY: PWR_CR1 (0x5802_4800) is the power control register on
            // STM32H7. Setting the DBP bit enables write access to the backup
            // domain. The PWR clock was enabled above. Volatile MMIO access required.
            unsafe {
                let cr1 = ptr::read_volatile(PWR_CR1 as *const u32);
                ptr::write_volatile(PWR_CR1 as *mut u32, cr1 | PWR_CR1_DBP);
            }

            // Enable backup SRAM clock
            const RCC_AHB4ENR: u32 = 0x5802_4400 + 0xE0;
            const RCC_AHB4ENR_BKPRAMEN: u32 = 1 << 28;

            // SAFETY: RCC_AHB4ENR (0x5802_44E0) is the AHB4 peripheral clock
            // enable register. Setting the BKPRAMEN bit enables the backup SRAM
            // clock. Volatile MMIO access required for hardware register.
            unsafe {
                let enr = ptr::read_volatile(RCC_AHB4ENR as *const u32);
                ptr::write_volatile(RCC_AHB4ENR as *mut u32, enr | RCC_AHB4ENR_BKPRAMEN);
            }
        }
    }

    /// Format the boot log (clear all entries)
    pub fn format(&mut self) -> Result<(), Error> {
        self.total_entries = 0;
        self.write_index = 0;

        // Write header
        // SAFETY: All HEADER_* addresses (MAGIC through CRC) are within the
        // backup SRAM log header region (0x3800_0100..0x3800_0114). Backup SRAM
        // is writable after enable_backup_sram() has been called. Volatile writes
        // ensure the values are committed to persistent SRAM.
        unsafe {
            ptr::write_volatile(HEADER_MAGIC as *mut u32, BOOT_LOG_MAGIC);
            ptr::write_volatile(HEADER_VERSION as *mut u32, BOOT_LOG_VERSION);
            ptr::write_volatile(HEADER_TOTAL_ENTRIES as *mut u32, 0);
            ptr::write_volatile(HEADER_WRITE_INDEX as *mut u32, 0);
            ptr::write_volatile(HEADER_CRC as *mut u32, self.calculate_header_crc());
        }

        // Clear all entries
        for i in 0..MAX_LOG_ENTRIES {
            let addr = ENTRIES_BASE + (i as u32 * LOG_ENTRY_SIZE as u32);
            // SAFETY: Each entry address is within the backup SRAM entries
            // region (ENTRIES_BASE + i * 64), bounded by MAX_LOG_ENTRIES.
            // Byte-wise volatile writes zero the entire entry to clear it.
            unsafe {
                for j in 0..LOG_ENTRY_SIZE {
                    ptr::write_volatile((addr + j as u32) as *mut u8, 0);
                }
            }
        }

        Ok(())
    }

    /// Log a boot failure
    pub fn log_failure(
        &mut self,
        stage: BootStage,
        category: ErrorCategory,
        error_code: u16,
    ) -> Result<(), Error> {
        if !self.initialized {
            self.init()?;
        }

        // Create log entry
        let entry = BootLogEntry::for_failure(
            self.total_entries + 1,
            stage,
            category,
            error_code,
        );

        // Write to circular buffer
        entry.write(self.write_index)?;

        // Update indices
        self.write_index = (self.write_index + 1) % MAX_LOG_ENTRIES;
        self.total_entries += 1;

        // Update header
        self.save_header()?;

        Ok(())
    }

    /// Log a boot failure with additional context
    pub fn log_failure_with_context(
        &mut self,
        stage: BootStage,
        category: ErrorCategory,
        error_code: u16,
        context: &[u8],
    ) -> Result<(), Error> {
        if !self.initialized {
            self.init()?;
        }

        // Create log entry
        let mut entry = BootLogEntry::for_failure(
            self.total_entries + 1,
            stage,
            category,
            error_code,
        );

        // Copy context (up to 16 bytes)
        let len = context.len().min(16);
        entry.context[..len].copy_from_slice(&context[..len]);

        // Recalculate CRC with context
        entry.crc = entry.calculate_crc();

        // Write to circular buffer
        entry.write(self.write_index)?;

        // Update indices
        self.write_index = (self.write_index + 1) % MAX_LOG_ENTRIES;
        self.total_entries += 1;

        // Update header
        self.save_header()?;

        Ok(())
    }

    /// Get the most recent log entry
    pub fn get_latest(&self) -> Option<BootLogEntry> {
        if self.total_entries == 0 {
            return None;
        }

        let index = if self.write_index == 0 {
            MAX_LOG_ENTRIES - 1
        } else {
            self.write_index - 1
        };

        BootLogEntry::read(index)
    }

    /// Get log entry by index (0 = most recent)
    pub fn get_entry(&self, index: usize) -> Option<BootLogEntry> {
        if index >= self.total_entries as usize || index >= MAX_LOG_ENTRIES {
            return None;
        }

        // Calculate actual index in circular buffer
        let count = self.total_entries.min(MAX_LOG_ENTRIES as u32) as usize;
        if index >= count {
            return None;
        }

        let actual_index = if self.write_index > index {
            self.write_index - index - 1
        } else {
            MAX_LOG_ENTRIES - (index - self.write_index) - 1
        };

        BootLogEntry::read(actual_index)
    }

    /// Get total number of failures logged
    pub fn total_failures(&self) -> u32 {
        self.total_entries
    }

    /// Get number of entries currently stored
    pub fn entry_count(&self) -> usize {
        (self.total_entries as usize).min(MAX_LOG_ENTRIES)
    }

    /// Calculate header CRC
    fn calculate_header_crc(&self) -> u32 {
        let mut data = [0u8; 16];
        data[0..4].copy_from_slice(&BOOT_LOG_MAGIC.to_le_bytes());
        data[4..8].copy_from_slice(&BOOT_LOG_VERSION.to_le_bytes());
        data[8..12].copy_from_slice(&self.total_entries.to_le_bytes());
        data[12..16].copy_from_slice(&(self.write_index as u32).to_le_bytes());
        crc32(&data)
    }

    /// Save header to backup RAM
    fn save_header(&self) -> Result<(), Error> {
        // SAFETY: HEADER_TOTAL_ENTRIES, HEADER_WRITE_INDEX, and HEADER_CRC are
        // fixed addresses within backup SRAM (0x3800_0108..0x3800_0110). The
        // SRAM was enabled during init(). Volatile writes ensure persistence.
        unsafe {
            ptr::write_volatile(HEADER_TOTAL_ENTRIES as *mut u32, self.total_entries);
            ptr::write_volatile(HEADER_WRITE_INDEX as *mut u32, self.write_index as u32);
            ptr::write_volatile(HEADER_CRC as *mut u32, self.calculate_header_crc());
        }
        Ok(())
    }

    /// Export log entries as bytes (for recovery protocol)
    pub fn export(&self, buffer: &mut [u8]) -> usize {
        let count = self.entry_count();
        let max_entries = buffer.len() / LOG_ENTRY_SIZE;
        let entries_to_export = count.min(max_entries);

        for i in 0..entries_to_export {
            if let Some(entry) = self.get_entry(i) {
                let offset = i * LOG_ENTRY_SIZE;
                let src = &entry as *const BootLogEntry as *const u8;
                // SAFETY: `entry` is a valid BootLogEntry (LOG_ENTRY_SIZE bytes).
                // The destination buffer slice `buffer[offset..]` is checked to
                // have room for at least LOG_ENTRY_SIZE bytes by the
                // `max_entries = buffer.len() / LOG_ENTRY_SIZE` bound above.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src,
                        buffer[offset..].as_mut_ptr(),
                        LOG_ENTRY_SIZE,
                    );
                }
            }
        }

        entries_to_export * LOG_ENTRY_SIZE
    }
}

impl Default for BootLog {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get current timestamp (RTC or uptime)
fn get_timestamp() -> u32 {
    #[cfg(target_arch = "arm")]
    {
        // Try to read RTC if available
        const RTC_TR: u32 = 0x5800_4000; // RTC time register

        // For now, return a simple counter or 0
        // Real implementation would read RTC_TR and convert
        // SAFETY: RTC_TR (0x5800_4000) is the RTC time register on STM32H7,
        // a memory-mapped peripheral register that is always readable.
        // Volatile read required because the RTC updates this register
        // asynchronously.
        unsafe { ptr::read_volatile(RTC_TR as *const u32) }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        0
    }
}

/// Get reset reason from RCC
fn get_reset_reason() -> u8 {
    #[cfg(target_arch = "arm")]
    {
        const RCC_RSR: u32 = 0x5802_4400 + 0xD0; // Reset Status Register

        // SAFETY: RCC_RSR (0x5802_44D0) is the RCC Reset Status Register on
        // STM32H7, always readable in privileged mode. Volatile read required
        // because the register reflects hardware reset state.
        let rsr = unsafe { ptr::read_volatile(RCC_RSR as *const u32) };

        // Map reset flags to reason code
        if rsr & (1 << 26) != 0 { 1 } // Low power reset
        else if rsr & (1 << 27) != 0 { 2 } // Window watchdog
        else if rsr & (1 << 28) != 0 { 3 } // Independent watchdog
        else if rsr & (1 << 29) != 0 { 4 } // Software reset
        else if rsr & (1 << 30) != 0 { 5 } // POR/PDR
        else if rsr & (1 << 31) != 0 { 6 } // Pin reset
        else { 0 }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        0
    }
}

/// CRC32 calculation (same algorithm as recovery module)
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;

    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }

    !crc
}

// ============================================================================
// Global Instance
// ============================================================================

/// Global boot log instance
static mut BOOT_LOG: BootLog = BootLog::new();

/// Initialize the global boot log
pub fn init() -> Result<(), Error> {
    // SAFETY: Access to the global mutable static BOOT_LOG. This is safe in
    // the bootloader's single-threaded, no-interrupt context during init.
    unsafe { (*core::ptr::addr_of_mut!(BOOT_LOG)).init() }
}

/// Log a boot failure to the global log
pub fn log_failure(stage: BootStage, category: ErrorCategory, error_code: u16) -> Result<(), Error> {
    // SAFETY: Access to global mutable static BOOT_LOG. The bootloader runs
    // single-threaded, so no data races are possible.
    unsafe { (*core::ptr::addr_of_mut!(BOOT_LOG)).log_failure(stage, category, error_code) }
}

/// Log a boot failure with context
pub fn log_failure_with_context(
    stage: BootStage,
    category: ErrorCategory,
    error_code: u16,
    context: &[u8],
) -> Result<(), Error> {
    // SAFETY: Access to global mutable static BOOT_LOG. The bootloader runs
    // single-threaded, so no data races are possible.
    unsafe { (*core::ptr::addr_of_mut!(BOOT_LOG)).log_failure_with_context(stage, category, error_code, context) }
}

/// Get the most recent failure from the global log
pub fn get_latest_failure() -> Option<BootLogEntry> {
    // SAFETY: Read-only access to global static BOOT_LOG in a single-threaded
    // bootloader context. No concurrent mutation is possible.
    unsafe { (*core::ptr::addr_of!(BOOT_LOG)).get_latest() }
}

/// Get total failure count
pub fn total_failures() -> u32 {
    // SAFETY: Read-only access to global static BOOT_LOG in a single-threaded
    // bootloader context.
    unsafe { (*core::ptr::addr_of!(BOOT_LOG)).total_failures() }
}

/// Export log entries
pub fn export_log(buffer: &mut [u8]) -> usize {
    // SAFETY: Read-only access to global static BOOT_LOG in a single-threaded
    // bootloader context. The buffer is caller-provided and valid.
    unsafe { (*core::ptr::addr_of!(BOOT_LOG)).export(buffer) }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_stage_conversion() {
        assert_eq!(BootStage::from(0), BootStage::EarlyInit);
        assert_eq!(BootStage::from(8), BootStage::KernelVerify);
        assert_eq!(BootStage::from(200), BootStage::Unknown);
    }

    #[test]
    fn test_error_category_conversion() {
        assert_eq!(ErrorCategory::from(0), ErrorCategory::None);
        assert_eq!(ErrorCategory::from(4), ErrorCategory::Verification);
        assert_eq!(ErrorCategory::from(200), ErrorCategory::Unknown);
    }

    #[test]
    fn test_crc32() {
        let data = b"hello";
        let crc1 = crc32(data);
        let crc2 = crc32(data);
        assert_eq!(crc1, crc2);

        let data2 = b"world";
        let crc3 = crc32(data2);
        assert_ne!(crc1, crc3);
    }

    #[test]
    fn test_log_entry_new() {
        let entry = BootLogEntry::new();
        assert_eq!(entry.magic, 0);
        assert_eq!(entry.boot_attempt, 0);
    }

    #[test]
    fn test_boot_log_new() {
        let log = BootLog::new();
        assert_eq!(log.total_entries, 0);
        assert_eq!(log.write_index, 0);
        assert!(!log.initialized);
    }
}
