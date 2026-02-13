// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! A/B Slot Management for Atomic Updates
//!
//! This module implements A/B (dual-bank) partition management for reliable,
//! atomic firmware updates with automatic fallback on boot failure.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      Flash Layout                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Bootloader (protected, not A/B)                   64 KB    │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Slot Metadata (both slots' state)                 4 KB     │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Slot A - Bank 1 (primary)                         960 KB   │
//! │    - Kernel                                                  │
//! │    - Application                                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Slot B - Bank 2 (secondary)                       960 KB   │
//! │    - Kernel                                                  │
//! │    - Application                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Update Flow
//!
//! 1. Write new image to inactive slot
//! 2. Verify written image (hash + signature)
//! 3. Mark inactive slot as "pending"
//! 4. Reboot
//! 5. Bootloader boots from pending slot
//! 6. If boot successful: mark slot as "active", clear other slot
//! 7. If boot fails: revert to previous active slot
//!
//! # Safety Features
//!
//! - Atomic slot switching (single write to switch active slot)
//! - Boot attempt counter (automatic rollback after N failures)
//! - Signature verification before switching
//! - CRC protection for slot metadata

use core::ptr;
use q_common::Error;

// ============================================================================
// Flash Layout Configuration
// ============================================================================

/// Flash base address
const FLASH_BASE: u32 = 0x0800_0000;

/// Bootloader size (protected, not part of A/B)
const BOOTLOADER_SIZE: u32 = 64 * 1024; // 64 KB

/// Slot metadata size
const METADATA_SIZE: u32 = 4 * 1024; // 4 KB

/// Single slot size
const SLOT_SIZE: u32 = 960 * 1024; // 960 KB

/// Slot metadata address
const METADATA_ADDR: u32 = FLASH_BASE + BOOTLOADER_SIZE;

/// Slot A address (Bank 1)
const SLOT_A_ADDR: u32 = METADATA_ADDR + METADATA_SIZE;

/// Slot B address (Bank 2)
const SLOT_B_ADDR: u32 = SLOT_A_ADDR + SLOT_SIZE;

/// Metadata magic number
const METADATA_MAGIC: u32 = 0x514D_4554; // "QMET"

/// Maximum boot attempts before rollback
const MAX_BOOT_ATTEMPTS: u8 = 3;

// ============================================================================
// Slot Identification
// ============================================================================

/// Slot identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Slot {
    /// Slot A (Bank 1, primary)
    A = 0,
    /// Slot B (Bank 2, secondary)
    B = 1,
}

impl Slot {
    /// Get the other slot
    #[must_use]
    pub fn other(&self) -> Self {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    /// Get flash address for this slot
    #[must_use]
    pub fn address(&self) -> u32 {
        match self {
            Slot::A => SLOT_A_ADDR,
            Slot::B => SLOT_B_ADDR,
        }
    }

    /// Get slot size
    #[must_use]
    pub fn size(&self) -> u32 {
        SLOT_SIZE
    }
}

impl From<u8> for Slot {
    fn from(value: u8) -> Self {
        match value {
            0 => Slot::A,
            _ => Slot::B,
        }
    }
}

// ============================================================================
// Slot State
// ============================================================================

/// State of a single slot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SlotState {
    /// Slot is empty (no valid image)
    Empty = 0,
    /// Slot has valid image but is not active
    Valid = 1,
    /// Slot is pending boot (will be tried on next boot)
    Pending = 2,
    /// Slot is currently active (booted from)
    Active = 3,
    /// Slot failed to boot (marked bad)
    Failed = 4,
    /// Unknown/corrupted state
    Invalid = 255,
}

impl SlotState {
    /// Check if slot is bootable
    #[must_use]
    pub fn is_bootable(&self) -> bool {
        matches!(self, SlotState::Valid | SlotState::Pending | SlotState::Active)
    }
}

impl From<u8> for SlotState {
    fn from(value: u8) -> Self {
        match value {
            0 => SlotState::Empty,
            1 => SlotState::Valid,
            2 => SlotState::Pending,
            3 => SlotState::Active,
            4 => SlotState::Failed,
            _ => SlotState::Invalid,
        }
    }
}

// ============================================================================
// Slot Metadata Structure
// ============================================================================

/// Per-slot metadata stored in flash
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SlotInfo {
    /// State of this slot
    pub state: u8,
    /// Boot attempt counter
    pub boot_attempts: u8,
    /// Reserved padding
    pub reserved: [u8; 2],
    /// Version number (major.minor.patch.build packed)
    pub version: u32,
    /// SHA3-256 hash of slot contents
    pub hash: [u8; 32],
    /// Last successful boot timestamp (if available)
    pub last_boot_time: u64,
}

impl SlotInfo {
    /// Size of slot info structure
    pub const SIZE: usize = 48;

    /// Create empty slot info
    pub const fn empty() -> Self {
        Self {
            state: SlotState::Empty as u8,
            boot_attempts: 0,
            reserved: [0; 2],
            version: 0,
            hash: [0; 32],
            last_boot_time: 0,
        }
    }

    /// Get slot state
    pub fn get_state(&self) -> SlotState {
        SlotState::from(self.state)
    }

    /// Set slot state
    pub fn set_state(&mut self, state: SlotState) {
        self.state = state as u8;
    }

    /// Parse version into components
    pub fn parse_version(&self) -> (u8, u8, u8, u8) {
        let major = (self.version >> 24) as u8;
        let minor = (self.version >> 16) as u8;
        let patch = (self.version >> 8) as u8;
        let build = self.version as u8;
        (major, minor, patch, build)
    }
}

/// Complete slot metadata (stored at METADATA_ADDR)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SlotMetadata {
    /// Magic number for validation
    pub magic: u32,
    /// Metadata version
    pub version: u16,
    /// Currently selected slot for boot
    pub selected_slot: u8,
    /// Reserved padding
    pub reserved: u8,
    /// Slot A information
    pub slot_a: SlotInfo,
    /// Slot B information
    pub slot_b: SlotInfo,
    /// Update in progress flag
    pub update_in_progress: u8,
    /// Target slot for pending update
    pub update_target: u8,
    /// Reserved padding
    pub padding: [u8; 2],
    /// CRC32 of metadata (excluding this field)
    pub crc32: u32,
}

impl SlotMetadata {
    /// Size of metadata structure
    pub const SIZE: usize = 112;

    /// Create default metadata
    pub const fn new() -> Self {
        Self {
            magic: METADATA_MAGIC,
            version: 1,
            selected_slot: Slot::A as u8,
            reserved: 0,
            slot_a: SlotInfo::empty(),
            slot_b: SlotInfo::empty(),
            update_in_progress: 0,
            update_target: 0,
            padding: [0; 2],
            crc32: 0,
        }
    }

    /// Get slot info for specified slot
    pub fn get_slot_info(&self, slot: Slot) -> &SlotInfo {
        match slot {
            Slot::A => &self.slot_a,
            Slot::B => &self.slot_b,
        }
    }

    /// Get mutable slot info
    pub fn get_slot_info_mut(&mut self, slot: Slot) -> &mut SlotInfo {
        match slot {
            Slot::A => &mut self.slot_a,
            Slot::B => &mut self.slot_b,
        }
    }

    /// Get selected slot
    pub fn get_selected_slot(&self) -> Slot {
        Slot::from(self.selected_slot)
    }

    /// Compute CRC32 of metadata (excluding CRC field)
    fn compute_crc(&self) -> u32 {
        // SAFETY: `SlotMetadata` is `#[repr(C, packed)]` with a known fixed size
        // (`Self::SIZE`). We create a byte slice over the struct excluding the
        // trailing 4-byte CRC field. The pointer is valid for the lifetime of
        // `&self` and the struct contains no padding that could be uninitialised
        // because all fields are integral types.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                Self::SIZE - 4, // Exclude CRC field
            )
        };

        compute_crc32(bytes)
    }

    /// Validate metadata
    pub fn validate(&self) -> Result<(), SlotError> {
        // Check magic
        if self.magic != METADATA_MAGIC {
            return Err(SlotError::InvalidMagic);
        }

        // Check CRC
        if self.crc32 != self.compute_crc() {
            return Err(SlotError::CrcMismatch);
        }

        Ok(())
    }

    /// Update CRC field
    pub fn update_crc(&mut self) {
        self.crc32 = self.compute_crc();
    }
}

impl Default for SlotMetadata {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Slot management error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotError {
    /// Invalid magic number
    InvalidMagic,
    /// CRC mismatch
    CrcMismatch,
    /// Slot is not valid
    InvalidSlot,
    /// No valid slot to boot
    NoBootableSlot,
    /// Flash operation failed
    FlashError,
    /// Update already in progress
    UpdateInProgress,
    /// Version rollback attempted
    RollbackAttempt,
    /// Slot verification failed
    VerificationFailed,
    /// Internal error
    InternalError,
}

impl From<SlotError> for Error {
    fn from(e: SlotError) -> Self {
        match e {
            SlotError::InvalidSlot | SlotError::NoBootableSlot => Error::PartitionSwitchFailed,
            SlotError::FlashError => Error::FlashError,
            SlotError::RollbackAttempt => Error::RollbackAttempted,
            SlotError::VerificationFailed => Error::UpdateCorrupted,
            SlotError::UpdateInProgress => Error::UpdateInProgress,
            _ => Error::InternalError,
        }
    }
}

// ============================================================================
// Slot Manager
// ============================================================================

/// A/B slot manager
pub struct SlotManager<F> {
    /// Flash interface
    flash: F,
    /// Cached metadata
    metadata: SlotMetadata,
    /// Metadata loaded flag
    loaded: bool,
}

impl<F: FlashInterface> SlotManager<F> {
    /// Create a new slot manager
    pub fn new(flash: F) -> Self {
        Self {
            flash,
            metadata: SlotMetadata::new(),
            loaded: false,
        }
    }

    /// Load metadata from flash
    pub fn load(&mut self) -> Result<(), SlotError> {
        // Read metadata from flash
        let mut buffer = [0u8; SlotMetadata::SIZE];
        self.flash
            .read(METADATA_ADDR, &mut buffer)
            .map_err(|_| SlotError::FlashError)?;

        // Parse metadata
        // SAFETY: `buffer` is a local array of exactly `SlotMetadata::SIZE` bytes
        // that was just populated by a flash read. `ptr::read_unaligned` is used
        // because `SlotMetadata` is `#[repr(C, packed)]` and the buffer may not
        // satisfy alignment requirements. All bit patterns are valid for the
        // struct's integral fields; semantic validity is checked by `validate()`.
        self.metadata = unsafe { ptr::read_unaligned(buffer.as_ptr() as *const SlotMetadata) };

        // Validate
        match self.metadata.validate() {
            Ok(()) => {
                self.loaded = true;
                Ok(())
            }
            Err(_) => {
                // Metadata invalid - initialize fresh
                self.metadata = SlotMetadata::new();
                self.save()?;
                self.loaded = true;
                Ok(())
            }
        }
    }

    /// Save metadata to flash
    pub fn save(&mut self) -> Result<(), SlotError> {
        // Update CRC
        self.metadata.update_crc();

        // Serialize
        // SAFETY: `SlotMetadata` is `#[repr(C, packed)]` with a known fixed size.
        // We create a read-only byte slice over the struct for serialisation to
        // flash. The pointer is derived from `&self.metadata` and is valid for
        // `SlotMetadata::SIZE` bytes. The struct contains only integral fields so
        // every byte is initialised.
        let buffer = unsafe {
            core::slice::from_raw_parts(
                &self.metadata as *const SlotMetadata as *const u8,
                SlotMetadata::SIZE,
            )
        };

        // Erase metadata sector
        self.flash
            .erase_page(METADATA_ADDR)
            .map_err(|_| SlotError::FlashError)?;

        // Write metadata
        self.flash
            .write(METADATA_ADDR, buffer)
            .map_err(|_| SlotError::FlashError)?;

        Ok(())
    }

    /// Get current active slot
    pub fn get_active_slot(&self) -> Slot {
        if !self.loaded {
            return Slot::A; // Default
        }

        // Find the active slot
        if self.metadata.slot_a.get_state() == SlotState::Active {
            Slot::A
        } else if self.metadata.slot_b.get_state() == SlotState::Active {
            Slot::B
        } else {
            self.metadata.get_selected_slot()
        }
    }

    /// Get slot to boot from
    ///
    /// Returns the slot that should be booted, considering pending updates
    /// and boot failure handling.
    pub fn get_boot_slot(&mut self) -> Result<Slot, SlotError> {
        if !self.loaded {
            self.load()?;
        }

        // Check for pending slot first
        let slot_a_state = self.metadata.slot_a.get_state();
        let slot_b_state = self.metadata.slot_b.get_state();

        // Priority: Pending > Active > Valid
        if slot_a_state == SlotState::Pending {
            // Check boot attempts
            if self.metadata.slot_a.boot_attempts < MAX_BOOT_ATTEMPTS {
                return Ok(Slot::A);
            } else {
                // Too many failures, mark as failed
                self.metadata.slot_a.set_state(SlotState::Failed);
                self.save()?;
            }
        }

        if slot_b_state == SlotState::Pending {
            if self.metadata.slot_b.boot_attempts < MAX_BOOT_ATTEMPTS {
                return Ok(Slot::B);
            } else {
                self.metadata.slot_b.set_state(SlotState::Failed);
                self.save()?;
            }
        }

        // No pending, use active
        if slot_a_state == SlotState::Active {
            return Ok(Slot::A);
        }
        if slot_b_state == SlotState::Active {
            return Ok(Slot::B);
        }

        // No active, try valid
        if slot_a_state == SlotState::Valid {
            return Ok(Slot::A);
        }
        if slot_b_state == SlotState::Valid {
            return Ok(Slot::B);
        }

        // No bootable slot
        Err(SlotError::NoBootableSlot)
    }

    /// Increment boot attempt counter for a slot
    pub fn increment_boot_attempts(&mut self, slot: Slot) -> Result<u8, SlotError> {
        if !self.loaded {
            self.load()?;
        }

        // Update boot attempts
        {
            let info = self.metadata.get_slot_info_mut(slot);
            info.boot_attempts = info.boot_attempts.saturating_add(1);
        }

        // Save after releasing the mutable borrow
        self.save()?;

        // Return the updated value
        let boot_attempts = self.metadata.get_slot_info(slot).boot_attempts;
        Ok(boot_attempts)
    }

    /// Mark boot successful (called after successful boot)
    pub fn mark_boot_successful(&mut self, slot: Slot) -> Result<(), SlotError> {
        if !self.loaded {
            self.load()?;
        }

        // Set slot as active
        let info = self.metadata.get_slot_info_mut(slot);
        info.set_state(SlotState::Active);
        info.boot_attempts = 0;

        // Mark other slot as valid (not active)
        let other_info = self.metadata.get_slot_info_mut(slot.other());
        if other_info.get_state() == SlotState::Active {
            other_info.set_state(SlotState::Valid);
        }

        self.metadata.selected_slot = slot as u8;

        self.save()
    }

    /// Get inactive slot (for updates)
    pub fn get_update_slot(&self) -> Slot {
        self.get_active_slot().other()
    }

    /// Begin update to inactive slot
    pub fn begin_update(&mut self, version: u32) -> Result<Slot, SlotError> {
        if !self.loaded {
            self.load()?;
        }

        if self.metadata.update_in_progress != 0 {
            return Err(SlotError::UpdateInProgress);
        }

        let target = self.get_update_slot();

        // Check version is not a rollback
        let current_info = self.metadata.get_slot_info(self.get_active_slot());
        if version < current_info.version {
            return Err(SlotError::RollbackAttempt);
        }

        // Mark update in progress
        self.metadata.update_in_progress = 1;
        self.metadata.update_target = target as u8;

        // Clear target slot
        let target_info = self.metadata.get_slot_info_mut(target);
        target_info.set_state(SlotState::Empty);
        target_info.version = version;
        target_info.boot_attempts = 0;

        self.save()?;
        Ok(target)
    }

    /// Complete update and mark slot as pending
    pub fn complete_update(&mut self, slot: Slot, hash: &[u8; 32]) -> Result<(), SlotError> {
        if !self.loaded {
            self.load()?;
        }

        if self.metadata.update_in_progress == 0 {
            return Err(SlotError::InternalError);
        }

        let info = self.metadata.get_slot_info_mut(slot);
        info.set_state(SlotState::Pending);
        info.hash.copy_from_slice(hash);
        info.boot_attempts = 0;

        self.metadata.update_in_progress = 0;

        self.save()
    }

    /// Cancel update
    pub fn cancel_update(&mut self) -> Result<(), SlotError> {
        if !self.loaded {
            self.load()?;
        }

        if self.metadata.update_in_progress != 0 {
            let target = Slot::from(self.metadata.update_target);
            let info = self.metadata.get_slot_info_mut(target);
            info.set_state(SlotState::Empty);

            self.metadata.update_in_progress = 0;
            self.save()?;
        }

        Ok(())
    }

    /// Get slot information
    pub fn get_slot_info(&self, slot: Slot) -> &SlotInfo {
        self.metadata.get_slot_info(slot)
    }

    /// Get both slots' status for diagnostics
    pub fn get_status(&self) -> SlotStatus {
        SlotStatus {
            active_slot: self.get_active_slot(),
            slot_a_state: self.metadata.slot_a.get_state(),
            slot_a_version: self.metadata.slot_a.version,
            slot_b_state: self.metadata.slot_b.get_state(),
            slot_b_version: self.metadata.slot_b.version,
            update_in_progress: self.metadata.update_in_progress != 0,
        }
    }

    /// Erase a slot (for recovery)
    pub fn erase_slot(&mut self, slot: Slot) -> Result<(), SlotError> {
        // Erase the flash region
        let start = slot.address();
        let end = start + slot.size();

        self.flash
            .erase_range(start, end)
            .map_err(|_| SlotError::FlashError)?;

        // Update metadata
        if !self.loaded {
            self.load()?;
        }

        let info = self.metadata.get_slot_info_mut(slot);
        *info = SlotInfo::empty();

        self.save()
    }
}

/// Slot status for diagnostics
#[derive(Debug, Clone, Copy)]
pub struct SlotStatus {
    /// Currently active slot
    pub active_slot: Slot,
    /// Slot A state
    pub slot_a_state: SlotState,
    /// Slot A version
    pub slot_a_version: u32,
    /// Slot B state
    pub slot_b_state: SlotState,
    /// Slot B version
    pub slot_b_version: u32,
    /// Update in progress
    pub update_in_progress: bool,
}

// ============================================================================
// Flash Interface Trait (minimal for slot manager)
// ============================================================================

/// Flash interface for slot management
pub trait FlashInterface {
    /// Read from flash
    fn read(&self, address: u32, buffer: &mut [u8]) -> Result<(), ()>;
    /// Write to flash
    fn write(&mut self, address: u32, data: &[u8]) -> Result<(), ()>;
    /// Erase a page/sector
    fn erase_page(&mut self, address: u32) -> Result<(), ()>;
    /// Erase a range
    fn erase_range(&mut self, start: u32, end: u32) -> Result<(), ()>;
}

// ============================================================================
// CRC32 Implementation
// ============================================================================

/// Compute CRC32 (IEEE 802.3 polynomial)
fn compute_crc32(data: &[u8]) -> u32 {
    const CRC32_TABLE: [u32; 256] = generate_crc32_table();

    let mut crc = 0xFFFF_FFFFu32;

    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }

    !crc
}

/// Generate CRC32 lookup table at compile time
const fn generate_crc32_table() -> [u32; 256] {
    const POLYNOMIAL: u32 = 0xEDB8_8320;
    let mut table = [0u32; 256];
    let mut i = 0;

    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLYNOMIAL;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }

    table
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_other() {
        assert_eq!(Slot::A.other(), Slot::B);
        assert_eq!(Slot::B.other(), Slot::A);
    }

    #[test]
    fn test_slot_addresses() {
        assert!(Slot::A.address() < Slot::B.address());
        assert_eq!(Slot::B.address() - Slot::A.address(), SLOT_SIZE);
    }

    #[test]
    fn test_slot_state_bootable() {
        assert!(!SlotState::Empty.is_bootable());
        assert!(SlotState::Valid.is_bootable());
        assert!(SlotState::Pending.is_bootable());
        assert!(SlotState::Active.is_bootable());
        assert!(!SlotState::Failed.is_bootable());
    }

    #[test]
    fn test_metadata_crc() {
        let mut meta = SlotMetadata::new();
        meta.update_crc();

        let crc = meta.crc32;
        assert_eq!(meta.compute_crc(), crc);

        // Modify and verify CRC changes
        meta.selected_slot = 1;
        assert_ne!(meta.compute_crc(), crc);
    }

    #[test]
    fn test_crc32_known_value() {
        // Test vector: "123456789" should produce CRC32 = 0xCBF43926
        let data = b"123456789";
        let crc = compute_crc32(data);
        assert_eq!(crc, 0xCBF4_3926);
    }
}
