// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Memory management
//!
//! Provides a simple bump allocator for static memory allocation in the kernel.
//! This allocator is designed for embedded systems where dynamic deallocation
//! is not needed — all allocations are permanent for the lifetime of the system.

use q_common::Error;

/// Memory region descriptor
pub struct MemoryRegion {
    /// Base address
    pub base: u32,
    /// Size in bytes
    pub size: u32,
    /// Permissions
    pub permissions: Permissions,
}

/// Memory permissions
#[derive(Clone, Copy)]
pub struct Permissions {
    /// Readable
    pub read: bool,
    /// Writable
    pub write: bool,
    /// Executable
    pub execute: bool,
}

impl Permissions {
    /// Read-only
    pub const RO: Self = Self { read: true, write: false, execute: false };
    /// Read-write
    pub const RW: Self = Self { read: true, write: true, execute: false };
    /// Read-execute
    pub const RX: Self = Self { read: true, write: false, execute: true };
}

// ============================================================================
// Bump Allocator
// ============================================================================

/// Size of the static memory pool (16KB default for embedded)
const POOL_SIZE: usize = 16 * 1024;

/// Static memory pool — all kernel allocations come from this buffer
static mut POOL: [u8; POOL_SIZE] = [0u8; POOL_SIZE];

/// Current allocation offset into the pool
static mut POOL_OFFSET: usize = 0;

/// Whether the allocator has been initialized
static mut INITIALIZED: bool = false;

/// Initialize memory manager
///
/// Must be called once during kernel startup before any allocations.
pub fn init() -> Result<(), Error> {
    // SAFETY: Called once during single-threaded kernel initialization,
    // before the scheduler starts. No concurrent access is possible.
    unsafe {
        POOL_OFFSET = 0;
        INITIALIZED = true;
    }
    Ok(())
}

/// Allocate from static pool (bump allocator)
///
/// Returns a pointer to `size` bytes aligned to `align`.
/// Allocations are permanent — `free()` is a no-op.
///
/// # Errors
/// Returns `Error::MemoryAllocationFailed` if the pool is exhausted
/// or the allocator is not initialized.
pub fn alloc(size: usize, align: usize) -> Result<*mut u8, Error> {
    if size == 0 {
        return Err(Error::MemoryAllocationFailed);
    }

    // SAFETY: Accesses global allocator state. In production, this is called
    // from kernel code with interrupts disabled (or during single-threaded
    // initialization). The bump allocator is lock-free by design — each
    // allocation only advances the offset forward.
    unsafe {
        if !INITIALIZED {
            return Err(Error::MemoryAllocationFailed);
        }

        let pool_base = core::ptr::addr_of!(POOL) as usize;

        // Align the current offset up to the requested alignment
        let current = pool_base + POOL_OFFSET;
        let aligned = (current + align - 1) & !(align - 1);
        let padding = aligned - current;
        let total_needed = padding + size;

        if POOL_OFFSET + total_needed > POOL_SIZE {
            return Err(Error::MemoryAllocationFailed);
        }

        // Advance the offset past this allocation
        POOL_OFFSET += total_needed;

        Ok(aligned as *mut u8)
    }
}

/// Free allocated memory (no-op for bump allocator)
///
/// The bump allocator does not support individual deallocation.
/// Memory is reclaimed only by calling `reset()` or at system restart.
pub fn free(_ptr: *mut u8) {
    // Bump allocator: deallocation is intentionally a no-op.
    // All memory is reclaimed on reset.
}

/// Reset the allocator, freeing all allocations
///
/// # Safety
/// All previously allocated pointers become invalid after this call.
/// Only safe to call when no references to allocated memory exist.
pub unsafe fn reset() {
    POOL_OFFSET = 0;
}

/// Get remaining available bytes in the pool
pub fn available() -> usize {
    // SAFETY: Read-only access to the pool offset. Safe to call from any context.
    unsafe {
        if !INITIALIZED {
            return 0;
        }
        POOL_SIZE - POOL_OFFSET
    }
}

/// Get total pool size
pub const fn pool_size() -> usize {
    POOL_SIZE
}
