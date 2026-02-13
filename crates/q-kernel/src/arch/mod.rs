// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Architecture-specific code
//!
//! This module contains architecture-specific implementations for:
//! - Context switching
//! - Exception handlers
//! - Memory protection (MPU/PMP)
//! - System calls
//!
//! Supported architectures:
//! - ARM Cortex-M (feature: `cortex-m`)
//! - RISC-V (feature: `riscv`)

// ============================================================================
// ARM Cortex-M Architecture
// ============================================================================

#[cfg(feature = "cortex-m")]
pub mod cortex_m;

#[cfg(feature = "cortex-m")]
pub use cortex_m::*;

// Re-export common types for Cortex-M
#[cfg(feature = "cortex-m")]
pub use cortex_m::context::{TaskContext, ContextSwitch};
#[cfg(feature = "cortex-m")]
pub use cortex_m::mpu::MpuConfig;
#[cfg(feature = "cortex-m")]
pub use cortex_m::syscall::SyscallHandler;

// ============================================================================
// RISC-V Architecture
// ============================================================================

#[cfg(feature = "riscv")]
pub mod riscv;

#[cfg(feature = "riscv")]
pub use riscv::*;

// Re-export common types for RISC-V
#[cfg(feature = "riscv")]
pub use riscv::context::{TaskContext, ContextSwitch};
#[cfg(feature = "riscv")]
pub use riscv::pmp::PmpConfig;
#[cfg(feature = "riscv")]
pub use riscv::syscall::SyscallHandler;

// ============================================================================
// Architecture-agnostic traits and types
// ============================================================================

/// Memory protection configuration trait
///
/// Implemented by architecture-specific memory protection units (MPU/PMP).
pub trait MemoryProtection {
    /// Memory protection error type
    type Error;

    /// Configure a memory region
    fn configure_region(
        &mut self,
        region: u8,
        base_addr: usize,
        size: usize,
        permissions: MemoryPermissions,
    ) -> Result<(), Self::Error>;

    /// Enable memory protection
    fn enable(&mut self);

    /// Disable memory protection
    fn disable(&mut self);
}

/// Memory access permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPermissions {
    /// Read access allowed
    pub read: bool,
    /// Write access allowed
    pub write: bool,
    /// Execute access allowed
    pub execute: bool,
    /// Privileged access only
    pub privileged: bool,
}

impl MemoryPermissions {
    /// No access
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
        privileged: false,
    };

    /// Read-only access
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
        privileged: false,
    };

    /// Read-write access
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
        privileged: false,
    };

    /// Execute-only access
    pub const EXECUTE_ONLY: Self = Self {
        read: false,
        write: false,
        execute: true,
        privileged: false,
    };

    /// Read-execute access (typical for code)
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
        privileged: false,
    };

    /// Full access
    pub const FULL: Self = Self {
        read: true,
        write: true,
        execute: true,
        privileged: false,
    };

    /// Privileged read-only
    pub const PRIVILEGED_READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
        privileged: true,
    };

    /// Privileged read-write
    pub const PRIVILEGED_READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
        privileged: true,
    };
}

/// Context switch trait
///
/// Implemented by architecture-specific context switch mechanisms.
pub trait ContextSwitchOps {
    /// Context type
    type Context;

    /// Save current context
    fn save_context(&mut self) -> &Self::Context;

    /// Restore context
    fn restore_context(&mut self, ctx: &Self::Context);

    /// Trigger a context switch
    fn trigger_switch(&mut self);
}

/// System call trait
///
/// Implemented by architecture-specific system call handlers.
pub trait SyscallOps {
    /// Result type
    type Result;

    /// Handle a system call
    fn handle_syscall(&mut self, number: usize, args: &[usize]) -> Self::Result;
}

// ============================================================================
// Fallback stubs for when no architecture is selected
// ============================================================================

#[cfg(not(any(feature = "cortex-m", feature = "riscv")))]
pub mod stub {
    //! Stub implementations for when no architecture is selected.
    //!
    //! These allow the code to compile for testing on host platforms.

    /// Stub task context (matching cortex-m API surface)
    #[derive(Clone, Copy, Default)]
    pub struct TaskContext {
        /// Stack pointer
        pub sp: u32,
        /// Program counter
        pub pc: u32,
    }

    impl TaskContext {
        /// Create a new context
        pub const fn new() -> Self {
            Self { sp: 0, pc: 0 }
        }

        /// Initialize context for a task (matches cortex-m signature)
        pub fn init_stack(
            &mut self,
            stack_top: u32,
            entry: extern "C" fn(),
            _arg: u32,
            _privileged: bool,
        ) -> u32 {
            self.pc = entry as u32;
            self.sp = stack_top;
            stack_top
        }
    }

    /// Stub context switch module
    pub mod context {
        /// Setup context switch (no-op on stub)
        pub fn setup_context_switch(_current: *mut u32, _next: *mut u32) {}

        /// Start first task (stub - loops forever)
        pub fn start_first_task(_sp: u32) -> ! {
            loop {
                core::hint::spin_loop();
            }
        }

        /// Re-export TaskContext
        pub use super::TaskContext;

        /// Stub context switch struct
        pub struct ContextSwitch;

        impl ContextSwitch {
            /// Create new context switch
            pub const fn new() -> Self {
                Self
            }
        }
    }

    /// Enable interrupts (no-op on stub)
    pub fn enable_interrupts() {}

    /// Disable interrupts (no-op on stub)
    pub fn disable_interrupts() {}

    /// Disable interrupts and save state
    pub fn disable_interrupts_save() -> usize {
        0
    }

    /// Restore interrupt state
    pub fn restore_interrupts(_state: usize) {}

    /// Wait for interrupt (no-op on stub)
    pub fn wfi() {}

    /// Data synchronization barrier (no-op on stub)
    pub fn dsb() {}

    /// Instruction synchronization barrier (no-op on stub)
    pub fn isb() {}

    /// Trigger context switch (no-op on stub)
    pub fn trigger_pendsv() {}

    /// Initialize core (no-op on stub)
    pub fn init_core() {}

    /// Configure SysTick timer (no-op on stub)
    pub fn configure_systick(_reload: u32) {}

    // NVIC stubs

    /// Enable IRQ (no-op on stub)
    pub fn nvic_enable_irq(_irq: u16) {}

    /// Disable IRQ (no-op on stub)
    pub fn nvic_disable_irq(_irq: u16) {}

    /// Set IRQ priority (no-op on stub)
    pub fn nvic_set_priority(_irq: u16, _priority: u8) {}

    /// Get IRQ priority (stub returns 0)
    pub fn nvic_get_priority(_irq: u16) -> u8 { 0 }

    /// Set pending IRQ (no-op on stub)
    pub fn nvic_set_pending(_irq: u16) {}

    /// Clear pending IRQ (no-op on stub)
    pub fn nvic_clear_pending(_irq: u16) {}

    /// Check if IRQ is active (stub returns false)
    pub fn nvic_is_active(_irq: u16) -> bool { false }

    /// Maximum handler table size (stub)
    const NVIC_HANDLER_TABLE_SIZE: usize = 150;

    /// Software interrupt handler table (stub)
    static mut INTERRUPT_HANDLERS: [Option<fn()>; NVIC_HANDLER_TABLE_SIZE] =
        [None; NVIC_HANDLER_TABLE_SIZE];

    /// Register interrupt handler (stub)
    pub fn nvic_register_handler(irq: u16, handler: fn()) -> Result<(), ()> {
        if (irq as usize) >= NVIC_HANDLER_TABLE_SIZE {
            return Err(());
        }
        // SAFETY: Accesses the module-level static INTERRUPT_HANDLERS array. In
        // the stub (host test) environment, this is single-threaded. The bounds
        // check is performed above.
        unsafe {
            INTERRUPT_HANDLERS[irq as usize] = Some(handler);
        }
        Ok(())
    }

    /// Unregister interrupt handler (stub)
    pub fn nvic_unregister_handler(irq: u16) {
        if (irq as usize) >= NVIC_HANDLER_TABLE_SIZE {
            return;
        }
        // SAFETY: Same as nvic_register_handler -- single-threaded stub access,
        // bounds-checked above.
        unsafe {
            INTERRUPT_HANDLERS[irq as usize] = None;
        }
    }

    /// Dispatch interrupt (stub)
    pub fn nvic_dispatch(irq: u16) {
        if (irq as usize) >= NVIC_HANDLER_TABLE_SIZE {
            return;
        }
        // SAFETY: Reads from the module-level static INTERRUPT_HANDLERS array.
        // Single-threaded stub environment. Bounds-checked above.
        let handler = unsafe { INTERRUPT_HANDLERS[irq as usize] };
        if let Some(handler_fn) = handler {
            handler_fn();
        }
    }
}

#[cfg(not(any(feature = "cortex-m", feature = "riscv")))]
pub use stub::*;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvic_register_handler() {
        use core::sync::atomic::{AtomicU32, Ordering};
        static CALL_COUNT: AtomicU32 = AtomicU32::new(0);

        fn test_handler() {
            CALL_COUNT.fetch_add(1, Ordering::Relaxed);
        }

        // Reset
        CALL_COUNT.store(0, Ordering::Relaxed);

        // Register
        assert!(stub::nvic_register_handler(42, test_handler).is_ok());

        // Dispatch should call handler
        stub::nvic_dispatch(42);
        assert_eq!(CALL_COUNT.load(Ordering::Relaxed), 1);

        // Dispatch again
        stub::nvic_dispatch(42);
        assert_eq!(CALL_COUNT.load(Ordering::Relaxed), 2);

        // Unregister
        stub::nvic_unregister_handler(42);

        // Dispatch should not call handler
        stub::nvic_dispatch(42);
        assert_eq!(CALL_COUNT.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_nvic_register_out_of_range() {
        fn dummy() {}
        assert!(stub::nvic_register_handler(200, dummy).is_err());
    }

    #[test]
    fn test_memory_permissions() {
        assert!(!MemoryPermissions::NONE.read);
        assert!(!MemoryPermissions::NONE.write);
        assert!(!MemoryPermissions::NONE.execute);

        assert!(MemoryPermissions::READ_ONLY.read);
        assert!(!MemoryPermissions::READ_ONLY.write);

        assert!(MemoryPermissions::FULL.read);
        assert!(MemoryPermissions::FULL.write);
        assert!(MemoryPermissions::FULL.execute);

        assert!(MemoryPermissions::PRIVILEGED_READ_ONLY.privileged);
    }
}
