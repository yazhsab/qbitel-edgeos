// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! ARM Cortex-M System Call (SVC) Handler
//!
//! This module implements the SVC (Supervisor Call) exception handler for
//! system calls on ARM Cortex-M processors.
//!
//! # SVC Mechanism
//!
//! The SVC instruction triggers a synchronous exception that transitions
//! from unprivileged (Thread) mode to privileged (Handler) mode, allowing
//! tasks to request kernel services.
//!
//! # Calling Convention
//!
//! System calls use the ARM AAPCS calling convention:
//! - R0-R3: Arguments (up to 4)
//! - R0: Return value
//! - SVC number: Encoded in the SVC instruction immediate field
//!
//! # Example Usage (from user task)
//!
//! ```no_run
//! // Yield to scheduler
//! unsafe { asm!("svc 0", options(nomem, nostack)); }
//!
//! // Sleep for N milliseconds
//! unsafe { asm!("svc 1", in("r0") ms, options(nomem, nostack)); }
//! ```

use core::arch::{asm, global_asm};
use core::ptr;

use super::context::ExceptionFrame;

// ============================================================================
// System Call Numbers
// ============================================================================

/// System call numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SyscallNumber {
    /// Yield to scheduler (cooperative multitasking)
    Yield = 0,
    /// Sleep for specified milliseconds
    Sleep = 1,
    /// Exit current task
    Exit = 2,
    /// Get current tick count
    GetTicks = 3,
    /// Get task ID
    GetTaskId = 4,
    /// Send IPC message
    IpcSend = 5,
    /// Receive IPC message
    IpcReceive = 6,
    /// Allocate memory
    MemAlloc = 7,
    /// Free memory
    MemFree = 8,
    /// Create a new task
    TaskCreate = 9,
    /// Wait for event
    WaitEvent = 10,
    /// Signal event
    SignalEvent = 11,
    /// Get random bytes
    GetRandom = 12,
    /// Read secure storage
    SecureRead = 13,
    /// Write secure storage
    SecureWrite = 14,
    /// Get hardware fingerprint
    GetHwFingerprint = 15,
    /// Attestation quote
    AttestQuote = 16,
    /// Unknown/invalid syscall
    Unknown = 255,
}

impl From<u8> for SyscallNumber {
    fn from(n: u8) -> Self {
        match n {
            0 => Self::Yield,
            1 => Self::Sleep,
            2 => Self::Exit,
            3 => Self::GetTicks,
            4 => Self::GetTaskId,
            5 => Self::IpcSend,
            6 => Self::IpcReceive,
            7 => Self::MemAlloc,
            8 => Self::MemFree,
            9 => Self::TaskCreate,
            10 => Self::WaitEvent,
            11 => Self::SignalEvent,
            12 => Self::GetRandom,
            13 => Self::SecureRead,
            14 => Self::SecureWrite,
            15 => Self::GetHwFingerprint,
            16 => Self::AttestQuote,
            _ => Self::Unknown,
        }
    }
}

// ============================================================================
// System Call Result
// ============================================================================

/// System call result codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SyscallResult {
    /// Success
    Ok = 0,
    /// Invalid syscall number
    InvalidSyscall = -1,
    /// Invalid argument
    InvalidArg = -2,
    /// Permission denied
    PermissionDenied = -3,
    /// Resource not found
    NotFound = -4,
    /// Resource busy
    Busy = -5,
    /// Timeout
    Timeout = -6,
    /// Out of memory
    OutOfMemory = -7,
    /// Operation would block
    WouldBlock = -8,
    /// Buffer too small
    BufferTooSmall = -9,
    /// Internal error
    InternalError = -10,
}

impl SyscallResult {
    /// Convert to i32 for return in R0
    pub fn to_i32(self) -> i32 {
        self as i32
    }
}

// ============================================================================
// System Call Handler
// ============================================================================

/// System call handler trait
///
/// Implement this trait to provide custom system call handling.
pub trait SyscallHandler {
    /// Handle a system call
    ///
    /// # Arguments
    /// * `number` - System call number
    /// * `args` - Arguments (R0-R3 from caller)
    ///
    /// # Returns
    /// Result value to place in R0
    fn handle(&mut self, number: SyscallNumber, args: &SyscallArgs) -> i32;
}

/// System call arguments (R0-R3)
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    /// R0 (first argument / return value)
    pub r0: u32,
    /// R1 (second argument)
    pub r1: u32,
    /// R2 (third argument)
    pub r2: u32,
    /// R3 (fourth argument)
    pub r3: u32,
}

impl SyscallArgs {
    /// Get argument as u32
    pub fn arg(&self, index: usize) -> u32 {
        match index {
            0 => self.r0,
            1 => self.r1,
            2 => self.r2,
            3 => self.r3,
            _ => 0,
        }
    }

    /// Get argument as pointer
    pub fn arg_ptr<T>(&self, index: usize) -> *const T {
        self.arg(index) as *const T
    }

    /// Get argument as mutable pointer
    pub fn arg_ptr_mut<T>(&self, index: usize) -> *mut T {
        self.arg(index) as *mut T
    }
}

// ============================================================================
// Default System Call Handler
// ============================================================================

/// Default system call handler
pub struct DefaultSyscallHandler {
    /// System tick counter
    ticks: u64,
    /// Current task ID
    current_task: u8,
}

impl DefaultSyscallHandler {
    /// Create new default handler
    pub const fn new() -> Self {
        Self {
            ticks: 0,
            current_task: 0,
        }
    }

    /// Set current task
    pub fn set_current_task(&mut self, task_id: u8) {
        self.current_task = task_id;
    }

    /// Increment tick counter
    pub fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
    }
}

impl Default for DefaultSyscallHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallHandler for DefaultSyscallHandler {
    fn handle(&mut self, number: SyscallNumber, args: &SyscallArgs) -> i32 {
        match number {
            SyscallNumber::Yield => {
                // Request context switch
                super::trigger_pendsv();
                SyscallResult::Ok.to_i32()
            }

            SyscallNumber::Sleep => {
                let ms = args.r0;
                // Put the current task to sleep for the specified milliseconds
                // The scheduler will wake it when the time elapses
                crate::scheduler::sleep_ms(ms);
                SyscallResult::Ok.to_i32()
            }

            SyscallNumber::Exit => {
                let _exit_code = args.r0 as i32;
                // Mark the current task as terminated and trigger context switch
                // The scheduler will not schedule this task again
                crate::scheduler::terminate_current();
                // This point should never be reached since terminate_current()
                // triggers a context switch, but return Ok for safety
                SyscallResult::Ok.to_i32()
            }

            SyscallNumber::GetTicks => {
                // Return lower 32 bits of tick count
                self.ticks as i32
            }

            SyscallNumber::GetTaskId => {
                self.current_task as i32
            }

            SyscallNumber::IpcSend => {
                let channel_id = args.r0 as u8;
                let data_ptr = args.r1 as *const u8;
                let data_len = args.r2 as usize;

                // Validate pointer and length
                if data_ptr.is_null() || data_len > crate::ipc::MAX_MESSAGE_SIZE {
                    return SyscallResult::InvalidArg.to_i32();
                }

                // Construct slice from user-space pointer
                // Safety: the pointer comes from the calling task's address space.
                // MPU ensures the task owns this memory region.
                let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len) };

                match crate::ipc::get_channel(channel_id) {
                    Ok(channel) => {
                        match channel.send(0, data, self.current_task) {
                            Ok(()) => SyscallResult::Ok.to_i32(),
                            Err(_) => SyscallResult::WouldBlock.to_i32(),
                        }
                    }
                    Err(_) => SyscallResult::NotFound.to_i32(),
                }
            }

            SyscallNumber::IpcReceive => {
                let channel_id = args.r0 as u8;
                let buf_ptr = args.r1 as *mut u8;
                let buf_len = args.r2 as usize;

                if buf_ptr.is_null() || buf_len == 0 {
                    return SyscallResult::InvalidArg.to_i32();
                }

                // SAFETY: The buffer pointer and length come from the calling task's registers
                // (R1, R2). The MPU enforces that the task owns this memory region. The pointer
                // is checked for null and length for zero above.
                let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buf_len) };

                match crate::ipc::get_channel(channel_id) {
                    Ok(channel) => {
                        match channel.receive(buf, self.current_task) {
                            Ok((_header, bytes_received)) => bytes_received as i32,
                            Err(q_common::Error::WouldBlock) => SyscallResult::WouldBlock.to_i32(),
                            Err(q_common::Error::BufferTooSmall) => SyscallResult::BufferTooSmall.to_i32(),
                            Err(_) => SyscallResult::InternalError.to_i32(),
                        }
                    }
                    Err(_) => SyscallResult::NotFound.to_i32(),
                }
            }

            SyscallNumber::MemAlloc => {
                // No heap allocator — return not supported
                SyscallResult::OutOfMemory.to_i32()
            }

            SyscallNumber::MemFree => {
                // No heap allocator — return not supported
                SyscallResult::InvalidArg.to_i32()
            }

            SyscallNumber::TaskCreate => {
                // Task creation from user space is restricted
                // R0 = entry point address, R1 = stack_size, R2 = priority
                SyscallResult::PermissionDenied.to_i32()
            }

            SyscallNumber::WaitEvent => {
                let event_mask = args.r0;
                let _timeout_ms = args.r1;

                // Check signals for the current task
                match crate::ipc::check_signals(self.current_task, event_mask) {
                    Ok(matched) if matched != 0 => matched as i32,
                    Ok(_) => {
                        // No signals matched — block the task
                        crate::scheduler::block();
                        SyscallResult::Timeout.to_i32()
                    }
                    Err(_) => SyscallResult::InvalidArg.to_i32(),
                }
            }

            SyscallNumber::SignalEvent => {
                let target_task = args.r0 as u8;
                let signals = args.r1;

                match crate::ipc::send_signal(target_task, signals) {
                    Ok(()) => {
                        // Unblock the target task if it was waiting
                        crate::scheduler::unblock(crate::task::TaskId::new(target_task));
                        SyscallResult::Ok.to_i32()
                    }
                    Err(_) => SyscallResult::InvalidArg.to_i32(),
                }
            }

            SyscallNumber::GetRandom => {
                // Requires HAL RNG service — not yet wired
                SyscallResult::InternalError.to_i32()
            }

            SyscallNumber::SecureRead => {
                // Requires HAL secure storage service
                SyscallResult::PermissionDenied.to_i32()
            }

            SyscallNumber::SecureWrite => {
                // Requires HAL secure storage service
                SyscallResult::PermissionDenied.to_i32()
            }

            SyscallNumber::GetHwFingerprint => {
                // Requires HAL PUF service
                SyscallResult::PermissionDenied.to_i32()
            }

            SyscallNumber::AttestQuote => {
                // Requires attestation subsystem
                SyscallResult::PermissionDenied.to_i32()
            }

            SyscallNumber::Unknown => {
                SyscallResult::InvalidSyscall.to_i32()
            }
        }
    }
}

// ============================================================================
// Global Handler Instance
// ============================================================================

/// Global syscall handler instance
static mut SYSCALL_HANDLER: DefaultSyscallHandler = DefaultSyscallHandler::new();

/// Get the syscall handler
///
/// # Safety
/// Must be called from handler mode (during SVC exception)
pub unsafe fn get_handler() -> *mut DefaultSyscallHandler {
    core::ptr::addr_of_mut!(SYSCALL_HANDLER)
}

// ============================================================================
// SVC Handler Implementation
// ============================================================================

/// Extract SVC number from the stacked PC
///
/// The SVC instruction encodes the syscall number in its immediate field.
/// We read the instruction at (PC - 2) to get the SVC number.
#[inline]
fn extract_svc_number(stacked_pc: u32) -> u8 {
    // SVC instruction is at PC - 2 (Thumb instruction)
    let svc_instruction_addr = (stacked_pc - 2) as *const u16;
    // SAFETY: The stacked_pc comes from the hardware-saved exception frame and points to the
    // instruction after the SVC. Reading (PC - 2) gives the SVC instruction itself (Thumb
    // encoding). The instruction is in the task's code region which is always readable.
    // volatile read is used because the instruction may be in flash.
    let svc_instruction = unsafe { ptr::read_volatile(svc_instruction_addr) };

    // SVC number is in bits 7:0 of the instruction
    (svc_instruction & 0xFF) as u8
}

// SVC exception handler (using global_asm! for stable Rust)
//
// This is called when an SVC instruction is executed. The handler:
// 1. Determines which stack (MSP/PSP) was in use
// 2. Extracts the SVC number from the stacked PC
// 3. Reads arguments from stacked R0-R3
// 4. Calls the syscall handler
// 5. Writes the result to stacked R0
#[cfg(target_arch = "arm")]
global_asm!(
    ".syntax unified",
    ".thumb",
    ".section .text.SVC_Handler",
    ".global SVC_Handler",
    ".type SVC_Handler, %function",
    ".thumb_func",
    "SVC_Handler:",
    // Determine which stack pointer was used (check EXC_RETURN bit 2)
    "    tst lr, #4",
    "    ite eq",
    "    mrseq r0, msp",      // If 0, exception used MSP
    "    mrsne r0, psp",      // If 1, exception used PSP
    // R0 now points to the exception frame
    // Call the C handler
    "    bl svc_handler_c",
    // Return from exception
    "    bx lr",
    ".size SVC_Handler, . - SVC_Handler",
);

/// C-callable SVC handler
///
/// # Arguments
/// * `frame` - Pointer to the stacked exception frame
#[no_mangle]
extern "C" fn svc_handler_c(frame: *mut ExceptionFrame) {
    // SAFETY: The frame pointer is provided by the SVC assembly trampoline, which extracts it
    // from MSP or PSP (the active stack when the SVC was executed). The hardware guarantees the
    // exception frame is valid. SYSCALL_HANDLER is a global instance only accessed from this
    // handler (SVC exception context) — no concurrent access is possible because SVC is
    // synchronous and non-reentrant. Writing to frame.r0 modifies the stacked R0, which becomes
    // the return value when the exception returns.
    unsafe {
        let frame = &mut *frame;

        // Extract SVC number from the instruction at (PC - 2)
        let svc_number = extract_svc_number(frame.pc);

        // Build syscall arguments from stacked registers
        let args = SyscallArgs {
            r0: frame.r0,
            r1: frame.r1,
            r2: frame.r2,
            r3: frame.r3,
        };

        // Get syscall number enum
        let syscall = SyscallNumber::from(svc_number);

        // Call handler
        let result = (*core::ptr::addr_of_mut!(SYSCALL_HANDLER)).handle(syscall, &args);

        // Write result to R0 in the exception frame
        frame.r0 = result as u32;
    }
}

// ============================================================================
// User-Space System Call Wrappers
// ============================================================================

/// Yield to scheduler
#[inline]
pub fn sys_yield() {
    // SAFETY: SVC 0 triggers a synchronous supervisor call to the SVC handler, which dispatches
    // to the Yield syscall. The nomem/nostack options are correct as the instruction only
    // triggers an exception.
    unsafe {
        asm!("svc 0", options(nomem, nostack));
    }
}

/// Sleep for specified milliseconds
#[inline]
pub fn sys_sleep(ms: u32) {
    // SAFETY: SVC 1 triggers the Sleep syscall. The ms argument is passed in R0 per ARM calling
    // convention. nomem/nostack correct — the SVC instruction itself doesn't access memory or
    // stack.
    unsafe {
        asm!(
            "svc 1",
            in("r0") ms,
            options(nomem, nostack)
        );
    }
}

/// Exit current task
#[inline]
pub fn sys_exit(code: i32) -> ! {
    // SAFETY: SVC 2 triggers the Exit syscall with the exit code in R0. The noreturn option
    // tells the compiler this diverges. The SVC handler terminates the task and triggers a
    // context switch, so control never returns here.
    unsafe {
        asm!(
            "svc 2",
            in("r0") code,
            options(nomem, nostack, noreturn)
        );
    }
}

/// Get current tick count
#[inline]
pub fn sys_get_ticks() -> u32 {
    let result: u32;
    // SAFETY: SVC 3 triggers GetTicks. The result is returned in R0 by the SVC handler.
    // nomem/nostack correct.
    unsafe {
        asm!(
            "svc 3",
            out("r0") result,
            options(nomem, nostack)
        );
    }
    result
}

/// Get current task ID
#[inline]
pub fn sys_get_task_id() -> u8 {
    let result: u32;
    // SAFETY: SVC 4 triggers GetTaskId. Result returned in R0. nomem/nostack correct.
    unsafe {
        asm!(
            "svc 4",
            out("r0") result,
            options(nomem, nostack)
        );
    }
    result as u8
}

/// Send IPC message
#[inline]
pub fn sys_ipc_send(channel: u32, data: &[u8]) -> i32 {
    let result: i32;
    // SAFETY: SVC 5 triggers IpcSend with channel in R0, data pointer in R1, length in R2. The
    // readonly option indicates the instruction only reads the data buffer. The caller provides
    // a valid slice.
    unsafe {
        asm!(
            "svc 5",
            in("r0") channel,
            in("r1") data.as_ptr(),
            in("r2") data.len(),
            lateout("r0") result,
            options(readonly, nostack)
        );
    }
    result
}

/// Receive IPC message
#[inline]
pub fn sys_ipc_receive(channel: u32, buffer: &mut [u8]) -> i32 {
    let result: i32;
    // SAFETY: SVC 6 triggers IpcReceive with channel in R0, buffer pointer in R1, length in R2.
    // The nostack option is correct. The caller provides a valid mutable buffer.
    unsafe {
        asm!(
            "svc 6",
            in("r0") channel,
            in("r1") buffer.as_mut_ptr(),
            in("r2") buffer.len(),
            lateout("r0") result,
            options(nostack)
        );
    }
    result
}

/// Get random bytes
#[inline]
pub fn sys_get_random(buffer: &mut [u8]) -> i32 {
    let result: i32;
    // SAFETY: SVC 12 triggers GetRandom with buffer pointer in R0 and length in R1. The nostack
    // option is correct. The caller provides a valid mutable buffer.
    unsafe {
        asm!(
            "svc 12",
            in("r0") buffer.as_mut_ptr(),
            in("r1") buffer.len(),
            lateout("r0") result,
            options(nostack)
        );
    }
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_number_conversion() {
        assert_eq!(SyscallNumber::from(0), SyscallNumber::Yield);
        assert_eq!(SyscallNumber::from(1), SyscallNumber::Sleep);
        assert_eq!(SyscallNumber::from(255), SyscallNumber::Unknown);
        assert_eq!(SyscallNumber::from(100), SyscallNumber::Unknown);
    }

    #[test]
    fn test_syscall_result() {
        assert_eq!(SyscallResult::Ok.to_i32(), 0);
        assert_eq!(SyscallResult::InvalidSyscall.to_i32(), -1);
    }

    #[test]
    fn test_default_handler_creation() {
        let handler = DefaultSyscallHandler::new();
        assert_eq!(handler.ticks, 0);
        assert_eq!(handler.current_task, 0);
    }

    #[test]
    fn test_handler_tick() {
        let mut handler = DefaultSyscallHandler::new();
        handler.tick();
        handler.tick();
        handler.tick();
        let args = SyscallArgs { r0: 0, r1: 0, r2: 0, r3: 0 };
        let result = handler.handle(SyscallNumber::GetTicks, &args);
        assert_eq!(result, 3);
    }

    #[test]
    fn test_handler_get_task_id() {
        let mut handler = DefaultSyscallHandler::new();
        handler.set_current_task(7);
        let args = SyscallArgs { r0: 0, r1: 0, r2: 0, r3: 0 };
        let result = handler.handle(SyscallNumber::GetTaskId, &args);
        assert_eq!(result, 7);
    }

    #[test]
    fn test_handler_unknown_syscall() {
        let mut handler = DefaultSyscallHandler::new();
        let args = SyscallArgs { r0: 0, r1: 0, r2: 0, r3: 0 };
        let result = handler.handle(SyscallNumber::Unknown, &args);
        assert_eq!(result, SyscallResult::InvalidSyscall.to_i32());
    }

    #[test]
    fn test_handler_mem_alloc_unsupported() {
        let mut handler = DefaultSyscallHandler::new();
        let args = SyscallArgs { r0: 1024, r1: 0, r2: 0, r3: 0 };
        let result = handler.handle(SyscallNumber::MemAlloc, &args);
        assert_eq!(result, SyscallResult::OutOfMemory.to_i32());
    }

    #[test]
    fn test_handler_secure_ops_denied() {
        let mut handler = DefaultSyscallHandler::new();
        let args = SyscallArgs { r0: 0, r1: 0, r2: 0, r3: 0 };

        assert_eq!(
            handler.handle(SyscallNumber::SecureRead, &args),
            SyscallResult::PermissionDenied.to_i32()
        );
        assert_eq!(
            handler.handle(SyscallNumber::SecureWrite, &args),
            SyscallResult::PermissionDenied.to_i32()
        );
        assert_eq!(
            handler.handle(SyscallNumber::GetHwFingerprint, &args),
            SyscallResult::PermissionDenied.to_i32()
        );
        assert_eq!(
            handler.handle(SyscallNumber::AttestQuote, &args),
            SyscallResult::PermissionDenied.to_i32()
        );
    }

    #[test]
    fn test_handler_task_create_denied() {
        let mut handler = DefaultSyscallHandler::new();
        let args = SyscallArgs { r0: 0x0800_0000, r1: 2048, r2: 2, r3: 0 };
        let result = handler.handle(SyscallNumber::TaskCreate, &args);
        assert_eq!(result, SyscallResult::PermissionDenied.to_i32());
    }

    #[test]
    fn test_ipc_send_null_pointer() {
        let mut handler = DefaultSyscallHandler::new();
        let args = SyscallArgs { r0: 0, r1: 0, r2: 10, r3: 0 }; // null data_ptr
        let result = handler.handle(SyscallNumber::IpcSend, &args);
        assert_eq!(result, SyscallResult::InvalidArg.to_i32());
    }

    #[test]
    fn test_ipc_receive_null_pointer() {
        let mut handler = DefaultSyscallHandler::new();
        let args = SyscallArgs { r0: 0, r1: 0, r2: 0, r3: 0 }; // null buf_ptr, zero len
        let result = handler.handle(SyscallNumber::IpcReceive, &args);
        assert_eq!(result, SyscallResult::InvalidArg.to_i32());
    }

    #[test]
    fn test_syscall_args_accessors() {
        let args = SyscallArgs { r0: 10, r1: 20, r2: 30, r3: 40 };
        assert_eq!(args.arg(0), 10);
        assert_eq!(args.arg(1), 20);
        assert_eq!(args.arg(2), 30);
        assert_eq!(args.arg(3), 40);
        assert_eq!(args.arg(4), 0); // out of range
    }
}
