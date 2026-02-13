// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! RISC-V System Call Handler
//!
//! This module provides the system call interface for RISC-V processors.
//! System calls are invoked via the ECALL instruction.
//!
//! # Calling Convention
//!
//! - Syscall number: a7
//! - Arguments: a0-a6
//! - Return value: a0
//! - Error code: a1 (if applicable)

use q_common::Error;

/// System call numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum SyscallNumber {
    /// Yield execution to scheduler
    Yield = 0,
    /// Sleep for specified ticks
    Sleep = 1,
    /// Exit current task
    Exit = 2,
    /// Get current task ID
    GetTaskId = 3,
    /// Get current time (ticks)
    GetTime = 4,
    /// Send IPC message
    IpcSend = 10,
    /// Receive IPC message
    IpcReceive = 11,
    /// Create IPC channel
    IpcCreateChannel = 12,
    /// Close IPC channel
    IpcCloseChannel = 13,
    /// Allocate memory
    MemAlloc = 20,
    /// Free memory
    MemFree = 21,
    /// Get memory info
    MemInfo = 22,
    /// Debug print
    DebugPrint = 100,
    /// System information
    SysInfo = 101,
    /// Unknown syscall
    Unknown = 0xFFFF,
}

impl From<usize> for SyscallNumber {
    fn from(value: usize) -> Self {
        match value {
            0 => Self::Yield,
            1 => Self::Sleep,
            2 => Self::Exit,
            3 => Self::GetTaskId,
            4 => Self::GetTime,
            10 => Self::IpcSend,
            11 => Self::IpcReceive,
            12 => Self::IpcCreateChannel,
            13 => Self::IpcCloseChannel,
            20 => Self::MemAlloc,
            21 => Self::MemFree,
            22 => Self::MemInfo,
            100 => Self::DebugPrint,
            101 => Self::SysInfo,
            _ => Self::Unknown,
        }
    }
}

/// System call result
#[derive(Debug, Clone, Copy)]
pub struct SyscallResult {
    /// Return value (in a0)
    pub value: usize,
    /// Error code (in a1, 0 = success)
    pub error: usize,
}

impl SyscallResult {
    /// Create a successful result
    pub const fn success(value: usize) -> Self {
        Self { value, error: 0 }
    }

    /// Create an error result
    pub const fn error(error: Error) -> Self {
        Self {
            value: 0,
            error: error as usize,
        }
    }

    /// Check if result is successful
    pub const fn is_ok(&self) -> bool {
        self.error == 0
    }
}

/// System call arguments
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    /// Argument 0 (a0)
    pub arg0: usize,
    /// Argument 1 (a1)
    pub arg1: usize,
    /// Argument 2 (a2)
    pub arg2: usize,
    /// Argument 3 (a3)
    pub arg3: usize,
    /// Argument 4 (a4)
    pub arg4: usize,
    /// Argument 5 (a5)
    pub arg5: usize,
    /// Argument 6 (a6)
    pub arg6: usize,
}

impl SyscallArgs {
    /// Create new syscall arguments
    pub const fn new(
        arg0: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> Self {
        Self {
            arg0,
            arg1,
            arg2,
            arg3,
            arg4,
            arg5,
            arg6,
        }
    }

    /// Create from register array
    pub const fn from_regs(regs: [usize; 7]) -> Self {
        Self {
            arg0: regs[0],
            arg1: regs[1],
            arg2: regs[2],
            arg3: regs[3],
            arg4: regs[4],
            arg5: regs[5],
            arg6: regs[6],
        }
    }
}

/// System call handler trait
pub trait SyscallHandler {
    /// Handle a system call
    fn handle(&mut self, number: SyscallNumber, args: SyscallArgs) -> SyscallResult;
}

/// Default system call handler
pub struct DefaultSyscallHandler;

impl DefaultSyscallHandler {
    /// Create a new default handler
    pub const fn new() -> Self {
        Self
    }
}

impl SyscallHandler for DefaultSyscallHandler {
    fn handle(&mut self, number: SyscallNumber, args: SyscallArgs) -> SyscallResult {
        match number {
            SyscallNumber::Yield => {
                // Trigger context switch
                super::trigger_software_interrupt();
                SyscallResult::success(0)
            }

            SyscallNumber::Sleep => {
                // Sleep for args.arg0 ticks
                let _ticks = args.arg0;
                // Actual implementation would update task state and trigger switch
                SyscallResult::success(0)
            }

            SyscallNumber::Exit => {
                // Exit with code args.arg0
                let _exit_code = args.arg0;
                // Actual implementation would mark task as terminated
                SyscallResult::success(0)
            }

            SyscallNumber::GetTaskId => {
                // Return current task ID
                // Actual implementation would query scheduler
                SyscallResult::success(0)
            }

            SyscallNumber::GetTime => {
                // Return current tick count
                let time = super::get_timer();
                SyscallResult::success(time as usize)
            }

            SyscallNumber::IpcSend => {
                // Send IPC message
                // args.arg0 = channel_id, args.arg1 = msg_ptr, args.arg2 = msg_len
                SyscallResult::success(0)
            }

            SyscallNumber::IpcReceive => {
                // Receive IPC message
                // args.arg0 = channel_id, args.arg1 = buf_ptr, args.arg2 = buf_len
                SyscallResult::success(0)
            }

            SyscallNumber::IpcCreateChannel => {
                // Create IPC channel
                SyscallResult::success(0)
            }

            SyscallNumber::IpcCloseChannel => {
                // Close IPC channel
                SyscallResult::success(0)
            }

            SyscallNumber::MemAlloc => {
                // Allocate memory
                // args.arg0 = size, args.arg1 = alignment
                SyscallResult::error(Error::NotImplemented)
            }

            SyscallNumber::MemFree => {
                // Free memory
                // args.arg0 = ptr
                SyscallResult::error(Error::NotImplemented)
            }

            SyscallNumber::MemInfo => {
                // Get memory info
                SyscallResult::success(0)
            }

            SyscallNumber::DebugPrint => {
                // Debug print
                // args.arg0 = string_ptr, args.arg1 = string_len
                SyscallResult::success(0)
            }

            SyscallNumber::SysInfo => {
                // System information
                SyscallResult::success(0)
            }

            SyscallNumber::Unknown => {
                SyscallResult::error(Error::InvalidParameter)
            }
        }
    }
}

/// Handle ECALL from trap handler
///
/// This function is called by the trap handler when an ECALL is detected.
/// It extracts the syscall number and arguments from the trap frame and
/// dispatches to the appropriate handler.
#[no_mangle]
pub extern "C" fn handle_ecall(
    syscall_num: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> SyscallResult {
    let number = SyscallNumber::from(syscall_num);
    let args = SyscallArgs::new(a0, a1, a2, a3, a4, a5, a6);

    // Use default handler for now
    // In a full implementation, this would dispatch to registered handlers
    let mut handler = DefaultSyscallHandler::new();
    handler.handle(number, args)
}

/// Invoke a system call from user code
///
/// # Safety
///
/// The caller must ensure that the arguments are valid for the given syscall.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[inline]
pub unsafe fn syscall(
    number: SyscallNumber,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> SyscallResult {
    let ret_val: usize;
    let ret_err: usize;

    // SAFETY: ECALL triggers a synchronous trap to the registered trap handler,
    // which dispatches to the syscall handler. The arguments are passed via
    // registers per the RISC-V calling convention. The caller (marked unsafe)
    // must ensure arguments are valid.
    core::arch::asm!(
        "ecall",
        inout("a0") arg0 => ret_val,
        inout("a1") arg1 => ret_err,
        in("a2") arg2,
        in("a3") arg3,
        in("a4") arg4,
        in("a5") arg5,
        in("a7") number as usize,
        options(nostack)
    );

    SyscallResult {
        value: ret_val,
        error: ret_err,
    }
}

/// Invoke a system call (stub for non-RISC-V targets)
#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
#[inline]
pub unsafe fn syscall(
    number: SyscallNumber,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> SyscallResult {
    let args = SyscallArgs::new(arg0, arg1, arg2, arg3, arg4, arg5, 0);
    let mut handler = DefaultSyscallHandler::new();
    handler.handle(number, args)
}

// ============================================================================
// Convenience wrappers for common syscalls
// ============================================================================

/// Yield execution to the scheduler
pub fn sys_yield() -> SyscallResult {
    unsafe { syscall(SyscallNumber::Yield, 0, 0, 0, 0, 0, 0) }
}

/// Sleep for specified ticks
pub fn sys_sleep(ticks: usize) -> SyscallResult {
    unsafe { syscall(SyscallNumber::Sleep, ticks, 0, 0, 0, 0, 0) }
}

/// Exit current task
pub fn sys_exit(code: usize) -> ! {
    unsafe {
        syscall(SyscallNumber::Exit, code, 0, 0, 0, 0, 0);
    }
    // Should not return, but loop just in case
    loop {
        super::wfi();
    }
}

/// Get current task ID
pub fn sys_get_task_id() -> usize {
    unsafe { syscall(SyscallNumber::GetTaskId, 0, 0, 0, 0, 0, 0).value }
}

/// Get current time in ticks
pub fn sys_get_time() -> usize {
    unsafe { syscall(SyscallNumber::GetTime, 0, 0, 0, 0, 0, 0).value }
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
        assert_eq!(SyscallNumber::from(2), SyscallNumber::Exit);
        assert_eq!(SyscallNumber::from(9999), SyscallNumber::Unknown);
    }

    #[test]
    fn test_syscall_result_success() {
        let result = SyscallResult::success(42);
        assert!(result.is_ok());
        assert_eq!(result.value, 42);
        assert_eq!(result.error, 0);
    }

    #[test]
    fn test_syscall_result_error() {
        let result = SyscallResult::error(Error::InvalidParameter);
        assert!(!result.is_ok());
        assert_eq!(result.value, 0);
    }

    #[test]
    fn test_syscall_args() {
        let args = SyscallArgs::new(1, 2, 3, 4, 5, 6, 7);
        assert_eq!(args.arg0, 1);
        assert_eq!(args.arg1, 2);
        assert_eq!(args.arg6, 7);
    }

    #[test]
    fn test_default_handler_yield() {
        let mut handler = DefaultSyscallHandler::new();
        let args = SyscallArgs::new(0, 0, 0, 0, 0, 0, 0);
        let result = handler.handle(SyscallNumber::Yield, args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_handler_unknown() {
        let mut handler = DefaultSyscallHandler::new();
        let args = SyscallArgs::new(0, 0, 0, 0, 0, 0, 0);
        let result = handler.handle(SyscallNumber::Unknown, args);
        assert!(!result.is_ok());
    }
}
