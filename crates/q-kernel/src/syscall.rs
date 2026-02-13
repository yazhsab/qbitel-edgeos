// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! System call interface
//!
//! Provides the kernel system call dispatch layer. User tasks invoke system
//! calls via SVC instruction (Cortex-M) or ECALL (RISC-V), which are routed
//! to `handle_syscall()` by the architecture exception handler.
//!
//! # System Call Numbers
//!
//! | Number | Name       | arg0          | arg1          | arg2          | Returns       |
//! |--------|------------|---------------|---------------|---------------|---------------|
//! | 0      | Yield      | —             | —             | —             | 0             |
//! | 1      | Sleep      | ticks (u32)   | —             | —             | 0             |
//! | 2      | IpcSend    | channel_id    | msg_type      | data_len      | 0 or -errno   |
//! | 3      | IpcReceive | channel_id    | buf_len       | —             | bytes or -err |
//! | 4      | GetTime    | —             | —             | —             | ticks (i32)   |
//! | 5      | Exit       | —             | —             | —             | (no return)   |

/// System call numbers
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syscall {
    /// Yield to scheduler
    Yield = 0,
    /// Sleep for ticks
    Sleep = 1,
    /// Send IPC message
    IpcSend = 2,
    /// Receive IPC message
    IpcReceive = 3,
    /// Get current time
    GetTime = 4,
    /// Exit task
    Exit = 5,
}

/// Error codes returned as negative i32 values
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    /// Unknown system call number
    InvalidSyscall = -1,
    /// Invalid argument
    InvalidArgument = -2,
    /// IPC operation failed
    IpcError = -3,
    /// Resource not found (channel, mailbox)
    NotFound = -4,
    /// Operation not supported on this platform
    NotSupported = -5,
}

/// System call handler — dispatches based on syscall number
///
/// Called from the architecture-specific SVC/ECALL exception handler.
///
/// # Arguments
/// * `number` — System call number (see [`Syscall`])
/// * `arg0`–`arg2` — Syscall-specific arguments
///
/// # Returns
/// Non-negative value on success, negative [`SyscallError`] on failure.
pub fn handle_syscall(number: u32, arg0: u32, arg1: u32, arg2: u32) -> i32 {
    match number {
        // Syscall 0: Yield
        0 => {
            crate::scheduler::yield_now();
            0
        }

        // Syscall 1: Sleep(ticks)
        1 => {
            crate::scheduler::sleep(arg0 as u64);
            0
        }

        // Syscall 2: IpcSend(channel_id, msg_type, data_len)
        2 => syscall_ipc_send(arg0, arg1, arg2),

        // Syscall 3: IpcReceive(channel_id, buf_len, _)
        3 => syscall_ipc_receive(arg0, arg1),

        // Syscall 4: GetTime
        4 => {
            let ticks = crate::scheduler::ticks();
            // Truncate to i32 (wraps every ~24 days at 1kHz)
            ticks as i32
        }

        // Syscall 5: Exit
        5 => {
            crate::scheduler::terminate_current();
            // terminate_current triggers a context switch;
            // this return is only reached on stub/host platforms.
            0
        }

        // Unknown syscall
        _ => SyscallError::InvalidSyscall as i32,
    }
}

/// IPC Send syscall implementation
///
/// Sends a message on the specified channel. On ARM targets the data pointer
/// is read from register R3 of the current task's saved context. On non-ARM
/// hosts, only signalling (zero-length messages) is supported.
fn syscall_ipc_send(channel_id: u32, msg_type: u32, data_len: u32) -> i32 {
    if data_len > crate::ipc::MAX_MESSAGE_SIZE as u32 {
        return SyscallError::InvalidArgument as i32;
    }

    // Get the current task ID for sender identification
    let sender_id = match crate::scheduler::current_task() {
        Some(id) => id.0,
        None => return SyscallError::IpcError as i32,
    };

    // Get the channel
    let channel = match crate::ipc::get_channel(channel_id as u8) {
        Ok(ch) => ch,
        Err(_) => return SyscallError::NotFound as i32,
    };

    if data_len == 0 {
        // Zero-length message: pure signalling, no data to copy
        let empty: [u8; 0] = [];
        return match channel.send(msg_type as u16, &empty, sender_id) {
            Ok(()) => 0,
            Err(_) => SyscallError::IpcError as i32,
        };
    }

    // Read the data from the task's memory via the pointer passed in R3.
    // On ARM Cortex-M, SVC arguments are R0-R3; the data pointer is in R3.
    #[cfg(target_arch = "arm")]
    {
        // Get the data pointer from the current task's saved register context.
        // R3 holds the pointer to the user-space buffer.
        let data_ptr = match crate::scheduler::current_task_register(3) {
            Some(ptr) => ptr as *const u8,
            None => return SyscallError::IpcError as i32,
        };

        // Validate the pointer is within the task's memory region
        if !crate::memory::validate_user_pointer(data_ptr, data_len as usize) {
            return SyscallError::InvalidArgument as i32;
        }

        // SAFETY: The pointer has been validated to be within the current
        // task's memory region and data_len <= MAX_MESSAGE_SIZE. The task's
        // memory is accessible in privileged mode.
        let data = unsafe {
            core::slice::from_raw_parts(data_ptr, data_len as usize)
        };

        match channel.send(msg_type as u16, data, sender_id) {
            Ok(()) => 0,
            Err(_) => SyscallError::IpcError as i32,
        }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        // On non-ARM hosts we cannot reconstruct user-space pointers.
        // Only zero-length (signalling) messages are supported above.
        SyscallError::NotSupported as i32
    }
}

/// IPC Receive syscall implementation
///
/// Receives a message from the specified channel. On ARM targets, the
/// received data is copied into the task's buffer (pointer from R2,
/// length from R3). Returns the number of bytes received on success,
/// or a negative error code.
fn syscall_ipc_receive(channel_id: u32, buf_len: u32) -> i32 {
    // Get the current task ID for receiver identification
    let receiver_id = match crate::scheduler::current_task() {
        Some(id) => id.0,
        None => return SyscallError::IpcError as i32,
    };

    // Get the channel
    let channel = match crate::ipc::get_channel(channel_id as u8) {
        Ok(ch) => ch,
        Err(_) => return SyscallError::NotFound as i32,
    };

    // Receive into a kernel-side buffer first
    let mut kernel_buf = [0u8; crate::ipc::MAX_MESSAGE_SIZE];
    let (header, bytes_received) = match channel.receive(&mut kernel_buf, receiver_id) {
        Ok(result) => result,
        Err(_) => return SyscallError::IpcError as i32,
    };

    let _ = header; // Message header available for future use

    // Copy received data to the task's user-space buffer
    #[cfg(target_arch = "arm")]
    {
        // R2 holds the destination buffer pointer, R3 holds max length
        let dest_ptr = match crate::scheduler::current_task_register(2) {
            Some(ptr) => ptr as *mut u8,
            None => return SyscallError::IpcError as i32,
        };

        let copy_len = bytes_received.min(buf_len as usize);

        // Validate the destination pointer
        if copy_len > 0 && !crate::memory::validate_user_pointer(dest_ptr as *const u8, copy_len) {
            return SyscallError::InvalidArgument as i32;
        }

        if copy_len > 0 {
            // SAFETY: dest_ptr validated to be within task memory,
            // copy_len <= buf_len and <= bytes_received.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    kernel_buf.as_ptr(),
                    dest_ptr,
                    copy_len,
                );
            }
        }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let _ = buf_len;
    }

    bytes_received as i32
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_yield() {
        let result = handle_syscall(0, 0, 0, 0);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_syscall_get_time() {
        let result = handle_syscall(4, 0, 0, 0);
        // Ticks should be 0 in test (scheduler not running)
        assert_eq!(result, 0);
    }

    #[test]
    fn test_syscall_invalid() {
        let result = handle_syscall(99, 0, 0, 0);
        assert_eq!(result, SyscallError::InvalidSyscall as i32);
    }

    #[test]
    fn test_syscall_sleep() {
        let result = handle_syscall(1, 100, 0, 0);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_syscall_exit() {
        // On host stub, terminate_current is a no-op
        let result = handle_syscall(5, 0, 0, 0);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_syscall_ipc_send_invalid_channel() {
        // Channel doesn't exist, should return NotFound
        let result = handle_syscall(2, 255, 0, 0);
        // Will be IpcError or NotFound depending on task state
        assert!(result < 0);
    }

    #[test]
    fn test_syscall_ipc_receive_invalid_channel() {
        let result = handle_syscall(3, 255, 64, 0);
        assert!(result < 0);
    }

    #[test]
    fn test_syscall_ipc_send_oversized() {
        // data_len > MAX_MESSAGE_SIZE should fail with InvalidArgument
        let result = handle_syscall(2, 0, 0, 1024);
        assert!(result < 0);
    }
}
