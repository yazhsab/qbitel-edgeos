// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Secure memory utilities
//!
//! This module provides secure memory handling utilities including
//! zeroization, constant-time operations, and secure buffers.

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};
use zeroize::Zeroize;

/// Securely zero memory, preventing compiler optimization
///
/// This function uses volatile writes to ensure the memory is actually
/// zeroed and not optimized away by the compiler.
#[inline(never)]
pub fn secure_zero(data: &mut [u8]) {
    // Use volatile writes to prevent optimization
    for byte in data.iter_mut() {
        // SAFETY: We're writing to valid memory that we have mutable access to
        unsafe {
            ptr::write_volatile(byte, 0);
        }
    }

    // Memory barrier to ensure writes complete before returning
    compiler_fence(Ordering::SeqCst);
}

/// Secure buffer that zeroizes on drop
///
/// This wrapper ensures sensitive data is zeroized when it goes out of scope.
#[derive(Clone)]
pub struct SecureBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecureBuffer<N> {
    /// Create a new zeroed secure buffer
    #[must_use]
    pub const fn new() -> Self {
        Self { data: [0u8; N] }
    }

    /// Create from a byte slice
    ///
    /// Returns `None` if the slice length doesn't match N.
    #[must_use]
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != N {
            return None;
        }
        let mut buf = Self::new();
        buf.data.copy_from_slice(slice);
        Some(buf)
    }

    /// Get the data as a slice
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the data as a mutable slice
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the buffer size
    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    /// Check if buffer is empty (always false for N > 0)
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> Default for SecureBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AsRef<[u8]> for SecureBuffer<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> AsMut<[u8]> for SecureBuffer<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> Zeroize for SecureBuffer<N> {
    fn zeroize(&mut self) {
        secure_zero(&mut self.data);
    }
}

impl<const N: usize> Drop for SecureBuffer<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Compare two byte slices in constant time
///
/// This function is resistant to timing attacks as it always performs
/// the same number of operations regardless of where differences occur.
#[must_use]
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Constant-time conditional select
///
/// Returns `a` if `choice` is 0, or `b` if `choice` is 1.
/// Any other value for `choice` has undefined behavior.
#[must_use]
pub fn constant_time_select(choice: u8, a: u8, b: u8) -> u8 {
    // Create mask: 0x00 if choice is 0, 0xFF if choice is 1
    let mask = (choice.wrapping_neg()) & 0xFF;
    (a & !mask) | (b & mask)
}

/// Constant-time conditional copy
///
/// Copies `src` to `dst` if `choice` is 1, does nothing if `choice` is 0.
pub fn constant_time_copy(choice: u8, dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());

    let mask = choice.wrapping_neg();
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = (*d & !mask) | (*s & mask);
    }
}

/// Check if all bytes are zero in constant time
#[must_use]
pub fn is_zero(data: &[u8]) -> bool {
    let mut acc: u8 = 0;
    for &byte in data {
        acc |= byte;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_zero() {
        let mut data = [0xFFu8; 32];
        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_buffer_zeroize() {
        let mut buf = SecureBuffer::<32>::from_slice(&[0xFF; 32]).unwrap();
        buf.zeroize();
        assert!(buf.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
        assert!(!constant_time_compare(&a, &[1, 2, 3])); // Different length
    }

    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(0, 0xAA, 0xBB), 0xAA);
        assert_eq!(constant_time_select(1, 0xAA, 0xBB), 0xBB);
    }

    #[test]
    fn test_is_zero() {
        assert!(is_zero(&[0, 0, 0, 0]));
        assert!(!is_zero(&[0, 0, 1, 0]));
        assert!(!is_zero(&[1, 0, 0, 0]));
    }
}
