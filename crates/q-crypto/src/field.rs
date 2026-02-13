// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Finite field arithmetic for lattice-based cryptography.
//!
//! This module provides constant-time field arithmetic operations
//! for the prime field Z_q used in Kyber and Dilithium.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use zeroize::Zeroize;

/// Kyber prime: q = 3329 = 13 * 256 + 1
pub const KYBER_Q: u16 = 3329;

/// Dilithium prime: q = 8380417 = 2^23 - 2^13 + 1
pub const DILITHIUM_Q: u32 = 8380417;

/// Field element for Kyber (mod 3329)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Zeroize)]
#[repr(transparent)]
pub struct KyberFieldElement(u16);

impl KyberFieldElement {
    /// Zero element
    pub const ZERO: Self = Self(0);

    /// One element
    pub const ONE: Self = Self(1);

    /// Create from u16, reducing mod q
    #[inline]
    pub const fn new(value: u16) -> Self {
        Self(value % KYBER_Q)
    }

    /// Create from i16, handling negative values
    #[inline]
    pub fn from_i16(value: i16) -> Self {
        let reduced = if value < 0 {
            ((value as i32) + (KYBER_Q as i32)) as u16
        } else {
            (value as u16) % KYBER_Q
        };
        Self(reduced)
    }

    /// Get the inner value
    #[inline]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Barrett reduction for values < q^2
    /// Reduces x mod q using precomputed constant
    #[inline]
    pub fn barrett_reduce(x: u32) -> Self {
        // Barrett constant: floor(2^26 / q) = 20158
        const BARRETT_CONST: u32 = 20158;
        const BARRETT_SHIFT: u32 = 26;

        let quotient = ((x as u64 * BARRETT_CONST as u64) >> BARRETT_SHIFT) as u32;
        let remainder = x.wrapping_sub(quotient.wrapping_mul(KYBER_Q as u32));

        // Conditional subtraction (constant-time) - may need multiple reductions
        let mut r = remainder;
        // First reduction
        let mask = ((r >= KYBER_Q as u32) as u32).wrapping_neg();
        r = r.wrapping_sub(mask & KYBER_Q as u32);
        // Second reduction (for safety)
        let mask = ((r >= KYBER_Q as u32) as u32).wrapping_neg();
        r = r.wrapping_sub(mask & KYBER_Q as u32);

        Self(r as u16)
    }

    /// Montgomery reduction
    /// Given x < q * R, compute x * R^-1 mod q
    #[inline]
    pub fn montgomery_reduce(x: u32) -> Self {
        // R = 2^16, q = 3329
        // q^-1 mod R = 62209
        const QINV: u32 = 62209;

        let t = (x.wrapping_mul(QINV)) & 0xFFFF;
        let u = t.wrapping_mul(KYBER_Q as u32);
        let result = (x.wrapping_add(u)) >> 16;

        // Conditional subtraction (using wrapping_sub for safety)
        let mask = ((result >= KYBER_Q as u32) as u32).wrapping_neg();
        let reduced = result.wrapping_sub(mask & KYBER_Q as u32);

        Self(reduced as u16)
    }

    /// Compute modular inverse using Fermat's little theorem
    /// a^-1 = a^(q-2) mod q
    #[inline]
    pub fn inverse(self) -> Self {
        // q - 2 = 3327 = 0b110011111111
        let mut result = Self::ONE;
        let mut base = self;
        let mut exp = KYBER_Q - 2;

        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }

        result
    }

    /// Constant-time conditional select
    /// Returns a if condition is 0, b if condition is 1
    #[inline]
    pub fn ct_select(a: Self, b: Self, condition: u16) -> Self {
        let mask = (condition.wrapping_neg()) as u16;
        Self((a.0 & !mask) | (b.0 & mask))
    }

    /// Compress to d bits
    #[inline]
    pub fn compress(self, d: u32) -> u16 {
        let x = self.0 as u32;
        let shifted = (x << d) + (KYBER_Q as u32 / 2);
        ((shifted / KYBER_Q as u32) & ((1 << d) - 1)) as u16
    }

    /// Decompress from d bits
    #[inline]
    pub fn decompress(x: u16, d: u32) -> Self {
        let x = x as u32;
        let decompressed = ((x * KYBER_Q as u32) + (1 << (d - 1))) >> d;
        Self(decompressed as u16)
    }
}

impl Add for KyberFieldElement {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let sum = (self.0 as u32) + (rhs.0 as u32);
        let mask = ((sum >= KYBER_Q as u32) as u32).wrapping_neg();
        Self((sum - (mask & KYBER_Q as u32)) as u16)
    }
}

impl AddAssign for KyberFieldElement {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for KyberFieldElement {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let diff = (self.0 as i32) - (rhs.0 as i32);
        let mask = ((diff < 0) as i32).wrapping_neg();
        Self((diff + (mask & KYBER_Q as i32)) as u16)
    }
}

impl SubAssign for KyberFieldElement {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for KyberFieldElement {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let product = (self.0 as u32) * (rhs.0 as u32);
        Self::barrett_reduce(product)
    }
}

impl MulAssign for KyberFieldElement {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Neg for KyberFieldElement {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        if self.0 == 0 {
            self
        } else {
            Self(KYBER_Q - self.0)
        }
    }
}

/// Field element for Dilithium (mod 8380417)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Zeroize)]
#[repr(transparent)]
pub struct DilithiumFieldElement(u32);

impl DilithiumFieldElement {
    /// Zero element
    pub const ZERO: Self = Self(0);

    /// One element
    pub const ONE: Self = Self(1);

    /// Create from u32, reducing mod q
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(value % DILITHIUM_Q)
    }

    /// Create from i32, handling negative values
    #[inline]
    pub fn from_i32(value: i32) -> Self {
        let reduced = if value < 0 {
            ((value as i64) + (DILITHIUM_Q as i64)) as u32
        } else {
            (value as u32) % DILITHIUM_Q
        };
        Self(reduced)
    }

    /// Get the inner value
    #[inline]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Convert to centered representation [-q/2, q/2]
    #[inline]
    pub fn to_centered(self) -> i32 {
        let half_q = (DILITHIUM_Q / 2) as i32;
        let val = self.0 as i32;
        if val > half_q {
            val - DILITHIUM_Q as i32
        } else {
            val
        }
    }

    /// Montgomery reduction for Dilithium
    /// R = 2^32, q = 8380417
    /// q^-1 mod R = 58728449
    #[inline]
    pub fn montgomery_reduce(x: i64) -> Self {
        const QINV: i64 = 58728449;

        let t = ((x as i64).wrapping_mul(QINV) as i32) as i64;
        let u = t.wrapping_mul(DILITHIUM_Q as i64);
        let result = ((x - u) >> 32) as i32;

        // Conditional addition/subtraction for proper range
        let mask_neg = (result >> 31) as i32;
        let mask_pos = ((result >= DILITHIUM_Q as i32) as i32).wrapping_neg();

        let reduced = result + (mask_neg & DILITHIUM_Q as i32) - (mask_pos & DILITHIUM_Q as i32);
        Self(reduced as u32)
    }

    /// Reduce mod q using Barrett reduction
    #[inline]
    pub fn reduce(x: i64) -> Self {
        // For values that might be negative or larger than q^2
        let x_mod = x.rem_euclid(DILITHIUM_Q as i64);
        Self(x_mod as u32)
    }

    /// Power of 2 rounding
    /// Returns (r0, r1) where a = r1 * 2^d + r0 and r0 is centered in (-2^(d-1), 2^(d-1)]
    #[inline]
    pub fn power2round(self, d: u32) -> (Self, Self) {
        let a = self.0;
        // r0 = a mod 2^d, then center
        let mut r0 = (a & ((1u32 << d) - 1)) as i32;
        if r0 > (1i32 << (d - 1)) {
            r0 -= 1i32 << d;
        }
        let r1 = ((a as i32 - r0) >> d) as u32;
        (Self::from_i32(r0), Self(r1))
    }

    /// Decompose for hint computation
    /// Returns (r0, r1) where a = r1*alpha + r0 with r0 centered in (-(alpha/2), alpha/2]
    #[inline]
    pub fn decompose(self, alpha: u32) -> (Self, Self) {
        let a = self.value();

        // a0 = a mod alpha (unsigned), then center
        let mut a0 = (a % alpha) as i32;
        // Center: if a0 > alpha/2, subtract alpha
        if a0 > (alpha / 2) as i32 {
            a0 -= alpha as i32;
        }

        // Compute a1
        let a1: i32;
        if (a as i32 - a0) == (DILITHIUM_Q as i32 - 1) {
            // Special case: a - a0 = q - 1
            a1 = 0;
            a0 -= 1;
        } else {
            a1 = ((a as i32 - a0) / alpha as i32) as i32;
        }

        // Handle negative a0 for field element conversion
        (Self::from_i32(a0), Self::from_i32(a1))
    }

    /// High bits extraction
    #[inline]
    pub fn high_bits(self, alpha: u32) -> Self {
        self.decompose(alpha).1
    }

    /// Low bits extraction
    #[inline]
    pub fn low_bits(self, alpha: u32) -> Self {
        self.decompose(alpha).0
    }

    /// Make hint for signature verification
    #[inline]
    pub fn make_hint(z: Self, r: Self, alpha: u32) -> bool {
        let r1 = r.high_bits(alpha);
        let v1 = (r + z).high_bits(alpha);
        r1 != v1
    }

    /// Use hint in verification
    #[inline]
    pub fn use_hint(h: bool, r: Self, alpha: u32) -> Self {
        let (r0, r1) = r.decompose(alpha);
        if !h {
            return r1;
        }

        let m = ((DILITHIUM_Q - 1) / alpha) as i32;
        let r0_centered = r0.to_centered();
        let r1_val = r1.value() as i32;
        if r0_centered > 0 {
            Self::new(((r1_val + 1) % m) as u32)
        } else {
            Self::new(((r1_val - 1 + m) % m) as u32)
        }
    }
}

impl Add for DilithiumFieldElement {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let sum = (self.0 as u64) + (rhs.0 as u64);
        let mask = ((sum >= DILITHIUM_Q as u64) as u64).wrapping_neg();
        Self((sum - (mask & DILITHIUM_Q as u64)) as u32)
    }
}

impl AddAssign for DilithiumFieldElement {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for DilithiumFieldElement {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let diff = (self.0 as i64) - (rhs.0 as i64);
        let mask = ((diff < 0) as i64).wrapping_neg();
        Self((diff + (mask & DILITHIUM_Q as i64)) as u32)
    }
}

impl SubAssign for DilithiumFieldElement {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for DilithiumFieldElement {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let product = (self.0 as i64) * (rhs.0 as i64);
        Self::reduce(product)
    }
}

impl MulAssign for DilithiumFieldElement {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Neg for DilithiumFieldElement {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        if self.0 == 0 {
            self
        } else {
            Self(DILITHIUM_Q - self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_field_add() {
        let a = KyberFieldElement::new(1000);
        let b = KyberFieldElement::new(2500);
        let sum = a + b;
        assert_eq!(sum.value(), (1000 + 2500) % KYBER_Q);
    }

    #[test]
    fn test_kyber_field_sub() {
        let a = KyberFieldElement::new(1000);
        let b = KyberFieldElement::new(2500);
        let diff = a - b;
        // 1000 - 2500 = -1500 + 3329 = 1829
        assert_eq!(diff.value(), 1829);
    }

    #[test]
    fn test_kyber_field_mul() {
        let a = KyberFieldElement::new(100);
        let b = KyberFieldElement::new(200);
        let prod = a * b;
        assert_eq!(prod.value(), (100 * 200) % KYBER_Q);
    }

    #[test]
    fn test_kyber_field_inverse() {
        let a = KyberFieldElement::new(1234);
        let a_inv = a.inverse();
        let product = a * a_inv;
        assert_eq!(product.value(), 1);
    }

    #[test]
    fn test_dilithium_field_add() {
        let a = DilithiumFieldElement::new(4000000);
        let b = DilithiumFieldElement::new(5000000);
        let sum = a + b;
        assert_eq!(sum.value(), (4000000 + 5000000) % DILITHIUM_Q);
    }

    #[test]
    fn test_dilithium_field_centered() {
        let a = DilithiumFieldElement::new(DILITHIUM_Q - 100);
        assert_eq!(a.to_centered(), -100);

        let b = DilithiumFieldElement::new(100);
        assert_eq!(b.to_centered(), 100);
    }
}
