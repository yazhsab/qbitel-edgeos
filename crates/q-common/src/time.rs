// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Time utilities for Qbitel EdgeOS
//!
//! This module provides time-related utilities for embedded systems,
//! including monotonic counters and duration calculations.

use core::ops::{Add, Sub};

/// System tick counter (platform-specific resolution)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ticks(u64);

impl Ticks {
    /// Create from raw tick count
    #[must_use]
    pub const fn new(ticks: u64) -> Self {
        Self(ticks)
    }

    /// Get the raw tick count
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Calculate elapsed ticks since this timestamp
    #[must_use]
    pub const fn elapsed(&self, now: Self) -> u64 {
        now.0.saturating_sub(self.0)
    }

    /// Check if duration has elapsed since this timestamp
    #[must_use]
    pub const fn has_elapsed(&self, now: Self, duration: u64) -> bool {
        self.elapsed(now) >= duration
    }
}

impl From<u64> for Ticks {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Ticks> for u64 {
    fn from(value: Ticks) -> Self {
        value.0
    }
}

impl Add<u64> for Ticks {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0.saturating_add(rhs))
    }
}

impl Sub<Ticks> for Ticks {
    type Output = u64;

    fn sub(self, rhs: Ticks) -> Self::Output {
        self.0.saturating_sub(rhs.0)
    }
}

/// Duration in milliseconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Millis(u32);

impl Millis {
    /// Create from milliseconds
    #[must_use]
    pub const fn new(ms: u32) -> Self {
        Self(ms)
    }

    /// Create from seconds
    #[must_use]
    pub const fn from_secs(secs: u32) -> Self {
        Self(secs.saturating_mul(1000))
    }

    /// Get as milliseconds
    #[must_use]
    pub const fn as_millis(&self) -> u32 {
        self.0
    }

    /// Get as seconds (truncated)
    #[must_use]
    pub const fn as_secs(&self) -> u32 {
        self.0 / 1000
    }

    /// Zero duration
    pub const ZERO: Self = Self(0);

    /// Maximum duration
    pub const MAX: Self = Self(u32::MAX);
}

impl From<u32> for Millis {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Millis> for u32 {
    fn from(value: Millis) -> Self {
        value.0
    }
}

impl Add for Millis {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl Sub for Millis {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_sub(rhs.0))
    }
}

/// Duration in microseconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Micros(u64);

impl Micros {
    /// Create from microseconds
    #[must_use]
    pub const fn new(us: u64) -> Self {
        Self(us)
    }

    /// Create from milliseconds
    #[must_use]
    pub const fn from_millis(ms: u32) -> Self {
        Self((ms as u64).saturating_mul(1000))
    }

    /// Get as microseconds
    #[must_use]
    pub const fn as_micros(&self) -> u64 {
        self.0
    }

    /// Get as milliseconds (truncated)
    #[must_use]
    pub const fn as_millis(&self) -> u32 {
        (self.0 / 1000) as u32
    }

    /// Zero duration
    pub const ZERO: Self = Self(0);
}

impl From<u64> for Micros {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Micros> for u64 {
    fn from(value: Micros) -> Self {
        value.0
    }
}

/// Simple deadline tracker
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    start: Ticks,
    timeout: u64,
}

impl Deadline {
    /// Create a new deadline
    #[must_use]
    pub const fn new(start: Ticks, timeout_ticks: u64) -> Self {
        Self {
            start,
            timeout: timeout_ticks,
        }
    }

    /// Check if the deadline has expired
    #[must_use]
    pub const fn is_expired(&self, now: Ticks) -> bool {
        self.start.elapsed(now) >= self.timeout
    }

    /// Get remaining time until deadline (0 if expired)
    #[must_use]
    pub const fn remaining(&self, now: Ticks) -> u64 {
        let elapsed = self.start.elapsed(now);
        if elapsed >= self.timeout {
            0
        } else {
            self.timeout - elapsed
        }
    }
}

/// Tick frequency for converting between ticks and time
#[derive(Debug, Clone, Copy)]
pub struct TickFrequency {
    /// Ticks per second
    hz: u32,
}

impl TickFrequency {
    /// Create from frequency in Hz
    #[must_use]
    pub const fn from_hz(hz: u32) -> Self {
        Self { hz }
    }

    /// 1 MHz (1 tick = 1 microsecond)
    pub const MHZ_1: Self = Self { hz: 1_000_000 };

    /// 1 kHz (1 tick = 1 millisecond)
    pub const KHZ_1: Self = Self { hz: 1_000 };

    /// Convert ticks to microseconds
    #[must_use]
    pub const fn ticks_to_micros(&self, ticks: u64) -> u64 {
        if self.hz == 0 {
            return 0;
        }
        (ticks * 1_000_000) / (self.hz as u64)
    }

    /// Convert ticks to milliseconds
    #[must_use]
    pub const fn ticks_to_millis(&self, ticks: u64) -> u32 {
        if self.hz == 0 {
            return 0;
        }
        ((ticks * 1_000) / (self.hz as u64)) as u32
    }

    /// Convert microseconds to ticks
    #[must_use]
    pub const fn micros_to_ticks(&self, micros: u64) -> u64 {
        (micros * (self.hz as u64)) / 1_000_000
    }

    /// Convert milliseconds to ticks
    #[must_use]
    pub const fn millis_to_ticks(&self, millis: u32) -> u64 {
        ((millis as u64) * (self.hz as u64)) / 1_000
    }
}
