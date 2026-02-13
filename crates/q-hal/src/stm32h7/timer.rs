// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32H7 Timer driver
//!
//! Provides system timing using SysTick and DWT peripherals.
//!
//! - **SysTick**: Configurable tick interrupt (default 1kHz)
//! - **DWT cycle counter**: Sub-tick microsecond precision
//! - **Tick rate**: Configurable via `set_tick_rate()` or `from_clock_config()`

use crate::error::HalResult;
use crate::traits::TimerInterface;
use core::sync::atomic::{AtomicU32, Ordering};

/// System tick counter (incremented by SysTick interrupt handler)
static TICK_COUNTER_HIGH: AtomicU32 = AtomicU32::new(0);

/// STM32H7 timer driver
pub struct Stm32h7Timer {
    /// System clock frequency in Hz
    sysclk_hz: u32,
    /// Tick interrupt rate in Hz (e.g. 1000 for 1ms ticks)
    tick_rate_hz: u32,
    /// Initialized state
    initialized: bool,
}

/// Default tick rate (1000 Hz = 1ms tick period)
const DEFAULT_TICK_RATE_HZ: u32 = 1000;

impl Stm32h7Timer {
    /// Create a new timer driver instance with defaults
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sysclk_hz: 480_000_000, // 480 MHz default
            tick_rate_hz: DEFAULT_TICK_RATE_HZ,
            initialized: false,
        }
    }

    /// Create a timer from a clock configuration
    ///
    /// # Arguments
    /// * `config` - Clock configuration with system clock frequency
    #[must_use]
    pub const fn from_clock_config(config: &super::ClockConfig) -> Self {
        Self {
            sysclk_hz: config.sysclk_hz,
            tick_rate_hz: DEFAULT_TICK_RATE_HZ,
            initialized: false,
        }
    }

    /// Set system clock frequency
    pub fn set_sysclk(&mut self, hz: u32) {
        self.sysclk_hz = hz;
    }

    /// Set tick rate in Hz
    ///
    /// Must be called before `init()`. Common values:
    /// - 1000 Hz (1ms ticks) — default
    /// - 100 Hz (10ms ticks) — lower overhead
    /// - 10000 Hz (100µs ticks) — high resolution
    pub fn set_tick_rate(&mut self, hz: u32) {
        self.tick_rate_hz = hz;
    }

    /// Get system clock frequency
    #[must_use]
    pub const fn sysclk(&self) -> u32 {
        self.sysclk_hz
    }

    /// Get configured tick rate
    #[must_use]
    pub const fn tick_rate(&self) -> u32 {
        self.tick_rate_hz
    }

    /// Handle SysTick interrupt (increment tick counter)
    ///
    /// This should be called from the SysTick interrupt handler.
    pub fn on_systick_interrupt() {
        TICK_COUNTER_HIGH.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for Stm32h7Timer {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerInterface for Stm32h7Timer {
    const FREQUENCY_HZ: u32 = 1_000_000;

    fn init(&mut self) -> HalResult<()> {
        use core::ptr;

        if self.initialized {
            return Ok(());
        }

        // SysTick register addresses
        const SYST_CSR: u32 = 0xE000_E010;  // Control and Status Register
        const SYST_RVR: u32 = 0xE000_E014;  // Reload Value Register
        const SYST_CVR: u32 = 0xE000_E018;  // Current Value Register

        // SysTick CSR bits
        const SYST_CSR_ENABLE: u32 = 1 << 0;
        const SYST_CSR_TICKINT: u32 = 1 << 1;
        const SYST_CSR_CLKSOURCE: u32 = 1 << 2; // 1 = processor clock

        // DWT (Data Watchpoint and Trace) registers for cycle counting
        const DWT_CTRL: u32 = 0xE000_1000;
        const DWT_CYCCNT: u32 = 0xE000_1004;
        const DEMCR: u32 = 0xE000_EDFC;

        // DWT/DEMCR bits
        const DWT_CTRL_CYCCNTENA: u32 = 1 << 0;
        const DEMCR_TRCENA: u32 = 1 << 24;

        // SAFETY: SysTick (0xE000_E010), DWT (0xE000_1000), and DEMCR (0xE000_EDFC) are
        // ARM Cortex-M architecturally-defined system registers. Volatile writes configure
        // the SysTick timer for periodic interrupts and enable the DWT cycle counter for
        // sub-tick microsecond precision timing.
        unsafe {
            // 1. Configure SysTick using configured tick rate
            let reload = (self.sysclk_hz / self.tick_rate_hz) - 1;

            // Disable SysTick while configuring
            ptr::write_volatile(SYST_CSR as *mut u32, 0);

            // Set reload value
            ptr::write_volatile(SYST_RVR as *mut u32, reload);

            // Clear current value
            ptr::write_volatile(SYST_CVR as *mut u32, 0);

            // Enable SysTick with interrupt and processor clock source
            ptr::write_volatile(
                SYST_CSR as *mut u32,
                SYST_CSR_ENABLE | SYST_CSR_TICKINT | SYST_CSR_CLKSOURCE,
            );

            // 2. Configure DWT cycle counter for microsecond precision
            // Enable trace in DEMCR
            let demcr = ptr::read_volatile(DEMCR as *const u32);
            ptr::write_volatile(DEMCR as *mut u32, demcr | DEMCR_TRCENA);

            // Reset cycle counter
            ptr::write_volatile(DWT_CYCCNT as *mut u32, 0);

            // Enable cycle counter
            let dwt_ctrl = ptr::read_volatile(DWT_CTRL as *const u32);
            ptr::write_volatile(DWT_CTRL as *mut u32, dwt_ctrl | DWT_CTRL_CYCCNTENA);
        }

        self.initialized = true;
        Ok(())
    }

    fn get_ticks(&self) -> u64 {
        use core::ptr;

        if !self.initialized {
            return 0;
        }

        // SysTick register addresses
        const SYST_CVR: u32 = 0xE000_E018;
        const SYST_RVR: u32 = 0xE000_E014;

        // Read high counter and SysTick atomically
        // Retry if high counter changed between reads
        loop {
            let high1 = TICK_COUNTER_HIGH.load(Ordering::Acquire);

            // SAFETY: SYST_RVR and SYST_CVR are ARM Cortex-M SysTick registers.
            // Volatile reads are required to get the current hardware timer state.
            let reload = unsafe { ptr::read_volatile(SYST_RVR as *const u32) };
            let current = unsafe { ptr::read_volatile(SYST_CVR as *const u32) };

            let high2 = TICK_COUNTER_HIGH.load(Ordering::Acquire);

            if high1 == high2 {
                // SysTick counts down: elapsed fraction = (reload - current) / (reload + 1)
                let elapsed_in_tick = reload.saturating_sub(current);

                // Convert tick count to microseconds:
                // tick_period_us = 1_000_000 / tick_rate_hz
                // total_us = ticks * tick_period_us + fraction * tick_period_us
                let tick_period_us = 1_000_000u64 / self.tick_rate_hz as u64;
                let frac_us = elapsed_in_tick as u64 * tick_period_us / (reload + 1) as u64;

                return high1 as u64 * tick_period_us + frac_us;
            }
        }
    }

    fn delay_us(&self, us: u32) {
        if !self.initialized || us == 0 {
            return;
        }

        let start = self.get_micros();
        let target = start.wrapping_add(us as u64);

        while self.get_micros() < target {
            core::hint::spin_loop();
        }
    }

    fn get_micros(&self) -> u64 {
        use core::ptr;

        if !self.initialized {
            return 0;
        }

        // SysTick register addresses
        const SYST_CVR: u32 = 0xE000_E018;
        const SYST_RVR: u32 = 0xE000_E014;

        // Use SysTick fraction for sub-tick precision (avoids DWT wrap issues)
        loop {
            let ticks = TICK_COUNTER_HIGH.load(Ordering::Acquire);

            // SAFETY: SYST_RVR and SYST_CVR are ARM Cortex-M SysTick registers.
            // Volatile reads are required to compute sub-tick microsecond precision.
            let reload = unsafe { ptr::read_volatile(SYST_RVR as *const u32) };
            let current = unsafe { ptr::read_volatile(SYST_CVR as *const u32) };

            let ticks2 = TICK_COUNTER_HIGH.load(Ordering::Acquire);

            if ticks == ticks2 {
                let tick_period_us = 1_000_000u64 / self.tick_rate_hz as u64;
                let elapsed = reload.saturating_sub(current);
                let frac_us = elapsed as u64 * tick_period_us / (reload + 1) as u64;

                return ticks as u64 * tick_period_us + frac_us;
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_creation() {
        let timer = Stm32h7Timer::new();
        assert_eq!(timer.sysclk(), 480_000_000);
        assert_eq!(timer.tick_rate(), 1000);
        assert!(!timer.initialized);
    }

    #[test]
    fn test_from_clock_config() {
        let config = super::super::ClockConfig {
            sysclk_hz: 400_000_000,
            hclk_hz: 200_000_000,
            pclk1_hz: 100_000_000,
            pclk2_hz: 100_000_000,
        };
        let timer = Stm32h7Timer::from_clock_config(&config);
        assert_eq!(timer.sysclk(), 400_000_000);
        assert_eq!(timer.tick_rate(), 1000);
    }

    #[test]
    fn test_set_tick_rate() {
        let mut timer = Stm32h7Timer::new();
        timer.set_tick_rate(10000);
        assert_eq!(timer.tick_rate(), 10000);
    }

    #[test]
    fn test_frequency_constant() {
        assert_eq!(Stm32h7Timer::FREQUENCY_HZ, 1_000_000);
    }

    #[test]
    fn test_uninitialized_returns_zero() {
        let timer = Stm32h7Timer::new();
        assert_eq!(timer.get_ticks(), 0);
        assert_eq!(timer.get_micros(), 0);
    }
}
