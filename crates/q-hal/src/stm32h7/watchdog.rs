// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32H7 Watchdog Timer Drivers
//!
//! This module implements watchdog timer drivers for the STM32H7:
//!
//! - **IWDG** (Independent Watchdog): Independent clock, always-on reset capability
//! - **WWDG** (Window Watchdog): Configurable window, early warning interrupt
//!
//! # Safety Features
//!
//! - Once started, IWDG cannot be stopped (except by reset)
//! - WWDG provides early warning interrupt for graceful handling
//! - Both protect against software lockups and infinite loops

use core::ptr;

use crate::error::{HalError, HalResult};

// ============================================================================
// IWDG (Independent Watchdog) Configuration
// ============================================================================

#[allow(dead_code)]
/// IWDG register base address
const IWDG_BASE: u32 = 0x5800_3000;

#[allow(dead_code)]
/// IWDG Key Register
const IWDG_KR: u32 = IWDG_BASE + 0x00;
#[allow(dead_code)]
/// IWDG Prescaler Register
const IWDG_PR: u32 = IWDG_BASE + 0x04;
#[allow(dead_code)]
/// IWDG Reload Register
const IWDG_RLR: u32 = IWDG_BASE + 0x08;
#[allow(dead_code)]
/// IWDG Status Register
const IWDG_SR: u32 = IWDG_BASE + 0x0C;
#[allow(dead_code)]
/// IWDG Window Register
const IWDG_WINR: u32 = IWDG_BASE + 0x10;

// IWDG Key values
#[allow(dead_code)]
const IWDG_KEY_RELOAD: u16 = 0xAAAA;
#[allow(dead_code)]
const IWDG_KEY_ENABLE: u16 = 0xCCCC;
#[allow(dead_code)]
const IWDG_KEY_ACCESS: u16 = 0x5555;

// IWDG Status bits
#[allow(dead_code)]
const IWDG_SR_PVU: u32 = 1 << 0;  // Prescaler update
#[allow(dead_code)]
const IWDG_SR_RVU: u32 = 1 << 1;  // Reload update
#[allow(dead_code)]
const IWDG_SR_WVU: u32 = 1 << 2;  // Window update

/// IWDG LSI frequency (approximately 32 kHz)
const LSI_FREQ_HZ: u32 = 32_000;

/// Maximum IWDG reload value
const IWDG_MAX_RELOAD: u16 = 0x0FFF;

/// IWDG prescaler options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IwdgPrescaler {
    /// Divide by 4
    Div4 = 0,
    /// Divide by 8
    Div8 = 1,
    /// Divide by 16
    Div16 = 2,
    /// Divide by 32
    Div32 = 3,
    /// Divide by 64
    Div64 = 4,
    /// Divide by 128
    Div128 = 5,
    /// Divide by 256
    Div256 = 6,
}

impl IwdgPrescaler {
    /// Get the divisor value
    pub const fn divisor(&self) -> u32 {
        match self {
            Self::Div4 => 4,
            Self::Div8 => 8,
            Self::Div16 => 16,
            Self::Div32 => 32,
            Self::Div64 => 64,
            Self::Div128 => 128,
            Self::Div256 => 256,
        }
    }
}

// ============================================================================
// WWDG (Window Watchdog) Configuration
// ============================================================================

#[allow(dead_code)]
/// WWDG register base address
const WWDG_BASE: u32 = 0x5000_3000;

#[allow(dead_code)]
/// WWDG Control Register
const WWDG_CR: u32 = WWDG_BASE + 0x00;
#[allow(dead_code)]
/// WWDG Configuration Register
const WWDG_CFR: u32 = WWDG_BASE + 0x04;
#[allow(dead_code)]
/// WWDG Status Register
const WWDG_SR: u32 = WWDG_BASE + 0x08;

// WWDG CR bits
#[allow(dead_code)]
const WWDG_CR_WDGA: u32 = 1 << 7;  // Activation bit
#[allow(dead_code)]
const WWDG_CR_T_MASK: u32 = 0x7F;  // Counter mask

// WWDG CFR bits
#[allow(dead_code)]
const WWDG_CFR_EWI: u32 = 1 << 9;    // Early wakeup interrupt
#[allow(dead_code)]
const WWDG_CFR_WDGTB_MASK: u32 = 0x3 << 11;  // Timer base
#[allow(dead_code)]
const WWDG_CFR_W_MASK: u32 = 0x7F;   // Window value

// WWDG SR bits
#[allow(dead_code)]
const WWDG_SR_EWIF: u32 = 1 << 0;  // Early wakeup interrupt flag

/// WWDG counter limits
const WWDG_COUNTER_MIN: u8 = 0x40;  // Counter must be > 0x3F
const WWDG_COUNTER_MAX: u8 = 0x7F;

/// WWDG prescaler options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WwdgPrescaler {
    /// Divide by 1
    Div1 = 0,
    /// Divide by 2
    Div2 = 1,
    /// Divide by 4
    Div4 = 2,
    /// Divide by 8
    Div8 = 3,
}

impl WwdgPrescaler {
    /// Get the divisor value
    pub const fn divisor(&self) -> u32 {
        match self {
            Self::Div1 => 1,
            Self::Div2 => 2,
            Self::Div4 => 4,
            Self::Div8 => 8,
        }
    }
}

// ============================================================================
// Independent Watchdog (IWDG)
// ============================================================================

/// Independent Watchdog driver
///
/// The IWDG uses an independent LSI clock (~32 kHz) and cannot be stopped
/// once started. It provides robust protection against software failures.
pub struct Stm32h7Iwdg {
    /// Configured prescaler
    prescaler: IwdgPrescaler,
    /// Configured reload value
    reload: u16,
    /// Window value (0 = disabled)
    window: u16,
    /// Started flag
    started: bool,
    /// Timeout in milliseconds
    timeout_ms: u32,
}

impl Stm32h7Iwdg {
    /// Create a new IWDG instance
    pub const fn new() -> Self {
        Self {
            prescaler: IwdgPrescaler::Div32,
            reload: 0x0FFF,
            window: 0,
            started: false,
            timeout_ms: 0,
        }
    }

    /// Calculate prescaler and reload for desired timeout
    fn calculate_config(timeout_ms: u32) -> Option<(IwdgPrescaler, u16)> {
        // Try each prescaler from smallest to largest
        let prescalers = [
            IwdgPrescaler::Div4,
            IwdgPrescaler::Div8,
            IwdgPrescaler::Div16,
            IwdgPrescaler::Div32,
            IwdgPrescaler::Div64,
            IwdgPrescaler::Div128,
            IwdgPrescaler::Div256,
        ];

        for prescaler in prescalers {
            // Calculate reload value
            // timeout = (reload + 1) * prescaler / LSI_FREQ
            // reload = (timeout * LSI_FREQ / prescaler) - 1
            let reload = (((timeout_ms as u64) * (LSI_FREQ_HZ as u64))
                / (prescaler.divisor() as u64 * 1000))
                .saturating_sub(1);

            if reload <= IWDG_MAX_RELOAD as u64 {
                return Some((prescaler, reload as u16));
            }
        }

        None
    }

    /// Configure IWDG with timeout in milliseconds
    pub fn configure(&mut self, timeout_ms: u32) -> HalResult<()> {
        if self.started {
            return Err(HalError::InvalidOperation);
        }

        let (prescaler, reload) = Self::calculate_config(timeout_ms)
            .ok_or(HalError::InvalidParameter)?;

        self.prescaler = prescaler;
        self.reload = reload;
        self.timeout_ms = timeout_ms;

        Ok(())
    }

    /// Configure window (optional, must be < reload)
    pub fn configure_window(&mut self, window_ms: u32) -> HalResult<()> {
        if self.started {
            return Err(HalError::InvalidOperation);
        }

        // Calculate window value using same formula as reload
        let window = (((window_ms as u64) * (LSI_FREQ_HZ as u64))
            / (self.prescaler.divisor() as u64 * 1000))
            .saturating_sub(1);

        if window >= self.reload as u64 {
            return Err(HalError::InvalidParameter);
        }

        self.window = window as u16;
        Ok(())
    }

    /// Start the watchdog (cannot be stopped!)
    pub fn start(&mut self) -> HalResult<()> {
        if self.started {
            return Ok(()); // Already started
        }

        #[cfg(target_arch = "arm")]
        {
            // Enable write access to registers
            // SAFETY: IWDG_KR is an architecturally-defined STM32H7 register at 0x5800_3000.
            // Volatile write of the access key (0x5555) enables writes to prescaler/reload registers.
            unsafe {
                ptr::write_volatile(IWDG_KR as *mut u16, IWDG_KEY_ACCESS);
            }

            // Wait for registers to be writable
            self.wait_ready()?;

            // Set prescaler
            // SAFETY: IWDG_PR is an architecturally-defined prescaler register.
            // Volatile write sets the IWDG clock divider. Write access was unlocked above.
            unsafe {
                ptr::write_volatile(IWDG_PR as *mut u32, self.prescaler as u32);
            }

            // Wait for prescaler update
            self.wait_ready()?;

            // Set reload value
            // SAFETY: IWDG_RLR is an architecturally-defined reload register.
            // Volatile write sets the IWDG counter reload value. Write access was unlocked above.
            unsafe {
                ptr::write_volatile(IWDG_RLR as *mut u32, self.reload as u32);
            }

            // Wait for reload update
            self.wait_ready()?;

            // Set window if configured
            if self.window > 0 {
                // SAFETY: IWDG_WINR is an architecturally-defined window register.
                // Volatile write sets the watchdog window value. Validated to be < reload.
                unsafe {
                    ptr::write_volatile(IWDG_WINR as *mut u32, self.window as u32);
                }
                self.wait_ready()?;
            }

            // Start the watchdog
            // SAFETY: IWDG_KR is an architecturally-defined key register.
            // Volatile write of enable key (0xCCCC) starts the watchdog. Once started,
            // the IWDG cannot be stopped except by system reset.
            unsafe {
                ptr::write_volatile(IWDG_KR as *mut u16, IWDG_KEY_ENABLE);
            }
        }

        self.started = true;
        Ok(())
    }

    /// Wait for register updates to complete
    #[cfg(target_arch = "arm")]
    fn wait_ready(&self) -> HalResult<()> {
        let mut timeout = 100_000u32;
        loop {
            // SAFETY: IWDG_SR is an architecturally-defined read-only status register.
            // Volatile read required to poll register update completion flags.
            let sr = unsafe { ptr::read_volatile(IWDG_SR as *const u32) };
            if (sr & (IWDG_SR_PVU | IWDG_SR_RVU | IWDG_SR_WVU)) == 0 {
                return Ok(());
            }
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(HalError::Timeout);
            }
        }
    }

    /// Reload (kick) the watchdog
    pub fn reload(&self) {
        if !self.started {
            return;
        }

        #[cfg(target_arch = "arm")]
        // SAFETY: IWDG_KR is an architecturally-defined key register.
        // Volatile write of reload key (0xAAAA) resets the watchdog counter to the reload value.
        unsafe {
            ptr::write_volatile(IWDG_KR as *mut u16, IWDG_KEY_RELOAD);
        }
    }

    /// Alias for reload
    #[inline]
    pub fn kick(&self) {
        self.reload();
    }

    /// Check if watchdog is running
    pub fn is_running(&self) -> bool {
        self.started
    }

    /// Get configured timeout in milliseconds
    pub fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }
}

impl Default for Stm32h7Iwdg {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Window Watchdog (WWDG)
// ============================================================================

/// Window Watchdog driver
///
/// The WWDG uses the APB clock and provides a window feature and
/// early warning interrupt. Can be stopped by disabling clock.
pub struct Stm32h7Wwdg {
    /// Prescaler value
    prescaler: WwdgPrescaler,
    /// Window value
    window: u8,
    /// Counter value
    counter: u8,
    /// Early warning interrupt enabled
    ewi_enabled: bool,
    /// Early warning callback
    ewi_callback: Option<fn()>,
    /// Started flag
    started: bool,
    /// APB clock frequency
    apb_freq_hz: u32,
}

impl Stm32h7Wwdg {
    /// Create a new WWDG instance
    pub const fn new() -> Self {
        Self {
            prescaler: WwdgPrescaler::Div8,
            window: WWDG_COUNTER_MAX,
            counter: WWDG_COUNTER_MAX,
            ewi_enabled: false,
            ewi_callback: None,
            started: false,
            apb_freq_hz: 120_000_000, // Default APB1 frequency
        }
    }

    /// Set APB clock frequency (needed for timeout calculation)
    pub fn set_apb_frequency(&mut self, freq_hz: u32) {
        self.apb_freq_hz = freq_hz;
    }

    /// Calculate timeout in microseconds
    /// Timeout = (4096 * prescaler * (counter - 0x3F)) / APB_freq
    pub fn calculate_timeout_us(&self) -> u32 {
        let t_wwdg = (4096 * self.prescaler.divisor() * ((self.counter - 0x3F) as u32)) as u64;
        ((t_wwdg * 1_000_000) / self.apb_freq_hz as u64) as u32
    }

    /// Configure WWDG with counter and window values
    pub fn configure(&mut self, counter: u8, window: u8, prescaler: WwdgPrescaler) -> HalResult<()> {
        if self.started {
            return Err(HalError::InvalidOperation);
        }

        // Validate counter
        if counter < WWDG_COUNTER_MIN || counter > WWDG_COUNTER_MAX {
            return Err(HalError::InvalidParameter);
        }

        // Validate window
        if window < WWDG_COUNTER_MIN || window > counter {
            return Err(HalError::InvalidParameter);
        }

        self.counter = counter;
        self.window = window;
        self.prescaler = prescaler;

        Ok(())
    }

    /// Enable early warning interrupt
    pub fn enable_early_warning(&mut self, callback: fn()) {
        self.ewi_enabled = true;
        self.ewi_callback = Some(callback);
    }

    /// Start the watchdog
    pub fn start(&mut self) -> HalResult<()> {
        if self.started {
            return Ok(());
        }

        #[cfg(target_arch = "arm")]
        {
            // Enable WWDG clock (in RCC)
            self.enable_clock();

            // Configure CFR: window + prescaler + EWI
            let cfr = ((self.prescaler as u32) << 11)
                | (self.window as u32)
                | if self.ewi_enabled { WWDG_CFR_EWI } else { 0 };

            // SAFETY: WWDG_CFR is an architecturally-defined configuration register.
            // Volatile write sets the window value, prescaler, and optional early warning interrupt.
            unsafe {
                ptr::write_volatile(WWDG_CFR as *mut u32, cfr);
            }

            // Enable and set counter
            let cr = WWDG_CR_WDGA | (self.counter as u32);
            // SAFETY: WWDG_CR is an architecturally-defined control register.
            // Volatile write enables the WWDG and sets the initial counter value.
            unsafe {
                ptr::write_volatile(WWDG_CR as *mut u32, cr);
            }
        }

        self.started = true;
        Ok(())
    }

    /// Enable WWDG clock
    #[cfg(target_arch = "arm")]
    fn enable_clock(&self) {
        const RCC_APB1LENR: u32 = 0x5802_44E8;
        const RCC_APB1LENR_WWDGEN: u32 = 1 << 11;

        // SAFETY: RCC_APB1LENR is an architecturally-defined RCC register.
        // Volatile read-modify-write enables the WWDG peripheral clock.
        unsafe {
            let val = ptr::read_volatile(RCC_APB1LENR as *const u32);
            ptr::write_volatile(RCC_APB1LENR as *mut u32, val | RCC_APB1LENR_WWDGEN);
        }
    }

    /// Reload (kick) the watchdog
    pub fn reload(&mut self) {
        if !self.started {
            return;
        }

        #[cfg(target_arch = "arm")]
        // SAFETY: WWDG_CR is an architecturally-defined control register.
        // Volatile write reloads the counter value with the activation bit set.
        unsafe {
            // Write counter with activation bit set
            let cr = WWDG_CR_WDGA | (self.counter as u32);
            ptr::write_volatile(WWDG_CR as *mut u32, cr);
        }
    }

    /// Alias for reload
    #[inline]
    pub fn kick(&mut self) {
        self.reload();
    }

    /// Handle early warning interrupt
    pub fn handle_ewi(&mut self) {
        #[cfg(target_arch = "arm")]
        {
            // Clear EWI flag
            // SAFETY: WWDG_SR is an architecturally-defined status register.
            // Volatile write of 0 clears the early warning interrupt flag.
            unsafe {
                ptr::write_volatile(WWDG_SR as *mut u32, 0);
            }
        }

        // Call callback if registered
        if let Some(callback) = self.ewi_callback {
            callback();
        }
    }

    /// Get current counter value
    pub fn current_counter(&self) -> u8 {
        #[cfg(target_arch = "arm")]
        {
            // SAFETY: WWDG_CR is an architecturally-defined control register.
            // Volatile read retrieves the current counter value from hardware.
            let cr = unsafe { ptr::read_volatile(WWDG_CR as *const u32) };
            (cr & WWDG_CR_T_MASK) as u8
        }

        #[cfg(not(target_arch = "arm"))]
        {
            self.counter
        }
    }

    /// Check if in refresh window
    pub fn is_in_window(&self) -> bool {
        let current = self.current_counter();
        current <= self.window && current > WWDG_COUNTER_MIN
    }

    /// Check if watchdog is running
    pub fn is_running(&self) -> bool {
        self.started
    }
}

impl Default for Stm32h7Wwdg {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Watchdog Manager
// ============================================================================

/// Combined watchdog manager
pub struct WatchdogManager {
    /// IWDG instance
    pub iwdg: Stm32h7Iwdg,
    /// WWDG instance
    pub wwdg: Stm32h7Wwdg,
}

impl WatchdogManager {
    /// Create new watchdog manager
    pub const fn new() -> Self {
        Self {
            iwdg: Stm32h7Iwdg::new(),
            wwdg: Stm32h7Wwdg::new(),
        }
    }

    /// Initialize and start IWDG with given timeout
    pub fn start_iwdg(&mut self, timeout_ms: u32) -> HalResult<()> {
        self.iwdg.configure(timeout_ms)?;
        self.iwdg.start()
    }

    /// Initialize and start WWDG
    pub fn start_wwdg(&mut self, counter: u8, window: u8) -> HalResult<()> {
        self.wwdg.configure(counter, window, WwdgPrescaler::Div8)?;
        self.wwdg.start()
    }

    /// Kick all active watchdogs
    pub fn kick_all(&mut self) {
        self.iwdg.kick();
        if self.wwdg.is_in_window() {
            self.wwdg.kick();
        }
    }
}

impl Default for WatchdogManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iwdg_config_calculation() {
        // Test 1 second timeout
        let result = Stm32h7Iwdg::calculate_config(1000);
        assert!(result.is_some());

        // Test 10 second timeout
        let result = Stm32h7Iwdg::calculate_config(10000);
        assert!(result.is_some());

        // Test 30 second timeout (maximum with Div256)
        let result = Stm32h7Iwdg::calculate_config(30000);
        assert!(result.is_some());
    }

    #[test]
    fn test_iwdg_prescaler_divisor() {
        assert_eq!(IwdgPrescaler::Div4.divisor(), 4);
        assert_eq!(IwdgPrescaler::Div32.divisor(), 32);
        assert_eq!(IwdgPrescaler::Div256.divisor(), 256);
    }

    #[test]
    fn test_wwdg_configure() {
        let mut wwdg = Stm32h7Wwdg::new();

        // Valid configuration
        assert!(wwdg.configure(0x7F, 0x50, WwdgPrescaler::Div8).is_ok());

        // Invalid: counter too low
        let mut wwdg2 = Stm32h7Wwdg::new();
        assert!(wwdg2.configure(0x30, 0x30, WwdgPrescaler::Div8).is_err());

        // Invalid: window > counter
        let mut wwdg3 = Stm32h7Wwdg::new();
        assert!(wwdg3.configure(0x60, 0x70, WwdgPrescaler::Div8).is_err());
    }

    #[test]
    fn test_wwdg_timeout_calculation() {
        let mut wwdg = Stm32h7Wwdg::new();
        wwdg.set_apb_frequency(120_000_000);
        wwdg.configure(0x7F, 0x50, WwdgPrescaler::Div8).unwrap();

        let timeout_us = wwdg.calculate_timeout_us();
        assert!(timeout_us > 0);
    }

    #[test]
    fn test_watchdog_manager() {
        let mut manager = WatchdogManager::new();

        // Just verify construction works
        assert!(!manager.iwdg.is_running());
        assert!(!manager.wwdg.is_running());
    }
}
