// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32H7 GPIO Driver
//!
//! Provides GPIO port and pin configuration for the STM32H7 series MCUs.
//! Supports all standard GPIO modes: input, output, alternate function, and analog.
//!
//! # STM32H7 GPIO Features
//!
//! - Up to 11 GPIO ports (GPIOA–GPIOK)
//! - 16 pins per port (0–15)
//! - Configurable output speed: low, medium, high, very high
//! - Pull-up / pull-down resistors
//! - Atomic set/reset via BSRR register
//!
//! # Usage
//!
//! ```no_run
//! use q_hal::stm32h7::gpio::*;
//!
//! let mut led = Stm32h7GpioPin::new(GpioPort::PortB, 0);
//! led.configure(GpioMode::Output, GpioOutputType::PushPull,
//!               GpioSpeed::Low, GpioPull::None);
//! led.set_high();
//! ```

use crate::error::{HalError, HalResult};
use crate::traits::GpioPin;
use core::ptr;

// ============================================================================
// STM32H7 GPIO Register Offsets
// ============================================================================

/// Mode register (2 bits per pin)
const GPIO_MODER_OFFSET: u32 = 0x00;
/// Output type register (1 bit per pin)
const GPIO_OTYPER_OFFSET: u32 = 0x04;
/// Output speed register (2 bits per pin)
const GPIO_OSPEEDR_OFFSET: u32 = 0x08;
/// Pull-up/pull-down register (2 bits per pin)
const GPIO_PUPDR_OFFSET: u32 = 0x0C;
/// Input data register
const GPIO_IDR_OFFSET: u32 = 0x10;
/// Output data register
const GPIO_ODR_OFFSET: u32 = 0x14;
/// Bit set/reset register (atomic set/reset)
const GPIO_BSRR_OFFSET: u32 = 0x18;
/// Alternate function low register (pins 0-7)
const GPIO_AFRL_OFFSET: u32 = 0x20;
/// Alternate function high register (pins 8-15)
const GPIO_AFRH_OFFSET: u32 = 0x24;

// ============================================================================
// RCC GPIO Clock Enable
// ============================================================================

/// RCC AHB4ENR register address (GPIO clocks)
const RCC_AHB4ENR: u32 = 0x5802_4400 + 0xE0;

// ============================================================================
// GPIO Port Base Addresses
// ============================================================================

/// GPIO port identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioPort {
    /// GPIOA
    PortA = 0,
    /// GPIOB
    PortB = 1,
    /// GPIOC
    PortC = 2,
    /// GPIOD
    PortD = 3,
    /// GPIOE
    PortE = 4,
    /// GPIOF
    PortF = 5,
    /// GPIOG
    PortG = 6,
    /// GPIOH
    PortH = 7,
    /// GPIOI
    PortI = 8,
    /// GPIOJ
    PortJ = 9,
    /// GPIOK
    PortK = 10,
}

impl GpioPort {
    /// Get the base address for this GPIO port
    const fn base_addr(&self) -> u32 {
        // GPIOA base = 0x5802_0000, each port is 0x400 apart
        0x5802_0000 + (*self as u32) * 0x400
    }

    /// Get the RCC AHB4ENR bit for this GPIO port
    const fn rcc_enable_bit(&self) -> u32 {
        1 << (*self as u32)
    }
}

/// GPIO pin mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioMode {
    /// Input mode (reset state for most pins)
    Input = 0b00,
    /// General purpose output
    Output = 0b01,
    /// Alternate function (UART, SPI, I2C, etc.)
    AlternateFunction = 0b10,
    /// Analog mode (ADC/DAC)
    Analog = 0b11,
}

/// GPIO output type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioOutputType {
    /// Push-pull output
    PushPull = 0,
    /// Open-drain output
    OpenDrain = 1,
}

/// GPIO output speed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioSpeed {
    /// Low speed
    Low = 0b00,
    /// Medium speed
    Medium = 0b01,
    /// High speed
    High = 0b10,
    /// Very high speed
    VeryHigh = 0b11,
}

/// GPIO pull-up/pull-down configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioPull {
    /// No pull-up or pull-down
    None = 0b00,
    /// Pull-up
    Up = 0b01,
    /// Pull-down
    Down = 0b10,
}

/// Alternate function number (AF0–AF15)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioAltFunction {
    Af0 = 0,
    Af1 = 1,
    Af2 = 2,
    Af3 = 3,
    Af4 = 4,
    Af5 = 5,
    Af6 = 6,
    Af7 = 7,
    Af8 = 8,
    Af9 = 9,
    Af10 = 10,
    Af11 = 11,
    Af12 = 12,
    Af13 = 13,
    Af14 = 14,
    Af15 = 15,
}

// ============================================================================
// GPIO Pin Driver
// ============================================================================

/// STM32H7 GPIO pin driver
///
/// Represents a single GPIO pin on a specific port. The pin must be
/// configured before use via [`configure()`] or [`configure_alternate()`].
pub struct Stm32h7GpioPin {
    /// GPIO port
    port: GpioPort,
    /// Pin number (0-15)
    pin: u8,
    /// Whether the port clock has been enabled
    clock_enabled: bool,
    /// Whether the pin has been configured
    configured: bool,
}

impl Stm32h7GpioPin {
    /// Create a new GPIO pin handle (unconfigured)
    ///
    /// # Arguments
    /// * `port` - GPIO port (A-K)
    /// * `pin` - Pin number (0-15)
    ///
    /// # Panics
    /// Panics if `pin > 15`.
    #[must_use]
    pub const fn new(port: GpioPort, pin: u8) -> Self {
        assert!(pin < 16, "GPIO pin must be 0-15");
        Self {
            port,
            pin,
            clock_enabled: false,
            configured: false,
        }
    }

    /// Enable the GPIO port clock in RCC
    fn enable_clock(&mut self) {
        if self.clock_enabled {
            return;
        }

        // SAFETY: RCC_AHB4ENR is the AHB4 peripheral clock enable register.
        // Setting a bit enables the corresponding GPIO port clock. This is a
        // read-modify-write on a memory-mapped register; volatile access is
        // required for MMIO correctness.
        unsafe {
            let val = ptr::read_volatile(RCC_AHB4ENR as *const u32);
            ptr::write_volatile(RCC_AHB4ENR as *mut u32, val | self.port.rcc_enable_bit());

            // Short delay for clock to stabilize (2 AHB cycles)
            let _ = ptr::read_volatile(RCC_AHB4ENR as *const u32);
        }

        self.clock_enabled = true;
    }

    /// Configure pin as input or output
    ///
    /// Enables the port clock and sets mode, output type, speed, and pull.
    pub fn configure(
        &mut self,
        mode: GpioMode,
        output_type: GpioOutputType,
        speed: GpioSpeed,
        pull: GpioPull,
    ) {
        self.enable_clock();
        let base = self.port.base_addr();
        let pin = self.pin as u32;

        // SAFETY: All addresses below are valid STM32H7 GPIO MMIO registers.
        // Each register is modified with a read-modify-write to preserve other
        // pins' configurations. Volatile accesses are required for MMIO.
        unsafe {
            // MODER: 2 bits per pin
            let moder = ptr::read_volatile((base + GPIO_MODER_OFFSET) as *const u32);
            let moder = (moder & !(0b11 << (pin * 2))) | ((mode as u32) << (pin * 2));
            ptr::write_volatile((base + GPIO_MODER_OFFSET) as *mut u32, moder);

            // OTYPER: 1 bit per pin
            let otyper = ptr::read_volatile((base + GPIO_OTYPER_OFFSET) as *const u32);
            let otyper = (otyper & !(1 << pin)) | ((output_type as u32) << pin);
            ptr::write_volatile((base + GPIO_OTYPER_OFFSET) as *mut u32, otyper);

            // OSPEEDR: 2 bits per pin
            let ospeedr = ptr::read_volatile((base + GPIO_OSPEEDR_OFFSET) as *const u32);
            let ospeedr = (ospeedr & !(0b11 << (pin * 2))) | ((speed as u32) << (pin * 2));
            ptr::write_volatile((base + GPIO_OSPEEDR_OFFSET) as *mut u32, ospeedr);

            // PUPDR: 2 bits per pin
            let pupdr = ptr::read_volatile((base + GPIO_PUPDR_OFFSET) as *const u32);
            let pupdr = (pupdr & !(0b11 << (pin * 2))) | ((pull as u32) << (pin * 2));
            ptr::write_volatile((base + GPIO_PUPDR_OFFSET) as *mut u32, pupdr);
        }

        self.configured = true;
    }

    /// Configure pin for alternate function
    ///
    /// Sets the pin to alternate function mode and selects the function number.
    pub fn configure_alternate(
        &mut self,
        af: GpioAltFunction,
        output_type: GpioOutputType,
        speed: GpioSpeed,
        pull: GpioPull,
    ) {
        // First configure mode, type, speed, pull
        self.configure(GpioMode::AlternateFunction, output_type, speed, pull);

        let base = self.port.base_addr();
        let pin = self.pin as u32;

        // SAFETY: AFRL/AFRH are valid STM32H7 GPIO MMIO registers. Each pin
        // occupies 4 bits in the appropriate register (AFRL for pins 0-7,
        // AFRH for pins 8-15). Read-modify-write preserves other pins' AF
        // settings. Volatile access required for MMIO.
        unsafe {
            if pin < 8 {
                // AFRL: pins 0-7, 4 bits per pin
                let afrl = ptr::read_volatile((base + GPIO_AFRL_OFFSET) as *const u32);
                let afrl = (afrl & !(0xF << (pin * 4))) | ((af as u32) << (pin * 4));
                ptr::write_volatile((base + GPIO_AFRL_OFFSET) as *mut u32, afrl);
            } else {
                // AFRH: pins 8-15, 4 bits per pin
                let idx = pin - 8;
                let afrh = ptr::read_volatile((base + GPIO_AFRH_OFFSET) as *const u32);
                let afrh = (afrh & !(0xF << (idx * 4))) | ((af as u32) << (idx * 4));
                ptr::write_volatile((base + GPIO_AFRH_OFFSET) as *mut u32, afrh);
            }
        }
    }

    /// Read the raw input data register bit for this pin
    fn read_idr(&self) -> bool {
        let base = self.port.base_addr();
        // SAFETY: GPIO_IDR is a read-only STM32H7 GPIO register. Volatile
        // read required for MMIO.
        let idr = unsafe { ptr::read_volatile((base + GPIO_IDR_OFFSET) as *const u32) };
        (idr >> self.pin) & 1 != 0
    }
}

impl GpioPin for Stm32h7GpioPin {
    /// Set pin output high using atomic BSRR register
    fn set_high(&mut self) -> HalResult<()> {
        if !self.configured {
            return Err(HalError::NotInitialized);
        }
        let base = self.port.base_addr();
        // SAFETY: GPIO_BSRR is a write-only STM32H7 register. Writing a 1
        // to bits [15:0] atomically sets the corresponding output pin.
        // No read-modify-write needed — BSRR is designed for atomic access.
        unsafe {
            ptr::write_volatile(
                (base + GPIO_BSRR_OFFSET) as *mut u32,
                1 << self.pin,
            );
        }
        Ok(())
    }

    /// Set pin output low using atomic BSRR register
    fn set_low(&mut self) -> HalResult<()> {
        if !self.configured {
            return Err(HalError::NotInitialized);
        }
        let base = self.port.base_addr();
        // SAFETY: GPIO_BSRR bits [31:16] atomically reset the corresponding
        // output pin. No read-modify-write needed.
        unsafe {
            ptr::write_volatile(
                (base + GPIO_BSRR_OFFSET) as *mut u32,
                1 << (self.pin + 16),
            );
        }
        Ok(())
    }

    /// Read pin input state
    fn is_high(&self) -> HalResult<bool> {
        if !self.configured {
            return Err(HalError::NotInitialized);
        }
        Ok(self.read_idr())
    }

    /// Toggle pin output using read-modify of ODR
    fn toggle(&mut self) -> HalResult<()> {
        if !self.configured {
            return Err(HalError::NotInitialized);
        }
        let base = self.port.base_addr();
        // SAFETY: GPIO_ODR is the output data register. XOR the bit to toggle.
        // Volatile read-modify-write required for MMIO.
        unsafe {
            let odr = ptr::read_volatile((base + GPIO_ODR_OFFSET) as *const u32);
            ptr::write_volatile(
                (base + GPIO_ODR_OFFSET) as *mut u32,
                odr ^ (1 << self.pin),
            );
        }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpio_port_base_addresses() {
        assert_eq!(GpioPort::PortA.base_addr(), 0x5802_0000);
        assert_eq!(GpioPort::PortB.base_addr(), 0x5802_0400);
        assert_eq!(GpioPort::PortC.base_addr(), 0x5802_0800);
        assert_eq!(GpioPort::PortK.base_addr(), 0x5802_0000 + 10 * 0x400);
    }

    #[test]
    fn test_gpio_rcc_enable_bits() {
        assert_eq!(GpioPort::PortA.rcc_enable_bit(), 1 << 0);
        assert_eq!(GpioPort::PortB.rcc_enable_bit(), 1 << 1);
        assert_eq!(GpioPort::PortK.rcc_enable_bit(), 1 << 10);
    }

    #[test]
    fn test_gpio_pin_new() {
        let pin = Stm32h7GpioPin::new(GpioPort::PortA, 5);
        assert_eq!(pin.port, GpioPort::PortA);
        assert_eq!(pin.pin, 5);
        assert!(!pin.clock_enabled);
        assert!(!pin.configured);
    }

    #[test]
    #[should_panic(expected = "GPIO pin must be 0-15")]
    fn test_gpio_pin_invalid() {
        let _ = Stm32h7GpioPin::new(GpioPort::PortA, 16);
    }

    #[test]
    fn test_gpio_not_initialized_error() {
        let pin = Stm32h7GpioPin::new(GpioPort::PortA, 0);
        // Unconfigured pin should return NotInitialized
        assert_eq!(pin.is_high(), Err(HalError::NotInitialized));
    }

    #[test]
    fn test_gpio_not_initialized_set_high() {
        let mut pin = Stm32h7GpioPin::new(GpioPort::PortB, 7);
        assert_eq!(pin.set_high(), Err(HalError::NotInitialized));
    }

    #[test]
    fn test_gpio_not_initialized_set_low() {
        let mut pin = Stm32h7GpioPin::new(GpioPort::PortC, 13);
        assert_eq!(pin.set_low(), Err(HalError::NotInitialized));
    }

    #[test]
    fn test_gpio_not_initialized_toggle() {
        let mut pin = Stm32h7GpioPin::new(GpioPort::PortD, 2);
        assert_eq!(pin.toggle(), Err(HalError::NotInitialized));
    }

    #[test]
    fn test_gpio_mode_values() {
        assert_eq!(GpioMode::Input as u8, 0b00);
        assert_eq!(GpioMode::Output as u8, 0b01);
        assert_eq!(GpioMode::AlternateFunction as u8, 0b10);
        assert_eq!(GpioMode::Analog as u8, 0b11);
    }

    #[test]
    fn test_gpio_speed_values() {
        assert_eq!(GpioSpeed::Low as u8, 0b00);
        assert_eq!(GpioSpeed::Medium as u8, 0b01);
        assert_eq!(GpioSpeed::High as u8, 0b10);
        assert_eq!(GpioSpeed::VeryHigh as u8, 0b11);
    }

    #[test]
    fn test_gpio_pull_values() {
        assert_eq!(GpioPull::None as u8, 0b00);
        assert_eq!(GpioPull::Up as u8, 0b01);
        assert_eq!(GpioPull::Down as u8, 0b10);
    }

    #[test]
    fn test_gpio_alt_function_values() {
        assert_eq!(GpioAltFunction::Af0 as u8, 0);
        assert_eq!(GpioAltFunction::Af7 as u8, 7);
        assert_eq!(GpioAltFunction::Af15 as u8, 15);
    }
}
