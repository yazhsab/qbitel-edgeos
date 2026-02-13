// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32H7 Hardware Abstraction Layer
//!
//! This module provides hardware drivers for the STM32H7 series
//! microcontrollers (ARM Cortex-M7 with TrustZone-M).
//!
//! # Supported Features
//!
//! - Internal flash (2MB with ECC)
//! - True random number generator (TRNG)
//! - Hardware crypto accelerator (AES, SHA)
//! - System timer (SysTick + TIM peripherals)
//! - OTP (One-Time Programmable) memory
//! - TrustZone configuration
//! - GPIO, SPI, I2C, UART peripherals

pub mod flash;
pub mod rng;
pub mod crypto;
pub mod timer;
pub mod secure_storage;
pub mod puf;
pub mod system_rng;
pub mod watchdog;
pub mod gpio;
pub mod uart;
pub mod spi;
pub mod i2c;

use crate::traits::{FlashInterface, RngInterface, TimerInterface, SecureStorageInterface, PufInterface};

// Re-export main types
pub use flash::Stm32h7Flash;
pub use rng::Stm32h7Rng;
pub use crypto::{Stm32h7Cryp, Stm32h7Hash, Stm32h7CryptoAccel};
pub use timer::Stm32h7Timer;
pub use secure_storage::Stm32h7SecureStorage;
pub use puf::Stm32h7Puf;
pub use system_rng::{HardwareSeededRng, init_system_rng, system_random_bytes};
pub use watchdog::{Stm32h7Iwdg, Stm32h7Wwdg, WatchdogManager};
pub use gpio::{Stm32h7GpioPin, GpioPort, GpioMode, GpioOutputType, GpioSpeed, GpioPull, GpioAltFunction};
pub use uart::{Stm32h7Uart, UartConfig, UartInstance, WordLength, Parity, StopBits};
pub use spi::{Stm32h7Spi, SpiInstance, SpiConfig, ClockPolarity, ClockPhase, BaudRatePrescaler};
pub use i2c::{Stm32h7I2c, I2cInstance, I2cConfig, I2cSpeed};

use crate::error::{HalError, HalResult};

/// STM32H7 system clock configuration
#[derive(Debug, Clone, Copy)]
pub struct ClockConfig {
    /// System clock frequency in Hz
    pub sysclk_hz: u32,
    /// AHB clock frequency in Hz
    pub hclk_hz: u32,
    /// APB1 clock frequency in Hz
    pub pclk1_hz: u32,
    /// APB2 clock frequency in Hz
    pub pclk2_hz: u32,
}

impl Default for ClockConfig {
    fn default() -> Self {
        Self {
            sysclk_hz: 480_000_000, // 480 MHz max
            hclk_hz: 240_000_000,   // 240 MHz
            pclk1_hz: 120_000_000,  // 120 MHz
            pclk2_hz: 120_000_000,  // 120 MHz
        }
    }
}

/// STM32H7 HAL instance
pub struct Stm32h7Hal {
    /// Clock configuration
    pub clock: ClockConfig,
    /// Flash driver
    pub flash: Stm32h7Flash,
    /// RNG driver
    pub rng: Stm32h7Rng,
    /// Crypto accelerator
    pub crypto: Stm32h7CryptoAccel,
    /// Timer driver
    pub timer: Stm32h7Timer,
    /// Secure storage driver
    pub secure_storage: Stm32h7SecureStorage,
    /// PUF (Physically Unclonable Function) driver
    pub puf: Stm32h7Puf,
    /// Initialization state
    initialized: bool,
}

impl Stm32h7Hal {
    /// Create a new uninitialized HAL instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            clock: ClockConfig {
                sysclk_hz: 480_000_000,
                hclk_hz: 240_000_000,
                pclk1_hz: 120_000_000,
                pclk2_hz: 120_000_000,
            },
            flash: Stm32h7Flash::new(),
            rng: Stm32h7Rng::new(),
            crypto: Stm32h7CryptoAccel::new(),
            timer: Stm32h7Timer::new(),
            secure_storage: Stm32h7SecureStorage::new(),
            puf: Stm32h7Puf::new(),
            initialized: false,
        }
    }

    /// Initialize all HAL peripherals
    pub fn init(&mut self) -> HalResult<()> {
        // CRITICAL: PUF must be initialized FIRST before any other SRAM access
        // This captures the SRAM startup values for PUF operation
        self.puf.init()?;

        // Initialize clock system (HSE -> PLL1 -> 480MHz SYSCLK)
        self.init_clocks()?;

        // Initialize peripherals
        self.flash.init()?;
        self.rng.init()?;
        self.crypto.init()?;
        self.timer.init()?;
        self.secure_storage.init()?;

        self.initialized = true;
        Ok(())
    }

    /// Check if HAL is initialized
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Initialize system clocks to 480MHz from HSE with PLL
    ///
    /// Clock tree:
    /// - HSE (25MHz external crystal) -> PLL1 -> SYSCLK (480MHz)
    /// - AHB = SYSCLK/2 = 240MHz
    /// - APB1/APB2/APB3/APB4 = AHB/2 = 120MHz
    fn init_clocks(&mut self) -> HalResult<()> {
        use core::ptr;

        // STM32H7 RCC register addresses
        const RCC_BASE: u32 = 0x5802_4400;
        const RCC_CR: u32 = RCC_BASE + 0x00;
        const RCC_CFGR: u32 = RCC_BASE + 0x10;
        const RCC_D1CFGR: u32 = RCC_BASE + 0x18;
        const RCC_D2CFGR: u32 = RCC_BASE + 0x1C;
        const RCC_D3CFGR: u32 = RCC_BASE + 0x20;
        const RCC_PLLCKSELR: u32 = RCC_BASE + 0x28;
        const RCC_PLLCFGR: u32 = RCC_BASE + 0x2C;
        const RCC_PLL1DIVR: u32 = RCC_BASE + 0x30;

        // Flash register addresses
        const FLASH_BASE: u32 = 0x5200_2000;
        const FLASH_ACR: u32 = FLASH_BASE + 0x00;

        // RCC_CR bits
        const RCC_CR_HSEON: u32 = 1 << 16;
        const RCC_CR_HSERDY: u32 = 1 << 17;
        const RCC_CR_PLL1ON: u32 = 1 << 24;
        const RCC_CR_PLL1RDY: u32 = 1 << 25;

        // RCC_CFGR bits
        const RCC_CFGR_SW_PLL1: u32 = 0b011;
        const RCC_CFGR_SWS_PLL1: u32 = 0b011 << 3;

        // Flash ACR bits
        const FLASH_ACR_LATENCY_7WS: u32 = 7;
        const FLASH_ACR_WRHIGHFREQ_2: u32 = 2 << 4;

        // SAFETY: All registers below (RCC_CR, RCC_CFGR, RCC_D1CFGR, RCC_D2CFGR, RCC_D3CFGR,
        // RCC_PLLCKSELR, RCC_PLLCFGR, PLL1DIVR, FLASH_ACR) are architecturally-defined STM32H7
        // MMIO registers. Volatile reads/writes are required to configure the system clock tree:
        // HSE oscillator, PLL1, flash wait states, bus prescalers, and clock switching.
        unsafe {
            // 1. Enable HSE (High Speed External) oscillator
            let cr = ptr::read_volatile(RCC_CR as *const u32);
            ptr::write_volatile(RCC_CR as *mut u32, cr | RCC_CR_HSEON);

            // Wait for HSE to stabilize (with timeout)
            let mut timeout = 100_000u32;
            while ptr::read_volatile(RCC_CR as *const u32) & RCC_CR_HSERDY == 0 {
                timeout = timeout.saturating_sub(1);
                if timeout == 0 {
                    return Err(HalError::InitFailed);
                }
                core::hint::spin_loop();
            }

            // 2. Configure Flash wait states for 480MHz (VOS1 range)
            // 7 wait states + write high frequency mode 2
            let acr = FLASH_ACR_LATENCY_7WS | FLASH_ACR_WRHIGHFREQ_2;
            ptr::write_volatile(FLASH_ACR as *mut u32, acr);

            // 3. Configure PLL1 for 480MHz
            // PLL1 input = HSE (25MHz)
            // PLL1_N = 192, PLL1_M = 5, PLL1_P = 2
            // VCO = 25MHz / 5 * 192 = 960MHz
            // PLL1_P output = 960MHz / 2 = 480MHz

            // Select HSE as PLL source, DIVM1 = 5
            let pllckselr = (5 << 4) | 0x2; // DIVM1 = 5, PLLSRC = HSE
            ptr::write_volatile(RCC_PLLCKSELR as *mut u32, pllckselr);

            // Configure PLL1: enable P output, set VCO range
            let pllcfgr = ptr::read_volatile(RCC_PLLCFGR as *const u32);
            let pllcfgr = (pllcfgr & !(0xF << 0)) | (1 << 16); // PLL1RGE=3 (8-16MHz), PLL1P enable
            ptr::write_volatile(RCC_PLLCFGR as *mut u32, pllcfgr);

            // PLL1 dividers: N=192, P=2, Q=4, R=4
            // DIVN1 = 191 (N-1), DIVP1 = 1 (P-1), DIVQ1 = 3, DIVR1 = 3
            let pll1divr: u32 = (191 << 0) | (1 << 9) | (3 << 16) | (3 << 24);
            ptr::write_volatile(RCC_PLL1DIVR as *mut u32, pll1divr);

            // 4. Enable PLL1
            let cr = ptr::read_volatile(RCC_CR as *const u32);
            ptr::write_volatile(RCC_CR as *mut u32, cr | RCC_CR_PLL1ON);

            // Wait for PLL1 to lock
            timeout = 100_000;
            while ptr::read_volatile(RCC_CR as *const u32) & RCC_CR_PLL1RDY == 0 {
                timeout = timeout.saturating_sub(1);
                if timeout == 0 {
                    return Err(HalError::InitFailed);
                }
                core::hint::spin_loop();
            }

            // 5. Configure bus prescalers
            // D1CPRE = 1 (SYSCLK not divided)
            // HPRE = 2 (SYSCLK/2 = 240MHz for AHB)
            // D1PPRE = 2 (AHB/2 = 120MHz for APB3)
            let d1cfgr: u32 = (0b0000 << 0) | (0b1000 << 4) | (0b100 << 8);
            ptr::write_volatile(RCC_D1CFGR as *mut u32, d1cfgr);

            // D2PPRE1 = 2, D2PPRE2 = 2
            let d2cfgr: u32 = (0b100 << 4) | (0b100 << 8);
            ptr::write_volatile(RCC_D2CFGR as *mut u32, d2cfgr);

            // D3PPRE = 2
            let d3cfgr: u32 = 0b100 << 4;
            ptr::write_volatile(RCC_D3CFGR as *mut u32, d3cfgr);

            // 6. Switch system clock to PLL1
            let cfgr = ptr::read_volatile(RCC_CFGR as *const u32);
            ptr::write_volatile(RCC_CFGR as *mut u32, (cfgr & !0x7) | RCC_CFGR_SW_PLL1);

            // Wait for clock switch
            timeout = 100_000;
            while (ptr::read_volatile(RCC_CFGR as *const u32) & (0x7 << 3)) != RCC_CFGR_SWS_PLL1 {
                timeout = timeout.saturating_sub(1);
                if timeout == 0 {
                    return Err(HalError::InitFailed);
                }
                core::hint::spin_loop();
            }
        }

        // Update clock configuration
        self.clock.sysclk_hz = 480_000_000;
        self.clock.hclk_hz = 240_000_000;
        self.clock.pclk1_hz = 120_000_000;
        self.clock.pclk2_hz = 120_000_000;

        Ok(())
    }

    /// Get system clock frequency
    #[must_use]
    pub const fn sysclk(&self) -> u32 {
        self.clock.sysclk_hz
    }

    /// Perform system reset via NVIC Application Interrupt and Reset Control Register
    ///
    /// This triggers a full system reset including all peripherals.
    /// The function never returns.
    pub fn reset(&mut self) -> ! {
        // SCB AIRCR (Application Interrupt and Reset Control Register)
        // Address: 0xE000_ED0C
        // Write key: 0x05FA in bits [31:16]
        // SYSRESETREQ: bit 2
        const SCB_AIRCR: *mut u32 = 0xE000_ED0C as *mut u32;
        const AIRCR_VECTKEY: u32 = 0x05FA_0000;
        const AIRCR_SYSRESETREQ: u32 = 1 << 2;

        // SAFETY: Writing to the AIRCR register with the correct VECTKEY
        // and SYSRESETREQ bit triggers a system reset. This is the standard
        // ARM Cortex-M reset mechanism. The write is volatile because it
        // has a hardware side effect (system reset).
        unsafe {
            // Data synchronization barrier to ensure all pending memory
            // accesses complete before reset
            core::arch::asm!("dsb sy", options(nomem, nostack));
            core::ptr::write_volatile(SCB_AIRCR, AIRCR_VECTKEY | AIRCR_SYSRESETREQ);
            // Instruction synchronization barrier
            core::arch::asm!("isb", options(nomem, nostack));
        }

        // Reset should happen immediately, but spin just in case
        loop {
            core::hint::spin_loop();
        }
    }
}

impl Default for Stm32h7Hal {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory-mapped register access utilities
pub(crate) mod registers {
    use core::ptr::{read_volatile, write_volatile};

    /// Read a 32-bit register
    ///
    /// # Safety
    /// The address must be a valid memory-mapped register.
    #[inline]
    pub unsafe fn read_reg(addr: u32) -> u32 {
        read_volatile(addr as *const u32)
    }

    /// Write a 32-bit register
    ///
    /// # Safety
    /// The address must be a valid memory-mapped register.
    #[inline]
    pub unsafe fn write_reg(addr: u32, value: u32) {
        write_volatile(addr as *mut u32, value);
    }

    /// Modify a 32-bit register (read-modify-write)
    ///
    /// # Safety
    /// The address must be a valid memory-mapped register.
    #[inline]
    #[allow(dead_code)]
    pub unsafe fn modify_reg<F>(addr: u32, f: F)
    where
        F: FnOnce(u32) -> u32,
    {
        let value = read_reg(addr);
        write_reg(addr, f(value));
    }

    /// Set bits in a register
    ///
    /// # Safety
    /// The address must be a valid memory-mapped register.
    #[inline]
    #[allow(dead_code)]
    pub unsafe fn set_bits(addr: u32, bits: u32) {
        modify_reg(addr, |v| v | bits);
    }

    /// Clear bits in a register
    ///
    /// # Safety
    /// The address must be a valid memory-mapped register.
    #[inline]
    #[allow(dead_code)]
    pub unsafe fn clear_bits(addr: u32, bits: u32) {
        modify_reg(addr, |v| v & !bits);
    }
}

/// STM32H7 peripheral base addresses
pub mod addresses {
    /// Flash memory base
    pub const FLASH_BASE: u32 = 0x0800_0000;
    /// System memory (bootloader) base
    pub const SYSTEM_MEMORY_BASE: u32 = 0x1FF0_0000;
    /// OTP area base
    pub const OTP_BASE: u32 = 0x1FF0_F000;
    /// Option bytes base
    pub const OPTION_BYTES_BASE: u32 = 0x1FF0_F800;

    /// SRAM1 base
    pub const SRAM1_BASE: u32 = 0x2000_0000;
    /// SRAM2 base
    pub const SRAM2_BASE: u32 = 0x2002_0000;
    /// SRAM3 base
    pub const SRAM3_BASE: u32 = 0x2004_0000;

    /// Backup SRAM base
    pub const BKPSRAM_BASE: u32 = 0x3800_0000;

    /// Flash controller registers
    pub const FLASH_R_BASE: u32 = 0x5200_2000;

    /// RNG registers
    pub const RNG_BASE: u32 = 0x4802_1800;

    /// RCC (Reset and Clock Control) registers
    pub const RCC_BASE: u32 = 0x5802_4400;
}
