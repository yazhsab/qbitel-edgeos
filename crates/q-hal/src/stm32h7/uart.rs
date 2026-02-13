// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32H7 UART/USART Driver
//!
//! Provides blocking UART communication for the STM32H7 series MCUs.
//! Supports USART1-3, UART4-5, USART6, UART7-8.
//!
//! # STM32H7 UART Features
//!
//! - Baud rates up to 10 Mbit/s (USART1/6) or 5 Mbit/s (others)
//! - 7, 8, or 9-bit word length
//! - Even, odd, or no parity
//! - 1 or 2 stop bits
//! - Hardware flow control (RTS/CTS)
//!
//! # Usage
//!
//! ```no_run
//! use q_hal::stm32h7::uart::*;
//!
//! let config = UartConfig::default(); // 115200, 8N1
//! let mut uart = Stm32h7Uart::new(UartInstance::Usart1, config);
//! uart.init(115_200).unwrap();
//! uart.write(b"Hello Qbitel EdgeOS\r\n").unwrap();
//! ```

use crate::error::{HalError, HalResult};
use crate::traits::UartInterface;
use core::ptr;

// ============================================================================
// USART Register Offsets (STM32H7 — different from F4/L4 families)
// ============================================================================

/// Control register 1
const USART_CR1_OFFSET: u32 = 0x00;
/// Control register 2
const USART_CR2_OFFSET: u32 = 0x04;
/// Control register 3
const USART_CR3_OFFSET: u32 = 0x08;
/// Baud rate register
const USART_BRR_OFFSET: u32 = 0x0C;
/// Request register
const USART_RQR_OFFSET: u32 = 0x18;
/// Interrupt & status register
const USART_ISR_OFFSET: u32 = 0x1C;
/// Interrupt flag clear register
const USART_ICR_OFFSET: u32 = 0x20;
/// Receive data register
const USART_RDR_OFFSET: u32 = 0x24;
/// Transmit data register
const USART_TDR_OFFSET: u32 = 0x28;

// ============================================================================
// CR1 bits
// ============================================================================

/// USART enable
const CR1_UE: u32 = 1 << 0;
/// Receiver enable
const CR1_RE: u32 = 1 << 2;
/// Transmitter enable
const CR1_TE: u32 = 1 << 3;
/// Parity control enable
const CR1_PCE: u32 = 1 << 10;
/// Parity selection (0=even, 1=odd)
const CR1_PS: u32 = 1 << 9;
/// Word length bit 0 (M0) — bit 12
const CR1_M0: u32 = 1 << 12;
/// Word length bit 1 (M1) — bit 28
const CR1_M1: u32 = 1 << 28;
/// Oversampling mode (0=16x, 1=8x)
const CR1_OVER8: u32 = 1 << 15;
/// FIFO mode enable (STM32H7 specific)
const CR1_FIFOEN: u32 = 1 << 29;

// ============================================================================
// CR2 bits
// ============================================================================

/// STOP bits field (bits 13:12)
const CR2_STOP_MASK: u32 = 0b11 << 12;
/// 1 stop bit
const CR2_STOP_1: u32 = 0b00 << 12;
/// 2 stop bits
const CR2_STOP_2: u32 = 0b10 << 12;

// ============================================================================
// ISR bits (Interrupt and Status Register)
// ============================================================================

/// Transmit data register empty (ready to accept data)
const ISR_TXE_TXFNF: u32 = 1 << 7;
/// Transmission complete
const ISR_TC: u32 = 1 << 6;
/// Read data register not empty (data available)
const ISR_RXNE_RXFNE: u32 = 1 << 5;
/// Overrun error
const ISR_ORE: u32 = 1 << 3;
/// Framing error
const ISR_FE: u32 = 1 << 1;

// ============================================================================
// ICR bits (Interrupt flag Clear Register)
// ============================================================================

/// Clear overrun error flag
const ICR_ORECF: u32 = 1 << 3;
/// Clear framing error flag
const ICR_FECF: u32 = 1 << 1;

// ============================================================================
// RCC Clock Enable Addresses
// ============================================================================

/// RCC APB2ENR (USART1, USART6)
const RCC_APB2ENR: u32 = 0x5802_4400 + 0xF0;
/// RCC APB1LENR (USART2, USART3, UART4, UART5, UART7, UART8)
const RCC_APB1LENR: u32 = 0x5802_4400 + 0xE8;

// ============================================================================
// UART Instance Definitions
// ============================================================================

/// UART/USART peripheral instance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UartInstance {
    /// USART1 (APB2, up to 10 Mbit/s)
    Usart1,
    /// USART2 (APB1)
    Usart2,
    /// USART3 (APB1)
    Usart3,
    /// UART4 (APB1)
    Uart4,
    /// UART5 (APB1)
    Uart5,
    /// USART6 (APB2, up to 10 Mbit/s)
    Usart6,
    /// UART7 (APB1)
    Uart7,
    /// UART8 (APB1)
    Uart8,
}

impl UartInstance {
    /// Get the base address for this UART instance
    const fn base_addr(&self) -> u32 {
        match self {
            Self::Usart1 => 0x4001_1000,
            Self::Usart2 => 0x4000_4400,
            Self::Usart3 => 0x4000_4800,
            Self::Uart4  => 0x4000_4C00,
            Self::Uart5  => 0x4000_5000,
            Self::Usart6 => 0x4001_1400,
            Self::Uart7  => 0x4000_7800,
            Self::Uart8  => 0x4000_7C00,
        }
    }

    /// Get the RCC enable register address and bit for this instance
    const fn rcc_enable(&self) -> (u32, u32) {
        match self {
            Self::Usart1 => (RCC_APB2ENR, 1 << 4),
            Self::Usart2 => (RCC_APB1LENR, 1 << 17),
            Self::Usart3 => (RCC_APB1LENR, 1 << 18),
            Self::Uart4  => (RCC_APB1LENR, 1 << 19),
            Self::Uart5  => (RCC_APB1LENR, 1 << 20),
            Self::Usart6 => (RCC_APB2ENR, 1 << 5),
            Self::Uart7  => (RCC_APB1LENR, 1 << 30),
            Self::Uart8  => (RCC_APB1LENR, 1 << 31),
        }
    }

    /// Whether this instance is on APB2 (higher clock domain)
    const fn is_apb2(&self) -> bool {
        matches!(self, Self::Usart1 | Self::Usart6)
    }
}

// ============================================================================
// UART Configuration
// ============================================================================

/// Word length
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordLength {
    /// 7 data bits
    Seven,
    /// 8 data bits (default)
    Eight,
    /// 9 data bits
    Nine,
}

/// Parity mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    /// No parity
    None,
    /// Even parity
    Even,
    /// Odd parity
    Odd,
}

/// Stop bits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopBits {
    /// 1 stop bit
    One,
    /// 2 stop bits
    Two,
}

/// UART configuration
#[derive(Debug, Clone, Copy)]
pub struct UartConfig {
    /// Word length
    pub word_length: WordLength,
    /// Parity
    pub parity: Parity,
    /// Stop bits
    pub stop_bits: StopBits,
    /// Enable FIFO mode (STM32H7 feature)
    pub fifo_enabled: bool,
    /// APB clock frequency for baud rate calculation (Hz)
    pub apb_clock_hz: u32,
}

impl Default for UartConfig {
    fn default() -> Self {
        Self {
            word_length: WordLength::Eight,
            parity: Parity::None,
            stop_bits: StopBits::One,
            fifo_enabled: false,
            apb_clock_hz: 120_000_000, // Default APB1/APB2 = 120 MHz
        }
    }
}

/// Timeout for blocking operations (loop iterations)
const BLOCKING_TIMEOUT: u32 = 1_000_000;

// ============================================================================
// UART Driver
// ============================================================================

/// STM32H7 UART driver
pub struct Stm32h7Uart {
    /// UART instance
    instance: UartInstance,
    /// Configuration
    config: UartConfig,
    /// Whether the UART is initialized
    initialized: bool,
}

impl Stm32h7Uart {
    /// Create a new UART driver instance
    #[must_use]
    pub const fn new(instance: UartInstance, config: UartConfig) -> Self {
        Self {
            instance,
            config,
            initialized: false,
        }
    }

    /// Enable the UART peripheral clock
    fn enable_clock(&self) {
        let (reg_addr, bit) = self.instance.rcc_enable();

        // SAFETY: RCC APBxENR registers are memory-mapped. Setting the
        // enable bit activates the peripheral clock. Volatile RMW required
        // for MMIO.
        unsafe {
            let val = ptr::read_volatile(reg_addr as *const u32);
            ptr::write_volatile(reg_addr as *mut u32, val | bit);
            // Dummy read for clock stabilization (2 APB cycles)
            let _ = ptr::read_volatile(reg_addr as *const u32);
        }
    }

    /// Read the ISR register
    fn read_isr(&self) -> u32 {
        let base = self.instance.base_addr();
        // SAFETY: USART_ISR is a read-only status register.
        unsafe { ptr::read_volatile((base + USART_ISR_OFFSET) as *const u32) }
    }

    /// Clear error flags
    fn clear_errors(&self) {
        let base = self.instance.base_addr();
        // SAFETY: Writing to USART_ICR clears the corresponding error flags.
        // Only the specific clear bits are written; other bits are reserved
        // and read as 0.
        unsafe {
            ptr::write_volatile(
                (base + USART_ICR_OFFSET) as *mut u32,
                ICR_ORECF | ICR_FECF,
            );
        }
    }

    /// Get the effective APB clock for this instance
    fn apb_clock(&self) -> u32 {
        // USART1 and USART6 are on APB2; others are on APB1.
        // In default STM32H7 config, APB1 = APB2 = 120 MHz.
        self.config.apb_clock_hz
    }
}

impl UartInterface for Stm32h7Uart {
    /// Initialize the UART with the given baud rate
    fn init(&mut self, baud_rate: u32) -> HalResult<()> {
        if baud_rate == 0 {
            return Err(HalError::InvalidParameter);
        }

        // Enable peripheral clock
        self.enable_clock();

        let base = self.instance.base_addr();

        // SAFETY: All register accesses below are to valid STM32H7 USART MMIO
        // registers. The UART is disabled (UE=0) during configuration to
        // prevent spurious transmissions. Volatile accesses required for MMIO.
        unsafe {
            // 1. Disable UART during configuration
            ptr::write_volatile((base + USART_CR1_OFFSET) as *mut u32, 0);

            // 2. Configure CR2: stop bits
            let cr2 = match self.config.stop_bits {
                StopBits::One => CR2_STOP_1,
                StopBits::Two => CR2_STOP_2,
            };
            ptr::write_volatile((base + USART_CR2_OFFSET) as *mut u32, cr2);

            // 3. Configure CR3 (no hardware flow control, no DMA for now)
            ptr::write_volatile((base + USART_CR3_OFFSET) as *mut u32, 0);

            // 4. Set baud rate (BRR = f_CK / baud_rate for 16x oversampling)
            let brr = self.apb_clock() / baud_rate;
            if brr < 16 || brr > 0xFFFF {
                return Err(HalError::InvalidParameter);
            }
            ptr::write_volatile((base + USART_BRR_OFFSET) as *mut u32, brr);

            // 5. Configure CR1: word length, parity, TX/RX enable, FIFO
            let mut cr1: u32 = CR1_TE | CR1_RE;

            // Word length: M[1:0] — M0 is bit 12, M1 is bit 28
            match self.config.word_length {
                WordLength::Seven => cr1 |= CR1_M1,          // M[1:0] = 10
                WordLength::Eight => {}                        // M[1:0] = 00 (default)
                WordLength::Nine => cr1 |= CR1_M0,           // M[1:0] = 01
            }

            // Parity
            match self.config.parity {
                Parity::None => {}
                Parity::Even => cr1 |= CR1_PCE,
                Parity::Odd => cr1 |= CR1_PCE | CR1_PS,
            }

            // FIFO mode
            if self.config.fifo_enabled {
                cr1 |= CR1_FIFOEN;
            }

            // 6. Enable UART (set UE last, after all configuration)
            cr1 |= CR1_UE;
            ptr::write_volatile((base + USART_CR1_OFFSET) as *mut u32, cr1);
        }

        // Clear any pending error flags
        self.clear_errors();

        self.initialized = true;
        Ok(())
    }

    /// Write a single byte (blocking)
    fn write_byte(&mut self, byte: u8) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let base = self.instance.base_addr();

        // Wait for TXE (transmit data register empty)
        let mut timeout = BLOCKING_TIMEOUT;
        while self.read_isr() & ISR_TXE_TXFNF == 0 {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(HalError::Timeout);
            }
            core::hint::spin_loop();
        }

        // SAFETY: Writing to USART_TDR loads data into the transmit shift
        // register. TXE flag was checked above guaranteeing the register is
        // ready to accept data.
        unsafe {
            ptr::write_volatile((base + USART_TDR_OFFSET) as *mut u32, byte as u32);
        }

        Ok(())
    }

    /// Read a single byte (blocking, with timeout)
    fn read_byte(&mut self) -> HalResult<u8> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let base = self.instance.base_addr();

        // Check and clear overrun error
        if self.read_isr() & ISR_ORE != 0 {
            self.clear_errors();
        }

        // Wait for RXNE (receive data register not empty)
        let mut timeout = BLOCKING_TIMEOUT;
        while self.read_isr() & ISR_RXNE_RXFNE == 0 {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(HalError::Timeout);
            }
            core::hint::spin_loop();
        }

        // SAFETY: Reading USART_RDR retrieves received data and clears
        // the RXNE flag. The flag was checked above guaranteeing data is
        // available.
        let data = unsafe { ptr::read_volatile((base + USART_RDR_OFFSET) as *const u32) };

        Ok((data & 0xFF) as u8)
    }

    /// Read into a buffer, returns the number of bytes actually read
    fn read(&mut self, buffer: &mut [u8]) -> HalResult<usize> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let mut count = 0;
        for slot in buffer.iter_mut() {
            // Non-blocking check: if no data available, stop
            if self.read_isr() & ISR_RXNE_RXFNE == 0 {
                break;
            }

            let base = self.instance.base_addr();
            // SAFETY: RXNE was checked above. Reading RDR clears RXNE.
            let data = unsafe { ptr::read_volatile((base + USART_RDR_OFFSET) as *const u32) };
            *slot = (data & 0xFF) as u8;
            count += 1;
        }

        Ok(count)
    }

    /// Check if data is available to read
    fn is_rx_available(&self) -> bool {
        self.initialized && (self.read_isr() & ISR_RXNE_RXFNE != 0)
    }

    /// Check if transmitter is ready
    fn is_tx_ready(&self) -> bool {
        self.initialized && (self.read_isr() & ISR_TXE_TXFNF != 0)
    }

    /// Flush the transmit buffer (wait for TC = Transmission Complete)
    fn flush(&mut self) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let mut timeout = BLOCKING_TIMEOUT;
        while self.read_isr() & ISR_TC == 0 {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(HalError::Timeout);
            }
            core::hint::spin_loop();
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
    fn test_uart_instance_base_addresses() {
        assert_eq!(UartInstance::Usart1.base_addr(), 0x4001_1000);
        assert_eq!(UartInstance::Usart2.base_addr(), 0x4000_4400);
        assert_eq!(UartInstance::Usart3.base_addr(), 0x4000_4800);
        assert_eq!(UartInstance::Uart4.base_addr(), 0x4000_4C00);
        assert_eq!(UartInstance::Uart5.base_addr(), 0x4000_5000);
        assert_eq!(UartInstance::Usart6.base_addr(), 0x4001_1400);
        assert_eq!(UartInstance::Uart7.base_addr(), 0x4000_7800);
        assert_eq!(UartInstance::Uart8.base_addr(), 0x4000_7C00);
    }

    #[test]
    fn test_uart_rcc_enable() {
        let (reg, bit) = UartInstance::Usart1.rcc_enable();
        assert_eq!(reg, RCC_APB2ENR);
        assert_eq!(bit, 1 << 4);

        let (reg, bit) = UartInstance::Usart2.rcc_enable();
        assert_eq!(reg, RCC_APB1LENR);
        assert_eq!(bit, 1 << 17);
    }

    #[test]
    fn test_uart_apb2_instances() {
        assert!(UartInstance::Usart1.is_apb2());
        assert!(UartInstance::Usart6.is_apb2());
        assert!(!UartInstance::Usart2.is_apb2());
        assert!(!UartInstance::Uart4.is_apb2());
    }

    #[test]
    fn test_uart_default_config() {
        let config = UartConfig::default();
        assert_eq!(config.word_length, WordLength::Eight);
        assert_eq!(config.parity, Parity::None);
        assert_eq!(config.stop_bits, StopBits::One);
        assert!(!config.fifo_enabled);
        assert_eq!(config.apb_clock_hz, 120_000_000);
    }

    #[test]
    fn test_uart_new() {
        let uart = Stm32h7Uart::new(UartInstance::Usart1, UartConfig::default());
        assert_eq!(uart.instance, UartInstance::Usart1);
        assert!(!uart.initialized);
    }

    #[test]
    fn test_uart_not_initialized_write() {
        let mut uart = Stm32h7Uart::new(UartInstance::Usart1, UartConfig::default());
        assert_eq!(uart.write_byte(0x41), Err(HalError::NotInitialized));
    }

    #[test]
    fn test_uart_not_initialized_read() {
        let mut uart = Stm32h7Uart::new(UartInstance::Usart2, UartConfig::default());
        assert_eq!(uart.read_byte(), Err(HalError::NotInitialized));
    }

    #[test]
    fn test_uart_not_initialized_flush() {
        let mut uart = Stm32h7Uart::new(UartInstance::Usart3, UartConfig::default());
        assert_eq!(uart.flush(), Err(HalError::NotInitialized));
    }

    #[test]
    fn test_uart_rx_not_available_when_uninit() {
        let uart = Stm32h7Uart::new(UartInstance::Uart4, UartConfig::default());
        assert!(!uart.is_rx_available());
    }

    #[test]
    fn test_uart_tx_not_ready_when_uninit() {
        let uart = Stm32h7Uart::new(UartInstance::Uart5, UartConfig::default());
        assert!(!uart.is_tx_ready());
    }

    #[test]
    fn test_word_length_values() {
        assert_eq!(WordLength::Seven as u8, 0);
        assert_eq!(WordLength::Eight as u8, 1);
        assert_eq!(WordLength::Nine as u8, 2);
    }

    #[test]
    fn test_stop_bits_values() {
        assert_eq!(StopBits::One as u8, 0);
        assert_eq!(StopBits::Two as u8, 1);
    }
}
