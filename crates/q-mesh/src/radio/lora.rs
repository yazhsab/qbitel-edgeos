// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! LoRa Radio Driver for SX1276/SX1278 transceivers
//!
//! This module implements a complete LoRa radio driver supporting:
//!
//! - SX1276/SX1278 chipset (Semtech)
//! - Multiple frequency bands (EU868, US915, AS923)
//! - Configurable spreading factor, bandwidth, and coding rate
//! - RSSI and SNR monitoring
//! - Channel Activity Detection (CAD)
//! - Listen-Before-Talk (LBT) support

use super::{Radio, RadioState, RadioEvent, ChannelConfig};
use q_common::Error;
use core::sync::atomic::{AtomicU8, AtomicBool, Ordering};

/// Maximum packet size for LoRa
pub const MAX_PACKET_SIZE: usize = 255;

/// FIFO size in SX127x
pub const FIFO_SIZE: usize = 256;

/// LoRa spreading factor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpreadingFactor {
    /// SF6 - Fastest, shortest range
    Sf6 = 6,
    /// SF7 - Default for LoRaWAN
    Sf7 = 7,
    /// SF8
    Sf8 = 8,
    /// SF9
    Sf9 = 9,
    /// SF10
    Sf10 = 10,
    /// SF11
    Sf11 = 11,
    /// SF12 - Slowest, longest range
    Sf12 = 12,
}

impl Default for SpreadingFactor {
    fn default() -> Self {
        Self::Sf7
    }
}

impl SpreadingFactor {
    /// Get the time on air multiplier for this SF
    #[must_use]
    pub const fn time_multiplier(&self) -> u32 {
        match self {
            Self::Sf6 => 1,
            Self::Sf7 => 2,
            Self::Sf8 => 4,
            Self::Sf9 => 8,
            Self::Sf10 => 16,
            Self::Sf11 => 32,
            Self::Sf12 => 64,
        }
    }
}

/// LoRa bandwidth
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Bandwidth {
    /// 7.8 kHz
    Bw7_8 = 0,
    /// 10.4 kHz
    Bw10_4 = 1,
    /// 15.6 kHz
    Bw15_6 = 2,
    /// 20.8 kHz
    Bw20_8 = 3,
    /// 31.25 kHz
    Bw31_25 = 4,
    /// 41.7 kHz
    Bw41_7 = 5,
    /// 62.5 kHz
    Bw62_5 = 6,
    /// 125 kHz - Default
    Bw125 = 7,
    /// 250 kHz
    Bw250 = 8,
    /// 500 kHz
    Bw500 = 9,
}

impl Default for Bandwidth {
    fn default() -> Self {
        Self::Bw125
    }
}

impl Bandwidth {
    /// Get bandwidth in Hz
    #[must_use]
    pub const fn hz(&self) -> u32 {
        match self {
            Self::Bw7_8 => 7_800,
            Self::Bw10_4 => 10_400,
            Self::Bw15_6 => 15_600,
            Self::Bw20_8 => 20_800,
            Self::Bw31_25 => 31_250,
            Self::Bw41_7 => 41_700,
            Self::Bw62_5 => 62_500,
            Self::Bw125 => 125_000,
            Self::Bw250 => 250_000,
            Self::Bw500 => 500_000,
        }
    }
}

/// LoRa coding rate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CodingRate {
    /// 4/5 - Minimum error correction
    Cr4_5 = 1,
    /// 4/6
    Cr4_6 = 2,
    /// 4/7
    Cr4_7 = 3,
    /// 4/8 - Maximum error correction
    Cr4_8 = 4,
}

impl Default for CodingRate {
    fn default() -> Self {
        Self::Cr4_5
    }
}

/// Frequency band configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrequencyBand {
    /// EU 863-870 MHz
    Eu868,
    /// US 902-928 MHz
    Us915,
    /// Asia 920-925 MHz
    As923,
    /// Custom frequency
    Custom(u32),
}

impl Default for FrequencyBand {
    fn default() -> Self {
        Self::Eu868
    }
}

impl FrequencyBand {
    /// Get center frequency in Hz
    #[must_use]
    pub const fn frequency(&self) -> u32 {
        match self {
            Self::Eu868 => 868_100_000,
            Self::Us915 => 915_000_000,
            Self::As923 => 923_200_000,
            Self::Custom(f) => *f,
        }
    }

    /// Get channel configuration for this band
    #[must_use]
    pub const fn channel_config(&self) -> ChannelConfig {
        match self {
            Self::Eu868 => ChannelConfig::eu868(),
            Self::Us915 => ChannelConfig::us915(),
            Self::As923 => ChannelConfig::as923(),
            Self::Custom(f) => ChannelConfig {
                frequency: *f,
                min_frequency: *f - 1_000_000,
                max_frequency: *f + 1_000_000,
                channel_spacing: 200_000,
                num_channels: 10,
            },
        }
    }
}

/// LoRa radio configuration
#[derive(Debug, Clone, Copy)]
pub struct LoRaConfig {
    /// Frequency band
    pub band: FrequencyBand,
    /// Spreading factor
    pub spreading_factor: SpreadingFactor,
    /// Bandwidth
    pub bandwidth: Bandwidth,
    /// Coding rate
    pub coding_rate: CodingRate,
    /// TX power in dBm
    pub tx_power: i8,
    /// Preamble length
    pub preamble_length: u16,
    /// Enable CRC
    pub crc_enabled: bool,
    /// Implicit header mode
    pub implicit_header: bool,
    /// Sync word (0x34 for public LoRaWAN, 0x12 for private)
    pub sync_word: u8,
    /// Enable low data rate optimization
    pub low_datarate_optimize: bool,
    /// Enable Listen-Before-Talk
    pub lbt_enabled: bool,
    /// LBT threshold in dBm
    pub lbt_threshold: i16,
}

impl Default for LoRaConfig {
    fn default() -> Self {
        Self {
            band: FrequencyBand::Eu868,
            spreading_factor: SpreadingFactor::Sf7,
            bandwidth: Bandwidth::Bw125,
            coding_rate: CodingRate::Cr4_5,
            tx_power: 14, // 14 dBm default
            preamble_length: 8,
            crc_enabled: true,
            implicit_header: false,
            sync_word: 0x12, // Private network
            low_datarate_optimize: false,
            lbt_enabled: true,
            lbt_threshold: -80, // -80 dBm
        }
    }
}

impl LoRaConfig {
    /// Create configuration for EU868 band
    #[must_use]
    pub const fn eu868() -> Self {
        Self {
            band: FrequencyBand::Eu868,
            spreading_factor: SpreadingFactor::Sf7,
            bandwidth: Bandwidth::Bw125,
            coding_rate: CodingRate::Cr4_5,
            tx_power: 14,
            preamble_length: 8,
            crc_enabled: true,
            implicit_header: false,
            sync_word: 0x12,
            low_datarate_optimize: false,
            lbt_enabled: true,
            lbt_threshold: -80,
        }
    }

    /// Create configuration for US915 band
    #[must_use]
    pub const fn us915() -> Self {
        Self {
            band: FrequencyBand::Us915,
            spreading_factor: SpreadingFactor::Sf7,
            bandwidth: Bandwidth::Bw125,
            coding_rate: CodingRate::Cr4_5,
            tx_power: 20, // Higher power in US
            preamble_length: 8,
            crc_enabled: true,
            implicit_header: false,
            sync_word: 0x12,
            low_datarate_optimize: false,
            lbt_enabled: false, // FCC allows without LBT
            lbt_threshold: -80,
        }
    }

    /// Create long-range configuration (SF12)
    #[must_use]
    pub const fn long_range() -> Self {
        Self {
            band: FrequencyBand::Eu868,
            spreading_factor: SpreadingFactor::Sf12,
            bandwidth: Bandwidth::Bw125,
            coding_rate: CodingRate::Cr4_8,
            tx_power: 14,
            preamble_length: 12,
            crc_enabled: true,
            implicit_header: false,
            sync_word: 0x12,
            low_datarate_optimize: true,
            lbt_enabled: true,
            lbt_threshold: -80,
        }
    }

    /// Calculate symbol time in microseconds
    #[must_use]
    pub fn symbol_time_us(&self) -> u32 {
        let bw = self.bandwidth.hz();
        let sf = self.spreading_factor as u32;
        // Ts = 2^SF / BW
        (1u32 << sf) * 1_000_000 / bw
    }

    /// Check if low data rate optimization should be enabled
    #[must_use]
    pub fn needs_ldro(&self) -> bool {
        self.symbol_time_us() > 16_000 // > 16ms symbol time
    }
}

/// SX127x register addresses
#[allow(dead_code)]
mod reg {
    pub const REG_FIFO: u8 = 0x00;
    pub const REG_OP_MODE: u8 = 0x01;
    pub const REG_FRF_MSB: u8 = 0x06;
    pub const REG_FRF_MID: u8 = 0x07;
    pub const REG_FRF_LSB: u8 = 0x08;
    pub const REG_PA_CONFIG: u8 = 0x09;
    pub const REG_PA_RAMP: u8 = 0x0A;
    pub const REG_OCP: u8 = 0x0B;
    pub const REG_LNA: u8 = 0x0C;
    pub const REG_FIFO_ADDR_PTR: u8 = 0x0D;
    pub const REG_FIFO_TX_BASE_ADDR: u8 = 0x0E;
    pub const REG_FIFO_RX_BASE_ADDR: u8 = 0x0F;
    pub const REG_FIFO_RX_CURRENT_ADDR: u8 = 0x10;
    pub const REG_IRQ_FLAGS_MASK: u8 = 0x11;
    pub const REG_IRQ_FLAGS: u8 = 0x12;
    pub const REG_RX_NB_BYTES: u8 = 0x13;
    pub const REG_PKT_SNR_VALUE: u8 = 0x19;
    pub const REG_PKT_RSSI_VALUE: u8 = 0x1A;
    pub const REG_RSSI_VALUE: u8 = 0x1B;
    pub const REG_MODEM_CONFIG_1: u8 = 0x1D;
    pub const REG_MODEM_CONFIG_2: u8 = 0x1E;
    pub const REG_SYMB_TIMEOUT_LSB: u8 = 0x1F;
    pub const REG_PREAMBLE_MSB: u8 = 0x20;
    pub const REG_PREAMBLE_LSB: u8 = 0x21;
    pub const REG_PAYLOAD_LENGTH: u8 = 0x22;
    pub const REG_MAX_PAYLOAD_LENGTH: u8 = 0x23;
    pub const REG_HOP_PERIOD: u8 = 0x24;
    pub const REG_MODEM_CONFIG_3: u8 = 0x26;
    pub const REG_DETECT_OPTIMIZE: u8 = 0x31;
    pub const REG_DETECTION_THRESHOLD: u8 = 0x37;
    pub const REG_SYNC_WORD: u8 = 0x39;
    pub const REG_DIO_MAPPING_1: u8 = 0x40;
    pub const REG_VERSION: u8 = 0x42;
}

/// IRQ flags
#[allow(dead_code)]
mod irq {
    pub const IRQ_CAD_DETECTED: u8 = 0x01;
    pub const IRQ_FHSS_CHANGE: u8 = 0x02;
    pub const IRQ_CAD_DONE: u8 = 0x04;
    pub const IRQ_TX_DONE: u8 = 0x08;
    pub const IRQ_VALID_HEADER: u8 = 0x10;
    pub const IRQ_PAYLOAD_CRC_ERROR: u8 = 0x20;
    pub const IRQ_RX_DONE: u8 = 0x40;
    pub const IRQ_RX_TIMEOUT: u8 = 0x80;
}

/// Operating modes
#[allow(dead_code)]
mod mode {
    pub const MODE_SLEEP: u8 = 0x00;
    pub const MODE_STDBY: u8 = 0x01;
    pub const MODE_FSTX: u8 = 0x02;
    pub const MODE_TX: u8 = 0x03;
    pub const MODE_FSRX: u8 = 0x04;
    pub const MODE_RX_CONTINUOUS: u8 = 0x05;
    pub const MODE_RX_SINGLE: u8 = 0x06;
    pub const MODE_CAD: u8 = 0x07;
    pub const MODE_LORA: u8 = 0x80;
}

/// SPI interface trait for radio communication
pub trait SpiInterface {
    /// Write a single register
    fn write_register(&mut self, addr: u8, value: u8) -> Result<(), Error>;
    /// Read a single register
    fn read_register(&mut self, addr: u8) -> Result<u8, Error>;
    /// Write multiple bytes to FIFO
    fn write_fifo(&mut self, data: &[u8]) -> Result<(), Error>;
    /// Read multiple bytes from FIFO
    fn read_fifo(&mut self, buffer: &mut [u8]) -> Result<(), Error>;
}

/// GPIO interface for radio control
pub trait GpioInterface {
    /// Set reset pin state
    fn set_reset(&mut self, state: bool);
    /// Read DIO0 pin (TX Done / RX Done)
    fn read_dio0(&self) -> bool;
    /// Read DIO1 pin (RX Timeout / FHSS)
    fn read_dio1(&self) -> bool;
    /// Delay in milliseconds
    fn delay_ms(&mut self, ms: u32);
}

/// LoRa Radio driver for SX1276/SX1278
pub struct LoRaRadio<SPI, GPIO>
where
    SPI: SpiInterface,
    GPIO: GpioInterface,
{
    /// SPI interface
    spi: SPI,
    /// GPIO interface
    gpio: GPIO,
    /// Configuration
    config: LoRaConfig,
    /// Current radio state
    state: AtomicU8,
    /// Last RSSI value
    last_rssi: i16,
    /// Last SNR value
    last_snr: i8,
    /// TX/RX buffer
    buffer: [u8; MAX_PACKET_SIZE],
    /// Bytes received
    rx_len: usize,
    /// Data available flag
    data_available: AtomicBool,
    /// Initialized flag
    initialized: bool,
    /// Current channel
    channel: u8,
}

impl<SPI, GPIO> LoRaRadio<SPI, GPIO>
where
    SPI: SpiInterface,
    GPIO: GpioInterface,
{
    /// Create a new LoRa radio instance
    pub fn new(spi: SPI, gpio: GPIO, config: LoRaConfig) -> Self {
        Self {
            spi,
            gpio,
            config,
            state: AtomicU8::new(RadioState::Sleep as u8),
            last_rssi: 0,
            last_snr: 0,
            buffer: [0u8; MAX_PACKET_SIZE],
            rx_len: 0,
            data_available: AtomicBool::new(false),
            initialized: false,
            channel: 0,
        }
    }

    /// Reset the radio hardware
    pub fn reset(&mut self) {
        self.gpio.set_reset(false);
        self.gpio.delay_ms(1);
        self.gpio.set_reset(true);
        self.gpio.delay_ms(10);
    }

    /// Read chip version
    pub fn version(&mut self) -> Result<u8, Error> {
        self.spi.read_register(reg::REG_VERSION)
    }

    /// Set operating mode
    fn set_mode(&mut self, mode: u8) -> Result<(), Error> {
        self.spi.write_register(reg::REG_OP_MODE, mode::MODE_LORA | mode)
    }

    /// Set frequency in Hz
    fn set_frequency(&mut self, freq: u32) -> Result<(), Error> {
        // Frf = (Fxosc * Frf_reg) / 2^19
        // Frf_reg = (Freq * 2^19) / Fxosc
        // Fxosc = 32 MHz
        let frf = ((freq as u64) << 19) / 32_000_000;

        self.spi.write_register(reg::REG_FRF_MSB, ((frf >> 16) & 0xFF) as u8)?;
        self.spi.write_register(reg::REG_FRF_MID, ((frf >> 8) & 0xFF) as u8)?;
        self.spi.write_register(reg::REG_FRF_LSB, (frf & 0xFF) as u8)?;
        Ok(())
    }

    /// Configure TX power
    fn set_tx_power(&mut self, power: i8) -> Result<(), Error> {
        // Using PA_BOOST pin
        // Pout = 17 - (15 - OutputPower) for PA_BOOST
        let output_power = if power > 17 {
            15 // Max power
        } else if power < 2 {
            0
        } else {
            (power - 2) as u8
        };

        // PA_BOOST selected, max power
        self.spi.write_register(reg::REG_PA_CONFIG, 0x80 | output_power)?;

        // Enable OCP at 100mA
        self.spi.write_register(reg::REG_OCP, 0x20 | 0x0B)?;

        Ok(())
    }

    /// Configure modem parameters
    fn configure_modem(&mut self) -> Result<(), Error> {
        let sf = self.config.spreading_factor as u8;
        let bw = self.config.bandwidth as u8;
        let cr = self.config.coding_rate as u8;

        // Modem Config 1: BW, CR, Implicit header
        let mc1 = (bw << 4) | (cr << 1) | (self.config.implicit_header as u8);
        self.spi.write_register(reg::REG_MODEM_CONFIG_1, mc1)?;

        // Modem Config 2: SF, CRC
        let mc2 = (sf << 4) | ((self.config.crc_enabled as u8) << 2);
        self.spi.write_register(reg::REG_MODEM_CONFIG_2, mc2)?;

        // Modem Config 3: LDRO, AGC
        let ldro = self.config.low_datarate_optimize || self.config.needs_ldro();
        let mc3 = ((ldro as u8) << 3) | 0x04; // AGC auto on
        self.spi.write_register(reg::REG_MODEM_CONFIG_3, mc3)?;

        // Preamble length
        self.spi.write_register(reg::REG_PREAMBLE_MSB, (self.config.preamble_length >> 8) as u8)?;
        self.spi.write_register(reg::REG_PREAMBLE_LSB, (self.config.preamble_length & 0xFF) as u8)?;

        // Sync word
        self.spi.write_register(reg::REG_SYNC_WORD, self.config.sync_word)?;

        // Detection optimize for SF6
        if sf == 6 {
            self.spi.write_register(reg::REG_DETECT_OPTIMIZE, 0x05)?;
            self.spi.write_register(reg::REG_DETECTION_THRESHOLD, 0x0C)?;
        } else {
            self.spi.write_register(reg::REG_DETECT_OPTIMIZE, 0x03)?;
            self.spi.write_register(reg::REG_DETECTION_THRESHOLD, 0x0A)?;
        }

        Ok(())
    }

    /// Configure DIO mappings
    fn configure_dio(&mut self) -> Result<(), Error> {
        // DIO0 = RxDone/TxDone, DIO1 = RxTimeout
        self.spi.write_register(reg::REG_DIO_MAPPING_1, 0x00)
    }

    /// Set channel number
    pub fn set_channel(&mut self, channel: u8) -> Result<(), Error> {
        let channel_config = self.config.band.channel_config();
        let freq = channel_config.channel_frequency(channel);
        self.channel = channel;
        self.set_frequency(freq)
    }

    /// Perform channel activity detection
    pub fn channel_activity_detection(&mut self) -> Result<bool, Error> {
        // Set to CAD mode
        self.set_mode(mode::MODE_CAD)?;
        self.state.store(RadioState::Cad as u8, Ordering::SeqCst);

        // Wait for CAD done (with timeout)
        let mut timeout = 1000u32;
        while timeout > 0 {
            let irq = self.spi.read_register(reg::REG_IRQ_FLAGS)?;
            if irq & irq::IRQ_CAD_DONE != 0 {
                // Clear IRQ
                self.spi.write_register(reg::REG_IRQ_FLAGS, irq::IRQ_CAD_DONE | irq::IRQ_CAD_DETECTED)?;
                self.state.store(RadioState::Standby as u8, Ordering::SeqCst);
                return Ok(irq & irq::IRQ_CAD_DETECTED != 0);
            }
            self.gpio.delay_ms(1);
            timeout -= 1;
        }

        self.state.store(RadioState::Standby as u8, Ordering::SeqCst);
        Err(Error::Timeout)
    }

    /// Read current RSSI value
    pub fn read_rssi(&mut self) -> Result<i16, Error> {
        let rssi_raw = self.spi.read_register(reg::REG_RSSI_VALUE)?;
        // RSSI = -157 + Rssi for HF port
        Ok(-157 + rssi_raw as i16)
    }

    /// Handle interrupt (call from ISR)
    pub fn handle_interrupt(&mut self) -> Result<Option<RadioEvent>, Error> {
        let irq = self.spi.read_register(reg::REG_IRQ_FLAGS)?;

        if irq & irq::IRQ_TX_DONE != 0 {
            self.spi.write_register(reg::REG_IRQ_FLAGS, irq::IRQ_TX_DONE)?;
            self.state.store(RadioState::Standby as u8, Ordering::SeqCst);
            return Ok(Some(RadioEvent::TxDone));
        }

        if irq & irq::IRQ_RX_DONE != 0 {
            // Check for CRC error
            if irq & irq::IRQ_PAYLOAD_CRC_ERROR != 0 {
                self.spi.write_register(reg::REG_IRQ_FLAGS, irq::IRQ_RX_DONE | irq::IRQ_PAYLOAD_CRC_ERROR)?;
                return Ok(Some(RadioEvent::CrcError));
            }

            // Read packet info
            let rx_addr = self.spi.read_register(reg::REG_FIFO_RX_CURRENT_ADDR)?;
            let rx_len = self.spi.read_register(reg::REG_RX_NB_BYTES)?;

            // Read SNR and RSSI
            let snr_raw = self.spi.read_register(reg::REG_PKT_SNR_VALUE)?;
            self.last_snr = (snr_raw as i8) / 4;

            let rssi_raw = self.spi.read_register(reg::REG_PKT_RSSI_VALUE)?;
            self.last_rssi = if self.last_snr < 0 {
                -157 + rssi_raw as i16 + self.last_snr as i16
            } else {
                -157 + (rssi_raw as i16 * 16 / 15)
            };

            // Read data from FIFO
            self.spi.write_register(reg::REG_FIFO_ADDR_PTR, rx_addr)?;
            let len = (rx_len as usize).min(MAX_PACKET_SIZE);
            self.spi.read_fifo(&mut self.buffer[..len])?;
            self.rx_len = len;

            self.spi.write_register(reg::REG_IRQ_FLAGS, irq::IRQ_RX_DONE)?;
            self.data_available.store(true, Ordering::SeqCst);
            return Ok(Some(RadioEvent::RxDone));
        }

        if irq & irq::IRQ_RX_TIMEOUT != 0 {
            self.spi.write_register(reg::REG_IRQ_FLAGS, irq::IRQ_RX_TIMEOUT)?;
            return Ok(Some(RadioEvent::RxTimeout));
        }

        if irq & irq::IRQ_CAD_DONE != 0 {
            let detected = irq & irq::IRQ_CAD_DETECTED != 0;
            self.spi.write_register(reg::REG_IRQ_FLAGS, irq::IRQ_CAD_DONE | irq::IRQ_CAD_DETECTED)?;
            if detected {
                return Ok(Some(RadioEvent::CadDetected));
            } else {
                return Ok(Some(RadioEvent::CadDone));
            }
        }

        Ok(None)
    }

    /// Get current state
    #[must_use]
    pub fn get_state(&self) -> RadioState {
        match self.state.load(Ordering::SeqCst) {
            0 => RadioState::Sleep,
            1 => RadioState::Standby,
            2 => RadioState::Tx,
            3 => RadioState::Rx,
            4 => RadioState::Cad,
            _ => RadioState::Standby,
        }
    }

    /// Get configuration
    #[must_use]
    pub fn config(&self) -> &LoRaConfig {
        &self.config
    }

    /// Update configuration
    pub fn set_config(&mut self, config: LoRaConfig) -> Result<(), Error> {
        self.config = config;
        if self.initialized {
            self.standby()?;
            self.set_frequency(self.config.band.frequency())?;
            self.set_tx_power(self.config.tx_power)?;
            self.configure_modem()?;
        }
        Ok(())
    }
}

impl<SPI, GPIO> Radio for LoRaRadio<SPI, GPIO>
where
    SPI: SpiInterface,
    GPIO: GpioInterface,
{
    fn init(&mut self) -> Result<(), Error> {
        // Reset the radio
        self.reset();

        // Check version (should be 0x12 for SX1276)
        let version = self.version()?;
        if version != 0x12 {
            return Err(Error::InvalidState);
        }

        // Set to sleep mode
        self.set_mode(mode::MODE_SLEEP)?;
        self.gpio.delay_ms(10);

        // Configure FIFO pointers
        self.spi.write_register(reg::REG_FIFO_TX_BASE_ADDR, 0x00)?;
        self.spi.write_register(reg::REG_FIFO_RX_BASE_ADDR, 0x00)?;

        // Set LNA to max gain
        self.spi.write_register(reg::REG_LNA, 0x23)?;

        // Set frequency
        self.set_frequency(self.config.band.frequency())?;

        // Set TX power
        self.set_tx_power(self.config.tx_power)?;

        // Configure modem
        self.configure_modem()?;

        // Configure DIO
        self.configure_dio()?;

        // Go to standby
        self.set_mode(mode::MODE_STDBY)?;
        self.state.store(RadioState::Standby as u8, Ordering::SeqCst);

        self.initialized = true;
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() > MAX_PACKET_SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Listen-Before-Talk if enabled
        if self.config.lbt_enabled {
            let rssi = self.read_rssi()?;
            if rssi > self.config.lbt_threshold {
                return Err(Error::Busy);
            }
        }

        // Go to standby
        self.set_mode(mode::MODE_STDBY)?;

        // Set FIFO pointer to TX base
        self.spi.write_register(reg::REG_FIFO_ADDR_PTR, 0x00)?;

        // Write data to FIFO
        self.spi.write_fifo(data)?;

        // Set payload length
        self.spi.write_register(reg::REG_PAYLOAD_LENGTH, data.len() as u8)?;

        // Start transmission
        self.set_mode(mode::MODE_TX)?;
        self.state.store(RadioState::Tx as u8, Ordering::SeqCst);

        // Wait for TX done (with timeout)
        let mut timeout = 5000u32; // 5 second timeout
        while timeout > 0 {
            if self.gpio.read_dio0() {
                let _ = self.handle_interrupt();
                return Ok(());
            }
            self.gpio.delay_ms(1);
            timeout -= 1;
        }

        // Timeout - go back to standby
        self.set_mode(mode::MODE_STDBY)?;
        self.state.store(RadioState::Standby as u8, Ordering::SeqCst);
        Err(Error::Timeout)
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        if !self.data_available.load(Ordering::SeqCst) {
            return Ok(0);
        }

        let len = self.rx_len.min(buffer.len());
        buffer[..len].copy_from_slice(&self.buffer[..len]);

        self.data_available.store(false, Ordering::SeqCst);
        self.rx_len = 0;

        Ok(len)
    }

    fn is_transmitting(&self) -> bool {
        self.state.load(Ordering::SeqCst) == RadioState::Tx as u8
    }

    fn available(&self) -> bool {
        self.data_available.load(Ordering::SeqCst)
    }

    fn last_rssi(&self) -> i16 {
        self.last_rssi
    }

    fn last_snr(&self) -> i8 {
        self.last_snr
    }

    fn sleep(&mut self) -> Result<(), Error> {
        self.set_mode(mode::MODE_SLEEP)?;
        self.state.store(RadioState::Sleep as u8, Ordering::SeqCst);
        Ok(())
    }

    fn standby(&mut self) -> Result<(), Error> {
        self.set_mode(mode::MODE_STDBY)?;
        self.state.store(RadioState::Standby as u8, Ordering::SeqCst);
        Ok(())
    }

    fn start_receive(&mut self) -> Result<(), Error> {
        // Go to standby first
        self.set_mode(mode::MODE_STDBY)?;

        // Clear IRQ flags
        self.spi.write_register(reg::REG_IRQ_FLAGS, 0xFF)?;

        // Set FIFO pointer to RX base
        self.spi.write_register(reg::REG_FIFO_ADDR_PTR, 0x00)?;

        // Set to continuous receive mode
        self.set_mode(mode::MODE_RX_CONTINUOUS)?;
        self.state.store(RadioState::Rx as u8, Ordering::SeqCst);

        Ok(())
    }
}

/// Mock SPI interface for testing
#[cfg(test)]
pub struct MockSpi {
    registers: [u8; 128],
    fifo: [u8; 256],
    fifo_ptr: usize,
}

#[cfg(test)]
impl MockSpi {
    pub fn new() -> Self {
        let mut registers = [0u8; 128];
        registers[reg::REG_VERSION as usize] = 0x12; // SX1276 version
        Self {
            registers,
            fifo: [0u8; 256],
            fifo_ptr: 0,
        }
    }
}

#[cfg(test)]
impl SpiInterface for MockSpi {
    fn write_register(&mut self, addr: u8, value: u8) -> Result<(), Error> {
        self.registers[addr as usize] = value;
        Ok(())
    }

    fn read_register(&mut self, addr: u8) -> Result<u8, Error> {
        Ok(self.registers[addr as usize])
    }

    fn write_fifo(&mut self, data: &[u8]) -> Result<(), Error> {
        let start = self.fifo_ptr;
        let end = start + data.len();
        if end > self.fifo.len() {
            return Err(Error::BufferTooSmall);
        }
        self.fifo[start..end].copy_from_slice(data);
        Ok(())
    }

    fn read_fifo(&mut self, buffer: &mut [u8]) -> Result<(), Error> {
        let start = self.fifo_ptr;
        let end = start + buffer.len();
        if end > self.fifo.len() {
            return Err(Error::BufferTooSmall);
        }
        buffer.copy_from_slice(&self.fifo[start..end]);
        Ok(())
    }
}

/// Mock GPIO interface for testing
#[cfg(test)]
pub struct MockGpio {
    reset_state: bool,
    dio0: bool,
    dio1: bool,
}

#[cfg(test)]
impl MockGpio {
    pub fn new() -> Self {
        Self {
            reset_state: true,
            dio0: false,
            dio1: false,
        }
    }

    pub fn set_dio0(&mut self, state: bool) {
        self.dio0 = state;
    }
}

#[cfg(test)]
impl GpioInterface for MockGpio {
    fn set_reset(&mut self, state: bool) {
        self.reset_state = state;
    }

    fn read_dio0(&self) -> bool {
        self.dio0
    }

    fn read_dio1(&self) -> bool {
        self.dio1
    }

    fn delay_ms(&mut self, _ms: u32) {
        // No-op in test
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spreading_factor() {
        assert_eq!(SpreadingFactor::Sf7 as u8, 7);
        assert_eq!(SpreadingFactor::Sf12 as u8, 12);
    }

    #[test]
    fn test_bandwidth_hz() {
        assert_eq!(Bandwidth::Bw125.hz(), 125_000);
        assert_eq!(Bandwidth::Bw500.hz(), 500_000);
    }

    #[test]
    fn test_default_config() {
        let config = LoRaConfig::default();
        assert_eq!(config.spreading_factor, SpreadingFactor::Sf7);
        assert_eq!(config.bandwidth, Bandwidth::Bw125);
        assert!(config.crc_enabled);
    }

    #[test]
    fn test_symbol_time() {
        let config = LoRaConfig::default();
        // SF7, BW125: 2^7 / 125000 * 1000000 = 1024 us
        assert_eq!(config.symbol_time_us(), 1024);
    }

    #[test]
    fn test_needs_ldro() {
        let config = LoRaConfig::default();
        assert!(!config.needs_ldro()); // SF7/BW125 doesn't need LDRO

        let long_range = LoRaConfig::long_range();
        assert!(long_range.needs_ldro()); // SF12/BW125 needs LDRO
    }

    #[test]
    fn test_radio_init() {
        let spi = MockSpi::new();
        let gpio = MockGpio::new();
        let config = LoRaConfig::default();

        let mut radio = LoRaRadio::new(spi, gpio, config);
        assert!(radio.init().is_ok());
        assert!(radio.initialized);
    }

    #[test]
    fn test_radio_version() {
        let spi = MockSpi::new();
        let gpio = MockGpio::new();
        let config = LoRaConfig::default();

        let mut radio = LoRaRadio::new(spi, gpio, config);
        radio.reset();
        assert_eq!(radio.version().unwrap(), 0x12);
    }

    #[test]
    fn test_radio_state() {
        let spi = MockSpi::new();
        let gpio = MockGpio::new();
        let config = LoRaConfig::default();

        let mut radio = LoRaRadio::new(spi, gpio, config);
        radio.init().unwrap();

        assert_eq!(radio.get_state(), RadioState::Standby);

        radio.sleep().unwrap();
        assert_eq!(radio.get_state(), RadioState::Sleep);

        radio.standby().unwrap();
        assert_eq!(radio.get_state(), RadioState::Standby);
    }

    #[test]
    fn test_frequency_band() {
        assert_eq!(FrequencyBand::Eu868.frequency(), 868_100_000);
        assert_eq!(FrequencyBand::Us915.frequency(), 915_000_000);
        assert_eq!(FrequencyBand::Custom(433_000_000).frequency(), 433_000_000);
    }
}
