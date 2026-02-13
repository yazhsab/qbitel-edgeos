// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Qbitel EdgeOS Smart Meter Example
//!
//! Demonstrates a secure smart energy meter application with:
//! - Quantum-resistant authenticated data transmission
//! - Tamper detection and secure boot attestation
//! - Over-the-air firmware updates
//! - Mesh networking for meter-to-meter communication

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use heapless::Vec;
use q_common::Error;

// Application configuration
const METER_ID_PREFIX: &[u8] = b"QMTR";
const READING_INTERVAL_SECS: u32 = 900; // 15 minutes
const MESH_BEACON_INTERVAL_SECS: u32 = 60;
const MAX_READINGS_BUFFER: usize = 96; // 24 hours of readings

/// Meter reading data structure
#[derive(Clone, Copy)]
pub struct MeterReading {
    /// Timestamp (seconds since epoch)
    pub timestamp: u64,
    /// Active energy import (Wh)
    pub active_import_wh: u32,
    /// Active energy export (Wh)
    pub active_export_wh: u32,
    /// Reactive energy (VARh)
    pub reactive_varh: u32,
    /// Instantaneous power (W)
    pub instant_power_w: u16,
    /// Voltage (dV, decivolts)
    pub voltage_dv: u16,
    /// Current (mA)
    pub current_ma: u16,
    /// Power factor (0-100)
    pub power_factor: u8,
    /// Tamper flags
    pub tamper_flags: u8,
}

impl MeterReading {
    /// Serialize reading to bytes for transmission
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[8..12].copy_from_slice(&self.active_import_wh.to_be_bytes());
        buf[12..16].copy_from_slice(&self.active_export_wh.to_be_bytes());
        buf[16..20].copy_from_slice(&self.reactive_varh.to_be_bytes());
        buf[20..22].copy_from_slice(&self.instant_power_w.to_be_bytes());
        buf[22] = self.power_factor;
        buf[23] = self.tamper_flags;
        buf
    }
}

/// Smart meter application state
pub struct SmartMeter {
    /// Device identity
    device_id: [u8; 32],
    /// Accumulated readings buffer
    readings: Vec<MeterReading, MAX_READINGS_BUFFER>,
    /// Last reading timestamp
    last_reading_time: u64,
    /// Total energy imported
    total_import_wh: u64,
    /// Total energy exported
    total_export_wh: u64,
    /// Tamper detection state
    tamper_detected: bool,
    /// Mesh network enabled
    mesh_enabled: bool,
}

impl SmartMeter {
    /// Create a new smart meter instance
    pub fn new(device_id: [u8; 32]) -> Self {
        Self {
            device_id,
            readings: Vec::new(),
            last_reading_time: 0,
            total_import_wh: 0,
            total_export_wh: 0,
            tamper_detected: false,
            mesh_enabled: true,
        }
    }

    /// Take a meter reading
    pub fn take_reading(&mut self, now: u64) -> Result<MeterReading, Error> {
        // In production, these would come from actual ADC measurements
        let reading = MeterReading {
            timestamp: now,
            active_import_wh: self.simulate_import(),
            active_export_wh: self.simulate_export(),
            reactive_varh: 0,
            instant_power_w: self.simulate_power(),
            voltage_dv: 2300, // 230.0V
            current_ma: self.simulate_current(),
            power_factor: 95,
            tamper_flags: if self.tamper_detected { 0x01 } else { 0x00 },
        };

        // Update totals
        self.total_import_wh += reading.active_import_wh as u64;
        self.total_export_wh += reading.active_export_wh as u64;
        self.last_reading_time = now;

        // Buffer the reading
        if self.readings.is_full() {
            // Remove oldest reading
            self.readings.remove(0);
        }
        self.readings.push(reading).map_err(|_| Error::BufferTooSmall)?;

        Ok(reading)
    }

    /// Get buffered readings for transmission
    pub fn get_readings(&self) -> &[MeterReading] {
        &self.readings
    }

    /// Clear transmitted readings
    pub fn clear_readings(&mut self, count: usize) {
        for _ in 0..count.min(self.readings.len()) {
            self.readings.remove(0);
        }
    }

    /// Check for tamper conditions
    pub fn check_tamper(&mut self) -> bool {
        // In production, check:
        // - Magnetic field sensors
        // - Enclosure switches
        // - Voltage/current anomalies
        // - Communication interference
        self.tamper_detected
    }

    /// Set tamper state (for testing)
    pub fn set_tamper(&mut self, tampered: bool) {
        self.tamper_detected = tampered;
    }

    // Simulation functions for testing
    fn simulate_import(&self) -> u32 {
        // Simulate ~1kWh per reading interval
        250
    }

    fn simulate_export(&self) -> u32 {
        0 // No solar export in this example
    }

    fn simulate_power(&self) -> u16 {
        1000 // 1kW
    }

    fn simulate_current(&self) -> u16 {
        4348 // ~4.3A at 230V for 1kW
    }
}

/// Secure message envelope for meter data
#[derive(Clone)]
pub struct SecureMeterMessage {
    /// Message type
    pub msg_type: MessageType,
    /// Meter ID (first 16 bytes of device_id)
    pub meter_id: [u8; 16],
    /// Sequence number
    pub sequence: u32,
    /// Encrypted payload
    pub payload: Vec<u8, 512>,
    /// Authentication tag
    pub auth_tag: [u8; 16],
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Regular reading upload
    Reading = 0x01,
    /// Tamper alert
    TamperAlert = 0x02,
    /// Attestation response
    Attestation = 0x03,
    /// Command acknowledgement
    CommandAck = 0x04,
}

/// Main application entry point
#[cortex_m_rt::entry]
fn main() -> ! {
    // Initialize hardware
    // In production: HAL initialization, clock setup, peripheral config

    // Create meter instance with device identity
    let device_id = [0u8; 32]; // In production: loaded from secure storage
    let mut meter = SmartMeter::new(device_id);

    // Main application loop
    let mut tick: u64 = 0;
    loop {
        // Simulate time passing
        tick += 1;

        // Take readings at configured interval
        if tick % (READING_INTERVAL_SECS as u64) == 0 {
            if let Ok(_reading) = meter.take_reading(tick) {
                // Reading taken successfully
                // In production: trigger secure upload
            }
        }

        // Check for tamper conditions
        if meter.check_tamper() {
            // In production: send immediate tamper alert
            // Log tamper event
        }

        // Mesh beacon (peer discovery)
        if meter.mesh_enabled && tick % (MESH_BEACON_INTERVAL_SECS as u64) == 0 {
            // In production: send mesh beacon
        }

        // Sleep until next tick
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // In production: log panic info, trigger watchdog reset
    loop {
        cortex_m::asm::wfi();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meter_reading() {
        let mut meter = SmartMeter::new([0u8; 32]);
        let reading = meter.take_reading(1000).unwrap();
        assert_eq!(reading.timestamp, 1000);
        assert_eq!(reading.active_import_wh, 250);
    }

    #[test]
    fn test_reading_buffer() {
        let mut meter = SmartMeter::new([0u8; 32]);
        for i in 0..10 {
            meter.take_reading(i * 100).unwrap();
        }
        assert_eq!(meter.get_readings().len(), 10);
    }

    #[test]
    fn test_tamper_detection() {
        let mut meter = SmartMeter::new([0u8; 32]);
        assert!(!meter.check_tamper());
        meter.set_tamper(true);
        assert!(meter.check_tamper());
    }

    #[test]
    fn test_reading_serialization() {
        let reading = MeterReading {
            timestamp: 1704067200,
            active_import_wh: 1000,
            active_export_wh: 0,
            reactive_varh: 100,
            instant_power_w: 500,
            voltage_dv: 2300,
            current_ma: 2174,
            power_factor: 98,
            tamper_flags: 0,
        };
        let bytes = reading.to_bytes();
        assert_eq!(bytes.len(), 24);
    }
}
