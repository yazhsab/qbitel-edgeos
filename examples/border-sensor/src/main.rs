// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Qbitel EdgeOS Border Sensor Example
//!
//! Remote surveillance sensor demonstrating:
//! - Mesh networking for remote areas without infrastructure
//! - Low-power operation for solar/battery deployment
//! - Secure event detection and reporting
//! - Multi-hop message relay to command center
//! - Air-gapped firmware updates

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use heapless::Vec;
use q_common::Error;

// Sensor configuration
const SENSOR_SCAN_INTERVAL_MS: u32 = 100;
const MESH_BEACON_INTERVAL_SECS: u32 = 30;
const HEARTBEAT_INTERVAL_SECS: u32 = 300; // 5 minutes
const LOW_POWER_THRESHOLD_MV: u16 = 3300; // 3.3V
const MAX_DETECTION_QUEUE: usize = 32;

/// Detection event types
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum DetectionType {
    /// Motion detected (PIR/radar)
    Motion = 0x01,
    /// Seismic activity (vibration)
    Seismic = 0x02,
    /// Magnetic anomaly (vehicle)
    Magnetic = 0x03,
    /// Acoustic signature
    Acoustic = 0x04,
    /// Infrared break-beam
    Infrared = 0x05,
    /// Multiple sensors triggered
    MultiSensor = 0x0F,
    /// Tamper detection
    Tamper = 0xFF,
}

/// Detection event with metadata
#[derive(Clone)]
pub struct DetectionEvent {
    /// Event timestamp (seconds since boot)
    pub timestamp: u64,
    /// Detection type
    pub detection_type: DetectionType,
    /// Confidence level (0-100)
    pub confidence: u8,
    /// Sensor readings at time of detection
    pub sensor_data: SensorReadings,
    /// GPS coordinates (if available)
    pub location: Option<GpsCoordinates>,
    /// Event ID for deduplication
    pub event_id: u32,
}

/// Raw sensor readings
#[derive(Clone, Copy, Default)]
pub struct SensorReadings {
    /// PIR sensor level
    pub pir_level: u16,
    /// Seismic sensor (accelerometer magnitude)
    pub seismic_mag: u16,
    /// Magnetometer reading (nT)
    pub magnetic_nt: i32,
    /// Acoustic level (dB)
    pub acoustic_db: u8,
    /// Ambient temperature (0.1C)
    pub temperature_dc: i16,
    /// Battery voltage (mV)
    pub battery_mv: u16,
    /// Solar panel voltage (mV)
    pub solar_mv: u16,
}

/// GPS coordinates
#[derive(Clone, Copy)]
pub struct GpsCoordinates {
    /// Latitude (microdegrees)
    pub latitude: i32,
    /// Longitude (microdegrees)
    pub longitude: i32,
    /// Altitude (cm above sea level)
    pub altitude_cm: i32,
    /// Horizontal accuracy (cm)
    pub accuracy_cm: u16,
}

/// Power management state
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// Full operation
    Active,
    /// Reduced scanning rate
    LowPower,
    /// Minimal operation (critical battery)
    UltraLowPower,
    /// Sleep (wake on interrupt only)
    Sleep,
}

/// Mesh network statistics
#[derive(Default)]
pub struct MeshStats {
    /// Messages sent
    pub tx_count: u32,
    /// Messages received
    pub rx_count: u32,
    /// Messages relayed
    pub relay_count: u32,
    /// Route discoveries
    pub route_discoveries: u16,
    /// Known neighbors
    pub neighbor_count: u8,
}

/// Border sensor application state
pub struct BorderSensor {
    /// Device identity
    device_id: [u8; 32],
    /// Current power state
    power_state: PowerState,
    /// Detection event queue
    events: Vec<DetectionEvent, MAX_DETECTION_QUEUE>,
    /// Last sensor readings
    last_readings: SensorReadings,
    /// Fixed GPS location (if configured)
    fixed_location: Option<GpsCoordinates>,
    /// Mesh network statistics
    mesh_stats: MeshStats,
    /// Event ID counter
    next_event_id: u32,
    /// Tamper detected flag
    tamper_detected: bool,
    /// Gateway device ID (for direct communication)
    gateway_id: Option<[u8; 32]>,
}

impl BorderSensor {
    /// Create a new border sensor instance
    pub fn new(device_id: [u8; 32]) -> Self {
        Self {
            device_id,
            power_state: PowerState::Active,
            events: Vec::new(),
            last_readings: SensorReadings::default(),
            fixed_location: None,
            mesh_stats: MeshStats::default(),
            next_event_id: 0,
            tamper_detected: false,
            gateway_id: None,
        }
    }

    /// Set fixed GPS location
    pub fn set_fixed_location(&mut self, location: GpsCoordinates) {
        self.fixed_location = Some(location);
    }

    /// Set gateway device ID
    pub fn set_gateway(&mut self, gateway_id: [u8; 32]) {
        self.gateway_id = Some(gateway_id);
    }

    /// Read all sensors
    pub fn read_sensors(&mut self) -> SensorReadings {
        // In production: read from actual sensor hardware
        let readings = SensorReadings {
            pir_level: self.simulate_pir(),
            seismic_mag: self.simulate_seismic(),
            magnetic_nt: self.simulate_magnetic(),
            acoustic_db: self.simulate_acoustic(),
            temperature_dc: 250, // 25.0C
            battery_mv: 3700,
            solar_mv: 5000,
        };
        self.last_readings = readings;
        readings
    }

    /// Process sensor readings and detect events
    pub fn process_sensors(&mut self, now: u64) -> Option<DetectionEvent> {
        let readings = self.read_sensors();

        // Check detection thresholds
        let mut detection_type = None;
        let mut confidence = 0u8;

        // PIR motion detection
        if readings.pir_level > 500 {
            detection_type = Some(DetectionType::Motion);
            confidence = ((readings.pir_level - 500) / 10).min(100) as u8;
        }

        // Seismic detection
        if readings.seismic_mag > 1000 {
            if detection_type.is_some() {
                detection_type = Some(DetectionType::MultiSensor);
                confidence = confidence.max(80);
            } else {
                detection_type = Some(DetectionType::Seismic);
                confidence = ((readings.seismic_mag - 1000) / 20).min(100) as u8;
            }
        }

        // Magnetic anomaly
        if readings.magnetic_nt.abs() > 50000 {
            if detection_type.is_some() {
                detection_type = Some(DetectionType::MultiSensor);
                confidence = confidence.max(90);
            } else {
                detection_type = Some(DetectionType::Magnetic);
                confidence = 75;
            }
        }

        // Create event if detection occurred
        detection_type.map(|dt| {
            let event = DetectionEvent {
                timestamp: now,
                detection_type: dt,
                confidence,
                sensor_data: readings,
                location: self.fixed_location,
                event_id: self.next_event_id,
            };
            self.next_event_id = self.next_event_id.wrapping_add(1);

            // Queue for transmission
            if !self.events.is_full() {
                let _ = self.events.push(event.clone());
            }

            event
        })
    }

    /// Update power state based on battery level
    pub fn update_power_state(&mut self) {
        let battery = self.last_readings.battery_mv;
        let solar = self.last_readings.solar_mv;

        self.power_state = if battery < 3000 {
            PowerState::UltraLowPower
        } else if battery < LOW_POWER_THRESHOLD_MV && solar < 1000 {
            PowerState::LowPower
        } else {
            PowerState::Active
        };
    }

    /// Get pending events for transmission
    pub fn pending_events(&self) -> &[DetectionEvent] {
        &self.events
    }

    /// Clear transmitted events
    pub fn clear_events(&mut self, count: usize) {
        for _ in 0..count.min(self.events.len()) {
            self.events.remove(0);
        }
    }

    /// Check tamper state
    pub fn check_tamper(&mut self) -> bool {
        // In production: check enclosure sensors, accelerometer for movement
        self.tamper_detected
    }

    /// Record tamper event
    pub fn record_tamper(&mut self, now: u64) {
        self.tamper_detected = true;
        let event = DetectionEvent {
            timestamp: now,
            detection_type: DetectionType::Tamper,
            confidence: 100,
            sensor_data: self.last_readings,
            location: self.fixed_location,
            event_id: self.next_event_id,
        };
        self.next_event_id = self.next_event_id.wrapping_add(1);
        let _ = self.events.push(event);
    }

    /// Get mesh statistics
    pub fn mesh_stats(&self) -> &MeshStats {
        &self.mesh_stats
    }

    /// Get power state
    pub fn power_state(&self) -> PowerState {
        self.power_state
    }

    // Simulation functions
    fn simulate_pir(&self) -> u16 { 100 }
    fn simulate_seismic(&self) -> u16 { 50 }
    fn simulate_magnetic(&self) -> i32 { 45000 }
    fn simulate_acoustic(&self) -> u8 { 30 }
}

/// Secure detection report for transmission
#[derive(Clone)]
pub struct SecureDetectionReport {
    /// Sensor device ID
    pub sensor_id: [u8; 16],
    /// Report sequence number
    pub sequence: u32,
    /// Number of events in this report
    pub event_count: u8,
    /// Encrypted event data
    pub encrypted_events: Vec<u8, 512>,
    /// Authentication tag
    pub auth_tag: [u8; 16],
    /// Hop count (for mesh routing)
    pub hop_count: u8,
}

/// Main application entry point
#[cortex_m_rt::entry]
fn main() -> ! {
    // Initialize hardware
    // In production: HAL init, sensor init, radio init, GPS init

    // Create sensor instance
    let device_id = [0u8; 32]; // In production: from secure storage
    let mut sensor = BorderSensor::new(device_id);

    // Set fixed location (configured during deployment)
    sensor.set_fixed_location(GpsCoordinates {
        latitude: 31_000_000,  // 31.0 degrees
        longitude: -104_000_000, // -104.0 degrees
        altitude_cm: 120000,   // 1200m
        accuracy_cm: 500,      // 5m
    });

    // Main sensor loop
    let mut tick: u64 = 0;
    loop {
        tick += 1;

        // Adjust behavior based on power state
        let scan_interval = match sensor.power_state() {
            PowerState::Active => SENSOR_SCAN_INTERVAL_MS as u64,
            PowerState::LowPower => SENSOR_SCAN_INTERVAL_MS as u64 * 5,
            PowerState::UltraLowPower => SENSOR_SCAN_INTERVAL_MS as u64 * 20,
            PowerState::Sleep => u64::MAX, // Wake on interrupt only
        };

        // Scan sensors
        if tick % scan_interval == 0 {
            if let Some(_event) = sensor.process_sensors(tick) {
                // Detection occurred - wake radio and transmit
                // In production: encrypt and send via mesh
            }
        }

        // Update power management
        sensor.update_power_state();

        // Check for tamper
        if sensor.check_tamper() {
            sensor.record_tamper(tick);
            // In production: immediate alert via mesh
        }

        // Mesh beacon
        if tick % (MESH_BEACON_INTERVAL_SECS as u64 * 1000) == 0 {
            // In production: send mesh beacon for neighbor discovery
        }

        // Heartbeat to command center
        if tick % (HEARTBEAT_INTERVAL_SECS as u64 * 1000) == 0 {
            // In production: send status report
        }

        // Sleep until next tick or interrupt
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // In production: log panic, attempt to send alert, enter low-power mode
    loop {
        cortex_m::asm::wfi();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensor_creation() {
        let sensor = BorderSensor::new([0u8; 32]);
        assert_eq!(sensor.power_state(), PowerState::Active);
        assert!(sensor.pending_events().is_empty());
    }

    #[test]
    fn test_detection_types() {
        assert_eq!(DetectionType::Motion as u8, 0x01);
        assert_eq!(DetectionType::Tamper as u8, 0xFF);
    }

    #[test]
    fn test_fixed_location() {
        let mut sensor = BorderSensor::new([0u8; 32]);
        let loc = GpsCoordinates {
            latitude: 40_000_000,
            longitude: -75_000_000,
            altitude_cm: 10000,
            accuracy_cm: 100,
        };
        sensor.set_fixed_location(loc);
        assert!(sensor.fixed_location.is_some());
    }

    #[test]
    fn test_tamper_recording() {
        let mut sensor = BorderSensor::new([0u8; 32]);
        sensor.tamper_detected = true;
        sensor.record_tamper(1000);
        assert_eq!(sensor.pending_events().len(), 1);
        assert_eq!(sensor.pending_events()[0].detection_type, DetectionType::Tamper);
    }

    #[test]
    fn test_event_clearing() {
        let mut sensor = BorderSensor::new([0u8; 32]);
        sensor.record_tamper(1000);
        sensor.record_tamper(2000);
        assert_eq!(sensor.pending_events().len(), 2);
        sensor.clear_events(1);
        assert_eq!(sensor.pending_events().len(), 1);
    }
}
