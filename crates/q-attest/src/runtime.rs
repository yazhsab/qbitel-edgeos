// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Runtime Attestation and Integrity Monitoring
//!
//! This module provides continuous runtime integrity monitoring for Qbitel EdgeOS.
//! It tracks system state, collects measurements, and detects anomalies.
//!
//! # Features
//!
//! - Periodic integrity measurements
//! - Memory region monitoring
//! - Code flow integrity tracking
//! - Timing-based anomaly detection
//! - Hardware watchdog integration

use heapless::Vec;
use q_common::Error;

/// Maximum runtime measurements to track
pub const MAX_MEASUREMENTS: usize = 32;

/// Maximum monitored regions
pub const MAX_MONITORED_REGIONS: usize = 16;

/// Measurement interval in milliseconds
pub const DEFAULT_MEASUREMENT_INTERVAL_MS: u32 = 1000;

/// Measurement types for runtime attestation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MeasurementType {
    /// Code section hash
    CodeSection = 0,
    /// Read-only data hash
    ReadOnlyData = 1,
    /// Stack canary verification
    StackCanary = 2,
    /// Heap integrity check
    HeapIntegrity = 3,
    /// Interrupt vector table
    InterruptVectors = 4,
    /// MPU configuration
    MpuConfiguration = 5,
    /// Peripheral state
    PeripheralState = 6,
    /// Task control blocks
    TaskControlBlocks = 7,
    /// Custom measurement
    Custom = 255,
}

impl From<u8> for MeasurementType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::CodeSection,
            1 => Self::ReadOnlyData,
            2 => Self::StackCanary,
            3 => Self::HeapIntegrity,
            4 => Self::InterruptVectors,
            5 => Self::MpuConfiguration,
            6 => Self::PeripheralState,
            7 => Self::TaskControlBlocks,
            _ => Self::Custom,
        }
    }
}

/// Runtime measurement record
#[derive(Clone, Copy)]
pub struct RuntimeMeasurement {
    /// Measurement type
    pub measurement_type: MeasurementType,
    /// Hash of measured component (SHA3-256)
    pub hash: [u8; 32],
    /// Timestamp of measurement (system ticks)
    pub timestamp: u64,
    /// Sequence number
    pub sequence: u32,
    /// Measurement passed verification
    pub verified: bool,
}

impl RuntimeMeasurement {
    /// Create a new measurement
    pub fn new(
        measurement_type: MeasurementType,
        hash: [u8; 32],
        timestamp: u64,
        sequence: u32,
    ) -> Self {
        Self {
            measurement_type,
            hash,
            timestamp,
            sequence,
            verified: false,
        }
    }

    /// Mark as verified against expected value
    pub fn set_verified(&mut self, expected: &[u8; 32]) -> bool {
        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in self.hash.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }
        self.verified = diff == 0;
        self.verified
    }
}

/// Monitored memory region
#[derive(Clone, Copy)]
pub struct MonitoredRegion {
    /// Region identifier
    pub id: u8,
    /// Start address
    pub start_addr: u32,
    /// Region size in bytes
    pub size: u32,
    /// Expected hash (if known)
    pub expected_hash: [u8; 32],
    /// Last measured hash
    pub last_hash: [u8; 32],
    /// Last measurement timestamp
    pub last_measured: u64,
    /// Is region active for monitoring
    pub active: bool,
}

impl MonitoredRegion {
    /// Create a new monitored region
    pub fn new(id: u8, start_addr: u32, size: u32) -> Self {
        Self {
            id,
            start_addr,
            size,
            expected_hash: [0u8; 32],
            last_hash: [0u8; 32],
            last_measured: 0,
            active: true,
        }
    }

    /// Set expected hash for comparison
    pub fn set_expected_hash(&mut self, hash: [u8; 32]) {
        self.expected_hash = hash;
    }

    /// Measure this region
    pub fn measure(&mut self, timestamp: u64) -> Result<[u8; 32], Error> {
        use q_crypto::hash::Sha3_256;
        use q_crypto::traits::Hash;

        // Read region memory
        let data = unsafe {
            core::slice::from_raw_parts(self.start_addr as *const u8, self.size as usize)
        };

        let hash = Sha3_256::hash(data);
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(hash.as_ref());

        self.last_hash = hash_bytes;
        self.last_measured = timestamp;

        Ok(hash_bytes)
    }

    /// Check if region matches expected hash
    pub fn verify(&self) -> bool {
        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in self.last_hash.iter().zip(self.expected_hash.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// Runtime monitor state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorState {
    /// Monitor not started
    Stopped,
    /// Monitor running normally
    Running,
    /// Monitor paused
    Paused,
    /// Anomaly detected
    AnomalyDetected,
    /// Error state
    Error,
}

/// Runtime monitoring configuration
pub struct MonitorConfig {
    /// Measurement interval in milliseconds
    pub interval_ms: u32,
    /// Enable code section monitoring
    pub monitor_code: bool,
    /// Enable data section monitoring
    pub monitor_data: bool,
    /// Enable stack canary checks
    pub monitor_stack: bool,
    /// Enable heap integrity checks
    pub monitor_heap: bool,
    /// Anomaly threshold (consecutive failures)
    pub anomaly_threshold: u8,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            interval_ms: DEFAULT_MEASUREMENT_INTERVAL_MS,
            monitor_code: true,
            monitor_data: true,
            monitor_stack: true,
            monitor_heap: false, // Heap checking is expensive
            anomaly_threshold: 3,
        }
    }
}

/// Runtime integrity monitor
pub struct RuntimeMonitor {
    /// Monitor state
    state: MonitorState,
    /// Configuration
    config: MonitorConfig,
    /// Monitored regions
    regions: Vec<MonitoredRegion, MAX_MONITORED_REGIONS>,
    /// Measurement history
    measurements: Vec<RuntimeMeasurement, MAX_MEASUREMENTS>,
    /// Current sequence number
    sequence: u32,
    /// Last tick time
    last_tick: u64,
    /// Consecutive failure count
    failure_count: u8,
    /// Total measurements taken
    total_measurements: u64,
    /// Total anomalies detected
    total_anomalies: u64,
}

impl RuntimeMonitor {
    /// Create a new runtime monitor
    pub fn new(config: MonitorConfig) -> Self {
        Self {
            state: MonitorState::Stopped,
            config,
            regions: Vec::new(),
            measurements: Vec::new(),
            sequence: 0,
            last_tick: 0,
            failure_count: 0,
            total_measurements: 0,
            total_anomalies: 0,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(MonitorConfig::default())
    }

    /// Get current state
    #[must_use]
    pub fn state(&self) -> MonitorState {
        self.state
    }

    /// Start the monitor
    pub fn start(&mut self, current_time: u64) {
        self.state = MonitorState::Running;
        self.last_tick = current_time;
        self.failure_count = 0;
    }

    /// Stop the monitor
    pub fn stop(&mut self) {
        self.state = MonitorState::Stopped;
    }

    /// Pause monitoring
    pub fn pause(&mut self) {
        if self.state == MonitorState::Running {
            self.state = MonitorState::Paused;
        }
    }

    /// Resume monitoring
    pub fn resume(&mut self) {
        if self.state == MonitorState::Paused {
            self.state = MonitorState::Running;
        }
    }

    /// Add a region to monitor
    pub fn add_region(&mut self, region: MonitoredRegion) -> Result<(), Error> {
        self.regions.push(region)
            .map_err(|_| Error::BufferTooSmall)
    }

    /// Remove a region by ID
    pub fn remove_region(&mut self, id: u8) -> bool {
        if let Some(pos) = self.regions.iter().position(|r| r.id == id) {
            self.regions.swap_remove(pos);
            true
        } else {
            false
        }
    }

    /// Tick the monitor (call periodically)
    pub fn tick(&mut self, current_time: u64) -> Result<Option<RuntimeMeasurement>, Error> {
        if self.state != MonitorState::Running {
            return Ok(None);
        }

        // Check if it's time for a measurement
        let elapsed = current_time.saturating_sub(self.last_tick);
        if elapsed < self.config.interval_ms as u64 {
            return Ok(None);
        }

        self.last_tick = current_time;

        // Perform measurements on all active regions
        let mut anomaly_detected = false;

        for region in self.regions.iter_mut() {
            if !region.active {
                continue;
            }

            // Measure the region
            let hash = region.measure(current_time)?;

            // Check against expected
            if !region.verify() {
                anomaly_detected = true;
            }

            // Record measurement
            let measurement = RuntimeMeasurement::new(
                MeasurementType::Custom,
                hash,
                current_time,
                self.sequence,
            );

            // Add to history (circular buffer behavior)
            if self.measurements.len() >= MAX_MEASUREMENTS {
                self.measurements.remove(0);
            }
            self.measurements.push(measurement).ok();

            self.sequence = self.sequence.wrapping_add(1);
            self.total_measurements += 1;
        }

        // Handle anomaly detection
        if anomaly_detected {
            self.failure_count += 1;
            self.total_anomalies += 1;

            if self.failure_count >= self.config.anomaly_threshold {
                self.state = MonitorState::AnomalyDetected;
                // Return the last measurement that triggered the anomaly
                return Ok(self.measurements.last().copied());
            }
        } else {
            self.failure_count = 0;
        }

        Ok(self.measurements.last().copied())
    }

    /// Get the last N measurements
    pub fn get_measurements(&self, count: usize) -> &[RuntimeMeasurement] {
        let start = self.measurements.len().saturating_sub(count);
        &self.measurements[start..]
    }

    /// Get statistics
    pub fn stats(&self) -> MonitorStats {
        MonitorStats {
            state: self.state,
            total_measurements: self.total_measurements,
            total_anomalies: self.total_anomalies,
            active_regions: self.regions.iter().filter(|r| r.active).count() as u8,
            failure_count: self.failure_count,
        }
    }

    /// Clear anomaly state and resume
    pub fn clear_anomaly(&mut self) {
        if self.state == MonitorState::AnomalyDetected {
            self.state = MonitorState::Running;
            self.failure_count = 0;
        }
    }

    /// Set expected hash for a region
    pub fn set_region_expected(&mut self, id: u8, expected: [u8; 32]) -> bool {
        if let Some(region) = self.regions.iter_mut().find(|r| r.id == id) {
            region.set_expected_hash(expected);
            true
        } else {
            false
        }
    }

    /// Take a baseline measurement of all regions
    pub fn baseline(&mut self, current_time: u64) -> Result<(), Error> {
        for region in self.regions.iter_mut() {
            if region.active {
                let hash = region.measure(current_time)?;
                region.set_expected_hash(hash);
            }
        }
        Ok(())
    }
}

/// Monitor statistics
#[derive(Debug, Clone, Copy)]
pub struct MonitorStats {
    /// Current state
    pub state: MonitorState,
    /// Total measurements taken
    pub total_measurements: u64,
    /// Total anomalies detected
    pub total_anomalies: u64,
    /// Number of active regions
    pub active_regions: u8,
    /// Current consecutive failure count
    pub failure_count: u8,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measurement_type_conversion() {
        assert_eq!(MeasurementType::from(0), MeasurementType::CodeSection);
        assert_eq!(MeasurementType::from(1), MeasurementType::ReadOnlyData);
        assert_eq!(MeasurementType::from(255), MeasurementType::Custom);
    }

    #[test]
    fn test_runtime_measurement() {
        let hash = [0x42u8; 32];
        let measurement = RuntimeMeasurement::new(
            MeasurementType::CodeSection,
            hash,
            1000,
            1,
        );

        assert_eq!(measurement.measurement_type, MeasurementType::CodeSection);
        assert_eq!(measurement.hash, hash);
        assert_eq!(measurement.timestamp, 1000);
        assert!(!measurement.verified);
    }

    #[test]
    fn test_measurement_verification() {
        let hash = [0x42u8; 32];
        let mut measurement = RuntimeMeasurement::new(
            MeasurementType::CodeSection,
            hash,
            1000,
            1,
        );

        // Should verify with same hash
        assert!(measurement.set_verified(&hash));
        assert!(measurement.verified);

        // Should not verify with different hash
        let different = [0xAAu8; 32];
        assert!(!measurement.set_verified(&different));
        assert!(!measurement.verified);
    }

    #[test]
    fn test_monitored_region() {
        let region = MonitoredRegion::new(1, 0x2000_0000, 4096);

        assert_eq!(region.id, 1);
        assert_eq!(region.start_addr, 0x2000_0000);
        assert_eq!(region.size, 4096);
        assert!(region.active);
    }

    #[test]
    fn test_monitor_state_transitions() {
        let mut monitor = RuntimeMonitor::with_defaults();

        assert_eq!(monitor.state(), MonitorState::Stopped);

        monitor.start(0);
        assert_eq!(monitor.state(), MonitorState::Running);

        monitor.pause();
        assert_eq!(monitor.state(), MonitorState::Paused);

        monitor.resume();
        assert_eq!(monitor.state(), MonitorState::Running);

        monitor.stop();
        assert_eq!(monitor.state(), MonitorState::Stopped);
    }

    #[test]
    fn test_monitor_config_default() {
        let config = MonitorConfig::default();

        assert_eq!(config.interval_ms, DEFAULT_MEASUREMENT_INTERVAL_MS);
        assert!(config.monitor_code);
        assert!(config.monitor_data);
        assert!(config.monitor_stack);
        assert!(!config.monitor_heap);
        assert_eq!(config.anomaly_threshold, 3);
    }

    #[test]
    fn test_add_remove_region() {
        let mut monitor = RuntimeMonitor::with_defaults();

        let region = MonitoredRegion::new(1, 0x2000_0000, 4096);
        assert!(monitor.add_region(region).is_ok());

        assert!(monitor.remove_region(1));
        assert!(!monitor.remove_region(1)); // Already removed
    }

    #[test]
    fn test_monitor_stats() {
        let monitor = RuntimeMonitor::with_defaults();
        let stats = monitor.stats();

        assert_eq!(stats.state, MonitorState::Stopped);
        assert_eq!(stats.total_measurements, 0);
        assert_eq!(stats.total_anomalies, 0);
        assert_eq!(stats.active_regions, 0);
    }
}
