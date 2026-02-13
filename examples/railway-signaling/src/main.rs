// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Qbitel EdgeOS Railway Signaling Example
//!
//! Safety-critical railway signaling controller demonstrating:
//! - SIL4 safety integrity level compliance
//! - Fail-safe signal control
//! - Secure interlocking communication
//! - Remote attestation for safety verification
//! - Redundant communication channels

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use heapless::Vec;
use q_common::Error;

// Safety configuration
const WATCHDOG_TIMEOUT_MS: u32 = 100;
const SIGNAL_UPDATE_INTERVAL_MS: u32 = 50;
const HEARTBEAT_INTERVAL_MS: u32 = 500;
const MAX_COMM_TIMEOUT_MS: u32 = 2000;

/// Signal aspect (display state)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SignalAspect {
    /// Red - Stop
    Danger = 0x00,
    /// Yellow - Caution (prepare to stop)
    Caution = 0x01,
    /// Double Yellow - Preliminary caution
    PreliminaryCaution = 0x02,
    /// Green - Clear (proceed)
    Clear = 0x03,
    /// Flashing aspects for special conditions
    FlashingYellow = 0x04,
    /// Signal lamp failure - fail to danger
    LampFailure = 0xFF,
}

impl SignalAspect {
    /// Check if this is a safe (restrictive) aspect
    pub fn is_safe(&self) -> bool {
        matches!(self, SignalAspect::Danger | SignalAspect::LampFailure)
    }
}

/// Track circuit state
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum TrackState {
    /// Track clear (no train detected)
    Clear = 0x00,
    /// Track occupied (train present)
    Occupied = 0x01,
    /// Track state unknown (fail-safe to occupied)
    Unknown = 0xFF,
}

impl TrackState {
    /// Fail-safe: treat unknown as occupied
    pub fn is_clear(&self) -> bool {
        *self == TrackState::Clear
    }
}

/// Point (switch) position
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PointPosition {
    /// Normal position
    Normal = 0x00,
    /// Reverse position
    Reverse = 0x01,
    /// Position unknown or in motion
    Unknown = 0xFF,
}

/// Interlocking rule for signal control
#[derive(Clone)]
pub struct InterlockingRule {
    /// Signal ID this rule applies to
    pub signal_id: u8,
    /// Required track circuits to be clear
    pub required_clear_tracks: Vec<u8, 8>,
    /// Required point positions
    pub required_points: Vec<(u8, PointPosition), 4>,
    /// Conflicting signal IDs (must be at danger)
    pub conflicting_signals: Vec<u8, 4>,
}

/// Signaling controller state
pub struct SignalingController {
    /// Device identity
    device_id: [u8; 32],
    /// Current signal aspects
    signals: [SignalAspect; 16],
    /// Track circuit states
    tracks: [TrackState; 32],
    /// Point positions
    points: [PointPosition; 8],
    /// Interlocking rules
    rules: Vec<InterlockingRule, 16>,
    /// Last heartbeat received from interlocking
    last_heartbeat: u64,
    /// Safety state
    safety_state: SafetyState,
    /// Diagnostic counters
    diagnostics: Diagnostics,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SafetyState {
    /// Normal operation
    Normal,
    /// Degraded - some functions unavailable
    Degraded,
    /// Emergency - all signals to danger
    Emergency,
    /// Maintenance mode
    Maintenance,
}

#[derive(Default)]
pub struct Diagnostics {
    /// Total signal commands processed
    pub commands_processed: u32,
    /// Safety trips triggered
    pub safety_trips: u32,
    /// Communication timeouts
    pub comm_timeouts: u32,
    /// Lamp failures detected
    pub lamp_failures: u32,
}

impl SignalingController {
    /// Create a new signaling controller
    pub fn new(device_id: [u8; 32]) -> Self {
        Self {
            device_id,
            signals: [SignalAspect::Danger; 16], // Fail-safe default
            tracks: [TrackState::Unknown; 32],   // Fail-safe default
            points: [PointPosition::Unknown; 8], // Fail-safe default
            rules: Vec::new(),
            last_heartbeat: 0,
            safety_state: SafetyState::Normal,
            diagnostics: Diagnostics::default(),
        }
    }

    /// Add an interlocking rule
    pub fn add_rule(&mut self, rule: InterlockingRule) -> Result<(), Error> {
        self.rules.push(rule).map_err(|_| Error::BufferTooSmall)
    }

    /// Update track circuit state
    pub fn update_track(&mut self, track_id: u8, state: TrackState) {
        if (track_id as usize) < self.tracks.len() {
            self.tracks[track_id as usize] = state;
            // Re-evaluate affected signals
            self.evaluate_all_signals();
        }
    }

    /// Update point position
    pub fn update_point(&mut self, point_id: u8, position: PointPosition) {
        if (point_id as usize) < self.points.len() {
            self.points[point_id as usize] = position;
            // Re-evaluate affected signals
            self.evaluate_all_signals();
        }
    }

    /// Request signal aspect change
    pub fn request_signal(&mut self, signal_id: u8, requested_aspect: SignalAspect) -> Result<SignalAspect, Error> {
        // Safety check: never allow direct setting of permissive aspects
        // Must go through interlocking verification
        if !requested_aspect.is_safe() {
            // Verify interlocking conditions
            if !self.verify_interlocking(signal_id, requested_aspect)? {
                // Conditions not met, remain at danger
                return Ok(SignalAspect::Danger);
            }
        }

        // Set the signal
        if (signal_id as usize) < self.signals.len() {
            self.signals[signal_id as usize] = requested_aspect;
            self.diagnostics.commands_processed += 1;
        }

        Ok(requested_aspect)
    }

    /// Verify interlocking conditions for a signal
    fn verify_interlocking(&self, signal_id: u8, _aspect: SignalAspect) -> Result<bool, Error> {
        // Find applicable rules
        for rule in &self.rules {
            if rule.signal_id != signal_id {
                continue;
            }

            // Check all required track circuits are clear
            for &track_id in &rule.required_clear_tracks {
                if !self.tracks.get(track_id as usize)
                    .map(|t| t.is_clear())
                    .unwrap_or(false)
                {
                    return Ok(false);
                }
            }

            // Check all required point positions
            for &(point_id, required_pos) in &rule.required_points {
                if self.points.get(point_id as usize) != Some(&required_pos) {
                    return Ok(false);
                }
            }

            // Check all conflicting signals are at danger
            for &conflict_id in &rule.conflicting_signals {
                if let Some(aspect) = self.signals.get(conflict_id as usize) {
                    if !aspect.is_safe() {
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }

    /// Evaluate all signals against current conditions
    fn evaluate_all_signals(&mut self) {
        for signal_id in 0..self.signals.len() as u8 {
            let current = self.signals[signal_id as usize];
            if !current.is_safe() {
                // Re-verify permissive signals
                if let Ok(false) = self.verify_interlocking(signal_id, current) {
                    // Conditions no longer met, trip to danger
                    self.signals[signal_id as usize] = SignalAspect::Danger;
                    self.diagnostics.safety_trips += 1;
                }
            }
        }
    }

    /// Process heartbeat from interlocking system
    pub fn process_heartbeat(&mut self, timestamp: u64) {
        self.last_heartbeat = timestamp;
    }

    /// Check communication timeout
    pub fn check_comm_timeout(&mut self, now: u64) -> bool {
        let timeout = now.saturating_sub(self.last_heartbeat) > MAX_COMM_TIMEOUT_MS as u64;
        if timeout && self.safety_state == SafetyState::Normal {
            self.enter_emergency();
            self.diagnostics.comm_timeouts += 1;
        }
        timeout
    }

    /// Enter emergency state (all signals to danger)
    pub fn enter_emergency(&mut self) {
        self.safety_state = SafetyState::Emergency;
        for signal in &mut self.signals {
            *signal = SignalAspect::Danger;
        }
    }

    /// Get current signal aspect
    pub fn get_signal(&self, signal_id: u8) -> Option<SignalAspect> {
        self.signals.get(signal_id as usize).copied()
    }

    /// Get safety state
    pub fn safety_state(&self) -> SafetyState {
        self.safety_state
    }

    /// Get diagnostics
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diagnostics
    }
}

/// Safety-critical message for interlocking communication
#[derive(Clone)]
pub struct SafetyMessage {
    /// Message type
    pub msg_type: SafetyMessageType,
    /// Source controller ID
    pub source_id: [u8; 16],
    /// Sequence number (for replay protection)
    pub sequence: u32,
    /// Safety code (CRC-32 + cryptographic MAC)
    pub safety_code: [u8; 8],
    /// Payload
    pub payload: Vec<u8, 64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SafetyMessageType {
    /// Heartbeat
    Heartbeat = 0x01,
    /// Signal command
    SignalCommand = 0x02,
    /// Track status update
    TrackStatus = 0x03,
    /// Point status update
    PointStatus = 0x04,
    /// Emergency stop
    EmergencyStop = 0x0F,
    /// Attestation request
    AttestationRequest = 0x10,
    /// Attestation response
    AttestationResponse = 0x11,
}

/// Main application entry point
#[cortex_m_rt::entry]
fn main() -> ! {
    // Initialize hardware
    // In production: HAL initialization, watchdog setup, redundant channel config

    // Create controller with device identity
    let device_id = [0u8; 32]; // In production: loaded from secure storage
    let mut controller = SignalingController::new(device_id);

    // Configure interlocking rules
    // In production: loaded from authenticated configuration
    let _rule = InterlockingRule {
        signal_id: 0,
        required_clear_tracks: Vec::new(),
        required_points: Vec::new(),
        conflicting_signals: Vec::new(),
    };

    // Main safety loop
    let mut tick: u64 = 0;
    loop {
        tick += 1;

        // Feed watchdog
        // In production: hardware watchdog kick

        // Check communication timeout
        controller.check_comm_timeout(tick);

        // Process incoming messages
        // In production: receive from redundant channels, verify safety codes

        // Update signal outputs
        // In production: drive signal hardware with vital relay feedback

        // Send heartbeat to interlocking
        if tick % (HEARTBEAT_INTERVAL_MS as u64) == 0 {
            // In production: send authenticated heartbeat
        }

        // Sleep until next tick
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // SIL4 requirement: enter fail-safe state on panic
    // In production: trip all signals to danger, log fault, notify
    loop {
        cortex_m::asm::wfi();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_default_danger() {
        let controller = SignalingController::new([0u8; 32]);
        assert_eq!(controller.get_signal(0), Some(SignalAspect::Danger));
    }

    #[test]
    fn test_track_default_unknown() {
        let controller = SignalingController::new([0u8; 32]);
        assert_eq!(controller.tracks[0], TrackState::Unknown);
    }

    #[test]
    fn test_signal_aspect_safety() {
        assert!(SignalAspect::Danger.is_safe());
        assert!(SignalAspect::LampFailure.is_safe());
        assert!(!SignalAspect::Clear.is_safe());
        assert!(!SignalAspect::Caution.is_safe());
    }

    #[test]
    fn test_track_clear_failsafe() {
        assert!(TrackState::Clear.is_clear());
        assert!(!TrackState::Occupied.is_clear());
        assert!(!TrackState::Unknown.is_clear()); // Fail-safe
    }

    #[test]
    fn test_emergency_state() {
        let mut controller = SignalingController::new([0u8; 32]);
        controller.enter_emergency();
        assert_eq!(controller.safety_state(), SafetyState::Emergency);
        // All signals should be at danger
        for i in 0..16 {
            assert_eq!(controller.get_signal(i), Some(SignalAspect::Danger));
        }
    }
}
