// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Anomaly Detection for Runtime Attestation
//!
//! This module provides algorithms for detecting anomalies in system behavior
//! and attestation measurements.
//!
//! # Detection Methods
//!
//! - Threshold-based detection
//! - Statistical deviation analysis
//! - Timing anomaly detection
//! - Behavioral pattern matching

use heapless::Vec;
use q_common::Error;

/// Maximum anomaly history
pub const MAX_ANOMALY_HISTORY: usize = 64;

/// Maximum detection rules
pub const MAX_DETECTION_RULES: usize = 16;

/// Anomaly type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AnomalyType {
    /// Unexpected measurement value
    UnexpectedMeasurement = 0,
    /// Version or configuration mismatch
    VersionMismatch = 1,
    /// Timing deviation from expected
    TimingAnomaly = 2,
    /// Behavioral pattern deviation
    BehaviorAnomaly = 3,
    /// Memory integrity violation
    MemoryViolation = 4,
    /// Control flow deviation
    ControlFlowAnomaly = 5,
    /// Resource usage anomaly
    ResourceAnomaly = 6,
    /// Communication pattern anomaly
    CommunicationAnomaly = 7,
    /// Unknown anomaly type
    Unknown = 255,
}

impl From<u8> for AnomalyType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::UnexpectedMeasurement,
            1 => Self::VersionMismatch,
            2 => Self::TimingAnomaly,
            3 => Self::BehaviorAnomaly,
            4 => Self::MemoryViolation,
            5 => Self::ControlFlowAnomaly,
            6 => Self::ResourceAnomaly,
            7 => Self::CommunicationAnomaly,
            _ => Self::Unknown,
        }
    }
}

/// Severity level for anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Severity {
    /// Informational, no action required
    Info = 0,
    /// Low severity, log and monitor
    Low = 1,
    /// Medium severity, alert operator
    Medium = 2,
    /// High severity, take protective action
    High = 3,
    /// Critical severity, immediate response required
    Critical = 4,
}

impl From<u8> for Severity {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Info,
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            _ => Self::Critical,
        }
    }
}

/// Response action for detected anomaly
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseAction {
    /// Log the anomaly only
    LogOnly = 0,
    /// Generate an alert
    Alert = 1,
    /// Rate limit the suspicious activity
    RateLimit = 2,
    /// Quarantine the affected component
    Quarantine = 3,
    /// Reset the affected component
    Reset = 4,
    /// Shutdown the system
    Shutdown = 5,
}

/// Detected anomaly record
#[derive(Clone, Copy)]
pub struct Anomaly {
    /// Anomaly type
    pub anomaly_type: AnomalyType,
    /// Severity level
    pub severity: Severity,
    /// Timestamp of detection
    pub timestamp: u64,
    /// Anomaly source identifier
    pub source_id: u8,
    /// Additional context data
    pub data: [u8; 64],
    /// Data length
    pub data_len: u8,
    /// Sequence number
    pub sequence: u32,
    /// Recommended response
    pub response: ResponseAction,
}

impl Anomaly {
    /// Create a new anomaly record
    pub fn new(
        anomaly_type: AnomalyType,
        severity: Severity,
        timestamp: u64,
        source_id: u8,
    ) -> Self {
        Self {
            anomaly_type,
            severity,
            timestamp,
            source_id,
            data: [0u8; 64],
            data_len: 0,
            sequence: 0,
            response: ResponseAction::LogOnly,
        }
    }

    /// Set additional context data
    pub fn with_data(mut self, data: &[u8]) -> Self {
        let len = data.len().min(64);
        self.data[..len].copy_from_slice(&data[..len]);
        self.data_len = len as u8;
        self
    }

    /// Set response action
    pub fn with_response(mut self, response: ResponseAction) -> Self {
        self.response = response;
        self
    }

    /// Set sequence number
    pub fn with_sequence(mut self, sequence: u32) -> Self {
        self.sequence = sequence;
        self
    }

    /// Get data slice
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len as usize]
    }

    /// Check if this is a critical anomaly
    pub fn is_critical(&self) -> bool {
        self.severity == Severity::Critical
    }

    /// Check if this requires immediate action
    pub fn requires_action(&self) -> bool {
        matches!(self.response, ResponseAction::Quarantine | ResponseAction::Reset | ResponseAction::Shutdown)
    }
}

/// Detection rule for identifying anomalies
#[derive(Clone, Copy)]
pub struct DetectionRule {
    /// Rule identifier
    pub id: u8,
    /// Rule enabled
    pub enabled: bool,
    /// Anomaly type this rule detects
    pub anomaly_type: AnomalyType,
    /// Minimum severity to trigger
    pub min_severity: Severity,
    /// Threshold value (interpretation depends on rule type)
    pub threshold: u32,
    /// Time window in milliseconds
    pub window_ms: u32,
    /// Count threshold within window
    pub count_threshold: u8,
    /// Response action when triggered
    pub response: ResponseAction,
}

impl DetectionRule {
    /// Create a new detection rule
    pub fn new(id: u8, anomaly_type: AnomalyType) -> Self {
        Self {
            id,
            enabled: true,
            anomaly_type,
            min_severity: Severity::Low,
            threshold: 0,
            window_ms: 1000,
            count_threshold: 1,
            response: ResponseAction::Alert,
        }
    }

    /// Set minimum severity
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.min_severity = severity;
        self
    }

    /// Set threshold
    pub fn with_threshold(mut self, threshold: u32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Set time window
    pub fn with_window(mut self, window_ms: u32) -> Self {
        self.window_ms = window_ms;
        self
    }

    /// Set count threshold
    pub fn with_count(mut self, count: u8) -> Self {
        self.count_threshold = count;
        self
    }

    /// Set response action
    pub fn with_response(mut self, response: ResponseAction) -> Self {
        self.response = response;
        self
    }

    /// Disable the rule
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Enable the rule
    pub fn enable(&mut self) {
        self.enabled = true;
    }
}

/// Anomaly detector state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorState {
    /// Detector not running
    Stopped,
    /// Detector running normally
    Running,
    /// Detector in learning mode
    Learning,
    /// Detector suspended
    Suspended,
}

/// Statistics for a single anomaly type
#[derive(Clone, Copy, Default)]
pub struct TypeStats {
    /// Total count
    pub count: u64,
    /// Count in current window
    pub window_count: u32,
    /// Last occurrence timestamp
    pub last_seen: u64,
    /// Highest severity seen
    pub max_severity: u8,
}

/// Anomaly detector
pub struct AnomalyDetector {
    /// Detector state
    state: DetectorState,
    /// Detection rules
    rules: Vec<DetectionRule, MAX_DETECTION_RULES>,
    /// Anomaly history
    history: Vec<Anomaly, MAX_ANOMALY_HISTORY>,
    /// Current sequence number
    sequence: u32,
    /// Statistics per anomaly type
    type_stats: [TypeStats; 8],
    /// Total anomalies detected
    total_detected: u64,
    /// Total critical anomalies
    critical_count: u64,
    /// Learning mode baseline samples
    learning_samples: u32,
}

impl AnomalyDetector {
    /// Create a new anomaly detector
    pub fn new() -> Self {
        Self {
            state: DetectorState::Stopped,
            rules: Vec::new(),
            history: Vec::new(),
            sequence: 0,
            type_stats: [TypeStats::default(); 8],
            total_detected: 0,
            critical_count: 0,
            learning_samples: 0,
        }
    }

    /// Get detector state
    #[must_use]
    pub fn state(&self) -> DetectorState {
        self.state
    }

    /// Start the detector
    pub fn start(&mut self) {
        self.state = DetectorState::Running;
    }

    /// Stop the detector
    pub fn stop(&mut self) {
        self.state = DetectorState::Stopped;
    }

    /// Enter learning mode
    pub fn start_learning(&mut self) {
        self.state = DetectorState::Learning;
        self.learning_samples = 0;
    }

    /// Suspend detection
    pub fn suspend(&mut self) {
        if self.state == DetectorState::Running {
            self.state = DetectorState::Suspended;
        }
    }

    /// Resume detection
    pub fn resume(&mut self) {
        if self.state == DetectorState::Suspended {
            self.state = DetectorState::Running;
        }
    }

    /// Add a detection rule
    pub fn add_rule(&mut self, rule: DetectionRule) -> Result<(), Error> {
        self.rules.push(rule)
            .map_err(|_| Error::BufferTooSmall)
    }

    /// Remove a rule by ID
    pub fn remove_rule(&mut self, id: u8) -> bool {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            self.rules.swap_remove(pos);
            true
        } else {
            false
        }
    }

    /// Enable a rule by ID
    pub fn enable_rule(&mut self, id: u8) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) {
            rule.enable();
            true
        } else {
            false
        }
    }

    /// Disable a rule by ID
    pub fn disable_rule(&mut self, id: u8) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) {
            rule.disable();
            true
        } else {
            false
        }
    }

    /// Report an anomaly
    pub fn report(&mut self, mut anomaly: Anomaly) -> Option<ResponseAction> {
        if self.state == DetectorState::Stopped {
            return None;
        }

        // Learning mode - just collect statistics
        if self.state == DetectorState::Learning {
            self.learning_samples += 1;
            self.update_stats(&anomaly);
            return None;
        }

        // Set sequence number
        anomaly.sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);

        // Update statistics
        self.update_stats(&anomaly);
        self.total_detected += 1;

        if anomaly.is_critical() {
            self.critical_count += 1;
        }

        // Find matching rules and determine response
        let mut highest_response = ResponseAction::LogOnly;

        for rule in self.rules.iter() {
            if !rule.enabled {
                continue;
            }

            if rule.anomaly_type == anomaly.anomaly_type
                && anomaly.severity >= rule.min_severity
            {
                // Check if count threshold exceeded in window
                let type_idx = anomaly.anomaly_type as usize;
                if type_idx < 8 {
                    let stats = &self.type_stats[type_idx];
                    if stats.window_count >= rule.count_threshold as u32 {
                        // Rule triggered
                        if rule.response as u8 > highest_response as u8 {
                            highest_response = rule.response;
                        }
                    }
                }
            }
        }

        // Set response based on rules
        anomaly.response = highest_response;

        // Add to history
        if self.history.len() >= MAX_ANOMALY_HISTORY {
            self.history.remove(0);
        }
        self.history.push(anomaly).ok();

        Some(highest_response)
    }

    /// Update statistics for an anomaly
    fn update_stats(&mut self, anomaly: &Anomaly) {
        let type_idx = anomaly.anomaly_type as usize;
        if type_idx < 8 {
            let stats = &mut self.type_stats[type_idx];
            stats.count += 1;
            stats.window_count += 1;
            stats.last_seen = anomaly.timestamp;
            if anomaly.severity as u8 > stats.max_severity {
                stats.max_severity = anomaly.severity as u8;
            }
        }
    }

    /// Reset window counts (call periodically)
    pub fn reset_window(&mut self) {
        for stats in self.type_stats.iter_mut() {
            stats.window_count = 0;
        }
    }

    /// Get recent anomalies
    pub fn get_history(&self, count: usize) -> &[Anomaly] {
        let start = self.history.len().saturating_sub(count);
        &self.history[start..]
    }

    /// Get statistics for an anomaly type
    pub fn get_type_stats(&self, anomaly_type: AnomalyType) -> Option<&TypeStats> {
        let idx = anomaly_type as usize;
        if idx < 8 {
            Some(&self.type_stats[idx])
        } else {
            None
        }
    }

    /// Get overall statistics
    pub fn stats(&self) -> DetectorStats {
        DetectorStats {
            state: self.state,
            total_detected: self.total_detected,
            critical_count: self.critical_count,
            rule_count: self.rules.len() as u8,
            history_count: self.history.len() as u8,
        }
    }

    /// Clear history
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Check if any critical anomalies have been detected recently
    pub fn has_critical(&self) -> bool {
        self.history.iter().any(|a| a.is_critical())
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Detector statistics
#[derive(Debug, Clone, Copy)]
pub struct DetectorStats {
    /// Current state
    pub state: DetectorState,
    /// Total anomalies detected
    pub total_detected: u64,
    /// Critical anomaly count
    pub critical_count: u64,
    /// Active rule count
    pub rule_count: u8,
    /// Current history count
    pub history_count: u8,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_type_conversion() {
        assert_eq!(AnomalyType::from(0), AnomalyType::UnexpectedMeasurement);
        assert_eq!(AnomalyType::from(1), AnomalyType::VersionMismatch);
        assert_eq!(AnomalyType::from(255), AnomalyType::Unknown);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_anomaly_creation() {
        let anomaly = Anomaly::new(
            AnomalyType::TimingAnomaly,
            Severity::High,
            1000,
            1,
        ).with_data(&[1, 2, 3, 4])
         .with_response(ResponseAction::Alert);

        assert_eq!(anomaly.anomaly_type, AnomalyType::TimingAnomaly);
        assert_eq!(anomaly.severity, Severity::High);
        assert_eq!(anomaly.data_len, 4);
        assert_eq!(anomaly.response, ResponseAction::Alert);
    }

    #[test]
    fn test_detection_rule() {
        let rule = DetectionRule::new(1, AnomalyType::MemoryViolation)
            .with_severity(Severity::High)
            .with_threshold(100)
            .with_window(5000)
            .with_count(3)
            .with_response(ResponseAction::Quarantine);

        assert_eq!(rule.id, 1);
        assert!(rule.enabled);
        assert_eq!(rule.anomaly_type, AnomalyType::MemoryViolation);
        assert_eq!(rule.min_severity, Severity::High);
        assert_eq!(rule.threshold, 100);
        assert_eq!(rule.window_ms, 5000);
        assert_eq!(rule.count_threshold, 3);
    }

    #[test]
    fn test_detector_state_transitions() {
        let mut detector = AnomalyDetector::new();

        assert_eq!(detector.state(), DetectorState::Stopped);

        detector.start();
        assert_eq!(detector.state(), DetectorState::Running);

        detector.suspend();
        assert_eq!(detector.state(), DetectorState::Suspended);

        detector.resume();
        assert_eq!(detector.state(), DetectorState::Running);

        detector.start_learning();
        assert_eq!(detector.state(), DetectorState::Learning);

        detector.stop();
        assert_eq!(detector.state(), DetectorState::Stopped);
    }

    #[test]
    fn test_add_remove_rules() {
        let mut detector = AnomalyDetector::new();

        let rule = DetectionRule::new(1, AnomalyType::TimingAnomaly);
        assert!(detector.add_rule(rule).is_ok());

        assert!(detector.remove_rule(1));
        assert!(!detector.remove_rule(1)); // Already removed
    }

    #[test]
    fn test_report_anomaly() {
        let mut detector = AnomalyDetector::new();
        detector.start();

        let anomaly = Anomaly::new(
            AnomalyType::BehaviorAnomaly,
            Severity::Medium,
            1000,
            1,
        );

        let response = detector.report(anomaly);
        assert!(response.is_some());

        let stats = detector.stats();
        assert_eq!(stats.total_detected, 1);
    }

    #[test]
    fn test_critical_detection() {
        let mut detector = AnomalyDetector::new();
        detector.start();

        let anomaly = Anomaly::new(
            AnomalyType::MemoryViolation,
            Severity::Critical,
            1000,
            1,
        );

        detector.report(anomaly);

        assert!(detector.has_critical());
        assert_eq!(detector.stats().critical_count, 1);
    }
}
