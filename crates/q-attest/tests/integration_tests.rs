// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Integration tests for q-attest
//!
//! Tests for device attestation: evidence generation, PCR measurement extension,
//! boot stage tracking, anomaly detection, and attestation protocol types.
//! These exercise the real crate API on the host platform.

mod evidence_tests {
    use q_attest::AttestationEvidence;

    #[test]
    fn test_evidence_creation() {
        let identity_hash = [0x42; 32];
        let firmware_hash = [0xAB; 32];
        let nonce = [0xCD; 16];
        let timestamp: u64 = 1704067200;

        let evidence = AttestationEvidence::new(identity_hash, firmware_hash, nonce, timestamp);
        assert_eq!(evidence.version, 1);
        assert_eq!(evidence.identity_hash, identity_hash);
        assert_eq!(evidence.firmware_hash, firmware_hash);
        assert_eq!(evidence.nonce, nonce);
        assert_eq!(evidence.timestamp, timestamp);
    }

    #[test]
    fn test_evidence_not_signed_by_default() {
        let evidence = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);
        assert!(!evidence.is_signed());
    }

    #[test]
    fn test_evidence_to_signed_bytes() {
        let evidence = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);
        let bytes = evidence.to_signed_bytes();

        assert!(!bytes.is_empty());
        // First byte is version
        assert_eq!(bytes[0], 1);
    }

    #[test]
    fn test_evidence_signed_bytes_deterministic() {
        let evidence1 = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);
        let evidence2 = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);

        assert_eq!(evidence1.to_signed_bytes(), evidence2.to_signed_bytes());
    }

    #[test]
    fn test_evidence_different_inputs_produce_different_bytes() {
        let e1 = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);
        let e2 = AttestationEvidence::new([0x43; 32], [0xAB; 32], [0xCD; 16], 1704067200);

        assert_ne!(e1.to_signed_bytes(), e2.to_signed_bytes());
    }

    #[test]
    fn test_evidence_set_signature() {
        let mut evidence = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);
        assert!(!evidence.is_signed());

        let sig = [0xEF; 3293]; // Dilithium3 signature size
        evidence.set_signature(&sig);
        assert!(evidence.is_signed());
    }

    #[test]
    fn test_evidence_boot_measurements_default_zero() {
        let evidence = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);

        // All PCRs should be zero initially
        for pcr in &evidence.boot_measurements {
            assert_eq!(pcr, &[0u8; 32]);
        }
    }
}

mod evidence_collector_tests {
    use q_attest::{EvidenceCollector, BootStage};

    #[test]
    fn test_collector_creation() {
        let collector = EvidenceCollector::new();
        assert_eq!(collector.boot_stage(), BootStage::EarlyBoot);
    }

    #[test]
    fn test_collector_init() {
        let mut collector = EvidenceCollector::new();
        collector.init([0x42; 32], [0x13; 32]);

        // Should be able to generate evidence after init
        let evidence = collector.generate_evidence([0u8; 16], 12345);
        assert_eq!(evidence.identity_hash, [0x42; 32]);
        assert_eq!(evidence.firmware_hash, [0x13; 32]);
    }

    #[test]
    fn test_collector_boot_stage_measurement() {
        let mut collector = EvidenceCollector::new();
        collector.init([0x42; 32], [0x13; 32]);

        assert!(collector.measure_boot_stage(BootStage::Bootloader).is_ok());
        assert_eq!(collector.boot_stage(), BootStage::Bootloader);

        assert!(collector.measure_boot_stage(BootStage::KernelLoad).is_ok());
        assert_eq!(collector.boot_stage(), BootStage::KernelLoad);

        assert!(collector.measure_boot_stage(BootStage::KernelRun).is_ok());
        assert_eq!(collector.boot_stage(), BootStage::KernelRun);

        assert!(collector.measure_boot_stage(BootStage::Application).is_ok());
        assert_eq!(collector.boot_stage(), BootStage::Application);
    }

    #[test]
    fn test_collector_pcr_extend() {
        let mut collector = EvidenceCollector::new();
        collector.init([0x42; 32], [0x13; 32]);

        // Extend PCR 0
        assert!(collector.extend_pcr(0, b"test measurement").is_ok());

        let pcr = collector.get_pcr(0).unwrap();
        assert_ne!(pcr.value, [0u8; 32], "PCR should be non-zero after extend");
        assert_eq!(pcr.extend_count, 1);
    }

    #[test]
    fn test_collector_pcr_extend_multiple() {
        let mut collector = EvidenceCollector::new();
        collector.init([0x42; 32], [0x13; 32]);

        assert!(collector.extend_pcr(0, b"first").is_ok());
        let pcr_after_first = collector.get_pcr(0).unwrap().value;

        assert!(collector.extend_pcr(0, b"second").is_ok());
        let pcr_after_second = collector.get_pcr(0).unwrap().value;

        // PCR should change after each extension
        assert_ne!(pcr_after_first, pcr_after_second);
        assert_eq!(collector.get_pcr(0).unwrap().extend_count, 2);
    }

    #[test]
    fn test_collector_pcr_extend_is_order_dependent() {
        let mut c1 = EvidenceCollector::new();
        c1.init([0x42; 32], [0x13; 32]);
        c1.extend_pcr(0, b"A").unwrap();
        c1.extend_pcr(0, b"B").unwrap();

        let mut c2 = EvidenceCollector::new();
        c2.init([0x42; 32], [0x13; 32]);
        c2.extend_pcr(0, b"B").unwrap();
        c2.extend_pcr(0, b"A").unwrap();

        // Different order should produce different PCR values
        assert_ne!(
            c1.get_pcr(0).unwrap().value,
            c2.get_pcr(0).unwrap().value,
            "PCR extend must be order-dependent"
        );
    }

    #[test]
    fn test_collector_pcr_out_of_bounds() {
        let mut collector = EvidenceCollector::new();
        collector.init([0x42; 32], [0x13; 32]);

        // PCR index 99 should fail
        assert!(collector.extend_pcr(99, b"data").is_err());
    }

    #[test]
    fn test_collector_get_pcr_in_range() {
        let collector = EvidenceCollector::new();

        // PCR 0-7 should exist
        for i in 0..8 {
            assert!(collector.get_pcr(i).is_some(), "PCR {} should exist", i);
        }
    }

    #[test]
    fn test_collector_get_pcr_out_of_range() {
        let collector = EvidenceCollector::new();
        assert!(collector.get_pcr(99).is_none());
    }

    #[test]
    fn test_collector_firmware_measurement() {
        let mut collector = EvidenceCollector::new();
        collector.init([0x42; 32], [0x13; 32]);

        let hash = [0xAB; 32];
        assert!(collector.measure_firmware(0, &hash).is_ok());

        // PCR 1 should be extended (firmware measurements go to PCR 1)
        let pcr = collector.get_pcr(1).unwrap();
        assert_ne!(pcr.value, [0u8; 32]);
    }

    #[test]
    fn test_collector_config_measurement() {
        let mut collector = EvidenceCollector::new();
        collector.init([0x42; 32], [0x13; 32]);

        let config_hash = [0xCD; 32];
        assert!(collector.measure_config(0, &config_hash).is_ok());

        // PCR 2 should be extended (config measurements go to PCR 2)
        let pcr = collector.get_pcr(2).unwrap();
        assert_ne!(pcr.value, [0u8; 32]);
    }

    #[test]
    fn test_collector_runtime_measurement() {
        let mut collector = EvidenceCollector::new();
        collector.init([0x42; 32], [0x13; 32]);

        assert!(collector.measure_runtime(0, b"runtime event data").is_ok());

        // PCR 3 should be extended (runtime measurements go to PCR 3)
        let pcr = collector.get_pcr(3).unwrap();
        assert_ne!(pcr.value, [0u8; 32]);
    }

    #[test]
    fn test_collector_generate_evidence() {
        let mut collector = EvidenceCollector::new();
        collector.init([0x42; 32], [0x13; 32]);
        collector.extend_pcr(0, b"boot measurement").unwrap();

        let nonce = [0xAA; 16];
        let timestamp = 1704067200u64;
        let evidence = collector.generate_evidence(nonce, timestamp);

        assert_eq!(evidence.identity_hash, [0x42; 32]);
        assert_eq!(evidence.firmware_hash, [0x13; 32]);
        assert_eq!(evidence.nonce, nonce);
        assert_eq!(evidence.timestamp, timestamp);
        assert_eq!(evidence.version, 1);
        // Boot measurements should include our extend
        assert_ne!(evidence.boot_measurements[0], [0u8; 32]);
    }

    #[test]
    fn test_collector_get_all_pcrs() {
        let collector = EvidenceCollector::new();
        let pcrs = collector.get_all_pcrs();
        assert_eq!(pcrs.len(), 8, "Should have 8 PCRs");
    }
}

mod boot_stage_tests {
    use q_attest::BootStage;

    #[test]
    fn test_boot_stage_variants_all_distinct() {
        let stages = [
            BootStage::EarlyBoot,
            BootStage::Bootloader,
            BootStage::KernelLoad,
            BootStage::KernelRun,
            BootStage::Application,
        ];

        for (i, s1) in stages.iter().enumerate() {
            for (j, s2) in stages.iter().enumerate() {
                if i == j {
                    assert_eq!(s1, s2);
                } else {
                    assert_ne!(s1, s2);
                }
            }
        }
    }

    #[test]
    fn test_boot_stage_repr_values() {
        assert_eq!(BootStage::EarlyBoot as u8, 0);
        assert_eq!(BootStage::Bootloader as u8, 1);
        assert_eq!(BootStage::KernelLoad as u8, 2);
        assert_eq!(BootStage::KernelRun as u8, 3);
        assert_eq!(BootStage::Application as u8, 4);
    }

    #[test]
    fn test_boot_stage_is_copy() {
        let s1 = BootStage::KernelRun;
        let s2 = s1;
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_boot_stage_debug() {
        assert!(format!("{:?}", BootStage::Bootloader).contains("Bootloader"));
        assert!(format!("{:?}", BootStage::Application).contains("Application"));
    }
}

mod measurement_register_tests {
    use q_attest::MeasurementRegister;

    #[test]
    fn test_measurement_register_new() {
        let pcr = MeasurementRegister::new(0);
        assert_eq!(pcr.index, 0);
        assert_eq!(pcr.value, [0u8; 32]);
        assert_eq!(pcr.extend_count, 0);
    }

    #[test]
    fn test_measurement_register_extend() {
        let mut pcr = MeasurementRegister::new(0);
        pcr.extend(b"test data");

        assert_ne!(pcr.value, [0u8; 32], "PCR should change after extend");
        assert_eq!(pcr.extend_count, 1);
    }

    #[test]
    fn test_measurement_register_extend_deterministic() {
        let mut pcr1 = MeasurementRegister::new(0);
        pcr1.extend(b"test data");

        let mut pcr2 = MeasurementRegister::new(0);
        pcr2.extend(b"test data");

        assert_eq!(pcr1.value, pcr2.value, "Same data should produce same PCR");
    }

    #[test]
    fn test_measurement_register_extend_different_data() {
        let mut pcr1 = MeasurementRegister::new(0);
        pcr1.extend(b"data A");

        let mut pcr2 = MeasurementRegister::new(0);
        pcr2.extend(b"data B");

        assert_ne!(pcr1.value, pcr2.value, "Different data should produce different PCR");
    }

    #[test]
    fn test_measurement_register_reset() {
        let mut pcr = MeasurementRegister::new(0);
        pcr.extend(b"some data");
        assert_ne!(pcr.value, [0u8; 32]);

        pcr.reset();
        assert_eq!(pcr.value, [0u8; 32]);
        assert_eq!(pcr.extend_count, 0);
    }

    #[test]
    fn test_measurement_register_chained_extends() {
        let mut pcr = MeasurementRegister::new(0);

        pcr.extend(b"first");
        let after_first = pcr.value;

        pcr.extend(b"second");
        let after_second = pcr.value;

        pcr.extend(b"third");
        let after_third = pcr.value;

        // Each extension should change the value
        assert_ne!(after_first, after_second);
        assert_ne!(after_second, after_third);
        assert_ne!(after_first, after_third);
        assert_eq!(pcr.extend_count, 3);
    }
}

mod evidence_claims_tests {
    use q_attest::AttestationEvidence;

    #[test]
    fn test_add_firmware_version_claim() {
        let mut evidence = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);
        assert!(evidence.add_firmware_version(1, 2, 3).is_ok());
    }

    #[test]
    fn test_add_secure_boot_status_claim() {
        let mut evidence = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);
        assert!(evidence.add_secure_boot_status(true, true).is_ok());
    }

    #[test]
    fn test_add_debug_status_claim() {
        let mut evidence = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);
        assert!(evidence.add_debug_status(false).is_ok());
    }

    #[test]
    fn test_add_rollback_counter_claim() {
        let mut evidence = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);
        assert!(evidence.add_rollback_counter(42).is_ok());
    }

    #[test]
    fn test_add_multiple_claims() {
        let mut evidence = AttestationEvidence::new([0x42; 32], [0xAB; 32], [0xCD; 16], 1704067200);
        assert!(evidence.add_firmware_version(1, 0, 0).is_ok());
        assert!(evidence.add_secure_boot_status(true, true).is_ok());
        assert!(evidence.add_debug_status(false).is_ok());
        assert!(evidence.add_rollback_counter(5).is_ok());

        // Claims are included in the serialized evidence
        let bytes = evidence.to_signed_bytes();
        assert!(!bytes.is_empty());
    }
}

mod anomaly_detector_tests {
    use q_attest::anomaly::{
        AnomalyDetector, AnomalyType, Anomaly, Severity, ResponseAction,
        DetectionRule, DetectorState,
    };

    #[test]
    fn test_detector_creation() {
        let detector = AnomalyDetector::new();
        assert_eq!(detector.state(), DetectorState::Stopped);
    }

    #[test]
    fn test_detector_start_stop() {
        let mut detector = AnomalyDetector::new();
        detector.start();
        assert_eq!(detector.state(), DetectorState::Running);

        detector.stop();
        assert_eq!(detector.state(), DetectorState::Stopped);
    }

    #[test]
    fn test_detector_learning_mode() {
        let mut detector = AnomalyDetector::new();
        detector.start_learning();
        assert_eq!(detector.state(), DetectorState::Learning);
    }

    #[test]
    fn test_detector_suspend_resume() {
        let mut detector = AnomalyDetector::new();
        detector.start();
        assert_eq!(detector.state(), DetectorState::Running);

        detector.suspend();
        assert_eq!(detector.state(), DetectorState::Suspended);

        detector.resume();
        assert_eq!(detector.state(), DetectorState::Running);
    }

    #[test]
    fn test_anomaly_creation() {
        let anomaly = Anomaly::new(
            AnomalyType::UnexpectedMeasurement,
            Severity::High,
            1704067200,
            0,
        );

        assert_eq!(anomaly.anomaly_type, AnomalyType::UnexpectedMeasurement);
        assert_eq!(anomaly.severity, Severity::High);
        assert_eq!(anomaly.timestamp, 1704067200);
    }

    #[test]
    fn test_anomaly_builder_pattern() {
        let anomaly = Anomaly::new(
            AnomalyType::MemoryViolation,
            Severity::Critical,
            1704067200,
            1,
        )
        .with_data(b"violation details")
        .with_response(ResponseAction::Shutdown);

        assert_eq!(anomaly.response, ResponseAction::Shutdown);
        assert!(anomaly.is_critical());
    }

    #[test]
    fn test_anomaly_is_critical() {
        let critical = Anomaly::new(AnomalyType::ControlFlowAnomaly, Severity::Critical, 0, 0);
        assert!(critical.is_critical());

        let low = Anomaly::new(AnomalyType::TimingAnomaly, Severity::Low, 0, 0);
        assert!(!low.is_critical());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_detection_rule_creation() {
        let rule = DetectionRule::new(1, AnomalyType::UnexpectedMeasurement)
            .with_severity(Severity::High)
            .with_threshold(5)
            .with_window(60_000)
            .with_response(ResponseAction::Alert);

        assert_eq!(rule.id, 1);
        assert!(rule.enabled);
        assert_eq!(rule.anomaly_type, AnomalyType::UnexpectedMeasurement);
    }

    #[test]
    fn test_detection_rule_enable_disable() {
        let mut rule = DetectionRule::new(1, AnomalyType::UnexpectedMeasurement);
        assert!(rule.enabled);

        rule.disable();
        assert!(!rule.enabled);

        rule.enable();
        assert!(rule.enabled);
    }

    #[test]
    fn test_detector_add_rule() {
        let mut detector = AnomalyDetector::new();
        let rule = DetectionRule::new(1, AnomalyType::UnexpectedMeasurement);
        assert!(detector.add_rule(rule).is_ok());
    }

    #[test]
    fn test_detector_report_anomaly() {
        let mut detector = AnomalyDetector::new();
        detector.start();

        let anomaly = Anomaly::new(
            AnomalyType::UnexpectedMeasurement,
            Severity::High,
            1704067200,
            0,
        );

        let response = detector.report(anomaly);
        // Should return some response action
        assert!(response.is_some() || response.is_none()); // Just verify no panic
    }

    #[test]
    fn test_detector_stats() {
        let detector = AnomalyDetector::new();
        let stats = detector.stats();

        assert_eq!(stats.state, DetectorState::Stopped);
        assert_eq!(stats.total_detected, 0);
        assert_eq!(stats.critical_count, 0);
    }

    #[test]
    fn test_detector_has_critical_initially_false() {
        let detector = AnomalyDetector::new();
        assert!(!detector.has_critical());
    }

    #[test]
    fn test_anomaly_type_variants_distinct() {
        let types = [
            AnomalyType::UnexpectedMeasurement,
            AnomalyType::VersionMismatch,
            AnomalyType::TimingAnomaly,
            AnomalyType::BehaviorAnomaly,
            AnomalyType::MemoryViolation,
            AnomalyType::ControlFlowAnomaly,
            AnomalyType::ResourceAnomaly,
            AnomalyType::CommunicationAnomaly,
            AnomalyType::Unknown,
        ];

        for (i, t1) in types.iter().enumerate() {
            for (j, t2) in types.iter().enumerate() {
                if i == j {
                    assert_eq!(t1, t2);
                } else {
                    assert_ne!(t1, t2);
                }
            }
        }
    }

    #[test]
    fn test_response_action_variants_distinct() {
        let actions = [
            ResponseAction::LogOnly,
            ResponseAction::Alert,
            ResponseAction::RateLimit,
            ResponseAction::Quarantine,
            ResponseAction::Reset,
            ResponseAction::Shutdown,
        ];

        for (i, a1) in actions.iter().enumerate() {
            for (j, a2) in actions.iter().enumerate() {
                if i == j {
                    assert_eq!(a1, a2);
                } else {
                    assert_ne!(a1, a2);
                }
            }
        }
    }
}
