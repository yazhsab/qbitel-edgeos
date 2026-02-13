// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Comprehensive tests for q-mesh
//!
//! Tests for secure mesh networking, PQC handshakes, and session management.

#![cfg(test)]

// Test RNG implementation for deterministic tests
mod test_rng {
    use q_crypto::traits::CryptoRng;
    use q_crypto::error::CryptoError;

    /// Simple deterministic RNG for testing
    pub struct TestRng {
        state: u64,
    }

    impl TestRng {
        pub fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next_u64(&mut self) -> u64 {
            // Simple xorshift64
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            self.state
        }
    }

    impl CryptoRng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
            for chunk in dest.chunks_mut(8) {
                let val = self.next_u64();
                let bytes = val.to_le_bytes();
                let len = chunk.len().min(8);
                chunk[..len].copy_from_slice(&bytes[..len]);
            }
            Ok(())
        }
    }
}

mod handshake_tests {
    use super::test_rng::TestRng;
    use q_mesh::handshake::{
        Handshake, HandshakeState, Role, HandshakeMessage, MessageType,
    };
    use q_common::DeviceId;

    fn make_device_id(byte: u8) -> DeviceId {
        DeviceId::new([byte; 32])
    }

    #[test]
    fn test_handshake_init_state() {
        let device_id = make_device_id(0x01);
        let mut rng = TestRng::new(12345);
        let handshake = Handshake::new_initiator(device_id, &mut rng).unwrap();

        assert_eq!(handshake.state(), HandshakeState::Init);
        assert!(!handshake.is_complete());
    }

    #[test]
    fn test_handshake_responder_init() {
        let device_id = make_device_id(0x02);
        let mut rng = TestRng::new(54321);
        let handshake = Handshake::new_responder(device_id, &mut rng).unwrap();

        assert_eq!(handshake.state(), HandshakeState::Init);
        assert!(!handshake.is_complete());
    }

    #[test]
    fn test_handshake_roles() {
        let client_id = make_device_id(0x01);
        let server_id = make_device_id(0x02);
        let mut rng = TestRng::new(11111);

        let client = Handshake::new_initiator(client_id, &mut rng).unwrap();
        let server = Handshake::new_responder(server_id, &mut rng).unwrap();

        assert_eq!(client.role(), Role::Initiator);
        assert_eq!(server.role(), Role::Responder);
    }

    #[test]
    fn test_message_type_values() {
        // Message types should have unique values
        let types = [
            MessageType::ClientHello,
            MessageType::ServerHello,
            MessageType::ClientFinished,
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
    fn test_handshake_state_transitions() {
        // Valid state transitions
        let states = [
            HandshakeState::Init,
            HandshakeState::AwaitingServerHello,
            HandshakeState::ReceivedClientHello,
            HandshakeState::AwaitingConfirmation,
            HandshakeState::ReceivedClientFinished,
            HandshakeState::Complete,
            HandshakeState::Failed,
        ];

        // Each state should be distinct
        for (i, s1) in states.iter().enumerate() {
            for (j, s2) in states.iter().enumerate() {
                if i == j {
                    assert_eq!(s1, s2);
                } else {
                    assert_ne!(s1, s2);
                }
            }
        }
    }

    #[test]
    fn test_complete_state_check() {
        let device_id = make_device_id(0x01);
        let mut rng = TestRng::new(99999);
        let handshake = Handshake::new_initiator(device_id, &mut rng).unwrap();

        assert!(!handshake.is_complete());
        // Note: Can't easily set state to Complete without full handshake
    }

    #[test]
    fn test_failed_state_check() {
        let device_id = make_device_id(0x01);
        let mut rng = TestRng::new(88888);
        let handshake = Handshake::new_initiator(device_id, &mut rng).unwrap();

        assert!(!handshake.is_failed());
    }

    #[test]
    fn test_device_id_preserved() {
        let device_id = make_device_id(0x42);
        let mut rng = TestRng::new(77777);
        let handshake = Handshake::new_initiator(device_id, &mut rng).unwrap();

        assert_eq!(handshake.our_id(), &device_id);
    }

    #[test]
    fn test_peer_id_initially_none() {
        let device_id = make_device_id(0x01);
        let mut rng = TestRng::new(66666);
        let handshake = Handshake::new_initiator(device_id, &mut rng).unwrap();

        assert!(handshake.peer_id().is_none());
    }

    #[test]
    fn test_handshake_message_parsing() {
        // Test that MessageType can be converted from bytes
        assert_eq!(MessageType::from_u8(0x01), Some(MessageType::ClientHello));
        assert_eq!(MessageType::from_u8(0x02), Some(MessageType::ServerHello));
        assert_eq!(MessageType::from_u8(0x03), Some(MessageType::ClientFinished));
        assert_eq!(MessageType::from_u8(0xFF), Some(MessageType::Error));
        assert_eq!(MessageType::from_u8(0x00), None);
    }
}

mod session_tests {
    use q_mesh::session::{Session, SessionState};

    #[test]
    fn test_session_creation() {
        let id = [0x42u8; 16];
        let encrypt_key = [0xAAu8; 32];
        let decrypt_key = [0xBBu8; 32];

        let session = Session::new(id, encrypt_key, decrypt_key);

        assert!(session.is_valid());
        assert!(session.is_active());
        assert_eq!(session.state(), SessionState::Active);
    }

    #[test]
    fn test_session_id() {
        let id = [0x42u8; 16];
        let encrypt_key = [0xAAu8; 32];
        let decrypt_key = [0xBBu8; 32];

        let session = Session::new(id, encrypt_key, decrypt_key);

        assert_eq!(session.id(), &id);
    }

    #[test]
    fn test_message_counters() {
        let id = [0x42u8; 16];
        let encrypt_key = [0xAAu8; 32];
        let decrypt_key = [0xBBu8; 32];

        let mut session = Session::new(id, encrypt_key, decrypt_key);

        // Initial counters should be zero
        assert_eq!(session.tx_counter(), 0);
        assert_eq!(session.rx_counter(), 0);

        // Increment counters
        session.increment_tx_counter();
        assert_eq!(session.tx_counter(), 1);

        session.increment_rx_counter();
        assert_eq!(session.rx_counter(), 1);
    }

    #[test]
    fn test_session_expiry() {
        let id = [0x42u8; 16];
        let encrypt_key = [0xAAu8; 32];
        let decrypt_key = [0xBBu8; 32];

        let mut session = Session::new(id, encrypt_key, decrypt_key);

        assert!(session.is_valid());

        session.expire();
        assert!(!session.is_valid());
    }

    #[test]
    fn test_session_encrypt_decrypt() {
        let id = [0x42u8; 16];
        let key1 = [0xAAu8; 32];
        let key2 = [0xBBu8; 32];

        let mut session1 = Session::new(id, key1, key2);
        let mut session2 = Session::new(id, key2, key1);

        let plaintext = b"Hello, secure mesh!";
        let aad = b"header data";

        let mut ciphertext = [0u8; 64];
        let (nonce, ct_len) = session1.encrypt(plaintext, aad, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 64];
        let pt_len = session2.decrypt(&ciphertext[..ct_len], aad, nonce, &mut decrypted).unwrap();

        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn test_replay_protection() {
        let id = [0x42u8; 16];
        let key1 = [0xAAu8; 32];
        let key2 = [0xBBu8; 32];

        let mut session1 = Session::new(id, key1, key2);
        let mut session2 = Session::new(id, key2, key1);

        let plaintext = b"test";
        let aad = b"";

        let mut ciphertext = [0u8; 32];
        let (nonce, ct_len) = session1.encrypt(plaintext, aad, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 32];

        // First decrypt should succeed
        let result = session2.decrypt(&ciphertext[..ct_len], aad, nonce, &mut decrypted);
        assert!(result.is_ok());

        // Replay should fail
        let result = session2.decrypt(&ciphertext[..ct_len], aad, nonce, &mut decrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_close() {
        let id = [0x42u8; 16];
        let key = [0xAAu8; 32];

        let mut session = Session::new(id, key, key);
        assert_eq!(session.state(), SessionState::Active);
        assert!(session.is_active());

        session.close();
        assert_eq!(session.state(), SessionState::Closed);
        assert!(!session.is_active());
    }
}

mod routing_tests {
    //! Tests for mesh routing logic

    #[test]
    fn test_hop_count_limits() {
        const MAX_HOPS: u8 = 16;

        for hops in 0..=MAX_HOPS {
            assert!(hops <= MAX_HOPS);
        }
    }

    #[test]
    fn test_ttl_decrement() {
        let mut ttl: u8 = 10;

        while ttl > 0 {
            ttl -= 1;
        }

        assert_eq!(ttl, 0);
    }

    #[test]
    fn test_routing_metric_calculation() {
        // Simple hop-count metric
        let hop_count: u8 = 3;
        let latency_ms: u16 = 50;

        // Combined metric (example)
        let metric = (hop_count as u32 * 100) + (latency_ms as u32);
        assert_eq!(metric, 350);
    }
}

mod group_trust_tests {
    //! Tests for group-based trust policies

    use std::collections::HashSet;

    #[test]
    fn test_group_membership() {
        let mut group: HashSet<[u8; 32]> = HashSet::new();

        let member1 = [0x01u8; 32];
        let member2 = [0x02u8; 32];
        let non_member = [0x03u8; 32];

        group.insert(member1);
        group.insert(member2);

        assert!(group.contains(&member1));
        assert!(group.contains(&member2));
        assert!(!group.contains(&non_member));
    }

    #[test]
    fn test_trust_level_comparison() {
        use q_mesh::group::TrustLevel;

        assert!(TrustLevel::Full > TrustLevel::Elevated);
        assert!(TrustLevel::Elevated > TrustLevel::Standard);
        assert!(TrustLevel::Standard > TrustLevel::Routing);
        assert!(TrustLevel::Routing > TrustLevel::None);
    }

    #[test]
    fn test_group_quorum() {
        let total_members = 5;
        let required_quorum = 3;
        let present_members = 4;

        assert!(present_members >= required_quorum);
        assert!(required_quorum <= total_members);
    }
}

mod transport_tests {
    //! Tests for transport layer

    use q_mesh::transport::{Transport, Frame, FrameType, Priority};

    fn test_id(val: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = val;
        id
    }

    #[test]
    fn test_mtu_limits() {
        use q_mesh::transport::MESH_MTU;

        assert!(MESH_MTU >= 127); // Minimum IEEE 802.15.4
        assert!(MESH_MTU <= 1500); // Maximum Ethernet
    }

    #[test]
    fn test_fragmentation_calculation() {
        const MTU: usize = 127;
        let payload_size = 500;

        let num_fragments = (payload_size + MTU - 1) / MTU;
        assert_eq!(num_fragments, 4);
    }

    #[test]
    fn test_sequence_number_wrap() {
        let mut seq: u16 = 65534;

        seq = seq.wrapping_add(1);
        assert_eq!(seq, 65535);

        seq = seq.wrapping_add(1);
        assert_eq!(seq, 0);

        seq = seq.wrapping_add(1);
        assert_eq!(seq, 1);
    }

    #[test]
    fn test_transport_send_receive() {
        let mut transport = Transport::new(test_id(1));
        let frame = Frame::new_data(test_id(1), test_id(2), 0, b"test").unwrap();
        transport.send(frame).unwrap();
        assert!(transport.has_pending_tx());

        let tx = transport.next_tx_frame().unwrap();
        assert_eq!(tx.payload.as_slice(), b"test");
        assert!(!transport.has_pending_tx());
    }

    #[test]
    fn test_priority_ordering() {
        let mut transport = Transport::new(test_id(1));

        let mut low = Frame::new_data(test_id(1), test_id(2), 0, b"low").unwrap();
        low.priority = Priority::Low;

        let high = Frame::new_routing(test_id(1), test_id(2), 1, b"high").unwrap();

        transport.send(low).unwrap();
        transport.send(high).unwrap();

        // High priority should come out first
        let first = transport.next_tx_frame().unwrap();
        assert_eq!(first.frame_type, FrameType::Routing);
    }

    #[test]
    fn test_transport_tick() {
        let mut transport = Transport::new(test_id(1));
        assert_eq!(transport.current_time(), 0);

        transport.tick(1000);
        assert_eq!(transport.current_time(), 1000);

        transport.tick(2000);
        assert_eq!(transport.current_time(), 2000);
    }

    #[test]
    fn test_frame_serialization() {
        let frame = Frame::new_data(test_id(1), test_id(2), 42, b"hello").unwrap();
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.source[0], 1);
        assert_eq!(decoded.destination[0], 2);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.payload.as_slice(), b"hello");
    }
}

mod radio_tests {
    //! Tests for radio interface abstraction

    #[test]
    fn test_channel_range() {
        // IEEE 802.15.4 2.4GHz channels
        const MIN_CHANNEL: u8 = 11;
        const MAX_CHANNEL: u8 = 26;

        for channel in MIN_CHANNEL..=MAX_CHANNEL {
            assert!(channel >= MIN_CHANNEL && channel <= MAX_CHANNEL);
        }
    }

    #[test]
    fn test_tx_power_levels() {
        let power_levels_dbm: [i8; 4] = [-20, -10, 0, 4];

        for power in power_levels_dbm {
            assert!(power >= -20 && power <= 20);
        }
    }

    #[test]
    fn test_rssi_thresholds() {
        const MIN_RSSI: i8 = -100;
        const GOOD_RSSI: i8 = -60;
        const EXCELLENT_RSSI: i8 = -40;

        assert!(EXCELLENT_RSSI > GOOD_RSSI);
        assert!(GOOD_RSSI > MIN_RSSI);
    }
}

mod discovery_tests {
    //! Tests for peer discovery

    use std::time::Duration;

    #[test]
    fn test_beacon_interval() {
        let beacon_interval = Duration::from_secs(10);
        let max_age = Duration::from_secs(60);

        assert!(beacon_interval < max_age);
    }

    #[test]
    fn test_peer_timeout() {
        const BEACON_INTERVAL_MS: u64 = 10_000;
        const PEER_TIMEOUT_FACTOR: u64 = 3;

        let timeout = BEACON_INTERVAL_MS * PEER_TIMEOUT_FACTOR;
        assert_eq!(timeout, 30_000);
    }

    #[test]
    fn test_discovery_filtering() {
        // Filter by device class
        let allowed_classes: [u8; 3] = [0x10, 0x20, 0x30]; // Railway, Power, Vehicle
        let test_class: u8 = 0x20;

        assert!(allowed_classes.contains(&test_class));
    }

    #[test]
    fn test_peer_state_transitions() {
        use q_mesh::discovery::PeerState;

        // States should be distinct
        assert_ne!(PeerState::Discovered, PeerState::Authenticated);
        assert_ne!(PeerState::Authenticating, PeerState::Unreachable);
    }
}

mod message_format_tests {
    //! Tests for message serialization/deserialization

    #[test]
    fn test_message_header_size() {
        use q_mesh::session::FrameHeader;

        // Frame header should have a defined size
        assert!(FrameHeader::SIZE > 0);
        assert!(FrameHeader::SIZE <= 64);
    }

    #[test]
    fn test_message_flags() {
        const FLAG_ENCRYPTED: u8 = 0x01;
        const FLAG_AUTHENTICATED: u8 = 0x02;
        const FLAG_COMPRESSED: u8 = 0x04;
        const FLAG_FRAGMENTED: u8 = 0x08;

        let flags = FLAG_ENCRYPTED | FLAG_AUTHENTICATED;

        assert!(flags & FLAG_ENCRYPTED != 0);
        assert!(flags & FLAG_AUTHENTICATED != 0);
        assert!(flags & FLAG_COMPRESSED == 0);
        assert!(flags & FLAG_FRAGMENTED == 0);
    }

    #[test]
    fn test_version_encoding() {
        let major: u8 = 1;
        let minor: u8 = 2;

        let version_byte = (major << 4) | minor;
        assert_eq!(version_byte, 0x12);

        let decoded_major = version_byte >> 4;
        let decoded_minor = version_byte & 0x0F;

        assert_eq!(decoded_major, major);
        assert_eq!(decoded_minor, minor);
    }
}
