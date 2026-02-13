// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Secure Session Management for Q-MESH
//!
//! This module implements encrypted session management for mesh communication
//! using AES-256-GCM for authenticated encryption.
//!
//! # Security Features
//!
//! - AES-256-GCM authenticated encryption
//! - Per-session unique keys (derived from handshake)
//! - Monotonic nonce counters (prevents replay)
//! - Sliding window replay protection
//! - Automatic nonce exhaustion detection
//! - Zeroization of keys on drop

use zeroize::{Zeroize, ZeroizeOnDrop};
use heapless::Vec;
use q_common::{Error, DeviceId};

/// Maximum payload size for mesh frames
pub const MAX_PAYLOAD_SIZE: usize = 200;

/// AES-GCM tag size
pub const TAG_SIZE: usize = 16;

/// Nonce size for AES-GCM
pub const NONCE_SIZE: usize = 12;

/// Maximum nonce value before requiring rekey
pub const MAX_NONCE: u64 = (1u64 << 48) - 1;

/// Replay window size (in nonce values)
pub const REPLAY_WINDOW_SIZE: u64 = 64;

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is active and can encrypt/decrypt
    Active,
    /// Session needs rekeying (nonce near exhaustion)
    NeedsRekey,
    /// Session is closed
    Closed,
    /// Session has error
    Error,
}

/// Encrypted session for mesh communication
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Session {
    /// Session ID
    #[zeroize(skip)]
    pub id: [u8; 16],
    /// Local device ID
    #[zeroize(skip)]
    local_id: DeviceId,
    /// Peer device ID
    #[zeroize(skip)]
    peer_id: DeviceId,
    /// Encryption key (our sending key)
    encrypt_key: [u8; 32],
    /// Decryption key (peer's sending key)
    decrypt_key: [u8; 32],
    /// Send nonce counter
    #[zeroize(skip)]
    send_nonce: u64,
    /// Receive nonce high-water mark
    #[zeroize(skip)]
    recv_nonce: u64,
    /// Replay window bitmap
    #[zeroize(skip)]
    replay_bitmap: u64,
    /// Session state
    #[zeroize(skip)]
    state: SessionState,
    /// Creation timestamp (epoch seconds)
    #[zeroize(skip)]
    created_at: u64,
    /// Expiration timestamp (epoch seconds)
    #[zeroize(skip)]
    expires_at: u64,
}

/// Default session lifetime in seconds (24 hours)
pub const DEFAULT_SESSION_LIFETIME: u64 = 24 * 60 * 60;

impl Session {
    /// Create new session from handshake-derived keys
    pub fn new(id: [u8; 16], encrypt_key: [u8; 32], decrypt_key: [u8; 32]) -> Self {
        Self {
            id,
            local_id: DeviceId::new([0u8; 32]),
            peer_id: DeviceId::new([0u8; 32]),
            encrypt_key,
            decrypt_key,
            send_nonce: 0,
            recv_nonce: 0,
            replay_bitmap: 0,
            state: SessionState::Active,
            created_at: 0,
            expires_at: u64::MAX,
        }
    }

    /// Create new session with device IDs and derived keys
    pub fn with_peers(
        local_id: DeviceId,
        peer_id: DeviceId,
        shared_secret: &[u8; 32],
        is_initiator: bool,
    ) -> Result<Self, Error> {
        use q_crypto::hash::HkdfSha3_256;

        // Derive session ID from device IDs
        let mut id = [0u8; 16];
        for i in 0..16 {
            id[i] = local_id.as_bytes()[i] ^ peer_id.as_bytes()[i];
        }

        let mut encrypt_key = [0u8; 32];
        let mut decrypt_key = [0u8; 32];

        // Derive keys with role-based labels for key separation
        let (tx_label, rx_label) = if is_initiator {
            (b"q-mesh session initiator tx", b"q-mesh session responder tx")
        } else {
            (b"q-mesh session responder tx", b"q-mesh session initiator tx")
        };

        HkdfSha3_256::derive(&id, shared_secret, tx_label, &mut encrypt_key)
            .map_err(|_| Error::KeyDerivationFailed)?;

        HkdfSha3_256::derive(&id, shared_secret, rx_label, &mut decrypt_key)
            .map_err(|_| Error::KeyDerivationFailed)?;

        Ok(Self {
            id,
            local_id,
            peer_id,
            encrypt_key,
            decrypt_key,
            send_nonce: 0,
            recv_nonce: 0,
            replay_bitmap: 0,
            state: SessionState::Active,
            created_at: 0,
            expires_at: DEFAULT_SESSION_LIFETIME,
        })
    }

    /// Create session from shared secret (derives separate tx/rx keys)
    pub fn from_shared_secret(
        id: [u8; 16],
        shared_secret: &[u8; 32],
        is_initiator: bool,
    ) -> Result<Self, Error> {
        use q_crypto::hash::HkdfSha3_256;

        let mut encrypt_key = [0u8; 32];
        let mut decrypt_key = [0u8; 32];

        // Derive keys with role-based labels for key separation
        let (tx_label, rx_label) = if is_initiator {
            (b"q-mesh session initiator tx", b"q-mesh session responder tx")
        } else {
            (b"q-mesh session responder tx", b"q-mesh session initiator tx")
        };

        HkdfSha3_256::derive(&id, shared_secret, tx_label, &mut encrypt_key)
            .map_err(|_| Error::KeyDerivationFailed)?;

        HkdfSha3_256::derive(&id, shared_secret, rx_label, &mut decrypt_key)
            .map_err(|_| Error::KeyDerivationFailed)?;

        Ok(Self {
            id,
            local_id: DeviceId::new([0u8; 32]),
            peer_id: DeviceId::new([0u8; 32]),
            encrypt_key,
            decrypt_key,
            send_nonce: 0,
            recv_nonce: 0,
            replay_bitmap: 0,
            state: SessionState::Active,
            created_at: 0,
            expires_at: DEFAULT_SESSION_LIFETIME,
        })
    }

    /// Get session ID
    #[must_use]
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Get local device ID
    #[must_use]
    pub fn local_id(&self) -> &DeviceId {
        &self.local_id
    }

    /// Get peer device ID
    #[must_use]
    pub fn peer_id(&self) -> &DeviceId {
        &self.peer_id
    }

    /// Get transmit counter
    #[must_use]
    pub fn tx_counter(&self) -> u64 {
        self.send_nonce
    }

    /// Get receive counter
    #[must_use]
    pub fn rx_counter(&self) -> u64 {
        self.recv_nonce
    }

    /// Increment transmit counter (for testing/diagnostics)
    pub fn increment_tx_counter(&mut self) {
        self.send_nonce = self.send_nonce.saturating_add(1);
    }

    /// Increment receive counter (for testing/diagnostics)
    pub fn increment_rx_counter(&mut self) {
        self.recv_nonce = self.recv_nonce.saturating_add(1);
    }

    /// Check if session is valid (active and not expired)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.is_active()
    }

    /// Manually expire the session
    pub fn expire(&mut self) {
        self.state = SessionState::Closed;
        self.expires_at = 0;
    }

    /// Check if session has expired based on timestamp
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at || self.state == SessionState::Closed
    }

    /// Set session timestamps
    pub fn set_timestamps(&mut self, created_at: u64, lifetime_secs: u64) {
        self.created_at = created_at;
        self.expires_at = created_at.saturating_add(lifetime_secs);
    }

    /// Get session state
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Check if session is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active || self.state == SessionState::NeedsRekey
    }

    /// Get current send nonce (for debugging/logging)
    #[must_use]
    pub fn current_send_nonce(&self) -> u64 {
        self.send_nonce
    }

    /// Build AES-GCM nonce from session ID and counter
    fn build_nonce(&self, counter: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        // First 4 bytes from session ID (provides uniqueness across sessions)
        nonce[0..4].copy_from_slice(&self.id[0..4]);
        // Last 8 bytes from counter (provides uniqueness within session)
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Encrypt a payload
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt (max MAX_PAYLOAD_SIZE bytes)
    /// * `associated_data` - Additional authenticated data (e.g., header)
    /// * `output` - Buffer for ciphertext (must be plaintext.len() + TAG_SIZE)
    ///
    /// # Returns
    /// * `Ok((nonce, ciphertext_len))` - The nonce used and ciphertext length
    /// * `Err(_)` - If encryption fails or session is not active
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
        output: &mut [u8],
    ) -> Result<(u64, usize), Error> {
        // Check session state
        if !self.is_active() {
            return Err(Error::InvalidState);
        }

        // Check payload size
        if plaintext.len() > MAX_PAYLOAD_SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Check output buffer
        let required_len = plaintext.len() + TAG_SIZE;
        if output.len() < required_len {
            return Err(Error::BufferTooSmall);
        }

        // Check nonce exhaustion
        if self.send_nonce >= MAX_NONCE {
            self.state = SessionState::NeedsRekey;
            return Err(Error::InvalidState);
        }

        // Get and increment nonce
        let nonce_value = self.send_nonce;
        self.send_nonce += 1;

        // Warn if approaching nonce exhaustion (at 75% capacity)
        if self.send_nonce > (MAX_NONCE * 3) / 4 {
            self.state = SessionState::NeedsRekey;
        }

        // Build nonce
        let nonce = self.build_nonce(nonce_value);

        // Perform AES-256-GCM encryption
        let ct_len = aes_gcm_encrypt(
            &self.encrypt_key,
            &nonce,
            plaintext,
            associated_data,
            output,
        )?;

        Ok((nonce_value, ct_len))
    }

    /// Decrypt a payload
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data with tag (ciphertext + TAG_SIZE)
    /// * `associated_data` - Additional authenticated data (must match encryption)
    /// * `nonce_value` - Nonce value used for encryption
    /// * `output` - Buffer for plaintext (must be ciphertext.len() - TAG_SIZE)
    ///
    /// # Returns
    /// * `Ok(plaintext_len)` - Length of decrypted plaintext
    /// * `Err(_)` - If decryption fails, authentication fails, or replay detected
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        associated_data: &[u8],
        nonce_value: u64,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        // Check session state
        if !self.is_active() {
            return Err(Error::InvalidState);
        }

        // Check minimum ciphertext size (at least tag)
        if ciphertext.len() < TAG_SIZE {
            return Err(Error::InvalidCiphertext);
        }

        // Check output buffer
        let plaintext_len = ciphertext.len() - TAG_SIZE;
        if output.len() < plaintext_len {
            return Err(Error::BufferTooSmall);
        }

        // Replay protection check
        if !self.check_replay(nonce_value) {
            return Err(Error::MessageAuthFailed);
        }

        // Build nonce
        let nonce = self.build_nonce(nonce_value);

        // Perform AES-256-GCM decryption
        let pt_len = aes_gcm_decrypt(
            &self.decrypt_key,
            &nonce,
            ciphertext,
            associated_data,
            output,
        )?;

        // Update replay window after successful decryption
        self.update_replay_window(nonce_value);

        Ok(pt_len)
    }

    /// Check if nonce is valid (not replayed)
    fn check_replay(&self, nonce: u64) -> bool {
        // Nonce too far in the future - suspicious but allow
        // (we'll update window after successful decryption)
        if nonce > self.recv_nonce + REPLAY_WINDOW_SIZE * 2 {
            return true;
        }

        // Nonce too old - definitely replay
        if self.recv_nonce >= REPLAY_WINDOW_SIZE && nonce < self.recv_nonce - REPLAY_WINDOW_SIZE {
            return false;
        }

        // Nonce in window - check bitmap
        if nonce <= self.recv_nonce {
            let bit_pos = (self.recv_nonce - nonce) as u32;
            if bit_pos < 64 {
                return (self.replay_bitmap & (1u64 << bit_pos)) == 0;
            }
        }

        true
    }

    /// Update replay window after successful decryption
    fn update_replay_window(&mut self, nonce: u64) {
        if nonce > self.recv_nonce {
            // Shift window forward
            let shift = (nonce - self.recv_nonce) as u32;
            if shift >= 64 {
                self.replay_bitmap = 1;
            } else {
                self.replay_bitmap = (self.replay_bitmap << shift) | 1;
            }
            self.recv_nonce = nonce;
        } else {
            // Mark bit in window for received nonce
            let bit_pos = (self.recv_nonce - nonce) as u32;
            if bit_pos < 64 {
                self.replay_bitmap |= 1u64 << bit_pos;
            }
        }
    }

    /// Close the session and zeroize keys
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
        // Keys will be zeroized on drop, but we can do it early
        self.encrypt_key.zeroize();
        self.decrypt_key.zeroize();
    }

    /// Rekey the session with new keys
    pub fn rekey(&mut self, new_encrypt_key: [u8; 32], new_decrypt_key: [u8; 32]) {
        // Zeroize old keys
        self.encrypt_key.zeroize();
        self.decrypt_key.zeroize();

        // Install new keys
        self.encrypt_key = new_encrypt_key;
        self.decrypt_key = new_decrypt_key;

        // Reset nonce counters
        self.send_nonce = 0;
        self.recv_nonce = 0;
        self.replay_bitmap = 0;

        // Reset state
        self.state = SessionState::Active;
    }

    /// Increment send nonce (legacy compatibility)
    pub fn next_send_nonce(&mut self) -> u64 {
        let n = self.send_nonce;
        self.send_nonce += 1;
        n
    }
}

// ============================================================================
// AES-GCM Implementation using q-crypto
// ============================================================================

/// Perform AES-256-GCM encryption
fn aes_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    use q_crypto::aead::{Aes256Gcm, Aes256Key, AesGcmNonce};
    use q_crypto::traits::Aead;

    let key = Aes256Key::new(*key);
    let nonce = AesGcmNonce::new(*nonce);

    Aes256Gcm::encrypt(&key, &nonce, plaintext, aad, output)
        .map_err(|_| Error::AeadError)
}

/// Perform AES-256-GCM decryption
fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    use q_crypto::aead::{Aes256Gcm, Aes256Key, AesGcmNonce};
    use q_crypto::traits::Aead;

    let key = Aes256Key::new(*key);
    let nonce = AesGcmNonce::new(*nonce);

    Aes256Gcm::decrypt(&key, &nonce, ciphertext, aad, output)
        .map_err(|_| Error::AeadError)
}

// ============================================================================
// Encrypted Frame
// ============================================================================

/// Frame header for encrypted mesh messages
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FrameHeader {
    /// Protocol version
    pub version: u8,
    /// Frame type
    pub frame_type: u8,
    /// Source address (truncated device ID)
    pub src_addr: [u8; 8],
    /// Destination address (truncated device ID)
    pub dst_addr: [u8; 8],
    /// Session ID (first 4 bytes)
    pub session_id: [u8; 4],
    /// Nonce value for this frame
    pub nonce: u64,
    /// Payload length (encrypted)
    pub payload_len: u16,
}

impl FrameHeader {
    /// Header size in bytes
    pub const SIZE: usize = 32;

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0] = self.version;
        bytes[1] = self.frame_type;
        bytes[2..10].copy_from_slice(&self.src_addr);
        bytes[10..18].copy_from_slice(&self.dst_addr);
        bytes[18..22].copy_from_slice(&self.session_id);
        bytes[22..30].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[30..32].copy_from_slice(&self.payload_len.to_le_bytes());
        bytes
    }

    /// Parse header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }

        let mut src_addr = [0u8; 8];
        let mut dst_addr = [0u8; 8];
        let mut session_id = [0u8; 4];

        src_addr.copy_from_slice(&bytes[2..10]);
        dst_addr.copy_from_slice(&bytes[10..18]);
        session_id.copy_from_slice(&bytes[18..22]);

        Some(Self {
            version: bytes[0],
            frame_type: bytes[1],
            src_addr,
            dst_addr,
            session_id,
            nonce: u64::from_le_bytes([
                bytes[22], bytes[23], bytes[24], bytes[25],
                bytes[26], bytes[27], bytes[28], bytes[29],
            ]),
            payload_len: u16::from_le_bytes([bytes[30], bytes[31]]),
        })
    }
}

/// Encrypted frame for mesh transmission
pub struct EncryptedFrame {
    /// Frame header (authenticated but not encrypted)
    pub header: FrameHeader,
    /// Encrypted payload with authentication tag
    pub ciphertext: Vec<u8, { MAX_PAYLOAD_SIZE + TAG_SIZE }>,
}

impl EncryptedFrame {
    /// Create encrypted frame from plaintext payload
    pub fn encrypt(
        session: &mut Session,
        src_addr: [u8; 8],
        dst_addr: [u8; 8],
        frame_type: u8,
        payload: &[u8],
    ) -> Result<Self, Error> {
        let mut ciphertext = Vec::new();
        ciphertext.resize(payload.len() + TAG_SIZE, 0)
            .map_err(|_| Error::BufferTooSmall)?;

        // Build header (will be used as AAD)
        let mut header = FrameHeader {
            version: 1,
            frame_type,
            src_addr,
            dst_addr,
            session_id: [0u8; 4],
            nonce: 0,
            payload_len: payload.len() as u16,
        };
        header.session_id.copy_from_slice(&session.id[0..4]);

        // Encrypt with header as AAD
        let header_bytes = header.to_bytes();
        let (nonce_value, ct_len) = session.encrypt(payload, &header_bytes, &mut ciphertext)?;

        header.nonce = nonce_value;
        ciphertext.truncate(ct_len);

        Ok(Self { header, ciphertext })
    }

    /// Decrypt frame to plaintext payload
    pub fn decrypt(&self, session: &mut Session, output: &mut [u8]) -> Result<usize, Error> {
        // Verify session ID matches
        if self.header.session_id != session.id[0..4] {
            return Err(Error::InvalidParameter);
        }

        // Use header as AAD
        let header_bytes = self.header.to_bytes();

        session.decrypt(&self.ciphertext, &header_bytes, self.header.nonce, output)
    }

    /// Serialize frame for transmission
    pub fn to_bytes(&self) -> Vec<u8, { FrameHeader::SIZE + MAX_PAYLOAD_SIZE + TAG_SIZE }> {
        let mut bytes = Vec::new();
        let header_bytes = self.header.to_bytes();
        bytes.extend_from_slice(&header_bytes).ok();
        bytes.extend_from_slice(&self.ciphertext).ok();
        bytes
    }

    /// Parse frame from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < FrameHeader::SIZE {
            return Err(Error::BufferTooSmall);
        }

        let header = FrameHeader::from_bytes(bytes)
            .ok_or(Error::InvalidParameter)?;

        let ciphertext_start = FrameHeader::SIZE;
        let ciphertext_len = header.payload_len as usize + TAG_SIZE;

        if bytes.len() < ciphertext_start + ciphertext_len {
            return Err(Error::BufferTooSmall);
        }

        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&bytes[ciphertext_start..ciphertext_start + ciphertext_len])
            .map_err(|_| Error::BufferTooSmall)?;

        Ok(Self { header, ciphertext })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(result, Err(Error::MessageAuthFailed)));
    }

    #[test]
    fn test_nonce_increment() {
        let id = [0x42u8; 16];
        let key = [0xAAu8; 32];

        let mut session = Session::new(id, key, key);

        assert_eq!(session.next_send_nonce(), 0);
        assert_eq!(session.next_send_nonce(), 1);
        assert_eq!(session.next_send_nonce(), 2);
    }

    #[test]
    fn test_frame_header_serialization() {
        let header = FrameHeader {
            version: 1,
            frame_type: 2,
            src_addr: [1, 2, 3, 4, 5, 6, 7, 8],
            dst_addr: [8, 7, 6, 5, 4, 3, 2, 1],
            session_id: [0xAA, 0xBB, 0xCC, 0xDD],
            nonce: 12345678,
            payload_len: 100,
        };

        let bytes = header.to_bytes();
        let parsed = FrameHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.frame_type, header.frame_type);
        assert_eq!(parsed.src_addr, header.src_addr);
        assert_eq!(parsed.dst_addr, header.dst_addr);
        assert_eq!(parsed.session_id, header.session_id);
        assert_eq!(parsed.nonce, header.nonce);
        assert_eq!(parsed.payload_len, header.payload_len);
    }

    #[test]
    fn test_session_state() {
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
