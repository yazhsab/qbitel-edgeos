// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Post-Quantum Cryptographic Handshake Protocol
//!
//! This module implements a secure handshake protocol for establishing
//! authenticated and encrypted communication channels between mesh nodes.
//!
//! # Protocol Overview
//!
//! The handshake uses a hybrid approach combining:
//! - ML-KEM-768 (Kyber) for key encapsulation
//! - ML-DSA-65 (Dilithium3) for signatures
//! - HKDF-SHA3-256 for key derivation
//! - AES-256-GCM for session encryption
//!
//! # Message Flow
//!
//! ```text
//! Initiator                                Responder
//!     |                                        |
//!     |  ------ ClientHello (KEM pk) ------>   |
//!     |                                        |
//!     |  <----- ServerHello (KEM ct, sig) ---  |
//!     |                                        |
//!     |  ------ ClientFinished (sig) ------>   |
//!     |                                        |
//!     |          Session Established           |
//! ```
//!
//! # Security Properties
//!
//! - Forward secrecy via ephemeral KEM keys
//! - Mutual authentication via identity signatures
//! - Post-quantum security (NIST Level 3)
//! - Resistance to replay attacks via nonces
//! - Cryptographic transcript binding via SHA3-256
//! - Session keys derived via HKDF-SHA3-256 with domain separation

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};
use heapless::Vec;
use q_common::{Error, DeviceId};
use q_crypto::hash::{Sha3_256, HkdfSha3_256};
use q_crypto::traits::Hash;
use q_crypto::kyber::{
    Kyber768, Kyber768PublicKey, Kyber768SecretKey, Kyber768Ciphertext, Kyber768SharedSecret,
    KYBER768_PUBLIC_KEY_SIZE, KYBER768_SECRET_KEY_SIZE, KYBER768_CIPHERTEXT_SIZE,
    KYBER768_SHARED_SECRET_SIZE,
};
use q_crypto::traits::{Kem, CryptoRng};

// Constants for buffer sizes
const NONCE_SIZE: usize = 32;
const SESSION_KEY_SIZE: usize = 32;
const MAX_HANDSHAKE_MSG: usize = 4096;
const TRANSCRIPT_HASH_SIZE: usize = 32;
const VERIFY_DATA_SIZE: usize = 32;

// ML-KEM-768 sizes (re-export from q-crypto)
const KYBER768_PK_SIZE: usize = KYBER768_PUBLIC_KEY_SIZE;
const KYBER768_SK_SIZE: usize = KYBER768_SECRET_KEY_SIZE;
const KYBER768_CT_SIZE: usize = KYBER768_CIPHERTEXT_SIZE;
const KYBER768_SS_SIZE: usize = KYBER768_SHARED_SECRET_SIZE;

// ML-DSA-65 sizes
const DILITHIUM3_SIG_SIZE: usize = 3293;

// HKDF labels for domain separation
const HKDF_LABEL_CLIENT_WRITE_KEY: &[u8] = b"q-mesh handshake client write key";
const HKDF_LABEL_SERVER_WRITE_KEY: &[u8] = b"q-mesh handshake server write key";
const HKDF_LABEL_CLIENT_WRITE_MAC: &[u8] = b"q-mesh handshake client write mac";
const HKDF_LABEL_SERVER_WRITE_MAC: &[u8] = b"q-mesh handshake server write mac";
const HKDF_LABEL_VERIFY_DATA: &[u8] = b"q-mesh handshake verify data";

// ============================================================================
// Handshake State Machine
// ============================================================================

/// Handshake state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state - ready to start
    Init,
    /// Client: Sent ClientHello, waiting for ServerHello
    AwaitingServerHello,
    /// Server: Received ClientHello, processing
    ReceivedClientHello,
    /// Client: Sent ClientFinished, waiting for confirmation
    AwaitingConfirmation,
    /// Server: Received ClientFinished, processing
    ReceivedClientFinished,
    /// Handshake completed successfully
    Complete,
    /// Handshake failed
    Failed,
}

impl fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init => write!(f, "Init"),
            Self::AwaitingServerHello => write!(f, "AwaitingServerHello"),
            Self::ReceivedClientHello => write!(f, "ReceivedClientHello"),
            Self::AwaitingConfirmation => write!(f, "AwaitingConfirmation"),
            Self::ReceivedClientFinished => write!(f, "ReceivedClientFinished"),
            Self::Complete => write!(f, "Complete"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

// ============================================================================
// Transcript Hasher - Uses SHA3-256
// ============================================================================

/// Cryptographic transcript hasher using SHA3-256
///
/// Maintains a running hash of all handshake messages to ensure
/// cryptographic binding of the entire handshake conversation.
struct TranscriptHasher {
    /// Running hash state
    hasher: Sha3_256,
    /// All data accumulated (for re-hashing)
    data: Vec<u8, 8192>,
}

impl TranscriptHasher {
    /// Create a new transcript hasher
    fn new() -> Self {
        Self {
            hasher: Sha3_256::new(),
            data: Vec::new(),
        }
    }

    /// Update transcript with data
    fn update(&mut self, data: &[u8]) {
        // Store data for potential re-hash
        self.data.extend_from_slice(data).ok();
        self.hasher.update(data);
    }

    /// Get current transcript hash
    fn current_hash(&self) -> [u8; TRANSCRIPT_HASH_SIZE] {
        // Hash all accumulated data
        let output = Sha3_256::hash(&self.data);
        let mut result = [0u8; TRANSCRIPT_HASH_SIZE];
        result.copy_from_slice(output.as_ref());
        result
    }
}

// ============================================================================
// Ephemeral Keys - Real ML-KEM-768
// ============================================================================

/// Ephemeral KEM keypair using real ML-KEM-768
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralKemKeypair {
    /// Public key bytes
    public_key_bytes: [u8; KYBER768_PK_SIZE],
    /// Secret key bytes (zeroized on drop)
    secret_key_bytes: [u8; KYBER768_SK_SIZE],
}

impl EphemeralKemKeypair {
    /// Generate a new keypair using ML-KEM-768
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Result<Self, Error> {
        let (pk, sk) = Kyber768::keypair(rng)
            .map_err(|_| Error::RngFailure)?;

        Ok(Self {
            public_key_bytes: pk.to_bytes(),
            secret_key_bytes: sk.to_bytes(),
        })
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> &[u8; KYBER768_PK_SIZE] {
        &self.public_key_bytes
    }

    /// Decapsulate a ciphertext to recover shared secret
    pub fn decapsulate(&self, ciphertext: &[u8; KYBER768_CT_SIZE]) -> Result<SharedSecret, Error> {
        let sk = Kyber768SecretKey::from_bytes(&self.secret_key_bytes)
            .map_err(|_| Error::InvalidKey)?;
        let ct = Kyber768Ciphertext::from_bytes(ciphertext)
            .map_err(|_| Error::InvalidCiphertext)?;

        let ss = Kyber768::decapsulate(&sk, &ct)
            .map_err(|_| Error::DecapsulationFailed)?;

        Ok(SharedSecret::from_kyber_shared_secret(&ss))
    }
}

/// Ephemeral shared secret
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; KYBER768_SS_SIZE]);

impl SharedSecret {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; KYBER768_SS_SIZE]) -> Self {
        Self(bytes)
    }

    /// Create from Kyber shared secret
    pub fn from_kyber_shared_secret(ss: &Kyber768SharedSecret) -> Self {
        let mut bytes = [0u8; KYBER768_SS_SIZE];
        bytes.copy_from_slice(ss.as_ref());
        Self(bytes)
    }

    /// Get as byte slice
    pub fn as_bytes(&self) -> &[u8; KYBER768_SS_SIZE] {
        &self.0
    }
}

// ============================================================================
// Encapsulation Result
// ============================================================================

/// Result of KEM encapsulation
pub struct EncapsulationResult {
    /// Ciphertext to send to peer
    pub ciphertext: [u8; KYBER768_CT_SIZE],
    /// Shared secret (kept private)
    pub shared_secret: SharedSecret,
}

impl EncapsulationResult {
    /// Encapsulate to a public key using real ML-KEM-768
    pub fn encapsulate<R: CryptoRng>(
        peer_public_key: &[u8; KYBER768_PK_SIZE],
        rng: &mut R,
    ) -> Result<Self, Error> {
        let pk = Kyber768PublicKey::from_bytes(peer_public_key)
            .map_err(|_| Error::InvalidKey)?;

        let (ct, ss) = Kyber768::encapsulate(&pk, rng)
            .map_err(|_| Error::RngFailure)?;

        // Copy ciphertext bytes from AsRef
        let mut ciphertext = [0u8; KYBER768_CT_SIZE];
        ciphertext.copy_from_slice(ct.as_ref());

        Ok(Self {
            ciphertext,
            shared_secret: SharedSecret::from_kyber_shared_secret(&ss),
        })
    }
}

// ============================================================================
// Handshake Messages
// ============================================================================

/// Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Client hello message
    ClientHello = 0x01,
    /// Server hello message
    ServerHello = 0x02,
    /// Client finished message
    ClientFinished = 0x03,
    /// Server finished message
    ServerFinished = 0x04,
    /// Error message
    Error = 0xFF,
}

impl MessageType {
    /// Convert from byte
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::ClientHello),
            0x02 => Some(Self::ServerHello),
            0x03 => Some(Self::ClientFinished),
            0x04 => Some(Self::ServerFinished),
            0xFF => Some(Self::Error),
            _ => None,
        }
    }
}

/// ClientHello message
pub struct ClientHello {
    /// Protocol version
    pub version: u8,
    /// Client random nonce
    pub client_random: [u8; NONCE_SIZE],
    /// Client's ephemeral KEM public key
    pub kem_public_key: [u8; KYBER768_PK_SIZE],
    /// Client's device ID
    pub client_id: DeviceId,
}

impl ClientHello {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8, MAX_HANDSHAKE_MSG> {
        let mut buf = Vec::new();

        let _ = buf.push(MessageType::ClientHello as u8);
        let _ = buf.push(self.version);
        buf.extend_from_slice(&self.client_random).ok();
        buf.extend_from_slice(&self.kem_public_key).ok();
        buf.extend_from_slice(self.client_id.as_bytes()).ok();

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        const MIN_SIZE: usize = 1 + 1 + NONCE_SIZE + KYBER768_PK_SIZE + 32;

        if data.len() < MIN_SIZE {
            return Err(Error::BufferTooSmall);
        }

        if data[0] != MessageType::ClientHello as u8 {
            return Err(Error::InvalidParameter);
        }

        let version = data[1];

        let mut client_random = [0u8; NONCE_SIZE];
        client_random.copy_from_slice(&data[2..2 + NONCE_SIZE]);

        let mut kem_public_key = [0u8; KYBER768_PK_SIZE];
        kem_public_key.copy_from_slice(&data[2 + NONCE_SIZE..2 + NONCE_SIZE + KYBER768_PK_SIZE]);

        let client_id = DeviceId::from_slice(&data[2 + NONCE_SIZE + KYBER768_PK_SIZE..])
            .ok_or(Error::InvalidParameter)?;

        Ok(Self {
            version,
            client_random,
            kem_public_key,
            client_id,
        })
    }
}

/// ServerHello message
pub struct ServerHello {
    /// Protocol version
    pub version: u8,
    /// Server random nonce
    pub server_random: [u8; NONCE_SIZE],
    /// KEM ciphertext (encapsulated shared secret)
    pub kem_ciphertext: [u8; KYBER768_CT_SIZE],
    /// Server's device ID
    pub server_id: DeviceId,
    /// Signature over handshake transcript
    pub signature: [u8; DILITHIUM3_SIG_SIZE],
}

impl ServerHello {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8, MAX_HANDSHAKE_MSG> {
        let mut buf = Vec::new();

        let _ = buf.push(MessageType::ServerHello as u8);
        let _ = buf.push(self.version);
        buf.extend_from_slice(&self.server_random).ok();
        buf.extend_from_slice(&self.kem_ciphertext).ok();
        buf.extend_from_slice(self.server_id.as_bytes()).ok();
        buf.extend_from_slice(&self.signature).ok();

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        const MIN_SIZE: usize = 1 + 1 + NONCE_SIZE + KYBER768_CT_SIZE + 32 + DILITHIUM3_SIG_SIZE;

        if data.len() < MIN_SIZE {
            return Err(Error::BufferTooSmall);
        }

        if data[0] != MessageType::ServerHello as u8 {
            return Err(Error::InvalidParameter);
        }

        let version = data[1];
        let mut offset = 2;

        let mut server_random = [0u8; NONCE_SIZE];
        server_random.copy_from_slice(&data[offset..offset + NONCE_SIZE]);
        offset += NONCE_SIZE;

        let mut kem_ciphertext = [0u8; KYBER768_CT_SIZE];
        kem_ciphertext.copy_from_slice(&data[offset..offset + KYBER768_CT_SIZE]);
        offset += KYBER768_CT_SIZE;

        let server_id = DeviceId::from_slice(&data[offset..offset + 32])
            .ok_or(Error::InvalidParameter)?;
        offset += 32;

        let mut signature = [0u8; DILITHIUM3_SIG_SIZE];
        signature.copy_from_slice(&data[offset..offset + DILITHIUM3_SIG_SIZE]);

        Ok(Self {
            version,
            server_random,
            kem_ciphertext,
            server_id,
            signature,
        })
    }
}

/// ClientFinished message
pub struct ClientFinished {
    /// Signature over handshake transcript
    pub signature: [u8; DILITHIUM3_SIG_SIZE],
    /// Verification data (HKDF-derived from transcript)
    pub verify_data: [u8; VERIFY_DATA_SIZE],
}

impl ClientFinished {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8, MAX_HANDSHAKE_MSG> {
        let mut buf = Vec::new();

        let _ = buf.push(MessageType::ClientFinished as u8);
        buf.extend_from_slice(&self.signature).ok();
        buf.extend_from_slice(&self.verify_data).ok();

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        const MIN_SIZE: usize = 1 + DILITHIUM3_SIG_SIZE + VERIFY_DATA_SIZE;

        if data.len() < MIN_SIZE {
            return Err(Error::BufferTooSmall);
        }

        if data[0] != MessageType::ClientFinished as u8 {
            return Err(Error::InvalidParameter);
        }

        let mut signature = [0u8; DILITHIUM3_SIG_SIZE];
        signature.copy_from_slice(&data[1..1 + DILITHIUM3_SIG_SIZE]);

        let mut verify_data = [0u8; VERIFY_DATA_SIZE];
        verify_data.copy_from_slice(&data[1 + DILITHIUM3_SIG_SIZE..]);

        Ok(Self { signature, verify_data })
    }
}

// ============================================================================
// Unified Handshake Message
// ============================================================================

/// Unified handshake message type for convenient parsing and handling
pub enum HandshakeMessage {
    /// Client hello message (initiator -> responder)
    ClientHello(ClientHello),
    /// Server hello message (responder -> initiator)
    ServerHello(ServerHello),
    /// Client finished message (initiator -> responder)
    ClientFinished(ClientFinished),
}

impl HandshakeMessage {
    /// Get the message type
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::ClientHello(_) => MessageType::ClientHello,
            Self::ServerHello(_) => MessageType::ServerHello,
            Self::ClientFinished(_) => MessageType::ClientFinished,
        }
    }

    /// Serialize the message to bytes
    pub fn to_bytes(&self) -> Vec<u8, MAX_HANDSHAKE_MSG> {
        match self {
            Self::ClientHello(msg) => msg.to_bytes(),
            Self::ServerHello(msg) => msg.to_bytes(),
            Self::ClientFinished(msg) => msg.to_bytes(),
        }
    }

    /// Parse a handshake message from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::BufferTooSmall);
        }

        let msg_type = MessageType::from_u8(data[0])
            .ok_or(Error::InvalidParameter)?;

        match msg_type {
            MessageType::ClientHello => {
                Ok(Self::ClientHello(ClientHello::from_bytes(data)?))
            }
            MessageType::ServerHello => {
                Ok(Self::ServerHello(ServerHello::from_bytes(data)?))
            }
            MessageType::ClientFinished => {
                Ok(Self::ClientFinished(ClientFinished::from_bytes(data)?))
            }
            _ => Err(Error::InvalidParameter),
        }
    }
}

// ============================================================================
// Session Keys - Derived using HKDF-SHA3-256
// ============================================================================

/// Derived session keys using HKDF-SHA3-256
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Client to server encryption key
    pub client_write_key: [u8; SESSION_KEY_SIZE],
    /// Server to client encryption key
    pub server_write_key: [u8; SESSION_KEY_SIZE],
    /// Client to server MAC key
    pub client_write_mac: [u8; SESSION_KEY_SIZE],
    /// Server to client MAC key
    pub server_write_mac: [u8; SESSION_KEY_SIZE],
}

impl SessionKeys {
    /// Derive session keys from shared secret using HKDF-SHA3-256
    ///
    /// Uses proper key derivation with domain separation labels to ensure
    /// each key is cryptographically independent.
    pub fn derive(
        shared_secret: &SharedSecret,
        client_random: &[u8; NONCE_SIZE],
        server_random: &[u8; NONCE_SIZE],
    ) -> Result<Self, Error> {
        // Construct salt from both randoms (provides freshness)
        let mut salt = [0u8; NONCE_SIZE * 2];
        salt[..NONCE_SIZE].copy_from_slice(client_random);
        salt[NONCE_SIZE..].copy_from_slice(server_random);

        let ikm = shared_secret.as_bytes();

        // Derive each key using HKDF with unique labels for domain separation
        let mut client_write_key = [0u8; SESSION_KEY_SIZE];
        let mut server_write_key = [0u8; SESSION_KEY_SIZE];
        let mut client_write_mac = [0u8; SESSION_KEY_SIZE];
        let mut server_write_mac = [0u8; SESSION_KEY_SIZE];

        HkdfSha3_256::derive(ikm, &salt, HKDF_LABEL_CLIENT_WRITE_KEY, &mut client_write_key)
            .map_err(|_| Error::KeyDerivationFailed)?;

        HkdfSha3_256::derive(ikm, &salt, HKDF_LABEL_SERVER_WRITE_KEY, &mut server_write_key)
            .map_err(|_| Error::KeyDerivationFailed)?;

        HkdfSha3_256::derive(ikm, &salt, HKDF_LABEL_CLIENT_WRITE_MAC, &mut client_write_mac)
            .map_err(|_| Error::KeyDerivationFailed)?;

        HkdfSha3_256::derive(ikm, &salt, HKDF_LABEL_SERVER_WRITE_MAC, &mut server_write_mac)
            .map_err(|_| Error::KeyDerivationFailed)?;

        Ok(Self {
            client_write_key,
            server_write_key,
            client_write_mac,
            server_write_mac,
        })
    }

    /// Compute verify data from transcript hash using HKDF
    ///
    /// This provides cryptographic binding between the shared secret
    /// and the entire handshake transcript.
    pub fn compute_verify_data(
        shared_secret: &SharedSecret,
        transcript_hash: &[u8; TRANSCRIPT_HASH_SIZE],
    ) -> Result<[u8; VERIFY_DATA_SIZE], Error> {
        let mut verify_data = [0u8; VERIFY_DATA_SIZE];

        HkdfSha3_256::derive(
            shared_secret.as_bytes(),
            transcript_hash,
            HKDF_LABEL_VERIFY_DATA,
            &mut verify_data,
        ).map_err(|_| Error::KeyDerivationFailed)?;

        Ok(verify_data)
    }
}

// ============================================================================
// Handshake Context
// ============================================================================

/// Role in the handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Initiator (client)
    Initiator,
    /// Responder (server)
    Responder,
}

/// Handshake context
///
/// Manages the state machine and cryptographic operations for
/// establishing a secure session between two mesh nodes.
pub struct Handshake {
    /// Current state
    pub state: HandshakeState,
    /// Our role
    role: Role,
    /// Our device ID
    our_id: DeviceId,
    /// Peer device ID (set after receiving their hello)
    peer_id: Option<DeviceId>,
    /// Our random nonce
    our_random: [u8; NONCE_SIZE],
    /// Peer random nonce
    peer_random: [u8; NONCE_SIZE],
    /// Our ephemeral keypair (initiator only)
    ephemeral_keypair: Option<EphemeralKemKeypair>,
    /// Peer's KEM public key (responder only)
    peer_kem_public_key: Option<[u8; KYBER768_PK_SIZE]>,
    /// KEM ciphertext (responder: sent, initiator: received)
    kem_ciphertext: Option<[u8; KYBER768_CT_SIZE]>,
    /// Shared secret (after encapsulation/decapsulation)
    shared_secret: Option<SharedSecret>,
    /// Derived session keys
    session_keys: Option<SessionKeys>,
    /// Handshake transcript hasher (SHA3-256)
    transcript: TranscriptHasher,
    /// Cached transcript hash
    transcript_hash: [u8; TRANSCRIPT_HASH_SIZE],
}

impl Handshake {
    /// Create a new handshake context as initiator
    pub fn new_initiator<R: CryptoRng>(our_id: DeviceId, rng: &mut R) -> Result<Self, Error> {
        let mut our_random = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut our_random)
            .map_err(|_| Error::RngFailure)?;

        let ephemeral_keypair = EphemeralKemKeypair::generate(rng)?;

        Ok(Self {
            state: HandshakeState::Init,
            role: Role::Initiator,
            our_id,
            peer_id: None,
            our_random,
            peer_random: [0u8; NONCE_SIZE],
            ephemeral_keypair: Some(ephemeral_keypair),
            peer_kem_public_key: None,
            kem_ciphertext: None,
            shared_secret: None,
            session_keys: None,
            transcript: TranscriptHasher::new(),
            transcript_hash: [0u8; TRANSCRIPT_HASH_SIZE],
        })
    }

    /// Create a new handshake context as responder
    pub fn new_responder<R: CryptoRng>(our_id: DeviceId, rng: &mut R) -> Result<Self, Error> {
        let mut our_random = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut our_random)
            .map_err(|_| Error::RngFailure)?;

        Ok(Self {
            state: HandshakeState::Init,
            role: Role::Responder,
            our_id,
            peer_id: None,
            our_random,
            peer_random: [0u8; NONCE_SIZE],
            ephemeral_keypair: None,
            peer_kem_public_key: None,
            kem_ciphertext: None,
            shared_secret: None,
            session_keys: None,
            transcript: TranscriptHasher::new(),
            transcript_hash: [0u8; TRANSCRIPT_HASH_SIZE],
        })
    }

    /// Get current state
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    /// Get our role
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Get our device ID
    #[must_use]
    pub fn our_id(&self) -> &DeviceId {
        &self.our_id
    }

    /// Get peer device ID (if known)
    #[must_use]
    pub fn peer_id(&self) -> Option<&DeviceId> {
        self.peer_id.as_ref()
    }

    /// Check if handshake is complete
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, HandshakeState::Complete)
    }

    /// Check if handshake failed
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self.state, HandshakeState::Failed)
    }

    /// Get session keys (only valid after handshake completes)
    #[must_use]
    pub fn session_keys(&self) -> Option<&SessionKeys> {
        if self.is_complete() {
            self.session_keys.as_ref()
        } else {
            None
        }
    }

    /// Update transcript with data
    fn update_transcript(&mut self, data: &[u8]) {
        self.transcript.update(data);
        self.transcript_hash = self.transcript.current_hash();
    }

    // =========================================================================
    // Initiator Operations
    // =========================================================================

    /// Create ClientHello message (initiator only)
    pub fn create_client_hello(&mut self) -> Result<ClientHello, Error> {
        if self.role != Role::Initiator || self.state != HandshakeState::Init {
            return Err(Error::InvalidState);
        }

        let keypair = self.ephemeral_keypair.as_ref()
            .ok_or(Error::InternalError)?;

        let hello = ClientHello {
            version: 1,
            client_random: self.our_random,
            kem_public_key: *keypair.public_key_bytes(),
            client_id: self.our_id,
        };

        // Update transcript hash with serialized message
        self.update_transcript(&hello.to_bytes());

        self.state = HandshakeState::AwaitingServerHello;
        Ok(hello)
    }

    /// Process ServerHello message (initiator only)
    pub fn process_server_hello(
        &mut self,
        hello: &ServerHello,
        verify_signature: impl FnOnce(&[u8], &[u8; DILITHIUM3_SIG_SIZE], &DeviceId) -> bool,
    ) -> Result<(), Error> {
        if self.role != Role::Initiator || self.state != HandshakeState::AwaitingServerHello {
            return Err(Error::InvalidState);
        }

        // Verify signature over current transcript
        if !verify_signature(&self.transcript_hash, &hello.signature, &hello.server_id) {
            self.state = HandshakeState::Failed;
            return Err(Error::InvalidSignature);
        }

        // Store peer info
        self.peer_id = Some(hello.server_id);
        self.peer_random = hello.server_random;
        self.kem_ciphertext = Some(hello.kem_ciphertext);

        // Decapsulate shared secret using real ML-KEM-768
        let keypair = self.ephemeral_keypair.as_ref()
            .ok_or(Error::InternalError)?;

        let shared_secret = keypair.decapsulate(&hello.kem_ciphertext)?;
        self.shared_secret = Some(shared_secret);

        // Derive session keys using HKDF-SHA3-256
        let shared = self.shared_secret.as_ref()
            .ok_or(Error::InternalError)?;

        self.session_keys = Some(SessionKeys::derive(
            shared,
            &self.our_random,
            &self.peer_random,
        )?);

        // Update transcript with server hello
        self.update_transcript(&hello.to_bytes());

        self.state = HandshakeState::AwaitingConfirmation;
        Ok(())
    }

    /// Create ClientFinished message (initiator only)
    pub fn create_client_finished(
        &mut self,
        sign: impl FnOnce(&[u8]) -> [u8; DILITHIUM3_SIG_SIZE],
    ) -> Result<ClientFinished, Error> {
        if self.role != Role::Initiator || self.state != HandshakeState::AwaitingConfirmation {
            return Err(Error::InvalidState);
        }

        // Sign current transcript
        let signature = sign(&self.transcript_hash);

        // Compute verify data using HKDF
        let shared = self.shared_secret.as_ref()
            .ok_or(Error::InternalError)?;

        let verify_data = SessionKeys::compute_verify_data(shared, &self.transcript_hash)?;

        let finished = ClientFinished {
            signature,
            verify_data,
        };

        self.update_transcript(&finished.to_bytes());
        self.state = HandshakeState::Complete;

        Ok(finished)
    }

    // =========================================================================
    // Responder Operations
    // =========================================================================

    /// Process ClientHello message (responder only)
    pub fn process_client_hello<R: CryptoRng>(
        &mut self,
        hello: &ClientHello,
        _rng: &mut R,
    ) -> Result<(), Error> {
        if self.role != Role::Responder || self.state != HandshakeState::Init {
            return Err(Error::InvalidState);
        }

        // Store peer info
        self.peer_id = Some(hello.client_id);
        self.peer_random = hello.client_random;
        self.peer_kem_public_key = Some(hello.kem_public_key);

        // Update transcript
        self.update_transcript(&hello.to_bytes());

        self.state = HandshakeState::ReceivedClientHello;
        Ok(())
    }

    /// Create ServerHello message (responder only)
    pub fn create_server_hello<R: CryptoRng>(
        &mut self,
        sign: impl FnOnce(&[u8]) -> [u8; DILITHIUM3_SIG_SIZE],
        rng: &mut R,
    ) -> Result<ServerHello, Error> {
        if self.role != Role::Responder || self.state != HandshakeState::ReceivedClientHello {
            return Err(Error::InvalidState);
        }

        // Get the peer's public key
        let peer_pk = self.peer_kem_public_key
            .ok_or(Error::InternalError)?;

        // Encapsulate using real ML-KEM-768
        let encap = EncapsulationResult::encapsulate(&peer_pk, rng)?;

        // Store shared secret and ciphertext
        self.shared_secret = Some(encap.shared_secret);
        self.kem_ciphertext = Some(encap.ciphertext);

        // Derive session keys using HKDF-SHA3-256
        let shared = self.shared_secret.as_ref()
            .ok_or(Error::InternalError)?;

        self.session_keys = Some(SessionKeys::derive(
            shared,
            &self.peer_random,
            &self.our_random,
        )?);

        // Sign transcript
        let signature = sign(&self.transcript_hash);

        let hello = ServerHello {
            version: 1,
            server_random: self.our_random,
            kem_ciphertext: encap.ciphertext,
            server_id: self.our_id,
            signature,
        };

        self.update_transcript(&hello.to_bytes());
        self.state = HandshakeState::ReceivedClientFinished;

        Ok(hello)
    }

    /// Process ClientFinished message (responder only)
    pub fn process_client_finished(
        &mut self,
        finished: &ClientFinished,
        verify_signature: impl FnOnce(&[u8], &[u8; DILITHIUM3_SIG_SIZE], &DeviceId) -> bool,
    ) -> Result<(), Error> {
        if self.role != Role::Responder || self.state != HandshakeState::ReceivedClientFinished {
            return Err(Error::InvalidState);
        }

        let peer_id = self.peer_id.as_ref().ok_or(Error::InternalError)?;

        // Verify signature
        if !verify_signature(&self.transcript_hash, &finished.signature, peer_id) {
            self.state = HandshakeState::Failed;
            return Err(Error::InvalidSignature);
        }

        // Verify verify_data using HKDF
        let shared = self.shared_secret.as_ref()
            .ok_or(Error::InternalError)?;

        let expected = SessionKeys::compute_verify_data(shared, &self.transcript_hash)?;

        // Constant-time comparison to prevent timing attacks
        let mut diff = 0u8;
        for (a, b) in finished.verify_data.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }

        if diff != 0 {
            self.state = HandshakeState::Failed;
            return Err(Error::MessageAuthFailed);
        }

        self.update_transcript(&finished.to_bytes());
        self.state = HandshakeState::Complete;

        Ok(())
    }

    /// Abort the handshake and zeroize all secrets
    pub fn abort(&mut self) {
        self.state = HandshakeState::Failed;

        // Zeroize all sensitive data
        if let Some(mut keys) = self.session_keys.take() {
            keys.zeroize();
        }
        if let Some(mut secret) = self.shared_secret.take() {
            secret.zeroize();
        }
        if let Some(mut keypair) = self.ephemeral_keypair.take() {
            keypair.zeroize();
        }
        self.our_random.zeroize();
        self.peer_random.zeroize();
        self.transcript_hash.zeroize();
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        // Ensure all secrets are zeroized on drop
        self.our_random.zeroize();
        self.peer_random.zeroize();
        self.transcript_hash.zeroize();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use q_crypto::error::CryptoError;

    /// Test RNG that wraps a closure
    struct TestRng<F: FnMut(&mut [u8])>(F);

    impl<F: FnMut(&mut [u8])> CryptoRng for TestRng<F> {
        fn fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
            (self.0)(buf);
            Ok(())
        }
    }

    fn test_rng_fn(buf: &mut [u8]) {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i * 7 + 13) as u8;
        }
    }

    fn dummy_sign(_data: &[u8]) -> [u8; DILITHIUM3_SIG_SIZE] {
        let mut sig = [0u8; DILITHIUM3_SIG_SIZE];
        sig[0] = 0xAB;
        sig
    }

    fn dummy_verify(_data: &[u8], sig: &[u8; DILITHIUM3_SIG_SIZE], _id: &DeviceId) -> bool {
        sig[0] == 0xAB
    }

    #[test]
    fn test_transcript_hasher() {
        let mut hasher = TranscriptHasher::new();
        hasher.update(b"hello");
        hasher.update(b" world");

        let hash = hasher.current_hash();
        assert_eq!(hash.len(), TRANSCRIPT_HASH_SIZE);
        assert_ne!(hash, [0u8; TRANSCRIPT_HASH_SIZE]);
    }

    #[test]
    fn test_session_key_derivation() {
        let ss = SharedSecret::from_bytes([0x42; KYBER768_SS_SIZE]);
        let client_random = [0x01; NONCE_SIZE];
        let server_random = [0x02; NONCE_SIZE];

        let keys = SessionKeys::derive(&ss, &client_random, &server_random).unwrap();

        // Keys should be non-zero and different from each other
        assert_ne!(keys.client_write_key, [0u8; SESSION_KEY_SIZE]);
        assert_ne!(keys.server_write_key, [0u8; SESSION_KEY_SIZE]);
        assert_ne!(keys.client_write_key, keys.server_write_key);
        assert_ne!(keys.client_write_mac, keys.server_write_mac);
    }

    #[test]
    fn test_session_key_determinism() {
        let ss = SharedSecret::from_bytes([0x42; KYBER768_SS_SIZE]);
        let client_random = [0x01; NONCE_SIZE];
        let server_random = [0x02; NONCE_SIZE];

        let keys1 = SessionKeys::derive(&ss, &client_random, &server_random).unwrap();
        let keys2 = SessionKeys::derive(&ss, &client_random, &server_random).unwrap();

        assert_eq!(keys1.client_write_key, keys2.client_write_key);
        assert_eq!(keys1.server_write_key, keys2.server_write_key);
    }

    #[test]
    fn test_verify_data_derivation() {
        let ss = SharedSecret::from_bytes([0x42; KYBER768_SS_SIZE]);
        let transcript_hash = [0xAB; TRANSCRIPT_HASH_SIZE];

        let verify_data = SessionKeys::compute_verify_data(&ss, &transcript_hash).unwrap();

        // Verify data should be deterministic
        let verify_data2 = SessionKeys::compute_verify_data(&ss, &transcript_hash).unwrap();
        assert_eq!(verify_data, verify_data2);
        assert_ne!(verify_data, [0u8; VERIFY_DATA_SIZE]);
    }

    #[test]
    fn test_message_serialization() {
        let id = DeviceId::new([0x42; 32]);

        let hello = ClientHello {
            version: 1,
            client_random: [0xAA; NONCE_SIZE],
            kem_public_key: [0xBB; KYBER768_PK_SIZE],
            client_id: id,
        };

        let bytes = hello.to_bytes();
        let parsed = ClientHello::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.client_random, [0xAA; NONCE_SIZE]);
        assert_eq!(parsed.client_id.as_bytes(), id.as_bytes());
    }

    #[test]
    fn test_server_hello_serialization() {
        let id = DeviceId::new([0x42; 32]);

        let hello = ServerHello {
            version: 1,
            server_random: [0xAA; NONCE_SIZE],
            kem_ciphertext: [0xBB; KYBER768_CT_SIZE],
            server_id: id,
            signature: [0xCC; DILITHIUM3_SIG_SIZE],
        };

        let bytes = hello.to_bytes();
        let parsed = ServerHello::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.server_random, [0xAA; NONCE_SIZE]);
        assert_eq!(parsed.server_id.as_bytes(), id.as_bytes());
    }

    #[test]
    fn test_client_finished_serialization() {
        let finished = ClientFinished {
            signature: [0xAA; DILITHIUM3_SIG_SIZE],
            verify_data: [0xBB; VERIFY_DATA_SIZE],
        };

        let bytes = finished.to_bytes();
        let parsed = ClientFinished::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.signature[0], 0xAA);
        assert_eq!(parsed.verify_data, [0xBB; VERIFY_DATA_SIZE]);
    }

    #[test]
    fn test_invalid_state_transitions() {
        let id = DeviceId::new([0x01; 32]);
        let mut rng = TestRng(test_rng_fn);

        // Try to create server hello as initiator
        let mut client = Handshake::new_initiator(id, &mut rng).unwrap();
        assert!(client.create_server_hello(dummy_sign, &mut rng).is_err());
    }

    #[test]
    fn test_handshake_abort() {
        let id = DeviceId::new([0x01; 32]);
        let mut rng = TestRng(test_rng_fn);

        let mut client = Handshake::new_initiator(id, &mut rng).unwrap();
        client.abort();

        assert!(client.is_failed());
        assert!(client.session_keys().is_none());
    }
}
