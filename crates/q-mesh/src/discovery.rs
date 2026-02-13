// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Peer discovery for Q-MESH
//!
//! Manages discovered peers and their state, including:
//! - Peer tracking with signal strength and capabilities
//! - Peer expiration and cleanup
//! - Peer capability negotiation

use heapless::Vec;
use q_common::Error;

/// Maximum number of discovered peers
const MAX_PEERS: usize = 32;

/// Peer timeout in seconds (no beacon heard)
const PEER_TIMEOUT_SECS: u64 = 120;

/// Peer capabilities bitflags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCapabilities(u16);

impl PeerCapabilities {
    /// Peer supports post-quantum key exchange
    pub const PQC_KEM: Self = Self(1 << 0);
    /// Peer supports post-quantum signatures
    pub const PQC_SIG: Self = Self(1 << 1);
    /// Peer supports mesh routing (relay)
    pub const MESH_RELAY: Self = Self(1 << 2);
    /// Peer supports group messaging
    pub const GROUP_MSG: Self = Self(1 << 3);
    /// Peer is a gateway node
    pub const GATEWAY: Self = Self(1 << 4);
    /// Peer supports firmware updates relay
    pub const UPDATE_RELAY: Self = Self(1 << 5);

    /// Create empty capabilities
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if capability is set
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Add a capability
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Get raw value
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Create from raw value
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }
}

/// Peer state in the discovery lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Peer discovered via beacon but not yet authenticated
    Discovered,
    /// Handshake in progress
    Authenticating,
    /// Peer authenticated and session established
    Authenticated,
    /// Peer unreachable (missed beacons)
    Unreachable,
}

/// Discovered peer information
#[derive(Clone)]
pub struct Peer {
    /// Peer device ID (full 32-byte identity)
    pub device_id: [u8; 32],
    /// Short ID for routing (first 16 bytes)
    pub short_id: [u8; 16],
    /// Last seen timestamp (seconds since boot)
    pub last_seen: u64,
    /// Signal strength (RSSI in dBm)
    pub rssi: i8,
    /// Signal-to-noise ratio
    pub snr: i8,
    /// Link quality metric (0-255)
    pub link_quality: u8,
    /// Current peer state
    pub state: PeerState,
    /// Peer capabilities
    pub capabilities: PeerCapabilities,
    /// Number of beacons received from this peer
    pub beacon_count: u32,
    /// Number of failed transmissions to this peer
    pub tx_failures: u16,
    /// Number of successful transmissions
    pub tx_successes: u16,
}

impl Peer {
    /// Create a new discovered peer
    pub fn new(device_id: [u8; 32], rssi: i8, now: u64) -> Self {
        let mut short_id = [0u8; 16];
        short_id.copy_from_slice(&device_id[..16]);

        Self {
            device_id,
            short_id,
            last_seen: now,
            rssi,
            snr: 0,
            link_quality: Self::rssi_to_quality(rssi),
            state: PeerState::Discovered,
            capabilities: PeerCapabilities::empty(),
            beacon_count: 1,
            tx_failures: 0,
            tx_successes: 0,
        }
    }

    /// Check if peer has expired
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.last_seen) > PEER_TIMEOUT_SECS
    }

    /// Update peer information from a new beacon
    pub fn update(&mut self, rssi: i8, snr: i8, capabilities: PeerCapabilities, now: u64) {
        self.last_seen = now;
        self.rssi = rssi;
        self.snr = snr;
        self.capabilities = capabilities;
        self.beacon_count = self.beacon_count.saturating_add(1);

        // Exponential moving average for link quality
        let new_quality = Self::rssi_to_quality(rssi);
        self.link_quality = ((self.link_quality as u16 * 7 + new_quality as u16) / 8) as u8;

        // Transition back to discovered if was unreachable
        if self.state == PeerState::Unreachable {
            self.state = PeerState::Discovered;
        }
    }

    /// Record a transmission result
    pub fn record_tx(&mut self, success: bool) {
        if success {
            self.tx_successes = self.tx_successes.saturating_add(1);
        } else {
            self.tx_failures = self.tx_failures.saturating_add(1);
        }
    }

    /// Get transmission success rate (0-100)
    pub fn tx_success_rate(&self) -> u8 {
        let total = self.tx_successes as u32 + self.tx_failures as u32;
        if total == 0 {
            return 100;
        }
        ((self.tx_successes as u32 * 100) / total) as u8
    }

    /// Convert RSSI to link quality (0-255)
    fn rssi_to_quality(rssi: i8) -> u8 {
        // Map -120 dBm (worst) to 0, -30 dBm (best) to 255
        let clamped = (rssi as i16).clamp(-120, -30);
        ((clamped + 120) * 255 / 90) as u8
    }
}

/// Peer discovery table
pub struct PeerDiscovery {
    /// Known peers
    peers: Vec<Peer, MAX_PEERS>,
    /// Local device ID
    local_id: [u8; 32],
    /// Discovery enabled flag
    enabled: bool,
}

impl PeerDiscovery {
    /// Create a new peer discovery instance
    pub fn new(local_id: [u8; 32]) -> Self {
        Self {
            peers: Vec::new(),
            local_id,
            enabled: true,
        }
    }

    /// Process a discovered peer (from beacon or direct contact)
    pub fn peer_discovered(
        &mut self,
        device_id: [u8; 32],
        rssi: i8,
        snr: i8,
        capabilities: PeerCapabilities,
        now: u64,
    ) -> Result<&Peer, Error> {
        // Don't add ourselves
        if device_id == self.local_id {
            return Err(Error::InvalidParameter);
        }

        // Check if peer already known
        if let Some(idx) = self.find_peer_idx(&device_id) {
            self.peers[idx].update(rssi, snr, capabilities, now);
            return Ok(&self.peers[idx]);
        }

        // Add new peer
        let peer = Peer::new(device_id, rssi, now);
        self.peers.push(peer).map_err(|_| Error::BufferTooSmall)?;
        let idx = self.peers.len() - 1;
        // Update with full info
        self.peers[idx].snr = snr;
        self.peers[idx].capabilities = capabilities;
        Ok(&self.peers[idx])
    }

    /// Mark a peer as authenticated
    pub fn peer_authenticated(&mut self, device_id: &[u8; 32]) -> Result<(), Error> {
        let idx = self
            .find_peer_idx(device_id)
            .ok_or(Error::InvalidParameter)?;
        self.peers[idx].state = PeerState::Authenticated;
        Ok(())
    }

    /// Find a peer by device ID
    pub fn find_peer(&self, device_id: &[u8; 32]) -> Option<&Peer> {
        self.peers.iter().find(|p| &p.device_id == device_id)
    }

    /// Find a peer by short ID
    pub fn find_peer_by_short_id(&self, short_id: &[u8; 16]) -> Option<&Peer> {
        self.peers.iter().find(|p| &p.short_id == short_id)
    }

    /// Get all authenticated peers
    pub fn authenticated_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers
            .iter()
            .filter(|p| p.state == PeerState::Authenticated)
    }

    /// Get all active (non-expired) peers
    pub fn active_peers(&self, now: u64) -> impl Iterator<Item = &Peer> {
        self.peers.iter().filter(move |p| !p.is_expired(now))
    }

    /// Get the number of known peers
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Cleanup expired peers
    pub fn cleanup(&mut self, now: u64) {
        // Mark expired peers
        for peer in self.peers.iter_mut() {
            if peer.is_expired(now) && peer.state != PeerState::Unreachable {
                peer.state = PeerState::Unreachable;
            }
        }

        // Remove long-expired peers (2x timeout)
        self.peers
            .retain(|p| now.saturating_sub(p.last_seen) <= PEER_TIMEOUT_SECS * 2);
    }

    /// Get the best peer by link quality
    pub fn best_peer(&self, now: u64) -> Option<&Peer> {
        self.peers
            .iter()
            .filter(|p| !p.is_expired(now) && p.state == PeerState::Authenticated)
            .max_by_key(|p| p.link_quality)
    }

    /// Enable/disable discovery
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if discovery is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Find peer index by device ID
    fn find_peer_idx(&self, device_id: &[u8; 32]) -> Option<usize> {
        self.peers.iter().position(|p| &p.device_id == device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id(val: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = val;
        id
    }

    #[test]
    fn test_peer_creation() {
        let peer = Peer::new(test_id(1), -60, 100);
        assert_eq!(peer.device_id[0], 1);
        assert_eq!(peer.rssi, -60);
        assert_eq!(peer.state, PeerState::Discovered);
        assert!(!peer.is_expired(100));
        assert!(peer.is_expired(300));
    }

    #[test]
    fn test_peer_update() {
        let mut peer = Peer::new(test_id(1), -80, 100);
        peer.update(-60, 10, PeerCapabilities::PQC_KEM, 200);
        assert_eq!(peer.last_seen, 200);
        assert_eq!(peer.rssi, -60);
        assert_eq!(peer.beacon_count, 2);
        assert!(peer.capabilities.contains(PeerCapabilities::PQC_KEM));
    }

    #[test]
    fn test_tx_success_rate() {
        let mut peer = Peer::new(test_id(1), -60, 0);
        assert_eq!(peer.tx_success_rate(), 100); // No transmissions

        peer.record_tx(true);
        peer.record_tx(true);
        peer.record_tx(false);
        assert_eq!(peer.tx_success_rate(), 66);
    }

    #[test]
    fn test_peer_discovery() {
        let mut disc = PeerDiscovery::new(test_id(0));

        disc.peer_discovered(test_id(1), -60, 10, PeerCapabilities::empty(), 100)
            .unwrap();
        disc.peer_discovered(test_id(2), -70, 8, PeerCapabilities::PQC_KEM, 100)
            .unwrap();

        assert_eq!(disc.peer_count(), 2);
        assert!(disc.find_peer(&test_id(1)).is_some());
        assert!(disc.find_peer(&test_id(3)).is_none());
    }

    #[test]
    fn test_self_discovery_rejected() {
        let mut disc = PeerDiscovery::new(test_id(0));
        let result =
            disc.peer_discovered(test_id(0), -60, 10, PeerCapabilities::empty(), 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_peer_cleanup() {
        let mut disc = PeerDiscovery::new(test_id(0));
        disc.peer_discovered(test_id(1), -60, 10, PeerCapabilities::empty(), 100)
            .unwrap();

        // Not expired yet
        disc.cleanup(200);
        assert_eq!(disc.peer_count(), 1);

        // Expired (2x timeout)
        disc.cleanup(100 + PEER_TIMEOUT_SECS * 2 + 1);
        assert_eq!(disc.peer_count(), 0);
    }

    #[test]
    fn test_peer_capabilities() {
        let caps = PeerCapabilities::PQC_KEM
            .with(PeerCapabilities::PQC_SIG)
            .with(PeerCapabilities::MESH_RELAY);

        assert!(caps.contains(PeerCapabilities::PQC_KEM));
        assert!(caps.contains(PeerCapabilities::PQC_SIG));
        assert!(caps.contains(PeerCapabilities::MESH_RELAY));
        assert!(!caps.contains(PeerCapabilities::GATEWAY));
    }

    #[test]
    fn test_peer_authentication() {
        let mut disc = PeerDiscovery::new(test_id(0));
        disc.peer_discovered(test_id(1), -60, 10, PeerCapabilities::empty(), 100)
            .unwrap();

        disc.peer_authenticated(&test_id(1)).unwrap();
        let peer = disc.find_peer(&test_id(1)).unwrap();
        assert_eq!(peer.state, PeerState::Authenticated);
    }

    #[test]
    fn test_rssi_to_quality() {
        // Best signal
        let q_best = Peer::rssi_to_quality(-30);
        assert_eq!(q_best, 255);

        // Worst signal
        let q_worst = Peer::rssi_to_quality(-120);
        assert_eq!(q_worst, 0);
    }
}
