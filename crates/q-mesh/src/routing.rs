// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Mesh Routing Protocol
//!
//! This module implements a distance-vector routing protocol for Q-MESH.
//! It supports:
//!
//! - **Automatic neighbor discovery**
//! - **Dynamic route computation**
//! - **Multi-hop message delivery**
//! - **Route failure detection and recovery**
//!
//! # Algorithm
//!
//! We use a simplified AODV-like (Ad hoc On-demand Distance Vector) protocol
//! optimized for low-power embedded devices:
//!
//! 1. Proactive: Periodic beacon broadcasts for neighbor discovery
//! 2. Reactive: Route discovery on-demand for destinations
//! 3. Maintenance: Route lifetime management and broken link detection

use q_common::Error;
use heapless::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum number of routing table entries
pub const MAX_ROUTES: usize = 32;

/// Maximum number of neighbors
pub const MAX_NEIGHBORS: usize = 16;

/// Maximum hops for a route
pub const MAX_HOPS: u8 = 15;

/// Route timeout in seconds
pub const ROUTE_TIMEOUT_SECS: u32 = 300; // 5 minutes

/// Neighbor timeout in seconds
pub const NEIGHBOR_TIMEOUT_SECS: u32 = 60; // 1 minute

/// Beacon interval in seconds
pub const BEACON_INTERVAL_SECS: u32 = 10;

/// Maximum pending route requests
pub const MAX_PENDING_RREQ: usize = 8;

// ============================================================================
// Node Identifier
// ============================================================================

/// 16-byte node identifier (truncated identity hash)
pub type NodeId = [u8; 16];

/// Broadcast address
pub const BROADCAST_ADDR: NodeId = [0xFF; 16];

/// Check if address is broadcast
pub fn is_broadcast(addr: &NodeId) -> bool {
    *addr == BROADCAST_ADDR
}

// ============================================================================
// Routing Messages
// ============================================================================

/// Routing message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RoutingMessageType {
    /// Beacon for neighbor discovery
    Beacon = 0x01,
    /// Route request
    RouteRequest = 0x02,
    /// Route reply
    RouteReply = 0x03,
    /// Route error (link broken)
    RouteError = 0x04,
    /// Hello (unicast neighbor check)
    Hello = 0x05,
    /// Hello acknowledgment
    HelloAck = 0x06,
}

/// Beacon message for neighbor discovery
#[derive(Debug, Clone)]
pub struct BeaconMessage {
    /// Sender node ID
    pub sender: NodeId,
    /// Sequence number
    pub sequence: u32,
    /// Number of known routes (for routing info sharing)
    pub route_count: u8,
    /// Link quality indicator (0-255)
    pub link_quality: u8,
    /// Capabilities flags
    pub capabilities: u8,
}

impl BeaconMessage {
    /// Create a new beacon
    pub fn new(sender: NodeId, sequence: u32) -> Self {
        Self {
            sender,
            sequence,
            route_count: 0,
            link_quality: 255,
            capabilities: 0,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        bytes[0] = RoutingMessageType::Beacon as u8;
        bytes[1..17].copy_from_slice(&self.sender);
        bytes[17..21].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[21] = self.route_count;
        bytes[22] = self.link_quality;
        bytes[23] = self.capabilities;
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 24 || bytes[0] != RoutingMessageType::Beacon as u8 {
            return None;
        }

        let mut sender = [0u8; 16];
        sender.copy_from_slice(&bytes[1..17]);

        Some(Self {
            sender,
            sequence: u32::from_le_bytes([bytes[17], bytes[18], bytes[19], bytes[20]]),
            route_count: bytes[21],
            link_quality: bytes[22],
            capabilities: bytes[23],
        })
    }
}

/// Route request message
#[derive(Debug, Clone)]
pub struct RouteRequestMsg {
    /// Request originator
    pub originator: NodeId,
    /// Request sequence number
    pub rreq_id: u32,
    /// Destination being sought
    pub destination: NodeId,
    /// Destination sequence number (if known)
    pub dest_seq: u32,
    /// Hop count from originator
    pub hop_count: u8,
    /// TTL (time to live)
    pub ttl: u8,
}

impl RouteRequestMsg {
    /// Create a new route request
    pub fn new(originator: NodeId, rreq_id: u32, destination: NodeId) -> Self {
        Self {
            originator,
            rreq_id,
            destination,
            dest_seq: 0,
            hop_count: 0,
            ttl: MAX_HOPS,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 44] {
        let mut bytes = [0u8; 44];
        bytes[0] = RoutingMessageType::RouteRequest as u8;
        bytes[1..17].copy_from_slice(&self.originator);
        bytes[17..21].copy_from_slice(&self.rreq_id.to_le_bytes());
        bytes[21..37].copy_from_slice(&self.destination);
        bytes[37..41].copy_from_slice(&self.dest_seq.to_le_bytes());
        bytes[41] = self.hop_count;
        bytes[42] = self.ttl;
        bytes[43] = 0; // Reserved
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 44 || bytes[0] != RoutingMessageType::RouteRequest as u8 {
            return None;
        }

        let mut originator = [0u8; 16];
        originator.copy_from_slice(&bytes[1..17]);

        let mut destination = [0u8; 16];
        destination.copy_from_slice(&bytes[21..37]);

        Some(Self {
            originator,
            rreq_id: u32::from_le_bytes([bytes[17], bytes[18], bytes[19], bytes[20]]),
            destination,
            dest_seq: u32::from_le_bytes([bytes[37], bytes[38], bytes[39], bytes[40]]),
            hop_count: bytes[41],
            ttl: bytes[42],
        })
    }
}

/// Route reply message
#[derive(Debug, Clone)]
pub struct RouteReplyMsg {
    /// Route destination
    pub destination: NodeId,
    /// Destination sequence number
    pub dest_seq: u32,
    /// Route originator (who requested)
    pub originator: NodeId,
    /// Hop count to destination
    pub hop_count: u8,
    /// Route lifetime in seconds
    pub lifetime: u16,
}

impl RouteReplyMsg {
    /// Create a new route reply
    pub fn new(destination: NodeId, originator: NodeId, hop_count: u8) -> Self {
        Self {
            destination,
            dest_seq: 0,
            originator,
            hop_count,
            lifetime: ROUTE_TIMEOUT_SECS as u16,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 42] {
        let mut bytes = [0u8; 42];
        bytes[0] = RoutingMessageType::RouteReply as u8;
        bytes[1..17].copy_from_slice(&self.destination);
        bytes[17..21].copy_from_slice(&self.dest_seq.to_le_bytes());
        bytes[21..37].copy_from_slice(&self.originator);
        bytes[37] = self.hop_count;
        bytes[38..40].copy_from_slice(&self.lifetime.to_le_bytes());
        bytes[40] = 0; // Reserved
        bytes[41] = 0; // Reserved
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 42 || bytes[0] != RoutingMessageType::RouteReply as u8 {
            return None;
        }

        let mut destination = [0u8; 16];
        destination.copy_from_slice(&bytes[1..17]);

        let mut originator = [0u8; 16];
        originator.copy_from_slice(&bytes[21..37]);

        Some(Self {
            destination,
            dest_seq: u32::from_le_bytes([bytes[17], bytes[18], bytes[19], bytes[20]]),
            originator,
            hop_count: bytes[37],
            lifetime: u16::from_le_bytes([bytes[38], bytes[39]]),
        })
    }
}

/// Route error message
#[derive(Debug, Clone)]
pub struct RouteErrorMsg {
    /// Unreachable destinations
    pub unreachable: Vec<NodeId, 4>,
    /// Destination sequence numbers
    pub dest_seqs: Vec<u32, 4>,
}

impl RouteErrorMsg {
    /// Create a new route error
    pub fn new() -> Self {
        Self {
            unreachable: Vec::new(),
            dest_seqs: Vec::new(),
        }
    }

    /// Add unreachable destination
    pub fn add_unreachable(&mut self, dest: NodeId, seq: u32) -> Result<(), Error> {
        self.unreachable.push(dest).map_err(|_| Error::BufferTooSmall)?;
        self.dest_seqs.push(seq).map_err(|_| Error::BufferTooSmall)?;
        Ok(())
    }
}

impl Default for RouteErrorMsg {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Neighbor Table
// ============================================================================

/// Neighbor entry
#[derive(Debug, Clone)]
pub struct Neighbor {
    /// Neighbor node ID
    pub node_id: NodeId,
    /// Link quality (0-255, higher is better)
    pub link_quality: u8,
    /// Last beacon sequence number
    pub last_sequence: u32,
    /// Last seen timestamp (seconds since boot)
    pub last_seen: u32,
    /// Bidirectional link confirmed
    pub bidirectional: bool,
}

impl Neighbor {
    /// Create a new neighbor entry
    pub fn new(node_id: NodeId, link_quality: u8, sequence: u32, timestamp: u32) -> Self {
        Self {
            node_id,
            link_quality,
            last_sequence: sequence,
            last_seen: timestamp,
            bidirectional: false,
        }
    }

    /// Check if neighbor has timed out
    pub fn is_expired(&self, current_time: u32) -> bool {
        current_time.saturating_sub(self.last_seen) > NEIGHBOR_TIMEOUT_SECS
    }

    /// Update neighbor with new beacon
    pub fn update(&mut self, link_quality: u8, sequence: u32, timestamp: u32) {
        self.link_quality = link_quality;
        self.last_sequence = sequence;
        self.last_seen = timestamp;
    }
}

/// Neighbor table
pub struct NeighborTable {
    /// Neighbor entries
    entries: [Option<Neighbor>; MAX_NEIGHBORS],
    /// Number of active neighbors
    count: usize,
}

impl NeighborTable {
    /// Create empty neighbor table
    pub const fn new() -> Self {
        const NONE: Option<Neighbor> = None;
        Self {
            entries: [NONE; MAX_NEIGHBORS],
            count: 0,
        }
    }

    /// Add or update neighbor
    pub fn update_neighbor(&mut self, neighbor: Neighbor) {
        // Check if neighbor exists
        for entry in &mut self.entries {
            if let Some(ref mut n) = entry {
                if n.node_id == neighbor.node_id {
                    n.update(neighbor.link_quality, neighbor.last_sequence, neighbor.last_seen);
                    return;
                }
            }
        }

        // Add new neighbor
        if self.count < MAX_NEIGHBORS {
            for entry in &mut self.entries {
                if entry.is_none() {
                    *entry = Some(neighbor);
                    self.count += 1;
                    return;
                }
            }
        }
    }

    /// Find neighbor by ID
    pub fn find(&self, node_id: &NodeId) -> Option<&Neighbor> {
        self.entries.iter()
            .filter_map(|e| e.as_ref())
            .find(|n| n.node_id == *node_id)
    }

    /// Remove expired neighbors
    pub fn cleanup(&mut self, current_time: u32) {
        for entry in &mut self.entries {
            if let Some(ref n) = entry {
                if n.is_expired(current_time) {
                    *entry = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
    }

    /// Get all active neighbors
    pub fn active_neighbors(&self) -> impl Iterator<Item = &Neighbor> {
        self.entries.iter().filter_map(|e| e.as_ref())
    }

    /// Get neighbor count
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for NeighborTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Routing Table
// ============================================================================

/// Route entry
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Destination node ID (16 bytes for internal use)
    destination_short: NodeId,
    /// Destination device ID (32-byte full ID for compatibility)
    pub destination: [u8; 32],
    /// Next hop node ID
    next_hop_short: NodeId,
    /// Next hop device ID (32-byte full ID)
    pub next_hop: [u8; 32],
    /// Hop count to destination
    pub hops: u8,
    /// Route metric
    pub metric: u16,
    /// Destination sequence number
    pub dest_seq: u32,
    /// Route lifetime (expiry timestamp)
    pub lifetime: u32,
    /// Route is valid
    pub valid: bool,
}

impl RouteEntry {
    /// Create a new route entry from short IDs
    pub fn new(destination: NodeId, next_hop: NodeId, hop_count: u8, lifetime: u32) -> Self {
        let mut dest_full = [0u8; 32];
        dest_full[..16].copy_from_slice(&destination);

        let mut next_full = [0u8; 32];
        next_full[..16].copy_from_slice(&next_hop);

        Self {
            destination_short: destination,
            destination: dest_full,
            next_hop_short: next_hop,
            next_hop: next_full,
            hops: hop_count,
            metric: hop_count as u16 * 100, // Simple metric
            dest_seq: 0,
            lifetime,
            valid: true,
        }
    }

    /// Create from full 32-byte IDs
    pub fn new_full(destination: [u8; 32], next_hop: [u8; 32], hop_count: u8, metric: u16) -> Self {
        let mut dest_short = [0u8; 16];
        dest_short.copy_from_slice(&destination[..16]);

        let mut next_short = [0u8; 16];
        next_short.copy_from_slice(&next_hop[..16]);

        Self {
            destination_short: dest_short,
            destination,
            next_hop_short: next_short,
            next_hop,
            hops: hop_count,
            metric,
            dest_seq: 0,
            lifetime: 0,
            valid: true,
        }
    }

    /// Check if route is expired
    pub fn is_expired(&self, current_time: u32) -> bool {
        self.lifetime > 0 && current_time > self.lifetime
    }

    /// Invalidate route
    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// Get short destination ID
    pub fn destination_id(&self) -> &NodeId {
        &self.destination_short
    }

    /// Get short next hop ID
    pub fn next_hop_id(&self) -> &NodeId {
        &self.next_hop_short
    }
}

/// Routing table
pub struct RoutingTable {
    /// Route entries
    entries: [Option<RouteEntry>; MAX_ROUTES],
    /// Number of active routes
    count: usize,
}

impl RoutingTable {
    /// Create empty routing table
    pub const fn new() -> Self {
        const NONE: Option<RouteEntry> = None;
        Self {
            entries: [NONE; MAX_ROUTES],
            count: 0,
        }
    }

    /// Add or update route
    pub fn update_route(&mut self, route: RouteEntry) {
        // Check if route to destination exists
        for entry in &mut self.entries {
            if let Some(ref mut r) = entry {
                if r.destination_short == route.destination_short {
                    // Update if new route is better (fewer hops or newer seq)
                    if route.hops < r.hops || route.dest_seq > r.dest_seq {
                        *r = route;
                    }
                    return;
                }
            }
        }

        // Add new route
        if self.count < MAX_ROUTES {
            for entry in &mut self.entries {
                if entry.is_none() {
                    *entry = Some(route);
                    self.count += 1;
                    return;
                }
            }
        }
    }

    /// Find route to destination
    pub fn find_route(&self, destination: &NodeId) -> Option<&RouteEntry> {
        self.entries.iter()
            .filter_map(|e| e.as_ref())
            .find(|r| r.destination_short == *destination && r.valid)
    }

    /// Find route by full destination ID
    pub fn find_route_full(&self, destination: &[u8; 32]) -> Option<&RouteEntry> {
        self.entries.iter()
            .filter_map(|e| e.as_ref())
            .find(|r| r.destination == *destination && r.valid)
    }

    /// Invalidate route
    pub fn invalidate_route(&mut self, destination: &NodeId) {
        for entry in &mut self.entries {
            if let Some(ref mut r) = entry {
                if r.destination_short == *destination {
                    r.invalidate();
                    return;
                }
            }
        }
    }

    /// Remove expired routes
    pub fn cleanup(&mut self, current_time: u32) {
        for entry in &mut self.entries {
            if let Some(ref r) = entry {
                if r.is_expired(current_time) || !r.valid {
                    *entry = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
    }

    /// Get all valid routes
    pub fn valid_routes(&self) -> impl Iterator<Item = &RouteEntry> {
        self.entries.iter()
            .filter_map(|e| e.as_ref())
            .filter(|r| r.valid)
    }

    /// Get route count
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Router
// ============================================================================

/// Mesh router
pub struct Router {
    /// Local node ID
    pub node_id: NodeId,
    /// Neighbor table
    pub neighbors: NeighborTable,
    /// Routing table
    pub routes: RoutingTable,
    /// Beacon sequence counter
    beacon_seq: AtomicU32,
    /// Route request ID counter
    rreq_seq: AtomicU32,
    /// Last beacon time
    last_beacon: u32,
    /// Pending route requests
    pending_rreq: Vec<(NodeId, u32), MAX_PENDING_RREQ>,
    /// Initialized flag
    initialized: bool,
}

impl Router {
    /// Create a new router
    pub const fn new() -> Self {
        Self {
            node_id: [0u8; 16],
            neighbors: NeighborTable::new(),
            routes: RoutingTable::new(),
            beacon_seq: AtomicU32::new(0),
            rreq_seq: AtomicU32::new(0),
            last_beacon: 0,
            pending_rreq: Vec::new(),
            initialized: false,
        }
    }

    /// Initialize router with node ID
    pub fn init(&mut self, node_id: NodeId) {
        self.node_id = node_id;
        self.initialized = true;
    }

    /// Generate beacon message
    pub fn generate_beacon(&self) -> BeaconMessage {
        let seq = self.beacon_seq.fetch_add(1, Ordering::Relaxed);
        let mut beacon = BeaconMessage::new(self.node_id, seq);
        beacon.route_count = self.routes.count() as u8;
        beacon
    }

    /// Process received beacon
    pub fn process_beacon(&mut self, beacon: &BeaconMessage, rssi: i8, current_time: u32) {
        // Convert RSSI to link quality (0-255)
        let link_quality = ((rssi + 100).max(0).min(100) as u32 * 255 / 100) as u8;

        let neighbor = Neighbor::new(
            beacon.sender,
            link_quality,
            beacon.sequence,
            current_time,
        );

        self.neighbors.update_neighbor(neighbor);

        // Add/update direct route to neighbor
        let route = RouteEntry::new(
            beacon.sender,
            beacon.sender, // Next hop is the neighbor itself
            1,
            current_time + ROUTE_TIMEOUT_SECS,
        );
        self.routes.update_route(route);
    }

    /// Initiate route discovery
    pub fn discover_route(&mut self, destination: NodeId) -> RouteRequestMsg {
        let rreq_id = self.rreq_seq.fetch_add(1, Ordering::Relaxed);

        // Track pending request
        let _ = self.pending_rreq.push((destination, rreq_id));

        RouteRequestMsg::new(self.node_id, rreq_id, destination)
    }

    /// Process received route request
    pub fn process_rreq(
        &mut self,
        rreq: &RouteRequestMsg,
        from: NodeId,
        current_time: u32,
    ) -> Option<(RouteReplyMsg, bool)> {
        // Don't process our own requests
        if rreq.originator == self.node_id {
            return None;
        }

        // Create reverse route to originator
        let reverse_route = RouteEntry::new(
            rreq.originator,
            from,
            rreq.hop_count + 1,
            current_time + ROUTE_TIMEOUT_SECS,
        );
        self.routes.update_route(reverse_route);

        // Check if we are the destination
        if rreq.destination == self.node_id {
            // Generate route reply
            let rrep = RouteReplyMsg::new(
                self.node_id,
                rreq.originator,
                0, // We are the destination
            );
            return Some((rrep, false)); // false = don't forward RREQ
        }

        // Check if we have a route to destination
        if let Some(route) = self.routes.find_route(&rreq.destination) {
            if route.valid && route.dest_seq >= rreq.dest_seq {
                // We have a valid route, generate reply
                let rrep = RouteReplyMsg::new(
                    rreq.destination,
                    rreq.originator,
                    route.hops,
                );
                return Some((rrep, false));
            }
        }

        // Forward RREQ if TTL > 0
        if rreq.ttl > 1 {
            return Some((RouteReplyMsg::new(rreq.destination, rreq.originator, 0), true));
        }

        None
    }

    /// Process received route reply
    pub fn process_rrep(
        &mut self,
        rrep: &RouteReplyMsg,
        from: NodeId,
        current_time: u32,
    ) -> bool {
        // Create forward route to destination
        let route = RouteEntry::new(
            rrep.destination,
            from,
            rrep.hop_count + 1,
            current_time + rrep.lifetime as u32,
        );
        self.routes.update_route(route);

        // Check if we are the originator
        if rrep.originator == self.node_id {
            // Remove from pending
            self.pending_rreq.retain(|(dest, _)| *dest != rrep.destination);
            return false; // Don't forward
        }

        // Forward RREP toward originator
        true
    }

    /// Get next hop for destination
    pub fn get_next_hop(&self, destination: &NodeId) -> Option<NodeId> {
        // Check if destination is a neighbor
        if self.neighbors.find(destination).is_some() {
            return Some(*destination);
        }

        // Check routing table
        self.routes.find_route(destination).map(|r| r.next_hop_short)
    }

    /// Handle link failure
    pub fn handle_link_failure(&mut self, failed_link: NodeId) -> RouteErrorMsg {
        let mut rerr = RouteErrorMsg::new();

        // Find all routes using this link
        for entry in self.routes.entries.iter_mut() {
            if let Some(ref mut route) = entry {
                if route.next_hop_short == failed_link {
                    let _ = rerr.add_unreachable(route.destination_short, route.dest_seq);
                    route.invalidate();
                }
            }
        }

        rerr
    }

    /// Periodic maintenance
    pub fn tick(&mut self, current_time: u32) {
        // Cleanup expired neighbors
        self.neighbors.cleanup(current_time);

        // Cleanup expired routes
        self.routes.cleanup(current_time);
    }

    /// Check if should send beacon
    pub fn should_beacon(&self, current_time: u32) -> bool {
        current_time.saturating_sub(self.last_beacon) >= BEACON_INTERVAL_SECS
    }

    /// Record beacon sent
    pub fn beacon_sent(&mut self, current_time: u32) {
        self.last_beacon = current_time;
    }

    /// Get neighbor count
    pub fn neighbor_count(&self) -> usize {
        self.neighbors.count()
    }

    /// Get route count
    pub fn route_count(&self) -> usize {
        self.routes.count()
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id(seed: u8) -> NodeId {
        [seed; 16]
    }

    #[test]
    fn test_beacon_serialization() {
        let beacon = BeaconMessage::new(make_node_id(1), 42);
        let bytes = beacon.to_bytes();
        let parsed = BeaconMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.sender, make_node_id(1));
        assert_eq!(parsed.sequence, 42);
    }

    #[test]
    fn test_rreq_serialization() {
        let rreq = RouteRequestMsg::new(make_node_id(1), 100, make_node_id(2));
        let bytes = rreq.to_bytes();
        let parsed = RouteRequestMsg::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.originator, make_node_id(1));
        assert_eq!(parsed.destination, make_node_id(2));
        assert_eq!(parsed.rreq_id, 100);
    }

    #[test]
    fn test_neighbor_table() {
        let mut table = NeighborTable::new();

        let n1 = Neighbor::new(make_node_id(1), 200, 1, 100);
        let n2 = Neighbor::new(make_node_id(2), 150, 1, 100);

        table.update_neighbor(n1);
        table.update_neighbor(n2);

        assert_eq!(table.count(), 2);
        assert!(table.find(&make_node_id(1)).is_some());
        assert!(table.find(&make_node_id(2)).is_some());
        assert!(table.find(&make_node_id(3)).is_none());
    }

    #[test]
    fn test_routing_table() {
        let mut table = RoutingTable::new();

        let r1 = RouteEntry::new(make_node_id(1), make_node_id(2), 2, 1000);
        let r2 = RouteEntry::new(make_node_id(3), make_node_id(4), 3, 1000);

        table.update_route(r1);
        table.update_route(r2);

        assert_eq!(table.count(), 2);

        let route = table.find_route(&make_node_id(1)).unwrap();
        assert_eq!(route.next_hop_short, make_node_id(2));
        assert_eq!(route.hops, 2);
    }

    #[test]
    fn test_router_beacon() {
        let mut router = Router::new();
        router.init(make_node_id(1));

        let beacon = router.generate_beacon();
        assert_eq!(beacon.sender, make_node_id(1));
        assert_eq!(beacon.sequence, 0);

        let beacon2 = router.generate_beacon();
        assert_eq!(beacon2.sequence, 1);
    }

    #[test]
    fn test_router_process_beacon() {
        let mut router = Router::new();
        router.init(make_node_id(1));

        let beacon = BeaconMessage::new(make_node_id(2), 1);
        router.process_beacon(&beacon, -50, 100);

        assert_eq!(router.neighbor_count(), 1);
        assert_eq!(router.route_count(), 1);

        let next_hop = router.get_next_hop(&make_node_id(2));
        assert_eq!(next_hop, Some(make_node_id(2)));
    }

    #[test]
    fn test_route_discovery() {
        let mut router = Router::new();
        router.init(make_node_id(1));

        let rreq = router.discover_route(make_node_id(5));
        assert_eq!(rreq.originator, make_node_id(1));
        assert_eq!(rreq.destination, make_node_id(5));
    }
}
