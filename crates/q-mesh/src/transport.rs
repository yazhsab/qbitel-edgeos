// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Transport layer for Q-MESH
//!
//! Provides frame-level abstraction over the radio layer, handling:
//! - Frame serialization and deserialization
//! - Frame type multiplexing (routing, data, control)
//! - MTU management and fragmentation
//! - Frame buffering for send/receive queues

use heapless::Vec;
use q_common::Error;

/// Maximum transmission unit for mesh frames (bytes)
pub const MESH_MTU: usize = 255;

/// Maximum payload size after header overhead
pub const MAX_PAYLOAD_SIZE: usize = 4096;

/// Maximum number of frames in the send queue
const TX_QUEUE_SIZE: usize = 8;

/// Maximum number of frames in the receive queue
const RX_QUEUE_SIZE: usize = 8;

/// Maximum number of fragments per message
const MAX_FRAGMENTS: usize = 32;

/// Frame type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Routing protocol messages (beacons, RREQ, RREP, RERR)
    Routing = 0x01,
    /// Encrypted application data
    Data = 0x02,
    /// Handshake messages for key establishment
    Handshake = 0x03,
    /// Control messages (ack, ping, status)
    Control = 0x04,
    /// Fragmented data frame
    Fragment = 0x05,
}

impl FrameType {
    /// Convert from raw byte
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Routing),
            0x02 => Some(Self::Data),
            0x03 => Some(Self::Handshake),
            0x04 => Some(Self::Control),
            0x05 => Some(Self::Fragment),
            _ => None,
        }
    }
}

/// Frame priority for queue ordering
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Priority {
    /// Low priority (background data)
    Low = 0,
    /// Normal priority (regular messages)
    Normal = 1,
    /// High priority (routing, handshake)
    High = 2,
    /// Critical priority (emergency, control)
    Critical = 3,
}

/// Wire frame header (18 bytes)
///
/// Layout:
/// ```text
/// [0]      Frame type (1 byte)
/// [1]      Flags (1 byte)
/// [2..18]  Source short ID (16 bytes)
/// [18..34] Destination short ID (16 bytes)
/// [34..38] Sequence number (4 bytes, big-endian)
/// [38..40] Payload length (2 bytes, big-endian)
/// ```
pub const FRAME_HEADER_SIZE: usize = 40;

/// Message frame for mesh transport
#[derive(Clone)]
pub struct Frame {
    /// Source device ID
    pub source: [u8; 32],
    /// Destination device ID
    pub destination: [u8; 32],
    /// Frame type
    pub frame_type: FrameType,
    /// Sequence number
    pub sequence: u32,
    /// Frame priority
    pub priority: Priority,
    /// Payload data
    pub payload: Vec<u8, MAX_PAYLOAD_SIZE>,
    /// Time-to-live (hop limit)
    pub ttl: u8,
    /// Whether this frame requires acknowledgement
    pub requires_ack: bool,
}

impl Frame {
    /// Create a new data frame
    pub fn new_data(
        source: [u8; 32],
        destination: [u8; 32],
        sequence: u32,
        payload: &[u8],
    ) -> Result<Self, Error> {
        let mut payload_vec = Vec::new();
        payload_vec
            .extend_from_slice(payload)
            .map_err(|_| Error::BufferTooSmall)?;

        Ok(Self {
            source,
            destination,
            frame_type: FrameType::Data,
            sequence,
            priority: Priority::Normal,
            payload: payload_vec,
            ttl: 15,
            requires_ack: true,
        })
    }

    /// Create a new routing frame
    pub fn new_routing(
        source: [u8; 32],
        destination: [u8; 32],
        sequence: u32,
        payload: &[u8],
    ) -> Result<Self, Error> {
        let mut payload_vec = Vec::new();
        payload_vec
            .extend_from_slice(payload)
            .map_err(|_| Error::BufferTooSmall)?;

        Ok(Self {
            source,
            destination,
            frame_type: FrameType::Routing,
            sequence,
            priority: Priority::High,
            payload: payload_vec,
            ttl: 15,
            requires_ack: false,
        })
    }

    /// Create a new control frame
    pub fn new_control(
        source: [u8; 32],
        destination: [u8; 32],
        sequence: u32,
        payload: &[u8],
    ) -> Result<Self, Error> {
        let mut payload_vec = Vec::new();
        payload_vec
            .extend_from_slice(payload)
            .map_err(|_| Error::BufferTooSmall)?;

        Ok(Self {
            source,
            destination,
            frame_type: FrameType::Control,
            sequence,
            priority: Priority::Critical,
            payload: payload_vec,
            ttl: 1,
            requires_ack: false,
        })
    }

    /// Serialize frame to bytes for transmission
    pub fn to_bytes(&self) -> Result<Vec<u8, { FRAME_HEADER_SIZE + MAX_PAYLOAD_SIZE }>, Error> {
        let mut buf = Vec::new();

        // Frame type
        buf.push(self.frame_type as u8)
            .map_err(|_| Error::BufferTooSmall)?;

        // Flags: [7] requires_ack, [6:4] priority, [3:0] reserved
        let flags = if self.requires_ack { 0x80 } else { 0x00 }
            | ((self.priority as u8) << 4)
            | (self.ttl & 0x0F);
        buf.push(flags).map_err(|_| Error::BufferTooSmall)?;

        // Source short ID (first 16 bytes of device ID)
        buf.extend_from_slice(&self.source[..16])
            .map_err(|_| Error::BufferTooSmall)?;

        // Destination short ID (first 16 bytes)
        buf.extend_from_slice(&self.destination[..16])
            .map_err(|_| Error::BufferTooSmall)?;

        // Sequence number (big-endian)
        buf.extend_from_slice(&self.sequence.to_be_bytes())
            .map_err(|_| Error::BufferTooSmall)?;

        // Payload length (big-endian)
        let payload_len = self.payload.len() as u16;
        buf.extend_from_slice(&payload_len.to_be_bytes())
            .map_err(|_| Error::BufferTooSmall)?;

        // Payload
        buf.extend_from_slice(&self.payload)
            .map_err(|_| Error::BufferTooSmall)?;

        Ok(buf)
    }

    /// Deserialize frame from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(Error::InvalidParameter);
        }

        let frame_type = FrameType::from_byte(data[0]).ok_or(Error::InvalidParameter)?;

        let flags = data[1];
        let requires_ack = (flags & 0x80) != 0;
        let priority = match (flags >> 4) & 0x07 {
            0 => Priority::Low,
            1 => Priority::Normal,
            2 => Priority::High,
            _ => Priority::Critical,
        };
        let ttl = flags & 0x0F;

        let mut source = [0u8; 32];
        source[..16].copy_from_slice(&data[2..18]);

        let mut destination = [0u8; 32];
        destination[..16].copy_from_slice(&data[18..34]);

        let sequence = u32::from_be_bytes([data[34], data[35], data[36], data[37]]);
        let payload_len = u16::from_be_bytes([data[38], data[39]]) as usize;

        if data.len() < FRAME_HEADER_SIZE + payload_len {
            return Err(Error::InvalidParameter);
        }

        let mut payload = Vec::new();
        payload
            .extend_from_slice(&data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len])
            .map_err(|_| Error::BufferTooSmall)?;

        Ok(Self {
            source,
            destination,
            frame_type,
            sequence,
            priority,
            payload,
            ttl,
            requires_ack,
        })
    }
}

/// Fragment header for large message fragmentation
#[derive(Debug, Clone)]
pub struct FragmentHeader {
    /// Original message ID
    pub message_id: u32,
    /// Fragment index (0-based)
    pub fragment_index: u8,
    /// Total number of fragments
    pub total_fragments: u8,
    /// Fragment payload offset in original message
    pub offset: u16,
}

impl FragmentHeader {
    /// Header size in bytes
    pub const SIZE: usize = 8;

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.message_id.to_be_bytes());
        buf[4] = self.fragment_index;
        buf[5] = self.total_fragments;
        buf[6..8].copy_from_slice(&self.offset.to_be_bytes());
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::InvalidParameter);
        }
        Ok(Self {
            message_id: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            fragment_index: data[4],
            total_fragments: data[5],
            offset: u16::from_be_bytes([data[6], data[7]]),
        })
    }
}

/// Reassembly buffer for fragmented messages
pub struct ReassemblyBuffer {
    /// Expected message ID
    message_id: u32,
    /// Total fragments expected
    total_fragments: u8,
    /// Received fragment bitmap
    received: u32,
    /// Reassembled payload
    payload: Vec<u8, MAX_PAYLOAD_SIZE>,
    /// Timestamp of first fragment (for timeout)
    started_at: u64,
}

impl ReassemblyBuffer {
    /// Create a new reassembly buffer
    pub fn new(message_id: u32, total_fragments: u8, now: u64) -> Self {
        Self {
            message_id,
            total_fragments,
            received: 0,
            payload: Vec::new(),
            started_at: now,
        }
    }

    /// Add a fragment to the reassembly buffer
    pub fn add_fragment(
        &mut self,
        header: &FragmentHeader,
        data: &[u8],
    ) -> Result<bool, Error> {
        if header.message_id != self.message_id {
            return Err(Error::InvalidParameter);
        }
        if header.fragment_index >= self.total_fragments {
            return Err(Error::InvalidParameter);
        }

        let bit = 1u32 << header.fragment_index;
        if self.received & bit != 0 {
            // Duplicate fragment, ignore
            return Ok(false);
        }

        // Mark as received
        self.received |= bit;

        // Copy fragment data at the correct offset
        let offset = header.offset as usize;
        while self.payload.len() < offset + data.len() {
            self.payload.push(0).map_err(|_| Error::BufferTooSmall)?;
        }
        self.payload[offset..offset + data.len()].copy_from_slice(data);

        Ok(self.is_complete())
    }

    /// Check if all fragments have been received
    pub fn is_complete(&self) -> bool {
        let mask = (1u32 << self.total_fragments) - 1;
        self.received & mask == mask
    }

    /// Check if the reassembly has timed out
    pub fn is_expired(&self, now: u64, timeout_secs: u64) -> bool {
        now.saturating_sub(self.started_at) > timeout_secs
    }

    /// Get the reassembled payload (only valid if complete)
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Transport layer managing frame send/receive queues
pub struct Transport {
    /// Transmit queue
    tx_queue: Vec<Frame, TX_QUEUE_SIZE>,
    /// Receive queue
    rx_queue: Vec<Frame, RX_QUEUE_SIZE>,
    /// Sequence counter
    next_sequence: u32,
    /// Local device ID
    local_id: [u8; 32],
    /// Reassembly buffers for incoming fragmented messages
    reassembly: Vec<ReassemblyBuffer, 4>,
    /// Current timestamp (updated by caller via tick())
    current_time: u64,
}

impl Transport {
    /// Create a new transport layer
    pub fn new(local_id: [u8; 32]) -> Self {
        Self {
            tx_queue: Vec::new(),
            rx_queue: Vec::new(),
            next_sequence: 0,
            local_id,
            reassembly: Vec::new(),
            current_time: 0,
        }
    }

    /// Update the current time (call periodically, e.g., once per second)
    pub fn tick(&mut self, now: u64) {
        self.current_time = now;
    }

    /// Get current timestamp
    pub fn current_time(&self) -> u64 {
        self.current_time
    }

    /// Queue a frame for transmission
    pub fn send(&mut self, frame: Frame) -> Result<(), Error> {
        self.tx_queue
            .push(frame)
            .map_err(|_| Error::BufferTooSmall)
    }

    /// Send data to a destination, handling fragmentation if needed
    pub fn send_data(
        &mut self,
        destination: [u8; 32],
        data: &[u8],
    ) -> Result<(), Error> {
        let max_fragment_payload = MESH_MTU - FRAME_HEADER_SIZE - FragmentHeader::SIZE;

        if data.len() <= MESH_MTU - FRAME_HEADER_SIZE {
            // Single frame
            let frame = Frame::new_data(self.local_id, destination, self.next_seq(), data)?;
            self.send(frame)
        } else {
            // Fragment the message
            let total_fragments = (data.len() + max_fragment_payload - 1) / max_fragment_payload;
            if total_fragments > MAX_FRAGMENTS {
                return Err(Error::BufferTooSmall);
            }

            let message_id = self.next_seq();
            for i in 0..total_fragments {
                let offset = i * max_fragment_payload;
                let end = core::cmp::min(offset + max_fragment_payload, data.len());
                let chunk = &data[offset..end];

                let frag_header = FragmentHeader {
                    message_id,
                    fragment_index: i as u8,
                    total_fragments: total_fragments as u8,
                    offset: offset as u16,
                };

                let mut payload_buf: Vec<u8, MAX_PAYLOAD_SIZE> = Vec::new();
                payload_buf
                    .extend_from_slice(&frag_header.to_bytes())
                    .map_err(|_| Error::BufferTooSmall)?;
                payload_buf
                    .extend_from_slice(chunk)
                    .map_err(|_| Error::BufferTooSmall)?;

                let mut frame =
                    Frame::new_data(self.local_id, destination, self.next_seq(), &payload_buf)?;
                frame.frame_type = FrameType::Fragment;
                self.send(frame)?;
            }

            Ok(())
        }
    }

    /// Dequeue the next frame to transmit (highest priority first)
    pub fn next_tx_frame(&mut self) -> Option<Frame> {
        if self.tx_queue.is_empty() {
            return None;
        }

        // Find highest priority frame
        let mut best_idx = 0;
        for i in 1..self.tx_queue.len() {
            if self.tx_queue[i].priority > self.tx_queue[best_idx].priority {
                best_idx = i;
            }
        }

        Some(self.tx_queue.swap_remove(best_idx))
    }

    /// Process a received raw frame
    pub fn receive(&mut self, frame: Frame) -> Result<Option<Frame>, Error> {
        match frame.frame_type {
            FrameType::Fragment => self.handle_fragment(frame),
            _ => {
                self.rx_queue
                    .push(frame)
                    .map_err(|_| Error::BufferTooSmall)?;
                Ok(self.rx_queue.last().cloned())
            }
        }
    }

    /// Get the next received frame from the queue
    pub fn next_rx_frame(&mut self) -> Option<Frame> {
        if self.rx_queue.is_empty() {
            None
        } else {
            Some(self.rx_queue.swap_remove(0))
        }
    }

    /// Check if there are frames pending transmission
    pub fn has_pending_tx(&self) -> bool {
        !self.tx_queue.is_empty()
    }

    /// Check if there are received frames waiting
    pub fn has_pending_rx(&self) -> bool {
        !self.rx_queue.is_empty()
    }

    /// Cleanup expired reassembly buffers
    pub fn cleanup(&mut self, now: u64) {
        let timeout = 30u64; // 30 second reassembly timeout
        self.reassembly.retain(|buf| !buf.is_expired(now, timeout));
    }

    /// Get next sequence number
    fn next_seq(&mut self) -> u32 {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        seq
    }

    /// Handle a fragmented frame
    fn handle_fragment(&mut self, frame: Frame) -> Result<Option<Frame>, Error> {
        if frame.payload.len() < FragmentHeader::SIZE {
            return Err(Error::InvalidParameter);
        }

        let frag_header = FragmentHeader::from_bytes(&frame.payload)?;
        let frag_data = &frame.payload[FragmentHeader::SIZE..];

        // Find or create reassembly buffer
        let buf_idx = self
            .reassembly
            .iter()
            .position(|b| b.message_id == frag_header.message_id);

        let idx = match buf_idx {
            Some(i) => i,
            None => {
                let buf = ReassemblyBuffer::new(
                    frag_header.message_id,
                    frag_header.total_fragments,
                    self.current_time,
                );
                self.reassembly
                    .push(buf)
                    .map_err(|_| Error::BufferTooSmall)?;
                self.reassembly.len() - 1
            }
        };

        let complete = self.reassembly[idx].add_fragment(&frag_header, frag_data)?;

        if complete {
            let buf = self.reassembly.swap_remove(idx);
            let reassembled = Frame::new_data(
                frame.source,
                frame.destination,
                frag_header.message_id,
                buf.payload(),
            )?;
            self.rx_queue
                .push(reassembled.clone())
                .map_err(|_| Error::BufferTooSmall)?;
            Ok(Some(reassembled))
        } else {
            Ok(None)
        }
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
    fn test_frame_roundtrip() {
        let payload = b"hello mesh";
        let frame = Frame::new_data(test_id(1), test_id(2), 42, payload).unwrap();
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.source[0], 1);
        assert_eq!(decoded.destination[0], 2);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.payload.as_slice(), payload);
        assert_eq!(decoded.frame_type, FrameType::Data);
    }

    #[test]
    fn test_frame_types() {
        assert_eq!(FrameType::from_byte(0x01), Some(FrameType::Routing));
        assert_eq!(FrameType::from_byte(0x02), Some(FrameType::Data));
        assert_eq!(FrameType::from_byte(0xFF), None);
    }

    #[test]
    fn test_fragment_header_roundtrip() {
        let header = FragmentHeader {
            message_id: 12345,
            fragment_index: 2,
            total_fragments: 5,
            offset: 512,
        };
        let bytes = header.to_bytes();
        let decoded = FragmentHeader::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.message_id, 12345);
        assert_eq!(decoded.fragment_index, 2);
        assert_eq!(decoded.total_fragments, 5);
        assert_eq!(decoded.offset, 512);
    }

    #[test]
    fn test_reassembly_buffer() {
        let mut buf = ReassemblyBuffer::new(100, 3, 0);
        assert!(!buf.is_complete());

        let h0 = FragmentHeader {
            message_id: 100,
            fragment_index: 0,
            total_fragments: 3,
            offset: 0,
        };
        let h1 = FragmentHeader {
            message_id: 100,
            fragment_index: 1,
            total_fragments: 3,
            offset: 4,
        };
        let h2 = FragmentHeader {
            message_id: 100,
            fragment_index: 2,
            total_fragments: 3,
            offset: 8,
        };

        assert!(!buf.add_fragment(&h0, b"aaaa").unwrap());
        assert!(!buf.add_fragment(&h1, b"bbbb").unwrap());
        assert!(buf.add_fragment(&h2, b"cccc").unwrap());
        assert!(buf.is_complete());
        assert_eq!(&buf.payload()[0..4], b"aaaa");
        assert_eq!(&buf.payload()[4..8], b"bbbb");
        assert_eq!(&buf.payload()[8..12], b"cccc");
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
}
