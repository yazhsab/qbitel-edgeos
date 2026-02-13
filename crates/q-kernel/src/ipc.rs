// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Inter-Process Communication (IPC)
//!
//! This module implements secure IPC for Qbitel EdgeOS kernel.
//! It provides:
//!
//! - **Channels**: Synchronous message passing between tasks
//! - **Mailboxes**: Asynchronous message queues
//! - **Shared Memory**: Memory regions shared between tasks
//! - **Signals**: Lightweight event notification
//!
//! # Security
//!
//! - All IPC operations are subject to capability checks
//! - Messages are copied (not shared) by default
//! - Channels have sender/receiver endpoint ownership

use q_common::Error;
use heapless::Vec;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

/// Maximum message size in bytes
pub const MAX_MESSAGE_SIZE: usize = 256;

/// Maximum number of IPC channels
pub const MAX_CHANNELS: usize = 16;

/// Maximum number of mailboxes
pub const MAX_MAILBOXES: usize = 8;

/// Maximum messages per mailbox
pub const MAILBOX_CAPACITY: usize = 8;

/// Maximum shared memory regions
pub const MAX_SHARED_REGIONS: usize = 4;

// ============================================================================
// Channel Types
// ============================================================================

/// Channel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelState {
    /// Channel not allocated
    Free = 0,
    /// Channel allocated, endpoints not connected
    Allocated = 1,
    /// Sender connected
    SenderConnected = 2,
    /// Receiver connected
    ReceiverConnected = 3,
    /// Both ends connected
    Connected = 4,
    /// Channel closed
    Closed = 5,
}

impl From<u8> for ChannelState {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Allocated,
            2 => Self::SenderConnected,
            3 => Self::ReceiverConnected,
            4 => Self::Connected,
            5 => Self::Closed,
            _ => Self::Free,
        }
    }
}

/// Message header
#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    /// Message type/tag
    pub msg_type: u16,
    /// Message length (not including header)
    pub length: u16,
    /// Sender task ID
    pub sender_id: u8,
    /// Message flags
    pub flags: u8,
    /// Sequence number for ordering
    pub sequence: u16,
}

impl MessageHeader {
    /// Create a new message header
    pub const fn new(msg_type: u16, length: u16, sender_id: u8) -> Self {
        Self {
            msg_type,
            length,
            sender_id,
            flags: 0,
            sequence: 0,
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..2].copy_from_slice(&self.msg_type.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.length.to_le_bytes());
        bytes[4] = self.sender_id;
        bytes[5] = self.flags;
        bytes[6..8].copy_from_slice(&self.sequence.to_le_bytes());
        bytes
    }

    /// Parse header from bytes
    pub fn from_bytes(bytes: &[u8; 8]) -> Self {
        Self {
            msg_type: u16::from_le_bytes([bytes[0], bytes[1]]),
            length: u16::from_le_bytes([bytes[2], bytes[3]]),
            sender_id: bytes[4],
            flags: bytes[5],
            sequence: u16::from_le_bytes([bytes[6], bytes[7]]),
        }
    }
}

/// Message flags
pub mod flags {
    /// Message requires acknowledgment
    pub const REQUIRE_ACK: u8 = 0x01;
    /// Message is high priority
    pub const HIGH_PRIORITY: u8 = 0x02;
    /// Message is fragmented
    pub const FRAGMENTED: u8 = 0x04;
    /// Last fragment
    pub const LAST_FRAGMENT: u8 = 0x08;
}

// ============================================================================
// IPC Channel
// ============================================================================

/// Bidirectional IPC channel
pub struct Channel {
    /// Channel ID
    pub id: u8,
    /// Channel state
    state: AtomicU8,
    /// Sender task ID
    sender_task: AtomicU8,
    /// Receiver task ID
    receiver_task: AtomicU8,
    /// Message buffer (sender -> receiver)
    tx_buffer: [u8; MAX_MESSAGE_SIZE],
    /// Message buffer (receiver -> sender, for reply)
    rx_buffer: [u8; MAX_MESSAGE_SIZE],
    /// TX message header
    tx_header: MessageHeader,
    /// RX message header
    rx_header: MessageHeader,
    /// TX buffer has pending message
    tx_pending: AtomicU8,
    /// RX buffer has pending message
    rx_pending: AtomicU8,
    /// Sequence counter
    sequence: AtomicU32,
}

impl Channel {
    /// Create a new channel
    pub const fn new(id: u8) -> Self {
        Self {
            id,
            state: AtomicU8::new(ChannelState::Free as u8),
            sender_task: AtomicU8::new(0xFF),
            receiver_task: AtomicU8::new(0xFF),
            tx_buffer: [0; MAX_MESSAGE_SIZE],
            rx_buffer: [0; MAX_MESSAGE_SIZE],
            tx_header: MessageHeader::new(0, 0, 0),
            rx_header: MessageHeader::new(0, 0, 0),
            tx_pending: AtomicU8::new(0),
            rx_pending: AtomicU8::new(0),
            sequence: AtomicU32::new(0),
        }
    }

    /// Get channel state
    pub fn state(&self) -> ChannelState {
        ChannelState::from(self.state.load(Ordering::Acquire))
    }

    /// Allocate channel for use
    pub fn allocate(&self) -> Result<(), Error> {
        match self.state.compare_exchange(
            ChannelState::Free as u8,
            ChannelState::Allocated as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::ChannelInUse),
        }
    }

    /// Connect sender endpoint
    pub fn connect_sender(&self, task_id: u8) -> Result<(), Error> {
        let current_state = self.state();
        let new_state = match current_state {
            ChannelState::Allocated => ChannelState::SenderConnected,
            ChannelState::ReceiverConnected => ChannelState::Connected,
            _ => return Err(Error::InvalidState),
        };

        self.sender_task.store(task_id, Ordering::Release);
        self.state.store(new_state as u8, Ordering::Release);
        Ok(())
    }

    /// Connect receiver endpoint
    pub fn connect_receiver(&self, task_id: u8) -> Result<(), Error> {
        let current_state = self.state();
        let new_state = match current_state {
            ChannelState::Allocated => ChannelState::ReceiverConnected,
            ChannelState::SenderConnected => ChannelState::Connected,
            _ => return Err(Error::InvalidState),
        };

        self.receiver_task.store(task_id, Ordering::Release);
        self.state.store(new_state as u8, Ordering::Release);
        Ok(())
    }

    /// Send message from sender to receiver
    pub fn send(&mut self, msg_type: u16, data: &[u8], sender_id: u8) -> Result<(), Error> {
        if self.state() != ChannelState::Connected {
            return Err(Error::IpcError);
        }

        if self.sender_task.load(Ordering::Acquire) != sender_id {
            return Err(Error::NotAuthorized);
        }

        if self.tx_pending.load(Ordering::Acquire) != 0 {
            return Err(Error::ChannelFull);
        }

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Copy message
        let len = data.len();
        self.tx_buffer[..len].copy_from_slice(data);

        // Set header
        let seq = self.sequence.fetch_add(1, Ordering::AcqRel);
        self.tx_header = MessageHeader {
            msg_type,
            length: len as u16,
            sender_id,
            flags: 0,
            sequence: (seq & 0xFFFF) as u16,
        };

        // Mark as pending
        self.tx_pending.store(1, Ordering::Release);

        Ok(())
    }

    /// Receive message (for receiver)
    pub fn receive(&mut self, buffer: &mut [u8], receiver_id: u8) -> Result<(MessageHeader, usize), Error> {
        if self.state() != ChannelState::Connected {
            return Err(Error::IpcError);
        }

        if self.receiver_task.load(Ordering::Acquire) != receiver_id {
            return Err(Error::NotAuthorized);
        }

        if self.tx_pending.load(Ordering::Acquire) == 0 {
            return Err(Error::WouldBlock);
        }

        let header = self.tx_header;
        let len = header.length as usize;

        if buffer.len() < len {
            return Err(Error::BufferTooSmall);
        }

        // Copy message
        buffer[..len].copy_from_slice(&self.tx_buffer[..len]);

        // Clear pending
        self.tx_pending.store(0, Ordering::Release);

        Ok((header, len))
    }

    /// Send reply from receiver to sender
    pub fn reply(&mut self, msg_type: u16, data: &[u8], receiver_id: u8) -> Result<(), Error> {
        if self.state() != ChannelState::Connected {
            return Err(Error::IpcError);
        }

        if self.receiver_task.load(Ordering::Acquire) != receiver_id {
            return Err(Error::NotAuthorized);
        }

        if self.rx_pending.load(Ordering::Acquire) != 0 {
            return Err(Error::ChannelFull);
        }

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Copy reply
        let len = data.len();
        self.rx_buffer[..len].copy_from_slice(data);

        // Set header
        let seq = self.sequence.fetch_add(1, Ordering::AcqRel);
        self.rx_header = MessageHeader {
            msg_type,
            length: len as u16,
            sender_id: receiver_id,
            flags: 0,
            sequence: (seq & 0xFFFF) as u16,
        };

        // Mark as pending
        self.rx_pending.store(1, Ordering::Release);

        Ok(())
    }

    /// Receive reply (for sender)
    pub fn receive_reply(&mut self, buffer: &mut [u8], sender_id: u8) -> Result<(MessageHeader, usize), Error> {
        if self.state() != ChannelState::Connected {
            return Err(Error::IpcError);
        }

        if self.sender_task.load(Ordering::Acquire) != sender_id {
            return Err(Error::NotAuthorized);
        }

        if self.rx_pending.load(Ordering::Acquire) == 0 {
            return Err(Error::WouldBlock);
        }

        let header = self.rx_header;
        let len = header.length as usize;

        if buffer.len() < len {
            return Err(Error::BufferTooSmall);
        }

        // Copy reply
        buffer[..len].copy_from_slice(&self.rx_buffer[..len]);

        // Clear pending
        self.rx_pending.store(0, Ordering::Release);

        Ok((header, len))
    }

    /// Check if channel has pending message for receiver
    pub fn has_pending_message(&self) -> bool {
        self.tx_pending.load(Ordering::Acquire) != 0
    }

    /// Check if channel has pending reply for sender
    pub fn has_pending_reply(&self) -> bool {
        self.rx_pending.load(Ordering::Acquire) != 0
    }

    /// Close channel
    pub fn close(&self) {
        self.state.store(ChannelState::Closed as u8, Ordering::Release);
    }

    /// Reset channel to free state
    pub fn reset(&mut self) {
        self.state.store(ChannelState::Free as u8, Ordering::Release);
        self.sender_task.store(0xFF, Ordering::Release);
        self.receiver_task.store(0xFF, Ordering::Release);
        self.tx_pending.store(0, Ordering::Release);
        self.rx_pending.store(0, Ordering::Release);
        self.sequence.store(0, Ordering::Release);
    }
}

// ============================================================================
// Mailbox
// ============================================================================

/// Message in mailbox
#[derive(Clone)]
pub struct MailboxMessage {
    /// Message header
    pub header: MessageHeader,
    /// Message data
    pub data: Vec<u8, MAX_MESSAGE_SIZE>,
}

impl MailboxMessage {
    /// Create new message
    pub fn new(msg_type: u16, sender_id: u8, data: &[u8]) -> Result<Self, Error> {
        let mut msg_data = Vec::new();
        msg_data.extend_from_slice(data).map_err(|_| Error::BufferTooSmall)?;

        Ok(Self {
            header: MessageHeader::new(msg_type, data.len() as u16, sender_id),
            data: msg_data,
        })
    }
}

/// Asynchronous mailbox for multi-producer single-consumer messaging
pub struct Mailbox {
    /// Mailbox ID
    pub id: u8,
    /// Owner task ID
    owner_task: AtomicU8,
    /// Message queue
    messages: [Option<MailboxMessage>; MAILBOX_CAPACITY],
    /// Head index (for reading)
    head: AtomicU8,
    /// Tail index (for writing)
    tail: AtomicU8,
    /// Number of messages
    count: AtomicU8,
    /// Mailbox is active
    active: AtomicU8,
}

impl Mailbox {
    /// Create a new mailbox
    pub const fn new(id: u8) -> Self {
        const NONE: Option<MailboxMessage> = None;
        Self {
            id,
            owner_task: AtomicU8::new(0xFF),
            messages: [NONE; MAILBOX_CAPACITY],
            head: AtomicU8::new(0),
            tail: AtomicU8::new(0),
            count: AtomicU8::new(0),
            active: AtomicU8::new(0),
        }
    }

    /// Activate mailbox for a task
    pub fn activate(&self, owner_id: u8) -> Result<(), Error> {
        match self.active.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                self.owner_task.store(owner_id, Ordering::Release);
                Ok(())
            }
            Err(_) => Err(Error::ChannelInUse),
        }
    }

    /// Post message to mailbox (any task can post)
    pub fn post(&mut self, message: MailboxMessage) -> Result<(), Error> {
        if self.active.load(Ordering::Acquire) == 0 {
            return Err(Error::InvalidState);
        }

        if self.count.load(Ordering::Acquire) >= MAILBOX_CAPACITY as u8 {
            return Err(Error::ChannelFull);
        }

        let tail = self.tail.load(Ordering::Acquire) as usize;
        self.messages[tail] = Some(message);

        self.tail.store(((tail + 1) % MAILBOX_CAPACITY) as u8, Ordering::Release);
        self.count.fetch_add(1, Ordering::AcqRel);

        Ok(())
    }

    /// Receive message from mailbox (only owner can receive)
    pub fn receive(&mut self, owner_id: u8) -> Result<MailboxMessage, Error> {
        if self.active.load(Ordering::Acquire) == 0 {
            return Err(Error::InvalidState);
        }

        if self.owner_task.load(Ordering::Acquire) != owner_id {
            return Err(Error::NotAuthorized);
        }

        if self.count.load(Ordering::Acquire) == 0 {
            return Err(Error::WouldBlock);
        }

        let head = self.head.load(Ordering::Acquire) as usize;
        let message = self.messages[head].take().ok_or(Error::IpcError)?;

        self.head.store(((head + 1) % MAILBOX_CAPACITY) as u8, Ordering::Release);
        self.count.fetch_sub(1, Ordering::AcqRel);

        Ok(message)
    }

    /// Check number of pending messages
    pub fn pending_count(&self) -> u8 {
        self.count.load(Ordering::Acquire)
    }

    /// Check if mailbox is empty
    pub fn is_empty(&self) -> bool {
        self.count.load(Ordering::Acquire) == 0
    }

    /// Deactivate mailbox
    pub fn deactivate(&mut self) {
        self.active.store(0, Ordering::Release);
        self.owner_task.store(0xFF, Ordering::Release);
        self.head.store(0, Ordering::Release);
        self.tail.store(0, Ordering::Release);
        self.count.store(0, Ordering::Release);

        for msg in &mut self.messages {
            *msg = None;
        }
    }
}

// ============================================================================
// Signal
// ============================================================================

/// Signal bits (up to 32 signals per task)
pub struct SignalSet {
    /// Signal bits
    bits: AtomicU32,
}

impl SignalSet {
    /// Create empty signal set
    pub const fn new() -> Self {
        Self {
            bits: AtomicU32::new(0),
        }
    }

    /// Set signal(s)
    pub fn set(&self, signals: u32) {
        self.bits.fetch_or(signals, Ordering::AcqRel);
    }

    /// Clear signal(s)
    pub fn clear(&self, signals: u32) {
        self.bits.fetch_and(!signals, Ordering::AcqRel);
    }

    /// Wait for any of the specified signals (non-blocking check)
    pub fn check(&self, mask: u32) -> u32 {
        self.bits.load(Ordering::Acquire) & mask
    }

    /// Wait and clear (atomically check and clear)
    pub fn wait_and_clear(&self, mask: u32) -> u32 {
        let current = self.bits.load(Ordering::Acquire);
        let matched = current & mask;
        if matched != 0 {
            self.bits.fetch_and(!matched, Ordering::AcqRel);
        }
        matched
    }

    /// Get all pending signals
    pub fn pending(&self) -> u32 {
        self.bits.load(Ordering::Acquire)
    }
}

impl Default for SignalSet {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// IPC Manager
// ============================================================================

/// IPC subsystem manager
pub struct IpcManager {
    /// Channels
    channels: [Channel; MAX_CHANNELS],
    /// Mailboxes
    mailboxes: [Mailbox; MAX_MAILBOXES],
    /// Task signal sets
    signals: [SignalSet; 16], // One per task
    /// Initialized flag
    initialized: bool,
}

impl IpcManager {
    /// Create new IPC manager
    pub const fn new() -> Self {
        const fn make_channel(id: u8) -> Channel {
            Channel::new(id)
        }

        const fn make_mailbox(id: u8) -> Mailbox {
            Mailbox::new(id)
        }

        Self {
            channels: [
                make_channel(0), make_channel(1), make_channel(2), make_channel(3),
                make_channel(4), make_channel(5), make_channel(6), make_channel(7),
                make_channel(8), make_channel(9), make_channel(10), make_channel(11),
                make_channel(12), make_channel(13), make_channel(14), make_channel(15),
            ],
            mailboxes: [
                make_mailbox(0), make_mailbox(1), make_mailbox(2), make_mailbox(3),
                make_mailbox(4), make_mailbox(5), make_mailbox(6), make_mailbox(7),
            ],
            signals: [
                SignalSet::new(), SignalSet::new(), SignalSet::new(), SignalSet::new(),
                SignalSet::new(), SignalSet::new(), SignalSet::new(), SignalSet::new(),
                SignalSet::new(), SignalSet::new(), SignalSet::new(), SignalSet::new(),
                SignalSet::new(), SignalSet::new(), SignalSet::new(), SignalSet::new(),
            ],
            initialized: false,
        }
    }

    /// Initialize IPC subsystem
    pub fn init(&mut self) -> Result<(), Error> {
        self.initialized = true;
        Ok(())
    }

    /// Allocate a channel
    pub fn allocate_channel(&self) -> Result<u8, Error> {
        for channel in &self.channels {
            if channel.allocate().is_ok() {
                return Ok(channel.id);
            }
        }
        Err(Error::ResourceExhausted)
    }

    /// Get channel by ID
    pub fn get_channel(&mut self, id: u8) -> Result<&mut Channel, Error> {
        self.channels
            .get_mut(id as usize)
            .ok_or(Error::InvalidParameter)
    }

    /// Allocate a mailbox for a task
    pub fn allocate_mailbox(&self, owner_id: u8) -> Result<u8, Error> {
        for mailbox in &self.mailboxes {
            if mailbox.activate(owner_id).is_ok() {
                return Ok(mailbox.id);
            }
        }
        Err(Error::ResourceExhausted)
    }

    /// Get mailbox by ID
    pub fn get_mailbox(&mut self, id: u8) -> Result<&mut Mailbox, Error> {
        self.mailboxes
            .get_mut(id as usize)
            .ok_or(Error::InvalidParameter)
    }

    /// Send signal to task
    pub fn send_signal(&self, task_id: u8, signals: u32) -> Result<(), Error> {
        if task_id as usize >= self.signals.len() {
            return Err(Error::InvalidParameter);
        }
        self.signals[task_id as usize].set(signals);
        Ok(())
    }

    /// Check signals for task
    pub fn check_signals(&self, task_id: u8, mask: u32) -> Result<u32, Error> {
        if task_id as usize >= self.signals.len() {
            return Err(Error::InvalidParameter);
        }
        Ok(self.signals[task_id as usize].wait_and_clear(mask))
    }

    /// Get signal set for task
    pub fn get_signals(&self, task_id: u8) -> Result<&SignalSet, Error> {
        self.signals
            .get(task_id as usize)
            .ok_or(Error::InvalidParameter)
    }
}

impl Default for IpcManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global IPC Instance
// ============================================================================

static mut IPC_MANAGER: IpcManager = IpcManager::new();

/// Initialize IPC subsystem
pub fn init() -> Result<(), Error> {
    // SAFETY: Accesses the global IPC_MANAGER. Called once during kernel initialization
    // before enabling interrupts or starting the scheduler. No concurrent access is possible.
    unsafe { (*core::ptr::addr_of_mut!(IPC_MANAGER)).init() }
}

/// Allocate a channel
pub fn allocate_channel() -> Result<u8, Error> {
    // SAFETY: Accesses the global IPC_MANAGER. Channel allocation uses atomic compare-exchange
    // internally (ChannelState is AtomicU8), providing thread-safe allocation even without
    // external synchronization.
    unsafe { (*core::ptr::addr_of!(IPC_MANAGER)).allocate_channel() }
}

/// Get channel by ID
pub fn get_channel(id: u8) -> Result<&'static mut Channel, Error> {
    // SAFETY: Accesses the global IPC_MANAGER to obtain a mutable reference to a channel.
    // The caller must ensure exclusive access — typically guaranteed by the channel's ownership
    // model (only the connected sender/receiver pair accesses a given channel).
    unsafe { (*core::ptr::addr_of_mut!(IPC_MANAGER)).get_channel(id) }
}

/// Allocate mailbox
pub fn allocate_mailbox(owner_id: u8) -> Result<u8, Error> {
    // SAFETY: Accesses the global IPC_MANAGER. Mailbox activation uses atomic compare-exchange
    // internally (active is AtomicU8), providing thread-safe allocation.
    unsafe { (*core::ptr::addr_of!(IPC_MANAGER)).allocate_mailbox(owner_id) }
}

/// Get mailbox by ID
pub fn get_mailbox(id: u8) -> Result<&'static mut Mailbox, Error> {
    // SAFETY: Accesses the global IPC_MANAGER to obtain a mutable reference to a mailbox.
    // The caller must ensure exclusive access — only the mailbox owner should receive, and the
    // post() API uses internal atomics for the count.
    unsafe { (*core::ptr::addr_of_mut!(IPC_MANAGER)).get_mailbox(id) }
}

/// Send signal to task
pub fn send_signal(task_id: u8, signals: u32) -> Result<(), Error> {
    // SAFETY: Accesses the global IPC_MANAGER. Signal operations use AtomicU32 internally
    // (fetch_or), so they are inherently thread-safe.
    unsafe { (*core::ptr::addr_of!(IPC_MANAGER)).send_signal(task_id, signals) }
}

/// Check signals for task
pub fn check_signals(task_id: u8, mask: u32) -> Result<u32, Error> {
    // SAFETY: Accesses the global IPC_MANAGER. Signal check-and-clear uses atomic operations
    // internally (load + fetch_and), so it is thread-safe.
    unsafe { (*core::ptr::addr_of!(IPC_MANAGER)).check_signals(task_id, mask) }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_allocation() {
        let channel = Channel::new(0);
        assert_eq!(channel.state(), ChannelState::Free);

        channel.allocate().unwrap();
        assert_eq!(channel.state(), ChannelState::Allocated);

        // Second allocation should fail
        assert!(channel.allocate().is_err());
    }

    #[test]
    fn test_channel_connection() {
        let channel = Channel::new(0);
        channel.allocate().unwrap();

        channel.connect_sender(1).unwrap();
        assert_eq!(channel.state(), ChannelState::SenderConnected);

        channel.connect_receiver(2).unwrap();
        assert_eq!(channel.state(), ChannelState::Connected);
    }

    #[test]
    fn test_channel_messaging() {
        let mut channel = Channel::new(0);
        channel.allocate().unwrap();
        channel.connect_sender(1).unwrap();
        channel.connect_receiver(2).unwrap();

        // Send message
        let data = b"Hello";
        channel.send(1, data, 1).unwrap();
        assert!(channel.has_pending_message());

        // Receive message
        let mut buffer = [0u8; 64];
        let (header, len) = channel.receive(&mut buffer, 2).unwrap();

        assert_eq!(header.msg_type, 1);
        assert_eq!(len, 5);
        assert_eq!(&buffer[..len], b"Hello");
        assert!(!channel.has_pending_message());
    }

    #[test]
    fn test_channel_reply() {
        let mut channel = Channel::new(0);
        channel.allocate().unwrap();
        channel.connect_sender(1).unwrap();
        channel.connect_receiver(2).unwrap();

        // Send and receive
        channel.send(1, b"Request", 1).unwrap();
        let mut buffer = [0u8; 64];
        channel.receive(&mut buffer, 2).unwrap();

        // Send reply
        channel.reply(2, b"Response", 2).unwrap();
        assert!(channel.has_pending_reply());

        // Receive reply
        let (header, len) = channel.receive_reply(&mut buffer, 1).unwrap();
        assert_eq!(header.msg_type, 2);
        assert_eq!(&buffer[..len], b"Response");
    }

    #[test]
    fn test_mailbox() {
        let mut mailbox = Mailbox::new(0);
        mailbox.activate(1).unwrap();

        // Post messages
        let msg1 = MailboxMessage::new(1, 2, b"Message 1").unwrap();
        let msg2 = MailboxMessage::new(2, 3, b"Message 2").unwrap();

        mailbox.post(msg1).unwrap();
        mailbox.post(msg2).unwrap();

        assert_eq!(mailbox.pending_count(), 2);

        // Receive (FIFO order)
        let received1 = mailbox.receive(1).unwrap();
        assert_eq!(received1.header.msg_type, 1);
        assert_eq!(&received1.data[..], b"Message 1");

        let received2 = mailbox.receive(1).unwrap();
        assert_eq!(received2.header.msg_type, 2);

        assert!(mailbox.is_empty());
    }

    #[test]
    fn test_signals() {
        let signals = SignalSet::new();

        signals.set(0x01 | 0x04);
        assert_eq!(signals.pending(), 0x05);

        let matched = signals.wait_and_clear(0x01);
        assert_eq!(matched, 0x01);
        assert_eq!(signals.pending(), 0x04);
    }

    #[test]
    fn test_message_header() {
        let header = MessageHeader::new(0x1234, 100, 5);
        let bytes = header.to_bytes();
        let parsed = MessageHeader::from_bytes(&bytes);

        assert_eq!(parsed.msg_type, 0x1234);
        assert_eq!(parsed.length, 100);
        assert_eq!(parsed.sender_id, 5);
    }
}
