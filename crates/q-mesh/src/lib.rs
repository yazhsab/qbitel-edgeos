// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Q-MESH for Qbitel EdgeOS
//!
//! Secure mesh networking with PQC handshakes:
//!
//! - **Discovery**: Peer discovery and announcement
//! - **Handshake**: PQC-based key exchange
//! - **Session**: Encrypted session management
//! - **Routing**: Multi-hop mesh routing
//! - **Group Trust**: Group-based trust policies

#![no_std]
#![warn(missing_docs)]

pub mod discovery;
pub mod handshake;
pub mod session;
pub mod routing;
pub mod group;
pub mod transport;
pub mod radio;

pub use session::{Session, SessionState, EncryptedFrame, FrameHeader};
pub use handshake::{
    Handshake, HandshakeState, HandshakeMessage, MessageType, Role,
    ClientHello, ServerHello, ClientFinished, SessionKeys,
};
pub use radio::{Radio, RadioEvent, RadioState, ChannelConfig};
pub use radio::lora::{LoRaRadio, LoRaConfig, SpreadingFactor, Bandwidth, CodingRate, FrequencyBand};
pub use routing::{Router, NeighborTable, RoutingTable, BeaconMessage};
pub use discovery::{PeerDiscovery, Peer, PeerState, PeerCapabilities};
pub use group::{GroupManager, GroupMembership, TrustLevel, GroupRole};
pub use transport::{Transport, Frame, FrameType, Priority};
