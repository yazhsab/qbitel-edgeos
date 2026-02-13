// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Group trust management for Q-MESH
//!
//! Provides group-based trust policies for mesh networking:
//! - Group creation and membership management
//! - Group key distribution
//! - Trust level enforcement
//! - Group messaging policies

use heapless::Vec;
use q_common::Error;

/// Maximum number of groups a device can belong to
const MAX_GROUPS: usize = 8;

/// Maximum members per group
const MAX_GROUP_MEMBERS: usize = 32;

/// Maximum number of trust policies per group
const MAX_POLICIES: usize = 8;

/// Group trust level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TrustLevel {
    /// No trust - deny all communication
    None = 0,
    /// Basic trust - routing only
    Routing = 1,
    /// Standard trust - encrypted data exchange
    Standard = 2,
    /// Elevated trust - key relay and update forwarding
    Elevated = 3,
    /// Full trust - administrative operations
    Full = 4,
}

impl TrustLevel {
    /// Convert from raw byte
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::None,
            1 => Self::Routing,
            2 => Self::Standard,
            3 => Self::Elevated,
            4 => Self::Full,
            _ => Self::None,
        }
    }
}

/// Group role for a member
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GroupRole {
    /// Regular member
    Member = 0,
    /// Can relay messages and manage routing
    Relay = 1,
    /// Can add/remove members
    Admin = 2,
    /// Group owner with full control
    Owner = 3,
}

impl GroupRole {
    /// Convert from raw byte
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Member,
            1 => Self::Relay,
            2 => Self::Admin,
            3 => Self::Owner,
            _ => Self::Member,
        }
    }
}

/// A member within a group
#[derive(Clone)]
pub struct GroupMember {
    /// Member device ID
    pub device_id: [u8; 32],
    /// Member's role in the group
    pub role: GroupRole,
    /// Trust level assigned to this member
    pub trust_level: TrustLevel,
    /// When the member was added (timestamp)
    pub joined_at: u64,
    /// Whether the member is currently active
    pub active: bool,
}

impl GroupMember {
    /// Create a new group member
    pub fn new(device_id: [u8; 32], role: GroupRole, trust_level: TrustLevel, now: u64) -> Self {
        Self {
            device_id,
            role,
            trust_level,
            joined_at: now,
            active: true,
        }
    }
}

/// Trust policy for group operations
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    /// Minimum trust level required
    pub min_trust: TrustLevel,
    /// Minimum role required
    pub min_role: GroupRole,
    /// Whether the policy is enforced
    pub enforced: bool,
    /// Policy description
    pub action: PolicyAction,
}

/// Actions that can be controlled by trust policies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Send data messages
    SendData,
    /// Relay messages for others
    RelayMessages,
    /// Initiate key exchange
    KeyExchange,
    /// Add new members
    AddMember,
    /// Remove members
    RemoveMember,
    /// Forward firmware updates
    ForwardUpdates,
    /// Access attestation data
    AccessAttestation,
    /// Modify group settings
    ModifyGroup,
}

/// Group membership and trust management
pub struct GroupMembership {
    /// Group ID
    pub group_id: [u8; 16],
    /// Group name (up to 32 bytes)
    pub name: Vec<u8, 32>,
    /// Group members
    members: Vec<GroupMember, MAX_GROUP_MEMBERS>,
    /// Trust policies
    policies: Vec<TrustPolicy, MAX_POLICIES>,
    /// Group creation timestamp
    pub created_at: u64,
    /// Group epoch (incremented on membership changes)
    pub epoch: u32,
    /// Whether the group requires mutual authentication
    pub require_mutual_auth: bool,
}

impl GroupMembership {
    /// Create a new group with an owner
    pub fn new(
        group_id: [u8; 16],
        name: &[u8],
        owner_id: [u8; 32],
        now: u64,
    ) -> Result<Self, Error> {
        let mut group_name = Vec::new();
        group_name
            .extend_from_slice(name)
            .map_err(|_| Error::BufferTooSmall)?;

        let owner = GroupMember::new(owner_id, GroupRole::Owner, TrustLevel::Full, now);
        let mut members = Vec::new();
        members.push(owner).map_err(|_| Error::BufferTooSmall)?;

        // Default policies
        let mut policies = Vec::new();
        policies
            .push(TrustPolicy {
                min_trust: TrustLevel::Standard,
                min_role: GroupRole::Member,
                enforced: true,
                action: PolicyAction::SendData,
            })
            .map_err(|_| Error::BufferTooSmall)?;
        policies
            .push(TrustPolicy {
                min_trust: TrustLevel::Elevated,
                min_role: GroupRole::Relay,
                enforced: true,
                action: PolicyAction::RelayMessages,
            })
            .map_err(|_| Error::BufferTooSmall)?;
        policies
            .push(TrustPolicy {
                min_trust: TrustLevel::Full,
                min_role: GroupRole::Admin,
                enforced: true,
                action: PolicyAction::AddMember,
            })
            .map_err(|_| Error::BufferTooSmall)?;
        policies
            .push(TrustPolicy {
                min_trust: TrustLevel::Full,
                min_role: GroupRole::Admin,
                enforced: true,
                action: PolicyAction::RemoveMember,
            })
            .map_err(|_| Error::BufferTooSmall)?;

        Ok(Self {
            group_id,
            name: group_name,
            members,
            policies,
            created_at: now,
            epoch: 0,
            require_mutual_auth: true,
        })
    }

    /// Add a member to the group
    pub fn add_member(
        &mut self,
        requester_id: &[u8; 32],
        new_member_id: [u8; 32],
        role: GroupRole,
        trust_level: TrustLevel,
        now: u64,
    ) -> Result<(), Error> {
        // Check authorization
        self.check_permission(requester_id, PolicyAction::AddMember)?;

        // Check if already a member
        if self.find_member(&new_member_id).is_some() {
            return Err(Error::InvalidParameter);
        }

        let member = GroupMember::new(new_member_id, role, trust_level, now);
        self.members
            .push(member)
            .map_err(|_| Error::BufferTooSmall)?;
        self.epoch = self.epoch.wrapping_add(1);

        Ok(())
    }

    /// Remove a member from the group
    pub fn remove_member(
        &mut self,
        requester_id: &[u8; 32],
        target_id: &[u8; 32],
    ) -> Result<(), Error> {
        // Check authorization
        self.check_permission(requester_id, PolicyAction::RemoveMember)?;

        // Cannot remove the owner
        if let Some(member) = self.find_member(target_id) {
            if member.role == GroupRole::Owner {
                return Err(Error::InvalidParameter);
            }
        }

        let initial_len = self.members.len();
        self.members.retain(|m| &m.device_id != target_id);

        if self.members.len() == initial_len {
            return Err(Error::InvalidParameter);
        }

        self.epoch = self.epoch.wrapping_add(1);
        Ok(())
    }

    /// Check if a device is a member of this group
    pub fn is_member(&self, device_id: &[u8; 32]) -> bool {
        self.find_member(device_id).is_some()
    }

    /// Find a member by device ID
    pub fn find_member(&self, device_id: &[u8; 32]) -> Option<&GroupMember> {
        self.members.iter().find(|m| &m.device_id == device_id)
    }

    /// Get the trust level for a device
    pub fn get_trust_level(&self, device_id: &[u8; 32]) -> TrustLevel {
        self.find_member(device_id)
            .map(|m| m.trust_level)
            .unwrap_or(TrustLevel::None)
    }

    /// Check if a member is authorized for an action
    pub fn check_permission(
        &self,
        device_id: &[u8; 32],
        action: PolicyAction,
    ) -> Result<(), Error> {
        let member = self
            .find_member(device_id)
            .ok_or(Error::InvalidParameter)?;

        // Find the matching policy
        let policy = self.policies.iter().find(|p| p.action == action);

        if let Some(policy) = policy {
            if policy.enforced {
                if member.trust_level < policy.min_trust {
                    return Err(Error::InvalidParameter);
                }
                if (member.role as u8) < (policy.min_role as u8) {
                    return Err(Error::InvalidParameter);
                }
            }
        }

        Ok(())
    }

    /// Update a member's trust level
    pub fn set_trust_level(
        &mut self,
        requester_id: &[u8; 32],
        target_id: &[u8; 32],
        trust_level: TrustLevel,
    ) -> Result<(), Error> {
        // Only admins and owners can change trust levels
        let requester = self
            .find_member(requester_id)
            .ok_or(Error::InvalidParameter)?;
        if (requester.role as u8) < (GroupRole::Admin as u8) {
            return Err(Error::InvalidParameter);
        }

        let target = self
            .members
            .iter_mut()
            .find(|m| &m.device_id == target_id)
            .ok_or(Error::InvalidParameter)?;
        target.trust_level = trust_level;
        self.epoch = self.epoch.wrapping_add(1);

        Ok(())
    }

    /// Get the number of active members
    pub fn member_count(&self) -> usize {
        self.members.iter().filter(|m| m.active).count()
    }

    /// Get all active members
    pub fn active_members(&self) -> impl Iterator<Item = &GroupMember> {
        self.members.iter().filter(|m| m.active)
    }

    /// Add a custom trust policy
    pub fn add_policy(&mut self, policy: TrustPolicy) -> Result<(), Error> {
        self.policies
            .push(policy)
            .map_err(|_| Error::BufferTooSmall)
    }
}

/// Group manager handling multiple groups
pub struct GroupManager {
    /// Groups this device belongs to
    groups: Vec<GroupMembership, MAX_GROUPS>,
    /// Local device ID
    local_id: [u8; 32],
}

impl GroupManager {
    /// Create a new group manager
    pub fn new(local_id: [u8; 32]) -> Self {
        Self {
            groups: Vec::new(),
            local_id,
        }
    }

    /// Create a new group (this device becomes owner)
    pub fn create_group(
        &mut self,
        group_id: [u8; 16],
        name: &[u8],
        now: u64,
    ) -> Result<&GroupMembership, Error> {
        let group = GroupMembership::new(group_id, name, self.local_id, now)?;
        self.groups
            .push(group)
            .map_err(|_| Error::BufferTooSmall)?;
        // SAFETY rationale: `push` succeeded on the line above (did not return
        // Err), so `groups` is guaranteed to be non-empty.
        Ok(self.groups.last().expect("BUG: groups empty after push"))
    }

    /// Find a group by ID
    pub fn find_group(&self, group_id: &[u8; 16]) -> Option<&GroupMembership> {
        self.groups.iter().find(|g| &g.group_id == group_id)
    }

    /// Find a group by ID (mutable)
    pub fn find_group_mut(&mut self, group_id: &[u8; 16]) -> Option<&mut GroupMembership> {
        self.groups.iter_mut().find(|g| &g.group_id == group_id)
    }

    /// Check if a peer is trusted in any shared group
    pub fn is_peer_trusted(&self, peer_id: &[u8; 32], min_trust: TrustLevel) -> bool {
        self.groups.iter().any(|g| {
            g.is_member(&self.local_id)
                && g.is_member(peer_id)
                && g.get_trust_level(peer_id) >= min_trust
        })
    }

    /// Get all groups this device belongs to
    pub fn my_groups(&self) -> impl Iterator<Item = &GroupMembership> {
        self.groups.iter().filter(|g| g.is_member(&self.local_id))
    }

    /// Number of groups
    pub fn group_count(&self) -> usize {
        self.groups.len()
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

    fn test_group_id(val: u8) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = val;
        id
    }

    #[test]
    fn test_create_group() {
        let group =
            GroupMembership::new(test_group_id(1), b"test-group", test_id(0), 100).unwrap();
        assert_eq!(group.member_count(), 1);
        assert!(group.is_member(&test_id(0)));
        assert_eq!(group.get_trust_level(&test_id(0)), TrustLevel::Full);
    }

    #[test]
    fn test_add_remove_member() {
        let owner = test_id(0);
        let member = test_id(1);
        let mut group =
            GroupMembership::new(test_group_id(1), b"test", owner, 100).unwrap();

        group
            .add_member(&owner, member, GroupRole::Member, TrustLevel::Standard, 200)
            .unwrap();
        assert_eq!(group.member_count(), 2);
        assert!(group.is_member(&member));

        group.remove_member(&owner, &member).unwrap();
        assert_eq!(group.member_count(), 1);
        assert!(!group.is_member(&member));
    }

    #[test]
    fn test_cannot_remove_owner() {
        let owner = test_id(0);
        let mut group =
            GroupMembership::new(test_group_id(1), b"test", owner, 100).unwrap();
        assert!(group.remove_member(&owner, &owner).is_err());
    }

    #[test]
    fn test_permission_check() {
        let owner = test_id(0);
        let member = test_id(1);
        let mut group =
            GroupMembership::new(test_group_id(1), b"test", owner, 100).unwrap();
        group
            .add_member(&owner, member, GroupRole::Member, TrustLevel::Standard, 200)
            .unwrap();

        // Member can send data (Standard trust)
        assert!(group
            .check_permission(&member, PolicyAction::SendData)
            .is_ok());
        // Member cannot add members (requires Admin + Full trust)
        assert!(group
            .check_permission(&member, PolicyAction::AddMember)
            .is_err());
    }

    #[test]
    fn test_trust_levels() {
        assert!(TrustLevel::Full > TrustLevel::Standard);
        assert!(TrustLevel::Standard > TrustLevel::Routing);
        assert!(TrustLevel::Routing > TrustLevel::None);
    }

    #[test]
    fn test_group_manager() {
        let mut mgr = GroupManager::new(test_id(0));
        mgr.create_group(test_group_id(1), b"group1", 100).unwrap();
        mgr.create_group(test_group_id(2), b"group2", 200).unwrap();

        assert_eq!(mgr.group_count(), 2);
        assert!(mgr.find_group(&test_group_id(1)).is_some());
        assert!(mgr.find_group(&test_group_id(3)).is_none());
    }

    #[test]
    fn test_peer_trust_across_groups() {
        let mut mgr = GroupManager::new(test_id(0));
        mgr.create_group(test_group_id(1), b"group1", 100).unwrap();

        let group = mgr.find_group_mut(&test_group_id(1)).unwrap();
        let owner = test_id(0);
        group
            .add_member(
                &owner,
                test_id(1),
                GroupRole::Member,
                TrustLevel::Standard,
                200,
            )
            .unwrap();

        assert!(mgr.is_peer_trusted(&test_id(1), TrustLevel::Standard));
        assert!(!mgr.is_peer_trusted(&test_id(1), TrustLevel::Full));
        assert!(!mgr.is_peer_trusted(&test_id(2), TrustLevel::Standard));
    }

    #[test]
    fn test_epoch_increments() {
        let owner = test_id(0);
        let mut group =
            GroupMembership::new(test_group_id(1), b"test", owner, 100).unwrap();
        let initial_epoch = group.epoch;

        group
            .add_member(
                &owner,
                test_id(1),
                GroupRole::Member,
                TrustLevel::Standard,
                200,
            )
            .unwrap();
        assert_eq!(group.epoch, initial_epoch + 1);

        group.remove_member(&owner, &test_id(1)).unwrap();
        assert_eq!(group.epoch, initial_epoch + 2);
    }
}
