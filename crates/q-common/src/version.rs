// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Version handling for Qbitel EdgeOS
//!
//! This module defines version types with strict monotonic ordering
//! for secure update verification. Rollback protection is enforced
//! by requiring versions to always increase.

use core::fmt;
use core::cmp::Ordering;

/// Semantic version with build number
///
/// Versions are compared for monotonic ordering to prevent rollback attacks.
/// The comparison order is: major > minor > patch > build
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Version {
    /// Major version (breaking changes)
    pub major: u16,
    /// Minor version (new features)
    pub minor: u16,
    /// Patch version (bug fixes)
    pub patch: u16,
    /// Build number (always incrementing)
    pub build: u32,
}

impl Version {
    /// Create a new version
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16, build: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            build,
        }
    }

    /// Create version 0.0.0.0
    pub const ZERO: Self = Self::new(0, 0, 0, 0);

    /// Create version 1.0.0.0
    pub const ONE: Self = Self::new(1, 0, 0, 0);

    /// Parse from bytes (8 bytes: major(2) + minor(2) + patch(2) + build(4))
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 10 {
            return None;
        }
        Some(Self {
            major: u16::from_le_bytes([bytes[0], bytes[1]]),
            minor: u16::from_le_bytes([bytes[2], bytes[3]]),
            patch: u16::from_le_bytes([bytes[4], bytes[5]]),
            build: u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
        })
    }

    /// Serialize to bytes
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 10] {
        let mut bytes = [0u8; 10];
        bytes[0..2].copy_from_slice(&self.major.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.minor.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.patch.to_le_bytes());
        bytes[6..10].copy_from_slice(&self.build.to_le_bytes());
        bytes
    }

    /// Check if this version is strictly greater than another
    ///
    /// Used for rollback protection - updates must have higher versions.
    #[must_use]
    pub const fn is_greater_than(&self, other: &Self) -> bool {
        if self.major != other.major {
            return self.major > other.major;
        }
        if self.minor != other.minor {
            return self.minor > other.minor;
        }
        if self.patch != other.patch {
            return self.patch > other.patch;
        }
        self.build > other.build
    }

    /// Check if this version is compatible with a minimum required version
    #[must_use]
    pub const fn is_compatible_with(&self, min_version: &Self) -> bool {
        if self.major != min_version.major {
            return self.major > min_version.major;
        }
        if self.minor != min_version.minor {
            return self.minor >= min_version.minor;
        }
        self.patch >= min_version.patch
    }

    /// Get the version as a u64 for compact storage
    ///
    /// Format: major(16) | minor(16) | patch(16) | build(16, truncated)
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        ((self.major as u64) << 48)
            | ((self.minor as u64) << 32)
            | ((self.patch as u64) << 16)
            | ((self.build & 0xFFFF) as u64)
    }

    /// Create from u64 compact representation
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self {
            major: ((value >> 48) & 0xFFFF) as u16,
            minor: ((value >> 32) & 0xFFFF) as u16,
            patch: ((value >> 16) & 0xFFFF) as u16,
            build: (value & 0xFFFF) as u32,
        }
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            Ordering::Equal => {}
            ord => return ord,
        }
        self.build.cmp(&other.build)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Version({}.{}.{}.{})",
            self.major, self.minor, self.patch, self.build
        )
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.patch, self.build
        )
    }
}

/// Version range for compatibility checking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    /// Minimum version (inclusive)
    pub min: Version,
    /// Maximum version (inclusive, None = no upper bound)
    pub max: Option<Version>,
}

impl VersionRange {
    /// Create a version range
    #[must_use]
    pub const fn new(min: Version, max: Option<Version>) -> Self {
        Self { min, max }
    }

    /// Create a range starting from a minimum version
    #[must_use]
    pub const fn from_min(min: Version) -> Self {
        Self { min, max: None }
    }

    /// Create a range for a single version
    #[must_use]
    pub const fn exact(version: Version) -> Self {
        Self {
            min: version,
            max: Some(version),
        }
    }

    /// Check if a version is within this range
    #[must_use]
    pub fn contains(&self, version: &Version) -> bool {
        if *version < self.min {
            return false;
        }
        if let Some(ref max) = self.max {
            if version > max {
                return false;
            }
        }
        true
    }
}

impl fmt::Display for VersionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.max {
            Some(ref max) if max == &self.min => write!(f, "={}", self.min),
            Some(ref max) => write!(f, ">={}, <={}", self.min, max),
            None => write!(f, ">={}", self.min),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_ordering() {
        let v1 = Version::new(1, 0, 0, 0);
        let v2 = Version::new(1, 0, 1, 0);
        let v3 = Version::new(1, 1, 0, 0);
        let v4 = Version::new(2, 0, 0, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
        assert!(v4.is_greater_than(&v1));
    }

    #[test]
    fn test_version_bytes_roundtrip() {
        let v = Version::new(1, 2, 3, 12345);
        let bytes = v.to_bytes();
        let v2 = Version::from_bytes(&bytes).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn test_version_range() {
        let range = VersionRange::new(
            Version::new(1, 0, 0, 0),
            Some(Version::new(2, 0, 0, 0)),
        );

        assert!(range.contains(&Version::new(1, 0, 0, 0)));
        assert!(range.contains(&Version::new(1, 5, 0, 0)));
        assert!(range.contains(&Version::new(2, 0, 0, 0)));
        assert!(!range.contains(&Version::new(0, 9, 0, 0)));
        assert!(!range.contains(&Version::new(2, 0, 1, 0)));
    }
}
