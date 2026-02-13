"""Firmware manifest creation for Qbitel EdgeOS."""

import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from Crypto.Hash import SHA3_256


# Manifest magic number
MANIFEST_MAGIC = b"QMAN"
MANIFEST_VERSION = 1


class ImageType(Enum):
    """Firmware image types."""

    BOOTLOADER = 0
    KERNEL = 1
    APPLICATION = 2

    @classmethod
    def from_string(cls, value: str) -> "ImageType":
        """Convert string to ImageType."""
        mapping = {
            "bootloader": cls.BOOTLOADER,
            "kernel": cls.KERNEL,
            "application": cls.APPLICATION,
        }
        return mapping[value.lower()]


@dataclass
class FirmwareManifest:
    """Firmware manifest describing a signed image."""

    # Image identification
    image_type: ImageType
    version_string: str
    rollback_version: int
    hardware_version: str

    # Image data
    image_size: int
    image_hash: bytes  # SHA3-256

    # Signing info
    signer_key_id: str
    created_at: datetime

    # Optional fields
    device_class: Optional[str] = None
    target_platform: Optional[str] = None
    dependencies: Optional[list[str]] = None

    def to_bytes(self) -> bytes:
        """Serialize manifest to bytes.

        Format:
        [4 bytes] Magic "QMAN"
        [4 bytes] Version
        [4 bytes] Image type
        [32 bytes] Version string (null-padded)
        [4 bytes] Rollback version
        [32 bytes] Hardware version (null-padded)
        [4 bytes] Image size
        [32 bytes] Image hash (SHA3-256)
        [32 bytes] Signer key ID (null-padded)
        [8 bytes] Created timestamp (Unix epoch)
        [32 bytes] Device class (null-padded, optional)
        [32 bytes] Target platform (null-padded, optional)
        [4 bytes] Number of dependencies
        [N * 64 bytes] Dependencies (null-padded strings)
        [32 bytes] Manifest checksum
        """
        # Fixed-size fields
        version_bytes = self.version_string.encode()[:32].ljust(32, b"\x00")
        hw_version_bytes = self.hardware_version.encode()[:32].ljust(32, b"\x00")
        key_id_bytes = self.signer_key_id.encode()[:32].ljust(32, b"\x00")
        timestamp = int(self.created_at.timestamp())

        device_class_bytes = (self.device_class or "").encode()[:32].ljust(32, b"\x00")
        platform_bytes = (self.target_platform or "").encode()[:32].ljust(32, b"\x00")

        # Build manifest without checksum
        manifest = struct.pack(
            "<4sIII32sI32sI32s32sQ32s32sI",
            MANIFEST_MAGIC,
            MANIFEST_VERSION,
            self.image_type.value,
            len(self.version_string),
            version_bytes,
            self.rollback_version,
            hw_version_bytes,
            self.image_size,
            self.image_hash,
            key_id_bytes,
            timestamp,
            device_class_bytes,
            platform_bytes,
            len(self.dependencies or []),
        )

        # Add dependencies
        for dep in self.dependencies or []:
            dep_bytes = dep.encode()[:64].ljust(64, b"\x00")
            manifest += dep_bytes

        # Add checksum
        checksum = SHA3_256.new(manifest).digest()
        manifest += checksum

        return manifest

    @classmethod
    def from_bytes(cls, data: bytes) -> "FirmwareManifest":
        """Deserialize manifest from bytes."""
        if len(data) < 232:  # Minimum size without dependencies
            raise ValueError("Manifest data too short")

        # Parse fixed header
        (
            magic,
            version,
            image_type,
            version_len,
            version_bytes,
            rollback_version,
            hw_version_bytes,
            image_size,
            image_hash,
            key_id_bytes,
            timestamp,
            device_class_bytes,
            platform_bytes,
            num_deps,
        ) = struct.unpack("<4sIII32sI32sI32s32sQ32s32sI", data[:232])

        if magic != MANIFEST_MAGIC:
            raise ValueError(f"Invalid manifest magic: {magic}")

        if version != MANIFEST_VERSION:
            raise ValueError(f"Unsupported manifest version: {version}")

        # Parse dependencies
        offset = 232
        dependencies = []
        for _ in range(num_deps):
            dep_bytes = data[offset : offset + 64]
            dep = dep_bytes.rstrip(b"\x00").decode()
            dependencies.append(dep)
            offset += 64

        # Verify checksum
        checksum = data[offset : offset + 32]
        expected_checksum = SHA3_256.new(data[:offset]).digest()
        if checksum != expected_checksum:
            raise ValueError("Manifest checksum mismatch")

        return cls(
            image_type=ImageType(image_type),
            version_string=version_bytes[:version_len].decode(),
            rollback_version=rollback_version,
            hardware_version=hw_version_bytes.rstrip(b"\x00").decode(),
            image_size=image_size,
            image_hash=image_hash,
            signer_key_id=key_id_bytes.rstrip(b"\x00").decode(),
            created_at=datetime.fromtimestamp(timestamp, tz=timezone.utc),
            device_class=device_class_bytes.rstrip(b"\x00").decode() or None,
            target_platform=platform_bytes.rstrip(b"\x00").decode() or None,
            dependencies=dependencies if dependencies else None,
        )


class ManifestBuilder:
    """Builder for firmware manifests."""

    def __init__(self) -> None:
        """Initialize manifest builder."""
        self._device_class: Optional[str] = None
        self._target_platform: Optional[str] = None
        self._dependencies: list[str] = []

    def with_device_class(self, device_class: str) -> "ManifestBuilder":
        """Set device class.

        Args:
            device_class: Device classification

        Returns:
            Self for chaining
        """
        self._device_class = device_class
        return self

    def with_target_platform(self, platform: str) -> "ManifestBuilder":
        """Set target platform.

        Args:
            platform: Target platform identifier

        Returns:
            Self for chaining
        """
        self._target_platform = platform
        return self

    def with_dependency(self, dependency: str) -> "ManifestBuilder":
        """Add a dependency.

        Args:
            dependency: Dependency identifier

        Returns:
            Self for chaining
        """
        self._dependencies.append(dependency)
        return self

    def build(
        self,
        image_data: bytes,
        image_type: ImageType,
        version: str,
        rollback_version: int,
        hardware_version: str,
        signer_key_id: str,
    ) -> FirmwareManifest:
        """Build a firmware manifest.

        Args:
            image_data: Raw firmware image data
            image_type: Type of image
            version: Semantic version string
            rollback_version: Monotonic rollback protection version
            hardware_version: Minimum hardware version required
            signer_key_id: ID of the signing key

        Returns:
            Complete firmware manifest
        """
        image_hash = SHA3_256.new(image_data).digest()

        return FirmwareManifest(
            image_type=image_type,
            version_string=version,
            rollback_version=rollback_version,
            hardware_version=hardware_version,
            image_size=len(image_data),
            image_hash=image_hash,
            signer_key_id=signer_key_id,
            created_at=datetime.now(timezone.utc),
            device_class=self._device_class,
            target_platform=self._target_platform,
            dependencies=self._dependencies if self._dependencies else None,
        )


def parse_version(version_string: str) -> tuple[int, int, int]:
    """Parse semantic version string.

    Args:
        version_string: Version in format "major.minor.patch"

    Returns:
        Tuple of (major, minor, patch)
    """
    parts = version_string.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid version format: {version_string}")

    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError as e:
        raise ValueError(f"Invalid version format: {version_string}") from e


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.

    Args:
        v1: First version
        v2: Second version

    Returns:
        -1 if v1 < v2, 0 if equal, 1 if v1 > v2
    """
    p1 = parse_version(v1)
    p2 = parse_version(v2)

    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    else:
        return 0
