"""Tests for q-sign manifest module."""

import os
from datetime import datetime, timezone

import pytest

from q_sign.manifest import (
    ImageType,
    FirmwareManifest,
    ManifestBuilder,
    MANIFEST_MAGIC,
    MANIFEST_VERSION,
    parse_version,
    compare_versions,
)


class TestImageType:
    """Tests for ImageType enum."""

    def test_image_types_exist(self):
        """Test all expected image types exist."""
        assert ImageType.BOOTLOADER.value == 0
        assert ImageType.KERNEL.value == 1
        assert ImageType.APPLICATION.value == 2

    def test_from_string(self):
        """Test creating image type from string."""
        assert ImageType.from_string("bootloader") == ImageType.BOOTLOADER
        assert ImageType.from_string("KERNEL") == ImageType.KERNEL
        assert ImageType.from_string("application") == ImageType.APPLICATION

    def test_from_string_invalid(self):
        """Test invalid image type string."""
        with pytest.raises(ValueError):
            ImageType.from_string("invalid_type")


class TestManifestConstants:
    """Tests for manifest constants."""

    def test_magic_bytes(self):
        """Test manifest magic bytes."""
        assert MANIFEST_MAGIC == b"QMAN"
        assert len(MANIFEST_MAGIC) == 4

    def test_version(self):
        """Test manifest version."""
        assert MANIFEST_VERSION == 1
        assert isinstance(MANIFEST_VERSION, int)


class TestFirmwareManifest:
    """Tests for FirmwareManifest dataclass."""

    def test_creation(self, sample_firmware: bytes):
        """Test creating a firmware manifest."""
        from Crypto.Hash import SHA3_256

        h = SHA3_256.new()
        h.update(sample_firmware)
        image_hash = h.digest()

        manifest = FirmwareManifest(
            image_type=ImageType.APPLICATION,
            version_string="1.2.3",
            rollback_version=5,
            hardware_version="2.0",
            image_size=len(sample_firmware),
            image_hash=image_hash,
            signer_key_id="test-key",
            created_at=datetime.now(timezone.utc),
        )

        assert manifest.image_type == ImageType.APPLICATION
        assert manifest.version_string == "1.2.3"
        assert manifest.rollback_version == 5
        assert manifest.image_size == len(sample_firmware)
        assert len(manifest.image_hash) == 32

    def test_with_optional_fields(self, sample_firmware: bytes):
        """Test manifest with optional fields."""
        from Crypto.Hash import SHA3_256

        h = SHA3_256.new()
        h.update(sample_firmware)

        manifest = FirmwareManifest(
            image_type=ImageType.KERNEL,
            version_string="2.0.0",
            rollback_version=10,
            hardware_version="1.5",
            image_size=len(sample_firmware),
            image_hash=h.digest(),
            signer_key_id="kernel-signer",
            created_at=datetime.now(timezone.utc),
            device_class="edge-gateway",
            target_platform="stm32h7",
            dependencies=["bootloader>=1.0.0", "hal>=2.0.0"],
        )

        assert manifest.device_class == "edge-gateway"
        assert manifest.target_platform == "stm32h7"
        assert len(manifest.dependencies) == 2

    def test_to_bytes_roundtrip(self, sample_firmware: bytes):
        """Test serialization and deserialization."""
        from Crypto.Hash import SHA3_256

        h = SHA3_256.new()
        h.update(sample_firmware)

        original = FirmwareManifest(
            image_type=ImageType.BOOTLOADER,
            version_string="1.0.0",
            rollback_version=1,
            hardware_version="1.0",
            image_size=len(sample_firmware),
            image_hash=h.digest(),
            signer_key_id="test",
            created_at=datetime.now(timezone.utc),
        )

        serialized = original.to_bytes()
        restored = FirmwareManifest.from_bytes(serialized)

        assert restored.image_type == original.image_type
        assert restored.version_string == original.version_string
        assert restored.rollback_version == original.rollback_version
        assert restored.image_hash == original.image_hash
        assert restored.image_size == original.image_size


class TestManifestBuilder:
    """Tests for ManifestBuilder class."""

    def test_basic_build(self, sample_firmware: bytes):
        """Test building a basic manifest."""
        manifest = ManifestBuilder().build(
            image_data=sample_firmware,
            image_type=ImageType.APPLICATION,
            version="1.0.0",
            rollback_version=1,
            hardware_version="1.0",
            signer_key_id="builder-test",
        )

        assert manifest.image_type == ImageType.APPLICATION
        assert manifest.version_string == "1.0.0"
        assert manifest.rollback_version == 1
        assert manifest.image_size == len(sample_firmware)
        assert len(manifest.image_hash) == 32

    def test_build_with_device_class(self, sample_firmware: bytes):
        """Test building manifest with device class."""
        manifest = (
            ManifestBuilder()
            .with_device_class("smart-meter")
            .build(
                image_data=sample_firmware,
                image_type=ImageType.APPLICATION,
                version="1.0.0",
                rollback_version=1,
                hardware_version="1.0",
                signer_key_id="test",
            )
        )

        assert manifest.device_class == "smart-meter"

    def test_build_with_platform(self, sample_firmware: bytes):
        """Test building manifest with target platform."""
        manifest = (
            ManifestBuilder()
            .with_target_platform("stm32u5")
            .build(
                image_data=sample_firmware,
                image_type=ImageType.KERNEL,
                version="2.0.0",
                rollback_version=5,
                hardware_version="2.0",
                signer_key_id="test",
            )
        )

        assert manifest.target_platform == "stm32u5"

    def test_build_with_dependencies(self, sample_firmware: bytes):
        """Test building manifest with dependencies."""
        manifest = (
            ManifestBuilder()
            .with_dependency("bootloader>=1.0.0")
            .with_dependency("crypto>=2.0.0")
            .build(
                image_data=sample_firmware,
                image_type=ImageType.APPLICATION,
                version="1.0.0",
                rollback_version=1,
                hardware_version="1.0",
                signer_key_id="test",
            )
        )

        assert manifest.dependencies is not None
        assert len(manifest.dependencies) == 2
        assert "bootloader>=1.0.0" in manifest.dependencies

    def test_builder_chaining(self, sample_firmware: bytes):
        """Test fluent builder pattern."""
        manifest = (
            ManifestBuilder()
            .with_device_class("railway-controller")
            .with_target_platform("stm32h7")
            .with_dependency("safety-core>=3.0.0")
            .build(
                image_data=sample_firmware,
                image_type=ImageType.KERNEL,
                version="3.0.0",
                rollback_version=10,
                hardware_version="3.0",
                signer_key_id="railway-signer",
            )
        )

        assert manifest.device_class == "railway-controller"
        assert manifest.target_platform == "stm32h7"
        assert len(manifest.dependencies) == 1

    def test_image_hash_computed(self, sample_firmware: bytes):
        """Test that image hash is correctly computed."""
        from Crypto.Hash import SHA3_256

        manifest = ManifestBuilder().build(
            image_data=sample_firmware,
            image_type=ImageType.APPLICATION,
            version="1.0.0",
            rollback_version=1,
            hardware_version="1.0",
            signer_key_id="test",
        )

        # Compute expected hash
        h = SHA3_256.new()
        h.update(sample_firmware)
        expected_hash = h.digest()

        assert manifest.image_hash == expected_hash


class TestVersionParsing:
    """Tests for version parsing functions."""

    def test_parse_version_semver(self):
        """Test parsing semantic version."""
        major, minor, patch = parse_version("1.2.3")
        assert major == 1
        assert minor == 2
        assert patch == 3

    def test_parse_version_two_parts(self):
        """Test parsing version with two parts."""
        major, minor, patch = parse_version("2.5")
        assert major == 2
        assert minor == 5
        assert patch == 0

    def test_parse_version_single(self):
        """Test parsing single version number."""
        major, minor, patch = parse_version("3")
        assert major == 3
        assert minor == 0
        assert patch == 0


class TestVersionComparison:
    """Tests for version comparison functions."""

    def test_compare_equal(self):
        """Test comparing equal versions."""
        assert compare_versions("1.0.0", "1.0.0") == 0

    def test_compare_greater(self):
        """Test comparing greater version."""
        assert compare_versions("2.0.0", "1.0.0") > 0
        assert compare_versions("1.1.0", "1.0.0") > 0
        assert compare_versions("1.0.1", "1.0.0") > 0

    def test_compare_lesser(self):
        """Test comparing lesser version."""
        assert compare_versions("1.0.0", "2.0.0") < 0
        assert compare_versions("1.0.0", "1.1.0") < 0
        assert compare_versions("1.0.0", "1.0.1") < 0

    def test_compare_complex(self):
        """Test comparing complex versions."""
        assert compare_versions("1.10.0", "1.9.0") > 0
        assert compare_versions("2.0.0", "1.99.99") > 0
