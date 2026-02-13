"""Tests for q-sign package module."""

import os
from pathlib import Path

import pytest

from q_sign.signer import SigningKey, SignatureAlgorithm
from q_sign.package import (
    PackageBuilder,
    PackageExtractor,
    PackageComponent,
    UpdatePackage,
    PACKAGE_MAGIC,
    PACKAGE_VERSION,
)


class TestPackageConstants:
    """Tests for package constants."""

    def test_magic_bytes(self):
        """Test package magic bytes."""
        assert PACKAGE_MAGIC == b"QPKG"
        assert len(PACKAGE_MAGIC) == 4

    def test_version(self):
        """Test package version."""
        assert PACKAGE_VERSION == 1


class TestPackageComponent:
    """Tests for PackageComponent dataclass."""

    def test_creation(self):
        """Test creating a package component."""
        data = os.urandom(1024)
        from Crypto.Hash import SHA3_256

        h = SHA3_256.new()
        h.update(data)

        component = PackageComponent(
            name="kernel.bin",
            image_type="kernel",
            data=data,
            hash=h.digest(),
        )

        assert component.name == "kernel.bin"
        assert component.image_type == "kernel"
        assert len(component.data) == 1024
        assert len(component.hash) == 32


class TestPackageBuilder:
    """Tests for PackageBuilder class."""

    @pytest.fixture
    def signing_key(self) -> SigningKey:
        """Create a signing key."""
        return SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="package-builder",
            purpose="updates",
        )

    @pytest.fixture
    def builder(self, signing_key: SigningKey) -> PackageBuilder:
        """Create a PackageBuilder."""
        return PackageBuilder(signing_key, target_platform="stm32h7")

    def test_creation(self, builder: PackageBuilder):
        """Test creating a PackageBuilder."""
        assert builder is not None

    def test_add_bootloader(
        self, builder: PackageBuilder, bootloader_file: Path
    ):
        """Test adding a bootloader to the package."""
        result = builder.add_bootloader(bootloader_file)
        assert result is builder  # Should return self for chaining

    def test_add_kernel(self, builder: PackageBuilder, kernel_file: Path):
        """Test adding a kernel to the package."""
        result = builder.add_kernel(kernel_file)
        assert result is builder

    def test_add_application(
        self, builder: PackageBuilder, firmware_file: Path
    ):
        """Test adding an application to the package."""
        result = builder.add_application(firmware_file)
        assert result is builder

    def test_build_package(
        self,
        builder: PackageBuilder,
        bootloader_file: Path,
        kernel_file: Path,
        firmware_file: Path,
    ):
        """Test building a complete package."""
        package_data = (
            builder.add_bootloader(bootloader_file)
            .add_kernel(kernel_file)
            .add_application(firmware_file)
            .build(version="1.0.0")
        )

        assert len(package_data) > 0
        # Should start with magic bytes
        assert package_data[:4] == PACKAGE_MAGIC

    def test_build_kernel_only(
        self, builder: PackageBuilder, kernel_file: Path
    ):
        """Test building package with only kernel."""
        package_data = builder.add_kernel(kernel_file).build(version="2.0.0")

        assert len(package_data) > 0
        assert package_data[:4] == PACKAGE_MAGIC

    def test_builder_chaining(
        self,
        signing_key: SigningKey,
        bootloader_file: Path,
        kernel_file: Path,
    ):
        """Test fluent builder pattern."""
        package_data = (
            PackageBuilder(signing_key, "stm32u5")
            .add_bootloader(bootloader_file)
            .add_kernel(kernel_file)
            .build("3.0.0")
        )

        assert len(package_data) > 0


class TestPackageExtractor:
    """Tests for PackageExtractor class."""

    @pytest.fixture
    def signing_key(self) -> SigningKey:
        """Create a signing key."""
        return SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="package-extractor",
            purpose="updates",
        )

    @pytest.fixture
    def extractor(self, signing_key: SigningKey) -> PackageExtractor:
        """Create a PackageExtractor with trusted key."""
        return PackageExtractor(trusted_keys={"package-extractor": signing_key})

    def test_creation(self, extractor: PackageExtractor):
        """Test creating a PackageExtractor."""
        assert extractor is not None

    def test_add_trusted_key(self, signing_key: SigningKey):
        """Test adding a trusted key."""
        extractor = PackageExtractor()
        extractor.add_trusted_key(signing_key)
        # Should not raise

    def test_extract_package(
        self,
        signing_key: SigningKey,
        extractor: PackageExtractor,
        kernel_file: Path,
        temp_dir: Path,
    ):
        """Test extracting a package."""
        # Build package
        builder = PackageBuilder(signing_key, "stm32h7")
        package_data = builder.add_kernel(kernel_file).build("1.0.0")

        # Extract
        output_dir = temp_dir / "extracted"
        output_dir.mkdir()

        package = extractor.extract(package_data, output_dir, verify=True)

        assert isinstance(package, UpdatePackage)
        assert package.version == "1.0.0"
        assert package.target_platform == "stm32h7"
        assert len(package.components) >= 1

    def test_extract_multiple_components(
        self,
        signing_key: SigningKey,
        extractor: PackageExtractor,
        bootloader_file: Path,
        kernel_file: Path,
        firmware_file: Path,
        temp_dir: Path,
    ):
        """Test extracting package with multiple components."""
        builder = PackageBuilder(signing_key, "stm32h7")
        package_data = (
            builder.add_bootloader(bootloader_file)
            .add_kernel(kernel_file)
            .add_application(firmware_file)
            .build("2.0.0")
        )

        output_dir = temp_dir / "multi_extract"
        output_dir.mkdir()

        package = extractor.extract(package_data, output_dir, verify=True)

        assert len(package.components) == 3

        # Check extracted files
        component_types = [c.image_type for c in package.components]
        assert "bootloader" in component_types
        assert "kernel" in component_types
        assert "application" in component_types

    def test_verify_only(
        self,
        signing_key: SigningKey,
        extractor: PackageExtractor,
        kernel_file: Path,
    ):
        """Test verifying without extracting."""
        builder = PackageBuilder(signing_key, "stm32h7")
        package_data = builder.add_kernel(kernel_file).build("1.0.0")

        result = extractor.verify_only(package_data)

        assert result is True

    def test_verify_tampered_package(
        self,
        signing_key: SigningKey,
        extractor: PackageExtractor,
        kernel_file: Path,
    ):
        """Test that tampered package fails verification."""
        builder = PackageBuilder(signing_key, "stm32h7")
        package_data = builder.add_kernel(kernel_file).build("1.0.0")

        # Tamper with package
        tampered = bytearray(package_data)
        tampered[len(tampered) // 2] ^= 0xFF
        tampered = bytes(tampered)

        result = extractor.verify_only(tampered)

        assert result is False


class TestUpdatePackage:
    """Tests for UpdatePackage dataclass."""

    def test_creation(self):
        """Test creating an UpdatePackage."""
        from datetime import datetime, timezone

        package = UpdatePackage(
            version="1.0.0",
            target_platform="stm32h7",
            created_at=datetime.now(timezone.utc),
            components=[],
            signature=None,
            signer_key_id=None,
        )

        assert package.version == "1.0.0"
        assert package.target_platform == "stm32h7"

    def test_with_components(self):
        """Test UpdatePackage with components."""
        from datetime import datetime, timezone

        components = [
            PackageComponent(
                name="kernel.bin",
                image_type="kernel",
                data=b"kernel_data",
                hash=os.urandom(32),
            ),
            PackageComponent(
                name="app.bin",
                image_type="application",
                data=b"app_data",
                hash=os.urandom(32),
            ),
        ]

        package = UpdatePackage(
            version="2.0.0",
            target_platform="stm32u5",
            created_at=datetime.now(timezone.utc),
            components=components,
            signature=os.urandom(3293),
            signer_key_id="test-key",
        )

        assert len(package.components) == 2
        assert package.signature is not None
        assert package.signer_key_id == "test-key"
