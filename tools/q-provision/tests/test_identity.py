"""Tests for q-provision identity module."""

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from q_provision.identity import (
    DeviceIdentity,
    DeviceIdentityPublic,
    DeviceIdentitySecrets,
    IdentityCommitment,
    IdentityGenerator,
    generate_batch_identities,
)
from q_provision.config import ProvisioningConfig


class TestDeviceIdentitySecrets:
    """Tests for DeviceIdentitySecrets dataclass."""

    def test_creation(self):
        """Test creating device identity secrets."""
        secrets = DeviceIdentitySecrets(
            kem_secret_key=os.urandom(2400),
            signature_secret_key=os.urandom(4000),
            hardware_secret=os.urandom(32),
        )
        assert len(secrets.kem_secret_key) == 2400
        assert len(secrets.signature_secret_key) == 4000
        assert len(secrets.hardware_secret) == 32


class TestDeviceIdentityPublic:
    """Tests for DeviceIdentityPublic dataclass."""

    def test_creation(self):
        """Test creating public device identity."""
        public = DeviceIdentityPublic(
            device_id=os.urandom(32),
            manufacturer_id=os.urandom(32),
            device_class="edge-sensor",
            kem_public_key=os.urandom(1184),
            signature_public_key=os.urandom(1952),
            created_at=datetime.now(timezone.utc),
        )
        assert public.device_class == "edge-sensor"
        assert len(public.device_id) == 32


class TestDeviceIdentity:
    """Tests for DeviceIdentity dataclass."""

    def test_creation(self):
        """Test creating complete device identity."""
        public = DeviceIdentityPublic(
            device_id=os.urandom(32),
            manufacturer_id=os.urandom(32),
            device_class="gateway",
            kem_public_key=os.urandom(1184),
            signature_public_key=os.urandom(1952),
            created_at=datetime.now(timezone.utc),
        )
        secrets = DeviceIdentitySecrets(
            kem_secret_key=os.urandom(2400),
            signature_secret_key=os.urandom(4000),
            hardware_secret=os.urandom(32),
        )
        identity = DeviceIdentity(public=public, secrets=secrets)

        assert identity.public.device_class == "gateway"
        assert len(identity.secrets.kem_secret_key) == 2400


class TestIdentityCommitment:
    """Tests for IdentityCommitment dataclass."""

    def test_creation(self):
        """Test creating identity commitment."""
        commitment = IdentityCommitment(
            version=1,
            hash=os.urandom(32),
            device_id=os.urandom(32),
            created_at=datetime.now(timezone.utc),
        )
        assert commitment.version == 1
        assert len(commitment.hash) == 32

    def test_to_bytes_roundtrip(self):
        """Test serialization and deserialization."""
        original = IdentityCommitment(
            version=1,
            hash=os.urandom(32),
            device_id=os.urandom(32),
            created_at=datetime.now(timezone.utc),
        )

        serialized = original.to_bytes()
        restored = IdentityCommitment.from_bytes(serialized)

        assert restored.version == original.version
        assert restored.hash == original.hash
        assert restored.device_id == original.device_id


class TestIdentityGenerator:
    """Tests for IdentityGenerator class."""

    @pytest.fixture
    def generator(self) -> IdentityGenerator:
        """Create an IdentityGenerator instance."""
        config = ProvisioningConfig()
        return IdentityGenerator(config)

    def test_creation(self, generator: IdentityGenerator):
        """Test creating generator."""
        assert generator is not None
        assert generator.COMMITMENT_VERSION == 1

    def test_generate_identity(
        self,
        generator: IdentityGenerator,
        sample_device_id: bytes,
        sample_manufacturer_id: bytes,
    ):
        """Test generating a device identity."""
        identity = generator.generate_identity(
            device_id=sample_device_id,
            manufacturer_id=sample_manufacturer_id,
            device_class="test-device",
            puf_response=None,
        )

        assert identity.public.device_id == sample_device_id
        assert identity.public.manufacturer_id == sample_manufacturer_id
        assert identity.public.device_class == "test-device"
        assert len(identity.public.kem_public_key) > 0
        assert len(identity.public.signature_public_key) > 0
        assert len(identity.secrets.kem_secret_key) > 0
        assert len(identity.secrets.signature_secret_key) > 0

    def test_generate_identity_with_puf(
        self,
        generator: IdentityGenerator,
        sample_device_id: bytes,
        sample_manufacturer_id: bytes,
        mock_puf_response: bytes,
    ):
        """Test generating identity with PUF response."""
        identity = generator.generate_identity(
            device_id=sample_device_id,
            manufacturer_id=sample_manufacturer_id,
            device_class="secure-device",
            puf_response=mock_puf_response,
        )

        assert identity.secrets.hardware_secret is not None
        # Hardware secret should incorporate PUF response
        assert len(identity.secrets.hardware_secret) == 32

    def test_create_commitment(
        self,
        generator: IdentityGenerator,
        sample_device_id: bytes,
        sample_manufacturer_id: bytes,
    ):
        """Test creating identity commitment."""
        identity = generator.generate_identity(
            device_id=sample_device_id,
            manufacturer_id=sample_manufacturer_id,
            device_class="test",
            puf_response=None,
        )

        commitment = generator.create_commitment(identity)

        assert commitment.version == generator.COMMITMENT_VERSION
        assert commitment.device_id == sample_device_id
        assert len(commitment.hash) == 32  # SHA3-256

    def test_save_and_load_identity(
        self,
        generator: IdentityGenerator,
        sample_device_id: bytes,
        sample_manufacturer_id: bytes,
        temp_dir: Path,
    ):
        """Test saving and loading identity."""
        identity = generator.generate_identity(
            device_id=sample_device_id,
            manufacturer_id=sample_manufacturer_id,
            device_class="test",
            puf_response=None,
        )
        commitment = generator.create_commitment(identity)

        output_path = temp_dir / "identity"
        generator.save_identity(identity, commitment, output_path)

        # Verify files created
        assert (output_path / "identity_public.json").exists()
        assert (output_path / "identity_secrets.bin").exists()
        assert (output_path / "commitment.bin").exists()

        # Load and verify
        loaded_identity, loaded_commitment = generator.load_identity(output_path)

        assert loaded_identity.public.device_id == identity.public.device_id
        assert loaded_identity.public.device_class == identity.public.device_class
        assert loaded_commitment.hash == commitment.hash


class TestBatchIdentityGeneration:
    """Tests for batch identity generation."""

    def test_generate_batch(self, temp_dir: Path, sample_manufacturer_id: bytes):
        """Test generating multiple identities."""
        config = ProvisioningConfig()
        count = 5
        prefix = b"\x00\x01"

        identities = generate_batch_identities(
            config=config,
            manufacturer_id=sample_manufacturer_id,
            device_class="batch-device",
            count=count,
            output_dir=temp_dir,
            id_prefix=prefix,
        )

        assert len(identities) == count

        # Verify each identity is unique
        device_ids = [id.public.device_id for id, _ in identities]
        assert len(set(device_ids)) == count  # All unique

        # Verify files created
        for i in range(count):
            device_dir = temp_dir / f"device_{i:04d}"
            assert device_dir.exists()

    def test_batch_identities_have_commitments(
        self, temp_dir: Path, sample_manufacturer_id: bytes
    ):
        """Test that batch identities have valid commitments."""
        config = ProvisioningConfig()

        identities = generate_batch_identities(
            config=config,
            manufacturer_id=sample_manufacturer_id,
            device_class="test",
            count=3,
            output_dir=temp_dir,
            id_prefix=b"\xAB",
        )

        for identity, commitment in identities:
            assert commitment.device_id == identity.public.device_id
            assert len(commitment.hash) == 32
            assert commitment.version == 1
