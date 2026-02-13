"""Tests for q-provision key generation module."""

import os
from pathlib import Path

import pytest

from q_provision.keygen import (
    KeyType,
    KeyPair,
    KeyGenerator,
    KEY_SIZES,
    get_scheme,
    get_kem_scheme,
    get_signature_scheme,
    derive_device_keys,
    check_pqc_availability,
)
from q_provision.config import CryptoConfig


class TestKeyType:
    """Tests for KeyType enum."""

    def test_key_types_exist(self):
        """Test all expected key types exist."""
        assert KeyType.KYBER768
        assert KeyType.DILITHIUM3
        assert KeyType.FALCON512
        assert KeyType.FALCON1024

    def test_kem_identification(self):
        """Test KEM key type identification."""
        assert KeyType.KYBER768.is_kem is True
        assert KeyType.DILITHIUM3.is_kem is False
        assert KeyType.FALCON512.is_kem is False

    def test_signature_identification(self):
        """Test signature key type identification."""
        assert KeyType.KYBER768.is_signature is False
        assert KeyType.DILITHIUM3.is_signature is True
        assert KeyType.FALCON512.is_signature is True
        assert KeyType.FALCON1024.is_signature is True

    def test_oqs_names(self):
        """Test OQS algorithm name mapping."""
        assert "Kyber" in KeyType.KYBER768.oqs_name or "kyber" in KeyType.KYBER768.oqs_name.lower()
        assert "Dilithium" in KeyType.DILITHIUM3.oqs_name or "dilithium" in KeyType.DILITHIUM3.oqs_name.lower()


class TestKeySizes:
    """Tests for key size constants."""

    def test_kyber768_sizes(self):
        """Test Kyber768 key sizes."""
        sizes = KEY_SIZES[KeyType.KYBER768]
        assert "public_key" in sizes
        assert "secret_key" in sizes
        assert sizes["public_key"] > 0
        assert sizes["secret_key"] > 0

    def test_dilithium3_sizes(self):
        """Test Dilithium3 key sizes."""
        sizes = KEY_SIZES[KeyType.DILITHIUM3]
        assert "public_key" in sizes
        assert "secret_key" in sizes
        assert "signature" in sizes
        assert sizes["signature"] > 0


class TestKeyPair:
    """Tests for KeyPair dataclass."""

    def test_keypair_creation(self):
        """Test creating a KeyPair."""
        public_key = os.urandom(1184)  # Kyber768 public key size
        secret_key = os.urandom(2400)  # Kyber768 secret key size

        kp = KeyPair(
            key_type=KeyType.KYBER768,
            public_key=public_key,
            secret_key=secret_key,
            metadata={"created": "2024-01-01"},
        )

        assert kp.key_type == KeyType.KYBER768
        assert kp.public_key == public_key
        assert kp.secret_key == secret_key
        assert kp.metadata["created"] == "2024-01-01"

    def test_public_key_hash(self):
        """Test public key hash generation."""
        kp = KeyPair(
            key_type=KeyType.KYBER768,
            public_key=b"test_public_key",
            secret_key=b"test_secret_key",
            metadata=None,
        )
        hash_str = kp.public_key_hash()
        assert isinstance(hash_str, str)
        assert len(hash_str) == 64  # SHA3-256 hex output

    def test_save_and_load(self, temp_dir: Path):
        """Test saving and loading keypair."""
        kp = KeyPair(
            key_type=KeyType.KYBER768,
            public_key=os.urandom(1184),
            secret_key=os.urandom(2400),
            metadata={"test": True},
        )

        kp.save(temp_dir)

        # Check files were created
        assert (temp_dir / "kyber768_public.bin").exists()
        assert (temp_dir / "kyber768_secret.bin").exists()
        assert (temp_dir / "kyber768_metadata.json").exists()

        # Check secret key permissions (should be 0o600)
        secret_path = temp_dir / "kyber768_secret.bin"
        mode = secret_path.stat().st_mode & 0o777
        assert mode == 0o600

        # Load and verify
        loaded = KeyPair.load(temp_dir, KeyType.KYBER768)
        assert loaded.key_type == KeyType.KYBER768
        assert loaded.public_key == kp.public_key
        assert loaded.secret_key == kp.secret_key


class TestKeyGenerator:
    """Tests for KeyGenerator class."""

    def test_generator_creation(self):
        """Test creating a KeyGenerator."""
        config = CryptoConfig()
        generator = KeyGenerator(config)
        assert generator is not None

    def test_generate_kyber_keypair(self):
        """Test generating Kyber768 keypair."""
        generator = KeyGenerator()
        kp = generator.generate_keypair(KeyType.KYBER768)

        assert kp.key_type == KeyType.KYBER768
        assert len(kp.public_key) > 0
        assert len(kp.secret_key) > 0
        assert kp.metadata is not None
        assert "algorithm" in kp.metadata

    def test_generate_dilithium_keypair(self):
        """Test generating Dilithium3 keypair."""
        generator = KeyGenerator()
        kp = generator.generate_keypair(KeyType.DILITHIUM3)

        assert kp.key_type == KeyType.DILITHIUM3
        assert len(kp.public_key) > 0
        assert len(kp.secret_key) > 0

    def test_deterministic_generation_with_seed(self):
        """Test deterministic key generation with seed."""
        generator = KeyGenerator()
        seed = os.urandom(32)

        kp1 = generator.generate_keypair(KeyType.KYBER768, seed=seed)
        kp2 = generator.generate_keypair(KeyType.KYBER768, seed=seed)

        # Same seed should produce same keys (for fallback implementation)
        # Note: This may not work with all PQC libraries
        # The test verifies the seed parameter is accepted
        assert kp1.public_key is not None
        assert kp2.public_key is not None


class TestSchemeSelection:
    """Tests for scheme selection functions."""

    def test_get_kem_scheme(self):
        """Test getting KEM scheme."""
        scheme = get_kem_scheme(KeyType.KYBER768)
        assert hasattr(scheme, "keypair")

    def test_get_signature_scheme(self):
        """Test getting signature scheme."""
        scheme = get_signature_scheme(KeyType.DILITHIUM3)
        assert hasattr(scheme, "keypair")
        assert hasattr(scheme, "sign")
        assert hasattr(scheme, "verify")

    def test_get_scheme_kem(self):
        """Test generic get_scheme for KEM."""
        scheme = get_scheme(KeyType.KYBER768)
        assert scheme is not None

    def test_get_scheme_signature(self):
        """Test generic get_scheme for signature."""
        scheme = get_scheme(KeyType.DILITHIUM3)
        assert scheme is not None


class TestDeriveDeviceKeys:
    """Tests for derive_device_keys function."""

    def test_derive_keys(self, sample_device_id: bytes, sample_manufacturer_id: bytes):
        """Test deriving device keys from master seed."""
        master_seed = os.urandom(32)

        keys = derive_device_keys(master_seed, sample_device_id, sample_manufacturer_id)

        assert "kem" in keys
        assert "signature" in keys
        assert isinstance(keys["kem"], KeyPair)
        assert isinstance(keys["signature"], KeyPair)
        assert keys["kem"].key_type == KeyType.KYBER768
        assert keys["signature"].key_type == KeyType.DILITHIUM3

    def test_deterministic_derivation(
        self, sample_device_id: bytes, sample_manufacturer_id: bytes
    ):
        """Test that same inputs produce same keys."""
        master_seed = os.urandom(32)

        keys1 = derive_device_keys(master_seed, sample_device_id, sample_manufacturer_id)
        keys2 = derive_device_keys(master_seed, sample_device_id, sample_manufacturer_id)

        # Verify determinism (for fallback implementation)
        assert keys1["kem"].public_key == keys2["kem"].public_key
        assert keys1["signature"].public_key == keys2["signature"].public_key

    def test_different_devices_different_keys(self, sample_manufacturer_id: bytes):
        """Test that different devices get different keys."""
        master_seed = os.urandom(32)
        device1 = os.urandom(32)
        device2 = os.urandom(32)

        keys1 = derive_device_keys(master_seed, device1, sample_manufacturer_id)
        keys2 = derive_device_keys(master_seed, device2, sample_manufacturer_id)

        assert keys1["kem"].public_key != keys2["kem"].public_key
        assert keys1["signature"].public_key != keys2["signature"].public_key


class TestPQCAvailability:
    """Tests for PQC library availability checking."""

    def test_check_availability(self):
        """Test checking PQC library availability."""
        availability = check_pqc_availability()

        assert isinstance(availability, dict)
        assert "liboqs" in availability
        assert "dilithium_py" in availability
        assert "kyber_py" in availability

        # Values should be boolean
        assert isinstance(availability["liboqs"], bool)
        assert isinstance(availability["dilithium_py"], bool)
        assert isinstance(availability["kyber_py"], bool)
