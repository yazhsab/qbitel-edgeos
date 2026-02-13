"""Tests for q-sign signer module."""

import os
from pathlib import Path

import pytest

from q_sign.signer import (
    SignatureAlgorithm,
    SigningKey,
    FirmwareSigner,
    SignatureVerifier,
    SignedManifest,
    get_signature_scheme,
    check_pqc_availability,
    ALGORITHM_SIZES,
)
from q_sign.manifest import FirmwareManifest, ImageType, ManifestBuilder


class TestSignatureAlgorithm:
    """Tests for SignatureAlgorithm enum."""

    def test_algorithms_exist(self):
        """Test all expected algorithms exist."""
        assert SignatureAlgorithm.DILITHIUM3
        assert SignatureAlgorithm.FALCON512
        assert SignatureAlgorithm.FALCON1024

    def test_from_string(self):
        """Test creating algorithm from string."""
        assert SignatureAlgorithm.from_string("dilithium3") == SignatureAlgorithm.DILITHIUM3
        assert SignatureAlgorithm.from_string("DILITHIUM3") == SignatureAlgorithm.DILITHIUM3
        assert SignatureAlgorithm.from_string("falcon512") == SignatureAlgorithm.FALCON512

    def test_from_string_invalid(self):
        """Test invalid algorithm string."""
        with pytest.raises(ValueError):
            SignatureAlgorithm.from_string("invalid_algorithm")

    def test_oqs_name(self):
        """Test OQS algorithm name property."""
        name = SignatureAlgorithm.DILITHIUM3.oqs_name
        assert "Dilithium" in name or "dilithium" in name.lower()


class TestAlgorithmSizes:
    """Tests for algorithm size constants."""

    def test_dilithium3_sizes(self):
        """Test Dilithium3 key/signature sizes."""
        sizes = ALGORITHM_SIZES[SignatureAlgorithm.DILITHIUM3]
        assert "public_key" in sizes
        assert "secret_key" in sizes
        assert "signature" in sizes
        assert sizes["public_key"] > 0
        assert sizes["secret_key"] > 0
        assert sizes["signature"] > 0

    def test_falcon_sizes(self):
        """Test Falcon key/signature sizes."""
        sizes512 = ALGORITHM_SIZES[SignatureAlgorithm.FALCON512]
        sizes1024 = ALGORITHM_SIZES[SignatureAlgorithm.FALCON1024]

        # Falcon1024 should have larger keys than Falcon512
        assert sizes1024["public_key"] > sizes512["public_key"]


class TestSigningKey:
    """Tests for SigningKey class."""

    def test_generate_dilithium_key(self):
        """Test generating Dilithium3 signing key."""
        key = SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="test-key-001",
            purpose="firmware",
        )

        assert key.algorithm == SignatureAlgorithm.DILITHIUM3
        assert key.key_id == "test-key-001"
        assert key.purpose == "firmware"
        assert len(key.public_key) > 0
        assert key.secret_key is not None
        assert len(key.secret_key) > 0

    def test_sign_and_verify(self):
        """Test signing and verifying a message."""
        key = SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="test",
            purpose="test",
        )

        message = b"test message to sign"
        signature = key.sign(message)

        assert len(signature) > 0
        assert key.verify(message, signature) is True

    def test_verify_wrong_message(self):
        """Test verification fails for wrong message."""
        key = SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="test",
            purpose="test",
        )

        message = b"original message"
        signature = key.sign(message)

        wrong_message = b"different message"
        assert key.verify(wrong_message, signature) is False

    def test_public_key_hash(self):
        """Test public key hash generation."""
        key = SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="test",
            purpose="test",
        )

        hash_str = key.public_key_hash()
        assert isinstance(hash_str, str)
        assert len(hash_str) == 64  # SHA3-256 hex

    def test_save_and_load(self, temp_dir: Path):
        """Test saving and loading signing key."""
        original = SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="persist-test",
            purpose="testing",
        )

        key_path = temp_dir / "signing_key"
        original.save(key_path)

        # Check files created
        assert (key_path.parent / f"{key_path.name}_secret.bin").exists() or \
               (key_path.with_suffix(".bin")).exists() or \
               key_path.exists()

        # Load and verify
        loaded = SigningKey.load(key_path)
        assert loaded.key_id == original.key_id
        assert loaded.algorithm == original.algorithm
        assert loaded.public_key == original.public_key

    def test_save_public_only(self, temp_dir: Path):
        """Test saving only public key."""
        key = SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="public-only",
            purpose="verification",
        )

        public_path = temp_dir / "public_key"
        key.save_public(public_path)

        # Load public key
        loaded = SigningKey.load_public(public_path)
        assert loaded.public_key == key.public_key
        assert loaded.secret_key is None  # No secret key

    def test_security_info(self):
        """Test security information retrieval."""
        key = SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="info-test",
            purpose="firmware",
        )

        info = key.security_info()
        assert "algorithm" in info
        assert "key_id" in info
        assert "purpose" in info
        assert "created_at" in info


class TestFirmwareSigner:
    """Tests for FirmwareSigner class."""

    @pytest.fixture
    def signing_key(self) -> SigningKey:
        """Create a signing key for tests."""
        return SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="test-signer",
            purpose="firmware",
        )

    @pytest.fixture
    def signer(self, signing_key: SigningKey) -> FirmwareSigner:
        """Create a FirmwareSigner instance."""
        return FirmwareSigner(signing_key)

    def test_sign_manifest(self, signer: FirmwareSigner, sample_firmware: bytes):
        """Test signing a firmware manifest."""
        manifest = ManifestBuilder().build(
            image_data=sample_firmware,
            image_type=ImageType.APPLICATION,
            version="1.0.0",
            rollback_version=1,
            hardware_version="1.0",
            signer_key_id="test-signer",
        )

        signed = signer.sign_manifest(manifest)

        assert isinstance(signed, SignedManifest)
        assert len(signed.signature) > 0
        assert signed.algorithm == SignatureAlgorithm.DILITHIUM3
        assert signed.signer_key_id == "test-signer"

    def test_create_signed_image(self, signer: FirmwareSigner, sample_firmware: bytes):
        """Test creating a complete signed image."""
        manifest = ManifestBuilder().build(
            image_data=sample_firmware,
            image_type=ImageType.APPLICATION,
            version="1.0.0",
            rollback_version=1,
            hardware_version="1.0",
            signer_key_id="test-signer",
        )

        signed_manifest = signer.sign_manifest(manifest)
        signed_image = signer.create_signed_image(sample_firmware, signed_manifest)

        assert len(signed_image) > len(sample_firmware)
        # Should start with magic bytes
        assert signed_image[:4] == b"QSIG"

    def test_parse_signed_image(self, signer: FirmwareSigner, sample_firmware: bytes):
        """Test parsing a signed image."""
        manifest = ManifestBuilder().build(
            image_data=sample_firmware,
            image_type=ImageType.APPLICATION,
            version="1.0.0",
            rollback_version=1,
            hardware_version="1.0",
            signer_key_id="test-signer",
        )

        signed_manifest = signer.sign_manifest(manifest)
        signed_image = signer.create_signed_image(sample_firmware, signed_manifest)

        # Parse it back
        manifest_data, signature, image_data, header = FirmwareSigner.parse_signed_image(
            signed_image
        )

        assert image_data == sample_firmware
        assert len(signature) > 0
        assert len(manifest_data) > 0


class TestSignatureVerifier:
    """Tests for SignatureVerifier class."""

    @pytest.fixture
    def key_pair(self) -> SigningKey:
        """Create a signing key for tests."""
        return SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="verifier-test",
            purpose="firmware",
        )

    def test_verify_manifest(self, key_pair: SigningKey, sample_firmware: bytes):
        """Test verifying a signed manifest."""
        signer = FirmwareSigner(key_pair)
        verifier = SignatureVerifier(key_pair)

        manifest = ManifestBuilder().build(
            image_data=sample_firmware,
            image_type=ImageType.APPLICATION,
            version="1.0.0",
            rollback_version=1,
            hardware_version="1.0",
            signer_key_id="verifier-test",
        )

        signed = signer.sign_manifest(manifest)
        result = verifier.verify_manifest(signed)

        assert result is True

    def test_verify_image(self, key_pair: SigningKey, sample_firmware: bytes):
        """Test verifying a complete signed image."""
        signer = FirmwareSigner(key_pair)
        verifier = SignatureVerifier(key_pair)

        manifest = ManifestBuilder().build(
            image_data=sample_firmware,
            image_type=ImageType.APPLICATION,
            version="1.0.0",
            rollback_version=1,
            hardware_version="1.0",
            signer_key_id="verifier-test",
        )

        signed_manifest = signer.sign_manifest(manifest)
        signed_image = signer.create_signed_image(sample_firmware, signed_manifest)

        valid, details = verifier.verify_image(signed_image)

        assert valid is True
        assert "manifest" in details or details.get("valid", False)

    def test_verify_tampered_image(self, key_pair: SigningKey, sample_firmware: bytes):
        """Test that tampered image fails verification."""
        signer = FirmwareSigner(key_pair)
        verifier = SignatureVerifier(key_pair)

        manifest = ManifestBuilder().build(
            image_data=sample_firmware,
            image_type=ImageType.APPLICATION,
            version="1.0.0",
            rollback_version=1,
            hardware_version="1.0",
            signer_key_id="verifier-test",
        )

        signed_manifest = signer.sign_manifest(manifest)
        signed_image = signer.create_signed_image(sample_firmware, signed_manifest)

        # Tamper with the image
        tampered = bytearray(signed_image)
        tampered[-100] ^= 0xFF  # Flip a bit in the firmware section
        tampered = bytes(tampered)

        valid, details = verifier.verify_image(tampered)

        assert valid is False


class TestGetSignatureScheme:
    """Tests for get_signature_scheme function."""

    def test_get_dilithium_scheme(self):
        """Test getting Dilithium scheme."""
        scheme = get_signature_scheme(SignatureAlgorithm.DILITHIUM3)
        assert hasattr(scheme, "keypair")
        assert hasattr(scheme, "sign")
        assert hasattr(scheme, "verify")

    def test_scheme_keypair_works(self):
        """Test that scheme can generate keypairs."""
        scheme = get_signature_scheme(SignatureAlgorithm.DILITHIUM3)
        public_key, secret_key = scheme.keypair()
        assert len(public_key) > 0
        assert len(secret_key) > 0


class TestPQCAvailability:
    """Tests for PQC availability checking."""

    def test_check_availability(self):
        """Test checking PQC library availability."""
        availability = check_pqc_availability()

        assert isinstance(availability, dict)
        assert "liboqs" in availability
        assert "dilithium_py" in availability

        # Values should be boolean
        for key, value in availability.items():
            assert isinstance(value, bool)
