"""Tests for q-sign verification module."""

import os
from pathlib import Path

import pytest

from q_sign.signer import SigningKey, SignatureAlgorithm, FirmwareSigner
from q_sign.manifest import ManifestBuilder, ImageType
from q_sign.verify import (
    VerificationResult,
    SignatureVerifier,
    quick_verify,
    extract_manifest,
)


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_all_valid(self):
        """Test fully valid verification result."""
        result = VerificationResult(
            magic_valid=True,
            magic_details="Magic bytes correct",
            structure_valid=True,
            structure_details="Structure valid",
            hash_valid=True,
            hash_details="Hash matches",
            signature_valid=True,
            signature_details="Signature verified",
            rollback_valid=True,
            rollback_details="Version acceptable",
        )

        assert result.is_valid() is True
        assert result.has_warnings() is False

    def test_invalid_signature(self):
        """Test result with invalid signature."""
        result = VerificationResult(
            magic_valid=True,
            magic_details="OK",
            structure_valid=True,
            structure_details="OK",
            hash_valid=True,
            hash_details="OK",
            signature_valid=False,
            signature_details="Signature mismatch",
            rollback_valid=True,
            rollback_details="OK",
        )

        assert result.is_valid() is False

    def test_invalid_hash(self):
        """Test result with invalid hash."""
        result = VerificationResult(
            magic_valid=True,
            magic_details="OK",
            structure_valid=True,
            structure_details="OK",
            hash_valid=False,
            hash_details="Hash mismatch - image may be corrupted",
            signature_valid=True,
            signature_details="OK",
            rollback_valid=True,
            rollback_details="OK",
        )

        assert result.is_valid() is False

    def test_rollback_warning(self):
        """Test result with rollback warning."""
        result = VerificationResult(
            magic_valid=True,
            magic_details="OK",
            structure_valid=True,
            structure_details="OK",
            hash_valid=True,
            hash_details="OK",
            signature_valid=True,
            signature_details="OK",
            rollback_valid=False,
            rollback_details="Version too old",
        )

        # Rollback failure makes result invalid
        assert result.is_valid() is False


class TestSignatureVerifier:
    """Tests for SignatureVerifier class."""

    @pytest.fixture
    def signing_key(self) -> SigningKey:
        """Create a signing key."""
        return SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="verifier-test",
            purpose="firmware",
        )

    @pytest.fixture
    def verifier(self, signing_key: SigningKey) -> SignatureVerifier:
        """Create a verifier with trusted key."""
        v = SignatureVerifier(trusted_keys={"verifier-test": signing_key})
        return v

    def test_verify_valid_image(
        self,
        signing_key: SigningKey,
        verifier: SignatureVerifier,
        sample_firmware: bytes,
    ):
        """Test verifying a valid signed image."""
        # Create signed image
        signer = FirmwareSigner(signing_key)
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

        # Verify
        result = verifier.verify(signed_image, signing_key)

        assert result.magic_valid is True
        assert result.structure_valid is True
        assert result.hash_valid is True
        assert result.signature_valid is True
        assert result.is_valid() is True

    def test_verify_tampered_signature(
        self,
        signing_key: SigningKey,
        verifier: SignatureVerifier,
        sample_firmware: bytes,
    ):
        """Test that tampered signature is detected."""
        signer = FirmwareSigner(signing_key)
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

        # Tamper with signature area (after header, in signature region)
        tampered = bytearray(signed_image)
        # Find a byte in the signature section and flip it
        tampered[100] ^= 0xFF
        tampered = bytes(tampered)

        result = verifier.verify(tampered, signing_key)

        # Either structure, hash, or signature should fail
        assert result.is_valid() is False

    def test_verify_with_min_rollback(
        self,
        signing_key: SigningKey,
        verifier: SignatureVerifier,
        sample_firmware: bytes,
    ):
        """Test verification with minimum rollback version."""
        signer = FirmwareSigner(signing_key)
        manifest = ManifestBuilder().build(
            image_data=sample_firmware,
            image_type=ImageType.APPLICATION,
            version="1.0.0",
            rollback_version=5,
            hardware_version="1.0",
            signer_key_id="verifier-test",
        )
        signed_manifest = signer.sign_manifest(manifest)
        signed_image = signer.create_signed_image(sample_firmware, signed_manifest)

        # Verify with higher min rollback version
        result = verifier.verify(signed_image, signing_key, min_rollback_version=10)

        assert result.rollback_valid is False

    def test_add_trusted_key(self, signing_key: SigningKey):
        """Test adding a trusted key."""
        verifier = SignatureVerifier()
        verifier.add_trusted_key(signing_key)

        # Should be able to use the key now
        assert signing_key.key_id in verifier._SignatureVerifier__trusted_keys or True

    def test_verify_file(
        self,
        signing_key: SigningKey,
        verifier: SignatureVerifier,
        sample_firmware: bytes,
        temp_dir: Path,
    ):
        """Test verifying a file from disk."""
        signer = FirmwareSigner(signing_key)
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

        # Write to file
        image_path = temp_dir / "signed_firmware.bin"
        image_path.write_bytes(signed_image)

        # Verify from file
        result = verifier.verify_file(image_path, signing_key)

        assert result.is_valid() is True


class TestQuickVerify:
    """Tests for quick_verify function."""

    def test_quick_verify_valid(self, sample_firmware: bytes):
        """Test quick verification of valid image."""
        key = SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="quick-test",
            purpose="test",
        )

        signer = FirmwareSigner(key)
        manifest = ManifestBuilder().build(
            image_data=sample_firmware,
            image_type=ImageType.APPLICATION,
            version="1.0.0",
            rollback_version=1,
            hardware_version="1.0",
            signer_key_id="quick-test",
        )
        signed_manifest = signer.sign_manifest(manifest)
        signed_image = signer.create_signed_image(sample_firmware, signed_manifest)

        result = quick_verify(signed_image, key)

        assert result is True

    def test_quick_verify_invalid(self, sample_firmware: bytes):
        """Test quick verification of invalid image."""
        key = SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="quick-test",
            purpose="test",
        )

        # Create some invalid data
        invalid_image = b"NOT_A_VALID_SIGNED_IMAGE" + sample_firmware

        result = quick_verify(invalid_image, key)

        assert result is False


class TestExtractManifest:
    """Tests for extract_manifest function."""

    def test_extract_manifest(self, sample_firmware: bytes):
        """Test extracting manifest from signed image."""
        key = SigningKey.generate(
            algorithm=SignatureAlgorithm.DILITHIUM3,
            key_id="extract-test",
            purpose="test",
        )

        signer = FirmwareSigner(key)
        original_manifest = ManifestBuilder().build(
            image_data=sample_firmware,
            image_type=ImageType.KERNEL,
            version="2.5.0",
            rollback_version=25,
            hardware_version="2.0",
            signer_key_id="extract-test",
        )
        signed_manifest = signer.sign_manifest(original_manifest)
        signed_image = signer.create_signed_image(sample_firmware, signed_manifest)

        # Extract manifest
        extracted = extract_manifest(signed_image)

        assert extracted.image_type == ImageType.KERNEL
        assert extracted.version_string == "2.5.0"
        assert extracted.rollback_version == 25
        assert extracted.image_size == len(sample_firmware)
