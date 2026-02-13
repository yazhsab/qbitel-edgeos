"""Tests for q-provision verification module."""

import os
from pathlib import Path

import pytest

from q_provision.verify import (
    VerificationResult,
    verify_commitment,
)


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_passed_result(self):
        """Test creating a passed verification result."""
        result = VerificationResult(
            passed=True,
            details="All checks passed",
            identity_valid=True,
            identity_details="Identity verified successfully",
        )
        assert result.passed is True
        assert result.identity_valid is True

    def test_failed_result(self):
        """Test creating a failed verification result."""
        result = VerificationResult(
            passed=False,
            details="Checksum mismatch",
            identity_valid=False,
            identity_details="Identity commitment invalid",
        )
        assert result.passed is False
        assert "mismatch" in result.details


class TestVerifyCommitment:
    """Tests for verify_commitment function."""

    def test_valid_commitment(self):
        """Test verifying a valid commitment."""
        # Create test data
        device_id = os.urandom(32)
        manufacturer_id = os.urandom(32)
        kem_public_key = os.urandom(1184)
        signature_public_key = os.urandom(1952)

        # Compute expected commitment (SHA3-256 of concatenated data)
        from Crypto.Hash import SHA3_256

        h = SHA3_256.new()
        h.update(device_id)
        h.update(manufacturer_id)
        h.update(kem_public_key)
        h.update(signature_public_key)
        expected_commitment = h.digest()

        # Verify
        result = verify_commitment(
            device_id=device_id,
            manufacturer_id=manufacturer_id,
            kem_public_key=kem_public_key,
            signature_public_key=signature_public_key,
            expected_commitment=expected_commitment,
        )

        assert result is True

    def test_invalid_commitment(self):
        """Test verifying an invalid commitment."""
        device_id = os.urandom(32)
        manufacturer_id = os.urandom(32)
        kem_public_key = os.urandom(1184)
        signature_public_key = os.urandom(1952)

        # Use wrong commitment
        wrong_commitment = os.urandom(32)

        result = verify_commitment(
            device_id=device_id,
            manufacturer_id=manufacturer_id,
            kem_public_key=kem_public_key,
            signature_public_key=signature_public_key,
            expected_commitment=wrong_commitment,
        )

        assert result is False

    def test_commitment_with_modified_device_id(self):
        """Test that modified device ID fails verification."""
        device_id = os.urandom(32)
        manufacturer_id = os.urandom(32)
        kem_public_key = os.urandom(1184)
        signature_public_key = os.urandom(1952)

        # Compute commitment with original device ID
        from Crypto.Hash import SHA3_256

        h = SHA3_256.new()
        h.update(device_id)
        h.update(manufacturer_id)
        h.update(kem_public_key)
        h.update(signature_public_key)
        commitment = h.digest()

        # Try to verify with different device ID
        different_device_id = os.urandom(32)

        result = verify_commitment(
            device_id=different_device_id,
            manufacturer_id=manufacturer_id,
            kem_public_key=kem_public_key,
            signature_public_key=signature_public_key,
            expected_commitment=commitment,
        )

        assert result is False

    def test_commitment_with_modified_keys(self):
        """Test that modified keys fail verification."""
        device_id = os.urandom(32)
        manufacturer_id = os.urandom(32)
        kem_public_key = os.urandom(1184)
        signature_public_key = os.urandom(1952)

        # Compute commitment
        from Crypto.Hash import SHA3_256

        h = SHA3_256.new()
        h.update(device_id)
        h.update(manufacturer_id)
        h.update(kem_public_key)
        h.update(signature_public_key)
        commitment = h.digest()

        # Modify one byte of the KEM key
        modified_kem_key = bytearray(kem_public_key)
        modified_kem_key[0] ^= 0xFF
        modified_kem_key = bytes(modified_kem_key)

        result = verify_commitment(
            device_id=device_id,
            manufacturer_id=manufacturer_id,
            kem_public_key=modified_kem_key,
            signature_public_key=signature_public_key,
            expected_commitment=commitment,
        )

        assert result is False
