"""Signature verification for Qbitel EdgeOS firmware."""

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from Crypto.Hash import SHA3_256

from .signer import SigningKey, SignatureAlgorithm, ALGORITHM_SIZES
from .manifest import FirmwareManifest, MANIFEST_MAGIC


@dataclass
class VerificationResult:
    """Result of firmware verification."""

    # Individual check results
    magic_valid: bool = False
    magic_details: str = ""

    structure_valid: bool = False
    structure_details: str = ""

    hash_valid: bool = False
    hash_details: str = ""

    signature_valid: bool = False
    signature_details: str = ""

    rollback_valid: bool = True  # Default true, only false if explicitly failed
    rollback_details: str = ""

    # Parsed data
    manifest: Optional[FirmwareManifest] = None
    image_data: Optional[bytes] = None

    def is_valid(self) -> bool:
        """Check if all critical verifications passed."""
        return (
            self.magic_valid
            and self.structure_valid
            and self.hash_valid
            and self.signature_valid
        )

    def has_warnings(self) -> bool:
        """Check if there are non-critical warnings."""
        return not self.rollback_valid


class SignatureVerifier:
    """Verifies signed firmware images."""

    # Algorithm ID to enum mapping
    ALGORITHM_IDS = {
        1: SignatureAlgorithm.DILITHIUM3,
        2: SignatureAlgorithm.FALCON512,
        3: SignatureAlgorithm.FALCON1024,
    }

    def __init__(self, trusted_keys: Optional[dict[str, SigningKey]] = None) -> None:
        """Initialize verifier.

        Args:
            trusted_keys: Dictionary of trusted public keys by key ID
        """
        self.trusted_keys = trusted_keys or {}

    def add_trusted_key(self, key: SigningKey) -> None:
        """Add a trusted public key.

        Args:
            key: Public key to trust
        """
        self.trusted_keys[key.key_id] = key

    def verify(
        self,
        signed_data: bytes,
        public_key: Optional[SigningKey] = None,
        min_rollback_version: Optional[int] = None,
    ) -> VerificationResult:
        """Verify a signed firmware image.

        Args:
            signed_data: Complete signed image data
            public_key: Optional public key override
            min_rollback_version: Minimum acceptable rollback version

        Returns:
            VerificationResult with detailed status
        """
        result = VerificationResult()

        # Parse header
        try:
            header = self._parse_header(signed_data)
            result.magic_valid = True
            result.magic_details = "Valid QSIG header"
        except ValueError as e:
            result.magic_valid = False
            result.magic_details = str(e)
            return result

        # Validate structure
        try:
            manifest_data, signature, image_data = self._extract_components(
                signed_data, header
            )
            result.structure_valid = True
            result.structure_details = (
                f"Manifest: {len(manifest_data)}B, "
                f"Signature: {len(signature)}B, "
                f"Image: {len(image_data)}B"
            )
        except ValueError as e:
            result.structure_valid = False
            result.structure_details = str(e)
            return result

        # Parse manifest
        try:
            manifest = FirmwareManifest.from_bytes(manifest_data)
            result.manifest = manifest
        except ValueError as e:
            result.structure_valid = False
            result.structure_details = f"Invalid manifest: {e}"
            return result

        # Verify image hash
        computed_hash = SHA3_256.new(image_data).digest()
        if computed_hash == manifest.image_hash:
            result.hash_valid = True
            result.hash_details = f"SHA3-256: {computed_hash.hex()[:16]}..."
        else:
            result.hash_valid = False
            result.hash_details = (
                f"Expected: {manifest.image_hash.hex()[:16]}..., "
                f"Got: {computed_hash.hex()[:16]}..."
            )
            return result

        result.image_data = image_data

        # Get verification key
        verify_key = public_key
        if verify_key is None:
            verify_key = self.trusted_keys.get(manifest.signer_key_id)

        if verify_key is None:
            result.signature_valid = False
            result.signature_details = f"No trusted key for ID: {manifest.signer_key_id}"
            return result

        # Verify signature
        algorithm = self.ALGORITHM_IDS.get(header["algorithm_id"])
        if algorithm is None:
            result.signature_valid = False
            result.signature_details = f"Unknown algorithm ID: {header['algorithm_id']}"
            return result

        if verify_key.algorithm != algorithm:
            result.signature_valid = False
            result.signature_details = (
                f"Algorithm mismatch: key={verify_key.algorithm.value}, "
                f"signature={algorithm.value}"
            )
            return result

        # Verify the signature
        if verify_key.verify(manifest_data, signature):
            result.signature_valid = True
            result.signature_details = f"Valid {algorithm.value} signature by {manifest.signer_key_id}"
        else:
            result.signature_valid = False
            result.signature_details = "Signature verification failed"
            return result

        # Check rollback version
        if min_rollback_version is not None:
            if manifest.rollback_version >= min_rollback_version:
                result.rollback_valid = True
                result.rollback_details = f"Version {manifest.rollback_version} >= {min_rollback_version}"
            else:
                result.rollback_valid = False
                result.rollback_details = (
                    f"Rollback detected: {manifest.rollback_version} < {min_rollback_version}"
                )
        else:
            result.rollback_valid = True
            result.rollback_details = f"Version {manifest.rollback_version} (no minimum set)"

        return result

    def _parse_header(self, data: bytes) -> dict:
        """Parse signed image header.

        Returns:
            Dictionary with header fields
        """
        if len(data) < 56:  # Header size
            raise ValueError("Data too short for header")

        (
            magic,
            version,
            manifest_len,
            signature_len,
            image_len,
            algorithm_id,
            reserved,
        ) = struct.unpack("<4sIIIII32s", data[:56])

        if magic != b"QSIG":
            raise ValueError(f"Invalid magic: {magic}")

        if version != 1:
            raise ValueError(f"Unsupported version: {version}")

        return {
            "version": version,
            "manifest_len": manifest_len,
            "signature_len": signature_len,
            "image_len": image_len,
            "algorithm_id": algorithm_id,
        }

    def _extract_components(
        self, data: bytes, header: dict
    ) -> tuple[bytes, bytes, bytes]:
        """Extract manifest, signature, and image from signed data.

        Returns:
            Tuple of (manifest_data, signature, image_data)
        """
        offset = 56  # Header size

        manifest_end = offset + header["manifest_len"]
        signature_end = manifest_end + header["signature_len"]
        image_end = signature_end + header["image_len"]

        if len(data) < image_end:
            raise ValueError(
                f"Data truncated: expected {image_end}, got {len(data)}"
            )

        manifest_data = data[offset:manifest_end]
        signature = data[manifest_end:signature_end]
        image_data = data[signature_end:image_end]

        return manifest_data, signature, image_data

    def verify_file(
        self,
        image_path: Path,
        public_key: Optional[SigningKey] = None,
        min_rollback_version: Optional[int] = None,
    ) -> VerificationResult:
        """Verify a signed firmware file.

        Args:
            image_path: Path to signed firmware image
            public_key: Optional public key override
            min_rollback_version: Minimum acceptable rollback version

        Returns:
            VerificationResult with detailed status
        """
        with open(image_path, "rb") as f:
            data = f.read()

        return self.verify(data, public_key, min_rollback_version)


def quick_verify(signed_data: bytes, public_key: SigningKey) -> bool:
    """Quick verification that returns only pass/fail.

    Args:
        signed_data: Signed firmware image
        public_key: Public key for verification

    Returns:
        True if verification passed
    """
    verifier = SignatureVerifier()
    result = verifier.verify(signed_data, public_key)
    return result.is_valid()


def extract_manifest(signed_data: bytes) -> FirmwareManifest:
    """Extract manifest from signed image without full verification.

    Args:
        signed_data: Signed firmware image

    Returns:
        Parsed manifest

    Raises:
        ValueError: If manifest cannot be extracted
    """
    if len(signed_data) < 56:
        raise ValueError("Data too short for header")

    (
        magic,
        version,
        manifest_len,
        signature_len,
        image_len,
        algorithm_id,
        reserved,
    ) = struct.unpack("<4sIIIII32s", signed_data[:56])

    if magic != b"QSIG":
        raise ValueError(f"Invalid magic: {magic}")

    manifest_data = signed_data[56 : 56 + manifest_len]
    return FirmwareManifest.from_bytes(manifest_data)
