"""Firmware signing for Qbitel EdgeOS with real PQC implementations.

This module provides firmware signing using post-quantum cryptographic
algorithms from the Open Quantum Safe (OQS) project or pure-Python
implementations as a fallback.

Supported algorithms:
- ML-DSA-65 (Dilithium3): NIST standardized, Level 3 security
- FN-DSA-512 (Falcon-512): Compact signatures, Level 1 security
- FN-DSA-1024 (Falcon-1024): NIST standardized, Level 5 security
"""

import json
import secrets
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple, Protocol, runtime_checkable

from Crypto.Hash import SHA3_256, SHA3_512, SHAKE256

# Try to import liboqs for real PQC implementation
try:
    import oqs
    HAS_LIBOQS = True
except ImportError:
    HAS_LIBOQS = False

# Try to import pure-Python dilithium implementation
try:
    from dilithium_py import Dilithium3 as PyDilithium3
    HAS_PY_DILITHIUM = True
except ImportError:
    HAS_PY_DILITHIUM = False


class SignatureAlgorithm(Enum):
    """Supported signature algorithms."""

    DILITHIUM3 = "dilithium3"  # ML-DSA-65
    FALCON512 = "falcon512"   # FN-DSA-512
    FALCON1024 = "falcon1024" # FN-DSA-1024

    @classmethod
    def from_string(cls, value: str) -> "SignatureAlgorithm":
        """Convert string to algorithm enum."""
        mapping = {
            "dilithium3": cls.DILITHIUM3,
            "ml-dsa-65": cls.DILITHIUM3,
            "mldsa65": cls.DILITHIUM3,
            "falcon512": cls.FALCON512,
            "fn-dsa-512": cls.FALCON512,
            "falcon1024": cls.FALCON1024,
            "fn-dsa-1024": cls.FALCON1024,
        }
        return mapping.get(value.lower(), cls.DILITHIUM3)

    @property
    def oqs_name(self) -> str:
        """Get liboqs algorithm name."""
        return {
            SignatureAlgorithm.DILITHIUM3: "Dilithium3",
            SignatureAlgorithm.FALCON512: "Falcon-512",
            SignatureAlgorithm.FALCON1024: "Falcon-1024",
        }[self]


# Key and signature sizes (NIST specified)
ALGORITHM_SIZES = {
    SignatureAlgorithm.DILITHIUM3: {
        "public_key": 1952,
        "secret_key": 4000,
        "signature": 3293,
        "security_level": 3,
    },
    SignatureAlgorithm.FALCON512: {
        "public_key": 897,
        "secret_key": 1281,
        "signature": 666,  # Average, can vary
        "security_level": 1,
    },
    SignatureAlgorithm.FALCON1024: {
        "public_key": 1793,
        "secret_key": 2305,
        "signature": 1280,  # Average, can vary
        "security_level": 5,
    },
}


@runtime_checkable
class SignatureScheme(Protocol):
    """Protocol for signature scheme implementations."""

    def keypair(self) -> Tuple[bytes, bytes]:
        """Generate key pair."""
        ...

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign a message."""
        ...

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature."""
        ...


class OQSSignatureScheme:
    """liboqs-based signature implementation."""

    def __init__(self, algorithm: SignatureAlgorithm) -> None:
        """Initialize with algorithm."""
        if not HAS_LIBOQS:
            raise RuntimeError("liboqs not available")
        self.algorithm = algorithm
        self.oqs_name = algorithm.oqs_name

    def keypair(self) -> Tuple[bytes, bytes]:
        """Generate key pair using liboqs."""
        with oqs.Signature(self.oqs_name) as sig:
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
            return (public_key, secret_key)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign message using liboqs."""
        with oqs.Signature(self.oqs_name, secret_key) as sig:
            return sig.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature using liboqs."""
        with oqs.Signature(self.oqs_name) as sig:
            return sig.verify(message, signature, public_key)


class PythonDilithiumScheme:
    """Pure Python Dilithium implementation."""

    def __init__(self) -> None:
        """Initialize Dilithium3 scheme."""
        if not HAS_PY_DILITHIUM:
            raise RuntimeError("dilithium-py not available")

    def keypair(self) -> Tuple[bytes, bytes]:
        """Generate key pair."""
        pk, sk = PyDilithium3.keygen()
        return (pk, sk)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign message."""
        return PyDilithium3.sign(secret_key, message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature."""
        try:
            PyDilithium3.verify(public_key, message, signature)
            return True
        except Exception:
            return False


class FallbackSignatureScheme:
    """Fallback using SHAKE256 for development/testing only.

    WARNING: This is NOT cryptographically secure for production use.
    It uses SHAKE256-based deterministic signing for development purposes only.
    """

    def __init__(self, algorithm: SignatureAlgorithm) -> None:
        """Initialize fallback scheme."""
        self.algorithm = algorithm
        self.sizes = ALGORITHM_SIZES[algorithm]

    def keypair(self) -> Tuple[bytes, bytes]:
        """Generate deterministic keypair from random seed."""
        seed = secrets.token_bytes(64)
        domain = f"{self.algorithm.value}_KEYGEN".encode()
        shake = SHAKE256.new(domain + seed)

        public_key = shake.read(self.sizes["public_key"])
        secret_key = seed + shake.read(self.sizes["secret_key"] - 64)

        return (public_key, secret_key)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Generate deterministic signature."""
        domain = f"{self.algorithm.value}_SIGN".encode()
        shake = SHAKE256.new(domain + secret_key + message)
        return shake.read(self.sizes["signature"])

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature length (fallback only checks length)."""
        # In fallback mode, we can't properly verify without the secret key
        # This is for development only
        if len(signature) != self.sizes["signature"]:
            return False
        return True


def get_signature_scheme(algorithm: SignatureAlgorithm) -> SignatureScheme:
    """Get the best available signature scheme for the algorithm.

    Priority:
    1. liboqs (if available) - production ready
    2. Pure Python implementation (if available)
    3. Fallback SHAKE256-based (development only)
    """
    # Try liboqs first
    if HAS_LIBOQS:
        try:
            return OQSSignatureScheme(algorithm)
        except Exception:
            pass

    # Try pure Python Dilithium for Dilithium3
    if algorithm == SignatureAlgorithm.DILITHIUM3 and HAS_PY_DILITHIUM:
        try:
            return PythonDilithiumScheme()
        except Exception:
            pass

    # Fallback to SHAKE256-based (development only)
    import warnings
    warnings.warn(
        f"Using FALLBACK signature scheme for {algorithm.value}. "
        "This is NOT secure for production use. "
        "Install liboqs-python for real PQC: pip install liboqs-python",
        category=UserWarning,
    )
    return FallbackSignatureScheme(algorithm)


@dataclass
class SignedManifest:
    """A signed firmware manifest."""

    manifest_data: bytes
    signature: bytes
    algorithm: SignatureAlgorithm
    signer_key_id: str


class SigningKey:
    """A cryptographic signing key with real PQC support."""

    def __init__(
        self,
        algorithm: SignatureAlgorithm,
        key_id: str,
        purpose: str,
        public_key: bytes,
        secret_key: Optional[bytes] = None,
        created_at: Optional[datetime] = None,
    ) -> None:
        """Initialize signing key.

        Args:
            algorithm: Signature algorithm
            key_id: Key identifier
            purpose: Key purpose (firmware, update, attestation)
            public_key: Public key bytes
            secret_key: Secret key bytes (None for public-only)
            created_at: Key creation timestamp
        """
        self.algorithm = algorithm
        self.key_id = key_id
        self.purpose = purpose
        self.public_key = public_key
        self.secret_key = secret_key
        self.created_at = created_at or datetime.now(timezone.utc)
        self._scheme = get_signature_scheme(algorithm)

    @classmethod
    def generate(
        cls,
        algorithm: SignatureAlgorithm,
        key_id: str,
        purpose: str = "firmware",
    ) -> "SigningKey":
        """Generate a new signing key pair.

        Uses the best available PQC implementation:
        - liboqs if available (production ready)
        - Pure Python implementation if available
        - SHAKE256 fallback for development

        Args:
            algorithm: Signature algorithm to use
            key_id: Key identifier
            purpose: Key purpose

        Returns:
            New SigningKey with both public and secret keys
        """
        scheme = get_signature_scheme(algorithm)
        public_key, secret_key = scheme.keypair()

        return cls(
            algorithm=algorithm,
            key_id=key_id,
            purpose=purpose,
            public_key=public_key,
            secret_key=secret_key,
        )

    def sign(self, message: bytes) -> bytes:
        """Sign a message using real PQC.

        Args:
            message: Message to sign

        Returns:
            Signature bytes

        Raises:
            ValueError: If secret key is not available
        """
        if self.secret_key is None:
            raise ValueError("Cannot sign without secret key")

        return self._scheme.sign(message, self.secret_key)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature using real PQC.

        Args:
            message: Original message
            signature: Signature to verify

        Returns:
            True if signature is valid
        """
        return self._scheme.verify(message, signature, self.public_key)

    def public_key_hash(self) -> str:
        """Get hash of public key for identification."""
        return SHA3_256.new(self.public_key).hexdigest()

    def security_info(self) -> dict:
        """Get security information about this key."""
        sizes = ALGORITHM_SIZES[self.algorithm]
        return {
            "algorithm": self.algorithm.value,
            "security_level": sizes["security_level"],
            "public_key_size": sizes["public_key"],
            "signature_size": sizes["signature"],
            "using_liboqs": HAS_LIBOQS,
            "using_py_dilithium": HAS_PY_DILITHIUM and self.algorithm == SignatureAlgorithm.DILITHIUM3,
            "is_fallback": not HAS_LIBOQS and not (HAS_PY_DILITHIUM and self.algorithm == SignatureAlgorithm.DILITHIUM3),
        }

    def save(self, path: Path) -> None:
        """Save key to file.

        Creates:
        - {path}_private.json - Full key with secret
        - {path}_public.json - Public key only
        """
        path = Path(path)

        # Save private key
        if self.secret_key:
            private_data = {
                "algorithm": self.algorithm.value,
                "key_id": self.key_id,
                "purpose": self.purpose,
                "created_at": self.created_at.isoformat(),
                "public_key": self.public_key.hex(),
                "secret_key": self.secret_key.hex(),
                "security_info": self.security_info(),
            }
            private_path = Path(f"{path}_private.json")
            with open(private_path, "w") as f:
                json.dump(private_data, f, indent=2)
            # Set restrictive permissions
            private_path.chmod(0o600)

        # Save public key
        public_data = {
            "algorithm": self.algorithm.value,
            "key_id": self.key_id,
            "purpose": self.purpose,
            "created_at": self.created_at.isoformat(),
            "public_key": self.public_key.hex(),
            "public_key_hash": self.public_key_hash(),
        }
        with open(f"{path}_public.json", "w") as f:
            json.dump(public_data, f, indent=2)

    def save_public(self, path: Path) -> None:
        """Save only public key to file."""
        public_data = {
            "algorithm": self.algorithm.value,
            "key_id": self.key_id,
            "purpose": self.purpose,
            "created_at": self.created_at.isoformat(),
            "public_key": self.public_key.hex(),
            "public_key_hash": self.public_key_hash(),
        }
        with open(path, "w") as f:
            json.dump(public_data, f, indent=2)

    @classmethod
    def load(cls, path: Path) -> "SigningKey":
        """Load key from file (with secret key)."""
        with open(f"{path}_private.json") as f:
            data = json.load(f)

        return cls(
            algorithm=SignatureAlgorithm(data["algorithm"]),
            key_id=data["key_id"],
            purpose=data["purpose"],
            public_key=bytes.fromhex(data["public_key"]),
            secret_key=bytes.fromhex(data["secret_key"]),
            created_at=datetime.fromisoformat(data["created_at"]),
        )

    @classmethod
    def load_public(cls, path: Path) -> "SigningKey":
        """Load public key only from file."""
        # Try loading as public key file
        try:
            with open(path) as f:
                data = json.load(f)
        except FileNotFoundError:
            with open(f"{path}_public.json") as f:
                data = json.load(f)

        return cls(
            algorithm=SignatureAlgorithm(data["algorithm"]),
            key_id=data["key_id"],
            purpose=data["purpose"],
            public_key=bytes.fromhex(data["public_key"]),
            secret_key=None,
            created_at=datetime.fromisoformat(data["created_at"]),
        )


class FirmwareSigner:
    """Signs firmware images and manifests using PQC."""

    def __init__(self, signing_key: SigningKey) -> None:
        """Initialize firmware signer.

        Args:
            signing_key: Key to use for signing
        """
        self.signing_key = signing_key

    def sign_manifest(self, manifest: "FirmwareManifest") -> SignedManifest:
        """Sign a firmware manifest.

        Args:
            manifest: Manifest to sign

        Returns:
            Signed manifest with signature
        """
        manifest_data = manifest.to_bytes()
        signature = self.signing_key.sign(manifest_data)

        return SignedManifest(
            manifest_data=manifest_data,
            signature=signature,
            algorithm=self.signing_key.algorithm,
            signer_key_id=self.signing_key.key_id,
        )

    def create_signed_image(
        self,
        image_data: bytes,
        signed_manifest: SignedManifest,
    ) -> bytes:
        """Create a signed firmware image.

        Image format:
        [Header - 64 bytes]
        [Manifest Data]
        [Signature]
        [Original Image Data]

        Header format:
        - [4 bytes] Magic "QSIG"
        - [4 bytes] Version
        - [4 bytes] Manifest length
        - [4 bytes] Signature length
        - [4 bytes] Image length
        - [4 bytes] Algorithm ID
        - [4 bytes] Flags
        - [36 bytes] Reserved

        Args:
            image_data: Original firmware image
            signed_manifest: Signed manifest

        Returns:
            Complete signed image
        """
        algorithm_ids = {
            SignatureAlgorithm.DILITHIUM3: 0x11,  # ML-DSA-65
            SignatureAlgorithm.FALCON512: 0x20,   # FN-DSA-512
            SignatureAlgorithm.FALCON1024: 0x21,  # FN-DSA-1024
        }

        # Flags
        flags = 0
        if HAS_LIBOQS:
            flags |= 0x01  # Signed with real PQC

        header = struct.pack(
            "<4sIIIIII36s",
            b"QSIG",
            1,  # Version
            len(signed_manifest.manifest_data),
            len(signed_manifest.signature),
            len(image_data),
            algorithm_ids[signed_manifest.algorithm],
            flags,
            b"\x00" * 36,  # Reserved
        )

        return (
            header
            + signed_manifest.manifest_data
            + signed_manifest.signature
            + image_data
        )

    @staticmethod
    def parse_signed_image(data: bytes) -> Tuple[bytes, bytes, bytes, dict]:
        """Parse a signed firmware image.

        Args:
            data: Signed image data

        Returns:
            Tuple of (manifest_data, signature, image_data, header_info)

        Raises:
            ValueError: If image format is invalid
        """
        if len(data) < 64:
            raise ValueError("Image too small for header")

        # Parse header
        magic, version, manifest_len, sig_len, image_len, algo_id, flags, _ = struct.unpack(
            "<4sIIIIII36s",
            data[:64]
        )

        if magic != b"QSIG":
            raise ValueError(f"Invalid magic: {magic}")

        if version != 1:
            raise ValueError(f"Unsupported version: {version}")

        offset = 64
        manifest_data = data[offset:offset + manifest_len]
        offset += manifest_len

        signature = data[offset:offset + sig_len]
        offset += sig_len

        image_data = data[offset:offset + image_len]

        algorithm_names = {
            0x11: "dilithium3",
            0x20: "falcon512",
            0x21: "falcon1024",
        }

        header_info = {
            "version": version,
            "algorithm": algorithm_names.get(algo_id, f"unknown-{algo_id}"),
            "algorithm_id": algo_id,
            "flags": flags,
            "uses_real_pqc": bool(flags & 0x01),
        }

        return (manifest_data, signature, image_data, header_info)

    def sign_data(self, data: bytes) -> bytes:
        """Sign arbitrary data.

        Args:
            data: Data to sign

        Returns:
            Signature bytes
        """
        return self.signing_key.sign(data)


class SignatureVerifier:
    """Verifies firmware signatures using PQC."""

    def __init__(self, public_key: SigningKey) -> None:
        """Initialize verifier with public key.

        Args:
            public_key: Public key for verification
        """
        if public_key.secret_key is not None:
            # Create a public-only copy
            self.public_key = SigningKey(
                algorithm=public_key.algorithm,
                key_id=public_key.key_id,
                purpose=public_key.purpose,
                public_key=public_key.public_key,
                secret_key=None,
                created_at=public_key.created_at,
            )
        else:
            self.public_key = public_key

    def verify_manifest(self, signed_manifest: SignedManifest) -> bool:
        """Verify a signed manifest.

        Args:
            signed_manifest: Manifest with signature

        Returns:
            True if signature is valid
        """
        return self.public_key.verify(
            signed_manifest.manifest_data,
            signed_manifest.signature
        )

    def verify_image(self, image_data: bytes) -> Tuple[bool, dict]:
        """Verify a signed firmware image.

        Args:
            image_data: Complete signed image

        Returns:
            Tuple of (is_valid, info_dict)
        """
        try:
            manifest_data, signature, _, header_info = FirmwareSigner.parse_signed_image(image_data)

            # Verify algorithm matches
            expected_algo = SignatureAlgorithm.from_string(header_info["algorithm"])
            if expected_algo != self.public_key.algorithm:
                return (False, {"error": "Algorithm mismatch"})

            is_valid = self.public_key.verify(manifest_data, signature)

            return (is_valid, {
                "algorithm": header_info["algorithm"],
                "uses_real_pqc": header_info["uses_real_pqc"],
                "key_id": self.public_key.key_id,
            })

        except Exception as e:
            return (False, {"error": str(e)})


# Import FirmwareManifest at runtime to avoid circular import
def _get_manifest_class():
    from .manifest import FirmwareManifest
    return FirmwareManifest


def check_pqc_availability() -> dict:
    """Check which PQC implementations are available.

    Returns:
        Dictionary with availability status
    """
    result = {
        "liboqs": HAS_LIBOQS,
        "dilithium_py": HAS_PY_DILITHIUM,
        "production_ready": HAS_LIBOQS,
        "available_algorithms": [],
    }

    if HAS_LIBOQS:
        result["available_algorithms"] = ["dilithium3", "falcon512", "falcon1024"]
        result["liboqs_version"] = getattr(oqs, "__version__", "unknown")
    elif HAS_PY_DILITHIUM:
        result["available_algorithms"] = ["dilithium3"]
    else:
        result["available_algorithms"] = ["dilithium3", "falcon512", "falcon1024"]
        result["warning"] = "Using FALLBACK mode - NOT secure for production"

    return result
