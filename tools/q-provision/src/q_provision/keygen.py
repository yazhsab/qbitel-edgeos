"""Post-quantum key generation for Qbitel EdgeOS devices.

This module provides real PQC key generation using:
- liboqs (Open Quantum Safe) for production use
- Pure Python implementations as fallback
- SHAKE256-based fallback for development only

Supported algorithms:
- ML-KEM-768 (Kyber768): NIST Level 3 KEM
- ML-DSA-65 (Dilithium3): NIST Level 3 signatures
- FN-DSA-512 (Falcon512): NIST Level 1 signatures
- FN-DSA-1024 (Falcon1024): NIST Level 5 signatures
"""

import hashlib
import secrets
import warnings
from dataclasses import dataclass
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

# Try to import pure-Python implementations
try:
    from dilithium_py import Dilithium3 as PyDilithium3
    HAS_PY_DILITHIUM = True
except ImportError:
    HAS_PY_DILITHIUM = False

try:
    from kyber_py import Kyber768 as PyKyber768
    HAS_PY_KYBER = True
except ImportError:
    HAS_PY_KYBER = False


class KeyType(Enum):
    """Supported key types for Qbitel EdgeOS."""

    KYBER768 = "kyber768"
    DILITHIUM3 = "dilithium3"
    FALCON512 = "falcon512"
    FALCON1024 = "falcon1024"

    @property
    def oqs_name(self) -> str:
        """Get liboqs algorithm name."""
        mapping = {
            KeyType.KYBER768: "Kyber768",
            KeyType.DILITHIUM3: "Dilithium3",
            KeyType.FALCON512: "Falcon-512",
            KeyType.FALCON1024: "Falcon-1024",
        }
        return mapping[self]

    @property
    def is_kem(self) -> bool:
        """Check if this is a KEM algorithm."""
        return self == KeyType.KYBER768

    @property
    def is_signature(self) -> bool:
        """Check if this is a signature algorithm."""
        return self in (KeyType.DILITHIUM3, KeyType.FALCON512, KeyType.FALCON1024)


# Key sizes from NIST PQC standards
KEY_SIZES = {
    KeyType.KYBER768: {
        "public_key": 1184,
        "secret_key": 2400,
        "ciphertext": 1088,
        "shared_secret": 32,
        "security_level": 3,
    },
    KeyType.DILITHIUM3: {
        "public_key": 1952,
        "secret_key": 4000,
        "signature": 3293,
        "security_level": 3,
    },
    KeyType.FALCON512: {
        "public_key": 897,
        "secret_key": 1281,
        "signature": 666,  # Average, can vary
        "security_level": 1,
    },
    KeyType.FALCON1024: {
        "public_key": 1793,
        "secret_key": 2305,
        "signature": 1280,  # Average, can vary
        "security_level": 5,
    },
}


@runtime_checkable
class KeyScheme(Protocol):
    """Protocol for key generation scheme implementations."""

    def keypair(self) -> Tuple[bytes, bytes]:
        """Generate a key pair. Returns (public_key, secret_key)."""
        ...


class OQSKemScheme:
    """liboqs-based KEM implementation."""

    def __init__(self, algorithm: KeyType) -> None:
        """Initialize with algorithm."""
        if not HAS_LIBOQS:
            raise RuntimeError("liboqs not available")
        self.algorithm = algorithm
        self.oqs_name = algorithm.oqs_name

    def keypair(self) -> Tuple[bytes, bytes]:
        """Generate KEM key pair using liboqs."""
        with oqs.KeyEncapsulation(self.oqs_name) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return (public_key, secret_key)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate to create shared secret."""
        with oqs.KeyEncapsulation(self.oqs_name) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return (ciphertext, shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate to recover shared secret."""
        with oqs.KeyEncapsulation(self.oqs_name, secret_key) as kem:
            return kem.decap_secret(ciphertext)


class OQSSignatureScheme:
    """liboqs-based signature implementation."""

    def __init__(self, algorithm: KeyType) -> None:
        """Initialize with algorithm."""
        if not HAS_LIBOQS:
            raise RuntimeError("liboqs not available")
        self.algorithm = algorithm
        self.oqs_name = algorithm.oqs_name

    def keypair(self) -> Tuple[bytes, bytes]:
        """Generate signature key pair using liboqs."""
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


class PythonKyberScheme:
    """Pure Python Kyber implementation."""

    def __init__(self) -> None:
        """Initialize Kyber768 scheme."""
        if not HAS_PY_KYBER:
            raise RuntimeError("kyber-py not available")

    def keypair(self) -> Tuple[bytes, bytes]:
        """Generate key pair."""
        pk, sk = PyKyber768.keygen()
        return (pk, sk)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate to create shared secret."""
        ciphertext, shared_secret = PyKyber768.encaps(public_key)
        return (ciphertext, shared_secret)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate to recover shared secret."""
        return PyKyber768.decaps(secret_key, ciphertext)


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


class FallbackScheme:
    """Fallback using SHAKE256 for development/testing only.

    WARNING: This is NOT cryptographically secure for production use.
    It uses SHAKE256-based deterministic key derivation for development purposes only.
    """

    def __init__(self, key_type: KeyType) -> None:
        """Initialize fallback scheme."""
        self.key_type = key_type
        self.sizes = KEY_SIZES[key_type]

    def keypair(self) -> Tuple[bytes, bytes]:
        """Generate deterministic keypair from random seed."""
        seed = secrets.token_bytes(64)
        domain = f"{self.key_type.value}_KEYGEN".encode()
        shake = SHAKE256.new(domain + seed)

        public_key = shake.read(self.sizes["public_key"])
        # Include seed in secret key for reproducibility
        secret_key = seed + shake.read(self.sizes["secret_key"] - 64)

        return (public_key, secret_key)

    def keypair_from_seed(self, seed: bytes) -> Tuple[bytes, bytes]:
        """Generate keypair from specific seed (for deterministic generation)."""
        domain = f"{self.key_type.value}_KEYGEN".encode()
        shake = SHAKE256.new(domain + seed)

        public_key = shake.read(self.sizes["public_key"])
        secret_key = seed + shake.read(self.sizes["secret_key"] - 64)

        return (public_key, secret_key)


def get_kem_scheme(key_type: KeyType) -> KeyScheme:
    """Get the best available KEM scheme.

    Priority:
    1. liboqs (if available) - production ready
    2. Pure Python implementation (if available)
    3. Fallback SHAKE256-based (development only)
    """
    if key_type != KeyType.KYBER768:
        raise ValueError(f"Not a KEM algorithm: {key_type}")

    # Try liboqs first
    if HAS_LIBOQS:
        try:
            return OQSKemScheme(key_type)
        except Exception:
            pass

    # Try pure Python Kyber
    if HAS_PY_KYBER:
        try:
            return PythonKyberScheme()
        except Exception:
            pass

    # Fallback
    warnings.warn(
        f"Using FALLBACK KEM scheme for {key_type.value}. "
        "This is NOT secure for production use. "
        "Install liboqs-python for real PQC: pip install liboqs-python",
        category=UserWarning,
    )
    return FallbackScheme(key_type)


def get_signature_scheme(key_type: KeyType) -> KeyScheme:
    """Get the best available signature scheme.

    Priority:
    1. liboqs (if available) - production ready
    2. Pure Python implementation (if available)
    3. Fallback SHAKE256-based (development only)
    """
    if key_type == KeyType.KYBER768:
        raise ValueError(f"Not a signature algorithm: {key_type}")

    # Try liboqs first
    if HAS_LIBOQS:
        try:
            return OQSSignatureScheme(key_type)
        except Exception:
            pass

    # Try pure Python Dilithium for Dilithium3
    if key_type == KeyType.DILITHIUM3 and HAS_PY_DILITHIUM:
        try:
            return PythonDilithiumScheme()
        except Exception:
            pass

    # Fallback
    warnings.warn(
        f"Using FALLBACK signature scheme for {key_type.value}. "
        "This is NOT secure for production use. "
        "Install liboqs-python for real PQC: pip install liboqs-python",
        category=UserWarning,
    )
    return FallbackScheme(key_type)


def get_scheme(key_type: KeyType) -> KeyScheme:
    """Get the best available scheme for the key type."""
    if key_type.is_kem:
        return get_kem_scheme(key_type)
    else:
        return get_signature_scheme(key_type)


@dataclass
class KeyPair:
    """A cryptographic key pair."""

    key_type: KeyType
    public_key: bytes
    secret_key: bytes
    metadata: Optional[dict] = None

    def save(self, output_dir: Path) -> None:
        """Save key pair to files.

        Creates:
        - {output_dir}_public.bin - Public key
        - {output_dir}_secret.bin - Secret key
        - {output_dir}_meta.json - Metadata
        """
        output_dir = Path(output_dir)
        output_dir.parent.mkdir(parents=True, exist_ok=True)

        # Save public key
        public_path = Path(f"{output_dir}_public.bin")
        with open(public_path, "wb") as f:
            f.write(self.public_key)

        # Save secret key with restrictive permissions
        secret_path = Path(f"{output_dir}_secret.bin")
        with open(secret_path, "wb") as f:
            f.write(self.secret_key)
        secret_path.chmod(0o600)

        # Save metadata if present
        if self.metadata:
            import json

            meta_path = Path(f"{output_dir}_meta.json")
            with open(meta_path, "w") as f:
                json.dump(self.metadata, f, indent=2)

    @classmethod
    def load(cls, input_dir: Path, key_type: KeyType) -> "KeyPair":
        """Load key pair from files."""
        public_path = Path(f"{input_dir}_public.bin")
        secret_path = Path(f"{input_dir}_secret.bin")

        with open(public_path, "rb") as f:
            public_key = f.read()

        with open(secret_path, "rb") as f:
            secret_key = f.read()

        metadata = None
        meta_path = Path(f"{input_dir}_meta.json")
        if meta_path.exists():
            import json

            with open(meta_path) as f:
                metadata = json.load(f)

        return cls(
            key_type=key_type,
            public_key=public_key,
            secret_key=secret_key,
            metadata=metadata,
        )

    def public_key_hash(self) -> str:
        """Get hash of public key for identification."""
        return SHA3_256.new(self.public_key).hexdigest()


class KeyGenerator:
    """Post-quantum key generator with real PQC support.

    Uses the best available PQC implementation:
    - liboqs (production ready)
    - Pure Python implementations
    - SHAKE256 fallback (development only)
    """

    def __init__(self, config: Optional["CryptoConfig"] = None) -> None:
        """Initialize key generator.

        Args:
            config: Cryptographic configuration options
        """
        self.config = config

    def generate_keypair(
        self,
        key_type: KeyType,
        seed: Optional[bytes] = None,
    ) -> KeyPair:
        """Generate a new key pair using real PQC when available.

        Args:
            key_type: Type of key to generate
            seed: Optional seed for deterministic generation (testing only)

        Returns:
            Generated key pair
        """
        scheme = get_scheme(key_type)

        # Use deterministic generation if seed provided
        if seed is not None and isinstance(scheme, FallbackScheme):
            public_key, secret_key = scheme.keypair_from_seed(seed)
        else:
            # Real PQC implementations generate their own randomness
            # Seed is ignored for real implementations
            public_key, secret_key = scheme.keypair()

        return KeyPair(
            key_type=key_type,
            public_key=public_key,
            secret_key=secret_key,
            metadata=self._create_metadata(key_type),
        )

    def _create_metadata(self, key_type: KeyType) -> dict:
        """Create metadata for generated key."""
        sizes = KEY_SIZES[key_type]
        algo_names = {
            KeyType.KYBER768: "ML-KEM-768",
            KeyType.DILITHIUM3: "ML-DSA-65",
            KeyType.FALCON512: "FN-DSA-512",
            KeyType.FALCON1024: "FN-DSA-1024",
        }

        return {
            "algorithm": algo_names[key_type],
            "nist_level": sizes["security_level"],
            "using_liboqs": HAS_LIBOQS,
            "using_pure_python": (
                (HAS_PY_KYBER and key_type == KeyType.KYBER768) or
                (HAS_PY_DILITHIUM and key_type == KeyType.DILITHIUM3)
            ),
            "is_fallback": not HAS_LIBOQS and not (
                (HAS_PY_KYBER and key_type == KeyType.KYBER768) or
                (HAS_PY_DILITHIUM and key_type == KeyType.DILITHIUM3)
            ),
        }


def derive_device_keys(
    master_seed: bytes,
    device_id: bytes,
    manufacturer_id: bytes,
) -> dict[str, KeyPair]:
    """Derive all device keys from a master seed.

    This function deterministically generates all required keys for a device
    from a single master seed, ensuring reproducibility for backup/recovery.

    Note: When using real PQC implementations, seed is used for domain
    separation but actual key generation uses proper randomness.

    Args:
        master_seed: 64-byte master seed
        device_id: Device identifier
        manufacturer_id: Manufacturer identifier

    Returns:
        Dictionary of key pairs keyed by purpose
    """
    if len(master_seed) < 64:
        raise ValueError("Master seed must be at least 64 bytes")

    # Create device-specific seed for domain separation
    device_seed = SHA3_512.new(
        b"Qbitel EdgeOS-DEVICE-KEYS" + master_seed + device_id + manufacturer_id
    ).digest()

    generator = KeyGenerator()

    # Generate KEM key for secure communication
    kem_seed = SHA3_512.new(b"KEM" + device_seed).digest()
    kem_keypair = generator.generate_keypair(KeyType.KYBER768, kem_seed)

    # Generate signature key for authentication
    sig_seed = SHA3_512.new(b"SIG" + device_seed).digest()
    sig_keypair = generator.generate_keypair(KeyType.DILITHIUM3, sig_seed)

    # Generate attestation key
    attest_seed = SHA3_512.new(b"ATTEST" + device_seed).digest()
    attest_keypair = generator.generate_keypair(KeyType.DILITHIUM3, attest_seed)

    return {
        "kem": kem_keypair,
        "signature": sig_keypair,
        "attestation": attest_keypair,
    }


def check_pqc_availability() -> dict:
    """Check which PQC implementations are available.

    Returns:
        Dictionary with availability status
    """
    result = {
        "liboqs": HAS_LIBOQS,
        "kyber_py": HAS_PY_KYBER,
        "dilithium_py": HAS_PY_DILITHIUM,
        "production_ready": HAS_LIBOQS,
        "available_algorithms": [],
        "warnings": [],
    }

    if HAS_LIBOQS:
        result["available_algorithms"] = ["kyber768", "dilithium3", "falcon512", "falcon1024"]
        result["liboqs_version"] = getattr(oqs, "__version__", "unknown")
    else:
        if HAS_PY_KYBER:
            result["available_algorithms"].append("kyber768")
        if HAS_PY_DILITHIUM:
            result["available_algorithms"].append("dilithium3")

        if not result["available_algorithms"]:
            result["available_algorithms"] = ["kyber768", "dilithium3", "falcon512", "falcon1024"]
            result["warnings"].append("Using FALLBACK mode - NOT secure for production")

    return result
