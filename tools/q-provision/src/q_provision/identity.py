"""Device identity generation for Qbitel EdgeOS."""

import json
import secrets
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from Crypto.Hash import SHA3_256, SHA3_512

from .config import ProvisioningConfig
from .keygen import KeyGenerator, KeyType, KeyPair


@dataclass
class DeviceIdentitySecrets:
    """Device identity secrets (stored securely on device)."""

    kem_secret_key: bytes
    signature_secret_key: bytes
    hardware_secret: bytes  # Derived from PUF/eFUSE


@dataclass
class DeviceIdentityPublic:
    """Device identity public data."""

    device_id: bytes
    manufacturer_id: bytes
    device_class: str
    kem_public_key: bytes
    signature_public_key: bytes
    created_at: datetime


@dataclass
class DeviceIdentity:
    """Complete device identity."""

    public: DeviceIdentityPublic
    secrets: DeviceIdentitySecrets


@dataclass
class IdentityCommitment:
    """Cryptographic commitment to device identity."""

    version: int
    hash: bytes
    device_id: bytes
    created_at: datetime

    def to_bytes(self) -> bytes:
        """Serialize commitment to bytes."""
        timestamp = int(self.created_at.timestamp())
        return (
            struct.pack("<I", self.version)
            + self.hash
            + self.device_id
            + struct.pack("<Q", timestamp)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "IdentityCommitment":
        """Deserialize commitment from bytes."""
        version = struct.unpack("<I", data[0:4])[0]
        hash_value = data[4:36]
        device_id = data[36:68]
        timestamp = struct.unpack("<Q", data[68:76])[0]

        return cls(
            version=version,
            hash=hash_value,
            device_id=device_id,
            created_at=datetime.fromtimestamp(timestamp, tz=timezone.utc),
        )


class IdentityGenerator:
    """Generates device identities for Qbitel EdgeOS provisioning."""

    COMMITMENT_VERSION = 1

    def __init__(self, config: ProvisioningConfig) -> None:
        """Initialize identity generator.

        Args:
            config: Provisioning configuration
        """
        self.config = config
        self.key_generator = KeyGenerator(config.crypto)

    def generate_identity(
        self,
        device_id: bytes,
        manufacturer_id: bytes,
        device_class: str,
        puf_response: Optional[bytes] = None,
    ) -> DeviceIdentity:
        """Generate a new device identity.

        Args:
            device_id: Unique device identifier (32 bytes)
            manufacturer_id: Manufacturer identifier
            device_class: Device classification
            puf_response: Optional PUF challenge-response data

        Returns:
            Complete device identity with keys
        """
        # Ensure device ID is 32 bytes
        if len(device_id) < 32:
            device_id = device_id.ljust(32, b"\x00")
        elif len(device_id) > 32:
            device_id = device_id[:32]

        # Ensure manufacturer ID is properly sized
        if len(manufacturer_id) < 4:
            manufacturer_id = manufacturer_id.ljust(4, b"\x00")

        # Generate hardware secret from PUF or random
        if puf_response:
            hardware_secret = SHA3_256.new(
                b"Qbitel EdgeOS-HW-SECRET" + device_id + puf_response
            ).digest()
        else:
            hardware_secret = secrets.token_bytes(32)

        # Derive key generation seed from hardware secret
        master_seed = SHA3_512.new(
            b"Qbitel EdgeOS-MASTER-SEED" + hardware_secret + device_id + manufacturer_id
        ).digest()

        # Generate KEM keypair
        kem_seed = SHA3_512.new(b"KEM" + master_seed).digest()
        kem_keypair = self.key_generator.generate_keypair(KeyType.KYBER768, kem_seed)

        # Generate signature keypair
        sig_seed = SHA3_512.new(b"SIG" + master_seed).digest()
        sig_keypair = self.key_generator.generate_keypair(KeyType.DILITHIUM3, sig_seed)

        now = datetime.now(timezone.utc)

        return DeviceIdentity(
            public=DeviceIdentityPublic(
                device_id=device_id,
                manufacturer_id=manufacturer_id,
                device_class=device_class,
                kem_public_key=kem_keypair.public_key,
                signature_public_key=sig_keypair.public_key,
                created_at=now,
            ),
            secrets=DeviceIdentitySecrets(
                kem_secret_key=kem_keypair.secret_key,
                signature_secret_key=sig_keypair.secret_key,
                hardware_secret=hardware_secret,
            ),
        )

    def create_commitment(self, identity: DeviceIdentity) -> IdentityCommitment:
        """Create cryptographic commitment to identity.

        The commitment binds the device ID to its public keys in a
        verifiable way without revealing the keys themselves.

        Commitment = H(device_id || manufacturer_id || H(kem_pk) || H(sig_pk))

        Args:
            identity: Device identity

        Returns:
            Identity commitment
        """
        # Hash public keys
        kem_hash = SHA3_256.new(identity.public.kem_public_key).digest()
        sig_hash = SHA3_256.new(identity.public.signature_public_key).digest()

        # Create commitment
        commitment_input = (
            identity.public.device_id
            + identity.public.manufacturer_id
            + kem_hash
            + sig_hash
        )
        commitment_hash = SHA3_256.new(commitment_input).digest()

        return IdentityCommitment(
            version=self.COMMITMENT_VERSION,
            hash=commitment_hash,
            device_id=identity.public.device_id,
            created_at=identity.public.created_at,
        )

    def save_identity(
        self,
        identity: DeviceIdentity,
        commitment: IdentityCommitment,
        output_path: Path,
    ) -> None:
        """Save identity and commitment to files.

        Creates:
        - device_id.bin - Device identifier
        - commitment.bin - Identity commitment hash
        - kem_public.bin - KEM public key
        - kem_secret.bin - KEM secret key (encrypted in production)
        - sig_public.bin - Signature public key
        - sig_secret.bin - Signature secret key (encrypted in production)
        - identity.json - Metadata
        """
        output_path.mkdir(parents=True, exist_ok=True)

        # Save device ID
        with open(output_path / "device_id.bin", "wb") as f:
            f.write(identity.public.device_id)

        # Save commitment
        with open(output_path / "commitment.bin", "wb") as f:
            f.write(commitment.hash)

        # Save KEM keys
        with open(output_path / "kem_public.bin", "wb") as f:
            f.write(identity.public.kem_public_key)

        with open(output_path / "kem_secret.bin", "wb") as f:
            f.write(identity.secrets.kem_secret_key)

        # Save signature keys
        with open(output_path / "sig_public.bin", "wb") as f:
            f.write(identity.public.signature_public_key)

        with open(output_path / "sig_secret.bin", "wb") as f:
            f.write(identity.secrets.signature_secret_key)

        # Save hardware secret
        with open(output_path / "hardware_secret.bin", "wb") as f:
            f.write(identity.secrets.hardware_secret)

        # Save metadata
        metadata = {
            "device_id": identity.public.device_id.hex(),
            "manufacturer_id": identity.public.manufacturer_id.hex(),
            "device_class": identity.public.device_class,
            "created_at": identity.public.created_at.isoformat(),
            "commitment_version": commitment.version,
            "commitment_hash": commitment.hash.hex(),
            "kem_public_key_hash": SHA3_256.new(identity.public.kem_public_key).hexdigest()[:16],
            "sig_public_key_hash": SHA3_256.new(identity.public.signature_public_key).hexdigest()[:16],
        }

        with open(output_path / "identity.json", "w") as f:
            json.dump(metadata, f, indent=2)

    def load_identity(self, input_path: Path) -> tuple[DeviceIdentity, IdentityCommitment]:
        """Load identity and commitment from files.

        Args:
            input_path: Directory containing identity files

        Returns:
            Tuple of (DeviceIdentity, IdentityCommitment)
        """
        # Load metadata
        with open(input_path / "identity.json") as f:
            metadata = json.load(f)

        # Load device ID
        with open(input_path / "device_id.bin", "rb") as f:
            device_id = f.read()

        # Load commitment
        with open(input_path / "commitment.bin", "rb") as f:
            commitment_hash = f.read()

        # Load keys
        with open(input_path / "kem_public.bin", "rb") as f:
            kem_public = f.read()

        with open(input_path / "kem_secret.bin", "rb") as f:
            kem_secret = f.read()

        with open(input_path / "sig_public.bin", "rb") as f:
            sig_public = f.read()

        with open(input_path / "sig_secret.bin", "rb") as f:
            sig_secret = f.read()

        with open(input_path / "hardware_secret.bin", "rb") as f:
            hardware_secret = f.read()

        created_at = datetime.fromisoformat(metadata["created_at"])

        identity = DeviceIdentity(
            public=DeviceIdentityPublic(
                device_id=device_id,
                manufacturer_id=bytes.fromhex(metadata["manufacturer_id"]),
                device_class=metadata["device_class"],
                kem_public_key=kem_public,
                signature_public_key=sig_public,
                created_at=created_at,
            ),
            secrets=DeviceIdentitySecrets(
                kem_secret_key=kem_secret,
                signature_secret_key=sig_secret,
                hardware_secret=hardware_secret,
            ),
        )

        commitment = IdentityCommitment(
            version=metadata["commitment_version"],
            hash=commitment_hash,
            device_id=device_id,
            created_at=created_at,
        )

        return identity, commitment


def generate_batch_identities(
    config: ProvisioningConfig,
    manufacturer_id: bytes,
    device_class: str,
    count: int,
    output_dir: Path,
    id_prefix: bytes = b"",
) -> list[tuple[DeviceIdentity, IdentityCommitment]]:
    """Generate multiple device identities for batch provisioning.

    Args:
        config: Provisioning configuration
        manufacturer_id: Manufacturer identifier
        device_class: Device classification
        count: Number of identities to generate
        output_dir: Output directory for identity files
        id_prefix: Optional prefix for device IDs

    Returns:
        List of (identity, commitment) tuples
    """
    generator = IdentityGenerator(config)
    results = []

    output_dir.mkdir(parents=True, exist_ok=True)

    for i in range(count):
        # Generate unique device ID
        device_id = id_prefix + secrets.token_bytes(32 - len(id_prefix))

        identity = generator.generate_identity(
            device_id=device_id,
            manufacturer_id=manufacturer_id,
            device_class=device_class,
        )

        commitment = generator.create_commitment(identity)

        # Save to subdirectory
        device_dir = output_dir / device_id.hex()[:16]
        generator.save_identity(identity, commitment, device_dir)

        results.append((identity, commitment))

    # Save batch manifest
    manifest = {
        "manufacturer_id": manufacturer_id.hex(),
        "device_class": device_class,
        "count": count,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "devices": [
            {
                "device_id": identity.public.device_id.hex(),
                "commitment_hash": commitment.hash.hex(),
            }
            for identity, commitment in results
        ],
    }

    with open(output_dir / "batch_manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    return results
