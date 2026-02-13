"""Update package building for Qbitel EdgeOS."""

import io
import json
import struct
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from Crypto.Hash import SHA3_256

from .signer import SigningKey, FirmwareSigner


# Package magic number
PACKAGE_MAGIC = b"QPKG"
PACKAGE_VERSION = 1


@dataclass
class PackageComponent:
    """A component in an update package."""

    name: str
    image_type: str
    data: bytes
    hash: bytes


@dataclass
class UpdatePackage:
    """Complete update package."""

    version: str
    target_platform: str
    created_at: datetime
    components: list[PackageComponent] = field(default_factory=list)
    signature: Optional[bytes] = None
    signer_key_id: Optional[str] = None


class PackageBuilder:
    """Builds update packages from signed firmware images."""

    def __init__(self, signing_key: SigningKey, target_platform: str) -> None:
        """Initialize package builder.

        Args:
            signing_key: Key for signing the package
            target_platform: Target platform identifier
        """
        self.signing_key = signing_key
        self.target_platform = target_platform
        self.signer = FirmwareSigner(signing_key)
        self._components: list[PackageComponent] = []

    def add_bootloader(self, image_path: Path) -> "PackageBuilder":
        """Add bootloader image to package.

        Args:
            image_path: Path to signed bootloader image

        Returns:
            Self for chaining
        """
        with open(image_path, "rb") as f:
            data = f.read()

        component = PackageComponent(
            name="bootloader",
            image_type="bootloader",
            data=data,
            hash=SHA3_256.new(data).digest(),
        )
        self._components.append(component)
        return self

    def add_kernel(self, image_path: Path) -> "PackageBuilder":
        """Add kernel image to package.

        Args:
            image_path: Path to signed kernel image

        Returns:
            Self for chaining
        """
        with open(image_path, "rb") as f:
            data = f.read()

        component = PackageComponent(
            name="kernel",
            image_type="kernel",
            data=data,
            hash=SHA3_256.new(data).digest(),
        )
        self._components.append(component)
        return self

    def add_application(self, image_path: Path) -> "PackageBuilder":
        """Add application image to package.

        Args:
            image_path: Path to signed application image

        Returns:
            Self for chaining
        """
        with open(image_path, "rb") as f:
            data = f.read()

        component = PackageComponent(
            name="application",
            image_type="application",
            data=data,
            hash=SHA3_256.new(data).digest(),
        )
        self._components.append(component)
        return self

    def build(self, version: str) -> bytes:
        """Build the update package.

        Package format (tar archive):
        - manifest.json: Package metadata and component list
        - bootloader.bin: Bootloader image (if present)
        - kernel.bin: Kernel image (if present)
        - application.bin: Application image (if present)
        - package.sig: Package signature

        Args:
            version: Package version string

        Returns:
            Complete package as bytes
        """
        now = datetime.now(timezone.utc)

        # Create manifest
        manifest = {
            "magic": PACKAGE_MAGIC.decode(),
            "version": PACKAGE_VERSION,
            "package_version": version,
            "target_platform": self.target_platform,
            "created_at": now.isoformat(),
            "signer_key_id": self.signing_key.key_id,
            "components": [
                {
                    "name": c.name,
                    "type": c.image_type,
                    "size": len(c.data),
                    "hash": c.hash.hex(),
                }
                for c in self._components
            ],
        }

        manifest_json = json.dumps(manifest, indent=2).encode()
        manifest_hash = SHA3_256.new(manifest_json).digest()

        # Sign the manifest
        signature = self.signer.sign_data(manifest_json)

        # Create tar archive
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            # Add manifest
            self._add_to_tar(tar, "manifest.json", manifest_json)

            # Add components
            for component in self._components:
                filename = f"{component.name}.bin"
                self._add_to_tar(tar, filename, component.data)

            # Add signature
            self._add_to_tar(tar, "package.sig", signature)

        return tar_buffer.getvalue()

    def _add_to_tar(
        self, tar: tarfile.TarFile, name: str, data: bytes
    ) -> None:
        """Add data to tar archive.

        Args:
            tar: TarFile object
            name: File name in archive
            data: File contents
        """
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        info.mtime = int(datetime.now(timezone.utc).timestamp())
        tar.addfile(info, io.BytesIO(data))


class PackageExtractor:
    """Extracts and verifies update packages."""

    def __init__(self, trusted_keys: Optional[dict[str, SigningKey]] = None) -> None:
        """Initialize package extractor.

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

    def extract(
        self,
        package_data: bytes,
        output_dir: Path,
        verify: bool = True,
    ) -> UpdatePackage:
        """Extract update package.

        Args:
            package_data: Package data
            output_dir: Directory to extract components to
            verify: Whether to verify signature

        Returns:
            UpdatePackage with metadata and components

        Raises:
            ValueError: If verification fails
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Extract tar archive
        tar_buffer = io.BytesIO(package_data)
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            # Extract manifest
            manifest_file = tar.extractfile("manifest.json")
            if manifest_file is None:
                raise ValueError("Package missing manifest.json")
            manifest_json = manifest_file.read()
            manifest = json.loads(manifest_json)

            # Extract signature
            sig_file = tar.extractfile("package.sig")
            if sig_file is None:
                raise ValueError("Package missing package.sig")
            signature = sig_file.read()

            # Verify signature if requested
            if verify:
                key_id = manifest.get("signer_key_id")
                if key_id not in self.trusted_keys:
                    raise ValueError(f"No trusted key for ID: {key_id}")

                key = self.trusted_keys[key_id]
                if not key.verify(manifest_json, signature):
                    raise ValueError("Package signature verification failed")

            # Extract components
            components = []
            for comp_info in manifest["components"]:
                filename = f"{comp_info['name']}.bin"
                comp_file = tar.extractfile(filename)
                if comp_file is None:
                    raise ValueError(f"Package missing {filename}")
                data = comp_file.read()

                # Verify hash
                computed_hash = SHA3_256.new(data).digest()
                expected_hash = bytes.fromhex(comp_info["hash"])
                if computed_hash != expected_hash:
                    raise ValueError(f"Hash mismatch for {comp_info['name']}")

                # Write to output
                output_path = output_dir / filename
                with open(output_path, "wb") as f:
                    f.write(data)

                components.append(
                    PackageComponent(
                        name=comp_info["name"],
                        image_type=comp_info["type"],
                        data=data,
                        hash=computed_hash,
                    )
                )

        return UpdatePackage(
            version=manifest["package_version"],
            target_platform=manifest["target_platform"],
            created_at=datetime.fromisoformat(manifest["created_at"]),
            components=components,
            signature=signature,
            signer_key_id=manifest.get("signer_key_id"),
        )

    def verify_only(self, package_data: bytes) -> bool:
        """Verify package without extracting.

        Args:
            package_data: Package data

        Returns:
            True if verification passed
        """
        try:
            tar_buffer = io.BytesIO(package_data)
            with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
                manifest_file = tar.extractfile("manifest.json")
                if manifest_file is None:
                    return False
                manifest_json = manifest_file.read()
                manifest = json.loads(manifest_json)

                sig_file = tar.extractfile("package.sig")
                if sig_file is None:
                    return False
                signature = sig_file.read()

                key_id = manifest.get("signer_key_id")
                if key_id not in self.trusted_keys:
                    return False

                key = self.trusted_keys[key_id]
                return key.verify(manifest_json, signature)
        except Exception:
            return False
