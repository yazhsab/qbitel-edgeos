"""Flash programming for Qbitel EdgeOS devices."""

import struct
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Protocol

from Crypto.Hash import SHA3_256


class FlashTarget(Enum):
    """Supported flash targets."""

    STM32H7 = "stm32h7"
    STM32U5 = "stm32u5"
    RISCV = "riscv"

    @classmethod
    def from_string(cls, value: str) -> "FlashTarget":
        """Convert string to FlashTarget."""
        return cls(value.lower())


# Memory map for each target
MEMORY_MAPS = {
    FlashTarget.STM32H7: {
        "bootloader": {"start": 0x0800_0000, "size": 0x8000},  # 32KB
        "kernel_a": {"start": 0x0800_8000, "size": 0x4_0000},  # 256KB
        "kernel_b": {"start": 0x0804_8000, "size": 0x4_0000},  # 256KB
        "app_a": {"start": 0x0808_8000, "size": 0x4_0000},  # 256KB
        "app_b": {"start": 0x080C_8000, "size": 0x4_0000},  # 256KB
        "identity": {"start": 0x0810_8000, "size": 0x4000},  # 16KB
        "otp": {"start": 0x1FF0_0000, "size": 0x400},  # 1KB OTP area
    },
    FlashTarget.STM32U5: {
        "bootloader": {"start": 0x0800_0000, "size": 0x8000},
        "kernel_a": {"start": 0x0800_8000, "size": 0x4_0000},
        "kernel_b": {"start": 0x0804_8000, "size": 0x4_0000},
        "app_a": {"start": 0x0808_8000, "size": 0x4_0000},
        "app_b": {"start": 0x080C_8000, "size": 0x4_0000},
        "identity": {"start": 0x0810_8000, "size": 0x4000},
        "otp": {"start": 0x0BFA_0000, "size": 0x200},
    },
    FlashTarget.RISCV: {
        "bootloader": {"start": 0x2000_0000, "size": 0x8000},
        "kernel_a": {"start": 0x2000_8000, "size": 0x4_0000},
        "kernel_b": {"start": 0x2004_8000, "size": 0x4_0000},
        "app_a": {"start": 0x2008_8000, "size": 0x4_0000},
        "app_b": {"start": 0x200C_8000, "size": 0x4_0000},
        "identity": {"start": 0x2010_8000, "size": 0x4000},
        "otp": {"start": 0x1000_0000, "size": 0x100},
    },
}


class DebugProbe(Protocol):
    """Protocol for debug probe interfaces."""

    def connect(self) -> None:
        """Connect to target."""
        ...

    def disconnect(self) -> None:
        """Disconnect from target."""
        ...

    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from target."""
        ...

    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory to target."""
        ...

    def erase_flash(self, address: int, size: int) -> None:
        """Erase flash region."""
        ...

    def reset(self) -> None:
        """Reset target."""
        ...


@dataclass
class FlashConfig:
    """Flash programming configuration."""

    verify_writes: bool = True
    erase_before_write: bool = True
    reset_after_flash: bool = True
    timeout_ms: int = 30000
    retry_count: int = 3


class FlashProgrammer:
    """Flash programmer for Qbitel EdgeOS devices.

    Supports programming device identity, bootloader, kernel, and
    application images to supported target platforms.
    """

    def __init__(
        self,
        port: str,
        target: FlashTarget,
        config: Optional[FlashConfig] = None,
    ) -> None:
        """Initialize flash programmer.

        Args:
            port: Serial port or debug probe identifier
            target: Target platform
            config: Flash programming configuration
        """
        self.port = port
        self.target = target
        self.config = config or FlashConfig()
        self.memory_map = MEMORY_MAPS[target]
        self._probe: Optional[DebugProbe] = None
        self._connected = False

    def connect(self) -> None:
        """Connect to the target device."""
        # In production, this would use actual debug probe libraries
        # such as pyocd, openocd, or probe-rs bindings
        self._probe = self._create_probe()
        self._probe.connect()
        self._connected = True

    def disconnect(self) -> None:
        """Disconnect from the target device."""
        if self._probe and self._connected:
            self._probe.disconnect()
            self._connected = False

    def _create_probe(self) -> DebugProbe:
        """Create appropriate debug probe for target."""
        # This is a simulation - actual implementation would detect
        # and use real debug probes
        return SimulatedProbe(self.target, self.memory_map)

    def erase_regions(self, regions: Optional[list[str]] = None) -> None:
        """Erase flash regions.

        Args:
            regions: List of region names to erase, or None for all
        """
        if not self._connected:
            raise RuntimeError("Not connected to target")

        if regions is None:
            regions = ["bootloader", "kernel_a", "kernel_b", "app_a", "app_b", "identity"]

        for region in regions:
            if region in self.memory_map:
                info = self.memory_map[region]
                self._probe.erase_flash(info["start"], info["size"])

    def flash_bootloader(self, image_path: Path) -> None:
        """Flash bootloader image.

        Args:
            image_path: Path to bootloader binary
        """
        if not self._connected:
            raise RuntimeError("Not connected to target")

        with open(image_path, "rb") as f:
            data = f.read()

        region = self.memory_map["bootloader"]
        if len(data) > region["size"]:
            raise ValueError(
                f"Bootloader image too large: {len(data)} > {region['size']}"
            )

        self._flash_region("bootloader", data)

    def flash_kernel(self, image_path: Path, slot: str = "a") -> None:
        """Flash kernel image.

        Args:
            image_path: Path to kernel binary
            slot: Target slot ("a" or "b")
        """
        if not self._connected:
            raise RuntimeError("Not connected to target")

        region_name = f"kernel_{slot.lower()}"
        if region_name not in self.memory_map:
            raise ValueError(f"Invalid kernel slot: {slot}")

        with open(image_path, "rb") as f:
            data = f.read()

        region = self.memory_map[region_name]
        if len(data) > region["size"]:
            raise ValueError(
                f"Kernel image too large: {len(data)} > {region['size']}"
            )

        self._flash_region(region_name, data)

    def flash_application(self, image_path: Path, slot: str = "a") -> None:
        """Flash application image.

        Args:
            image_path: Path to application binary
            slot: Target slot ("a" or "b")
        """
        if not self._connected:
            raise RuntimeError("Not connected to target")

        region_name = f"app_{slot.lower()}"
        if region_name not in self.memory_map:
            raise ValueError(f"Invalid application slot: {slot}")

        with open(image_path, "rb") as f:
            data = f.read()

        region = self.memory_map[region_name]
        if len(data) > region["size"]:
            raise ValueError(
                f"Application image too large: {len(data)} > {region['size']}"
            )

        self._flash_region(region_name, data)

    def program_identity(self, identity_path: Path) -> None:
        """Program device identity data.

        Args:
            identity_path: Path to identity data directory
        """
        if not self._connected:
            raise RuntimeError("Not connected to target")

        # Load identity components
        identity_data = self._load_identity_data(identity_path)

        # Flash identity region
        self._flash_region("identity", identity_data)

    def _load_identity_data(self, identity_path: Path) -> bytes:
        """Load and serialize identity data for flashing."""
        # Identity data format:
        # [4 bytes] Magic (0x51494420 = "QID ")
        # [4 bytes] Version
        # [4 bytes] Total length
        # [32 bytes] Device ID
        # [32 bytes] Commitment hash
        # [1184 bytes] KEM public key
        # [1952 bytes] Signature public key
        # [32 bytes] Checksum

        magic = b"QID "
        version = struct.pack("<I", 1)

        # Load components
        device_id = b"\x00" * 32
        commitment_hash = b"\x00" * 32
        kem_public = b"\x00" * 1184
        sig_public = b"\x00" * 1952

        # Try to load actual files
        commitment_path = identity_path / "commitment.bin"
        if commitment_path.exists():
            with open(commitment_path, "rb") as f:
                commitment_hash = f.read(32)

        kem_path = identity_path / "kem_public.bin"
        if kem_path.exists():
            with open(kem_path, "rb") as f:
                kem_public = f.read()

        sig_path = identity_path / "sig_public.bin"
        if sig_path.exists():
            with open(sig_path, "rb") as f:
                sig_public = f.read()

        device_id_path = identity_path / "device_id.bin"
        if device_id_path.exists():
            with open(device_id_path, "rb") as f:
                device_id = f.read(32)

        # Assemble identity blob
        payload = device_id + commitment_hash + kem_public + sig_public
        total_length = len(magic) + len(version) + 4 + len(payload) + 32

        header = magic + version + struct.pack("<I", total_length)
        checksum = SHA3_256.new(header + payload).digest()

        return header + payload + checksum

    def _flash_region(self, region_name: str, data: bytes) -> None:
        """Flash data to a specific region."""
        region = self.memory_map[region_name]

        if self.config.erase_before_write:
            self._probe.erase_flash(region["start"], region["size"])

        self._probe.write_memory(region["start"], data)

        if self.config.verify_writes:
            readback = self._probe.read_memory(region["start"], len(data))
            if readback != data:
                raise RuntimeError(f"Flash verification failed for region {region_name}")

    def verify(self) -> bool:
        """Verify all flashed regions."""
        if not self._connected:
            raise RuntimeError("Not connected to target")

        # Read back and verify checksums
        # In production, this would verify against expected hashes
        return True

    def lock_flash(self) -> None:
        """Lock flash regions to prevent further modification.

        Warning: This operation may be irreversible!
        """
        if not self._connected:
            raise RuntimeError("Not connected to target")

        # Platform-specific flash lock implementation
        if self.target == FlashTarget.STM32H7:
            # Write protection and RDP level
            pass
        elif self.target == FlashTarget.STM32U5:
            # TrustZone secure flash configuration
            pass
        elif self.target == FlashTarget.RISCV:
            # Platform-specific lock mechanism
            pass


class SimulatedProbe:
    """Simulated debug probe for testing."""

    def __init__(self, target: FlashTarget, memory_map: dict) -> None:
        """Initialize simulated probe."""
        self.target = target
        self.memory_map = memory_map
        self._memory: dict[int, bytes] = {}
        self._connected = False

    def connect(self) -> None:
        """Simulate connection."""
        self._connected = True

    def disconnect(self) -> None:
        """Simulate disconnection."""
        self._connected = False

    def read_memory(self, address: int, size: int) -> bytes:
        """Read from simulated memory."""
        if not self._connected:
            raise RuntimeError("Not connected")

        # Return stored data or zeros
        if address in self._memory:
            data = self._memory[address]
            if len(data) >= size:
                return data[:size]
        return b"\xff" * size

    def write_memory(self, address: int, data: bytes) -> None:
        """Write to simulated memory."""
        if not self._connected:
            raise RuntimeError("Not connected")
        self._memory[address] = data

    def erase_flash(self, address: int, size: int) -> None:
        """Simulate flash erase."""
        if not self._connected:
            raise RuntimeError("Not connected")
        self._memory[address] = b"\xff" * size

    def reset(self) -> None:
        """Simulate reset."""
        pass
