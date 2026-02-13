"""Pytest configuration and fixtures for q-sign tests."""

import os
import tempfile
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_firmware() -> bytes:
    """Sample firmware image for testing."""
    # Create a realistic-looking firmware image
    header = b"QEDGE\x00\x01\x00"  # Magic + version
    padding = b"\x00" * 56  # Pad to 64 bytes
    code = os.urandom(4096)  # Simulated code section
    return header + padding + code


@pytest.fixture
def sample_bootloader() -> bytes:
    """Sample bootloader image."""
    header = b"QBOOT\x00\x01\x00"
    padding = b"\x00" * 56
    code = os.urandom(8192)
    return header + padding + code


@pytest.fixture
def sample_kernel() -> bytes:
    """Sample kernel image."""
    header = b"QKERN\x00\x01\x00"
    padding = b"\x00" * 56
    code = os.urandom(32768)
    return header + padding + code


@pytest.fixture
def firmware_file(temp_dir: Path, sample_firmware: bytes) -> Path:
    """Create a firmware file on disk."""
    path = temp_dir / "firmware.bin"
    path.write_bytes(sample_firmware)
    return path


@pytest.fixture
def bootloader_file(temp_dir: Path, sample_bootloader: bytes) -> Path:
    """Create a bootloader file on disk."""
    path = temp_dir / "bootloader.bin"
    path.write_bytes(sample_bootloader)
    return path


@pytest.fixture
def kernel_file(temp_dir: Path, sample_kernel: bytes) -> Path:
    """Create a kernel file on disk."""
    path = temp_dir / "kernel.bin"
    path.write_bytes(sample_kernel)
    return path
