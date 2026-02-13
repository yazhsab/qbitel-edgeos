"""Pytest configuration and fixtures for q-provision tests."""

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
def sample_device_id() -> bytes:
    """Sample 32-byte device ID for testing."""
    return bytes.fromhex("0123456789abcdef" * 4)


@pytest.fixture
def sample_manufacturer_id() -> bytes:
    """Sample 32-byte manufacturer ID for testing."""
    return bytes.fromhex("fedcba9876543210" * 4)


@pytest.fixture
def sample_config_yaml(temp_dir: Path) -> Path:
    """Create a sample YAML configuration file."""
    config_content = """
crypto:
  kem_algorithm: kyber768
  signature_algorithm: dilithium3
  hash_algorithm: sha3-256
  aead_algorithm: aes-256-gcm
  security_level: 3

flash:
  verify_writes: true
  erase_before_write: true
  reset_after_flash: true
  timeout_ms: 30000
  retry_count: 3

identity:
  use_puf: true
  use_efuse: false
  commitment_version: 1
  hardware_binding_enabled: true

security:
  enable_secure_boot: true
  enable_debug_lock: false
  enable_flash_encryption: true
  enable_tamper_detection: true
  rdp_level: 1

manufacturer_id: "0001"
product_id: "0001"
hardware_version: "1.0.0"
firmware_version: "0.1.0"
output_directory: "./test_output"
log_directory: "./test_logs"
"""
    config_path = temp_dir / "config.yaml"
    config_path.write_text(config_content)
    return config_path


@pytest.fixture
def sample_config_json(temp_dir: Path) -> Path:
    """Create a sample JSON configuration file."""
    import json

    config = {
        "crypto": {
            "kem_algorithm": "kyber768",
            "signature_algorithm": "dilithium3",
            "hash_algorithm": "sha3-256",
            "aead_algorithm": "aes-256-gcm",
            "security_level": 3,
        },
        "flash": {
            "verify_writes": True,
            "erase_before_write": True,
            "reset_after_flash": True,
            "timeout_ms": 30000,
            "retry_count": 3,
        },
        "identity": {
            "use_puf": True,
            "use_efuse": False,
            "commitment_version": 1,
            "hardware_binding_enabled": True,
        },
        "security": {
            "enable_secure_boot": True,
            "enable_debug_lock": False,
            "enable_flash_encryption": True,
            "enable_tamper_detection": True,
            "rdp_level": 1,
        },
        "manufacturer_id": "0001",
        "product_id": "0001",
        "hardware_version": "1.0.0",
        "firmware_version": "0.1.0",
        "output_directory": "./test_output",
        "log_directory": "./test_logs",
    }
    config_path = temp_dir / "config.json"
    config_path.write_text(json.dumps(config, indent=2))
    return config_path


@pytest.fixture
def mock_puf_response() -> bytes:
    """Mock PUF challenge-response data."""
    return os.urandom(32)
