"""Configuration management for Qbitel EdgeOS provisioning."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel


class CryptoConfig(BaseModel):
    """Cryptographic configuration."""

    kem_algorithm: str = "kyber768"
    signature_algorithm: str = "dilithium3"
    hash_algorithm: str = "sha3-256"
    aead_algorithm: str = "aes-256-gcm"
    security_level: int = 3


class FlashConfig(BaseModel):
    """Flash programming configuration."""

    verify_writes: bool = True
    erase_before_write: bool = True
    reset_after_flash: bool = True
    timeout_ms: int = 30000
    retry_count: int = 3


class IdentityConfig(BaseModel):
    """Identity provisioning configuration."""

    use_puf: bool = True
    use_efuse: bool = True
    commitment_version: int = 1
    hardware_binding_enabled: bool = True


class SecurityConfig(BaseModel):
    """Security configuration."""

    enable_secure_boot: bool = True
    enable_debug_lock: bool = False
    enable_flash_encryption: bool = True
    enable_tamper_detection: bool = True
    rdp_level: int = 1  # Read-out protection level


class ProvisioningConfig(BaseModel):
    """Complete provisioning configuration."""

    crypto: CryptoConfig = CryptoConfig()
    flash: FlashConfig = FlashConfig()
    identity: IdentityConfig = IdentityConfig()
    security: SecurityConfig = SecurityConfig()

    # Manufacturing settings
    manufacturer_id: str = "0001"
    product_id: str = "0001"
    hardware_version: str = "1.0.0"
    firmware_version: str = "0.1.0"

    # Output paths
    output_directory: str = "./provisioning_output"
    log_directory: str = "./provisioning_logs"


def load_config(config_path: Path) -> ProvisioningConfig:
    """Load configuration from file.

    Supports YAML and JSON formats.

    Args:
        config_path: Path to configuration file

    Returns:
        ProvisioningConfig object
    """
    with open(config_path) as f:
        if config_path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(f)
        elif config_path.suffix == ".json":
            data = json.load(f)
        else:
            raise ValueError(f"Unsupported config format: {config_path.suffix}")

    return ProvisioningConfig(**data)


def save_config(config: ProvisioningConfig, config_path: Path) -> None:
    """Save configuration to file.

    Args:
        config: Configuration to save
        config_path: Output path
    """
    data = config.model_dump()

    with open(config_path, "w") as f:
        if config_path.suffix in (".yaml", ".yml"):
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
        elif config_path.suffix == ".json":
            json.dump(data, f, indent=2)
        else:
            raise ValueError(f"Unsupported config format: {config_path.suffix}")


def generate_default_config(format: str = "yaml") -> str:
    """Generate default configuration content.

    Args:
        format: Output format ("yaml" or "json")

    Returns:
        Configuration file content as string
    """
    config = ProvisioningConfig()
    data = config.model_dump()

    if format == "yaml":
        return yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
    elif format == "json":
        return json.dumps(data, indent=2)
    else:
        raise ValueError(f"Unsupported format: {format}")


# Default configuration templates for different environments
DEVELOPMENT_CONFIG = ProvisioningConfig(
    security=SecurityConfig(
        enable_secure_boot=False,
        enable_debug_lock=False,
        enable_flash_encryption=False,
        enable_tamper_detection=False,
        rdp_level=0,
    ),
)

STAGING_CONFIG = ProvisioningConfig(
    security=SecurityConfig(
        enable_secure_boot=True,
        enable_debug_lock=False,
        enable_flash_encryption=True,
        enable_tamper_detection=True,
        rdp_level=1,
    ),
)

PRODUCTION_CONFIG = ProvisioningConfig(
    security=SecurityConfig(
        enable_secure_boot=True,
        enable_debug_lock=True,
        enable_flash_encryption=True,
        enable_tamper_detection=True,
        rdp_level=2,
    ),
)
