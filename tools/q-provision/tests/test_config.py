"""Tests for q-provision configuration module."""

import json
from pathlib import Path

import pytest

from q_provision.config import (
    CryptoConfig,
    FlashConfig,
    IdentityConfig,
    ProvisioningConfig,
    SecurityConfig,
    load_config,
    save_config,
    generate_default_config,
    DEVELOPMENT_CONFIG,
    STAGING_CONFIG,
    PRODUCTION_CONFIG,
)


class TestCryptoConfig:
    """Tests for CryptoConfig."""

    def test_default_values(self):
        """Test default configuration values."""
        config = CryptoConfig()
        assert config.kem_algorithm == "kyber768"
        assert config.signature_algorithm == "dilithium3"
        assert config.hash_algorithm == "sha3-256"
        assert config.aead_algorithm == "aes-256-gcm"
        assert config.security_level == 3

    def test_custom_values(self):
        """Test custom configuration values."""
        config = CryptoConfig(
            kem_algorithm="kyber512",
            signature_algorithm="dilithium2",
            security_level=2,
        )
        assert config.kem_algorithm == "kyber512"
        assert config.signature_algorithm == "dilithium2"
        assert config.security_level == 2


class TestFlashConfig:
    """Tests for FlashConfig."""

    def test_default_values(self):
        """Test default flash configuration."""
        config = FlashConfig()
        assert config.verify_writes is True
        assert config.erase_before_write is True
        assert config.reset_after_flash is True
        assert config.timeout_ms == 30000
        assert config.retry_count == 3

    def test_custom_timeout(self):
        """Test custom timeout setting."""
        config = FlashConfig(timeout_ms=60000, retry_count=5)
        assert config.timeout_ms == 60000
        assert config.retry_count == 5


class TestIdentityConfig:
    """Tests for IdentityConfig."""

    def test_default_values(self):
        """Test default identity configuration."""
        config = IdentityConfig()
        assert config.use_puf is True
        assert config.use_efuse is True
        assert config.commitment_version == 1
        assert config.hardware_binding_enabled is True


class TestSecurityConfig:
    """Tests for SecurityConfig."""

    def test_default_values(self):
        """Test default security configuration."""
        config = SecurityConfig()
        assert config.enable_secure_boot is True
        assert config.enable_debug_lock is False
        assert config.enable_flash_encryption is True
        assert config.enable_tamper_detection is True
        assert config.rdp_level == 1

    def test_production_security(self):
        """Test production-grade security settings."""
        config = SecurityConfig(
            enable_debug_lock=True,
            rdp_level=2,
        )
        assert config.enable_debug_lock is True
        assert config.rdp_level == 2


class TestProvisioningConfig:
    """Tests for ProvisioningConfig."""

    def test_default_values(self):
        """Test default provisioning configuration."""
        config = ProvisioningConfig()
        assert isinstance(config.crypto, CryptoConfig)
        assert isinstance(config.flash, FlashConfig)
        assert isinstance(config.identity, IdentityConfig)
        assert isinstance(config.security, SecurityConfig)
        assert config.manufacturer_id == "0001"
        assert config.product_id == "0001"

    def test_nested_config(self):
        """Test nested configuration objects."""
        config = ProvisioningConfig(
            crypto=CryptoConfig(security_level=5),
            manufacturer_id="ACME",
        )
        assert config.crypto.security_level == 5
        assert config.manufacturer_id == "ACME"


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_yaml_config(self, sample_config_yaml: Path):
        """Test loading YAML configuration."""
        config = load_config(sample_config_yaml)
        assert isinstance(config, ProvisioningConfig)
        assert config.crypto.kem_algorithm == "kyber768"
        assert config.flash.verify_writes is True

    def test_load_json_config(self, sample_config_json: Path):
        """Test loading JSON configuration."""
        config = load_config(sample_config_json)
        assert isinstance(config, ProvisioningConfig)
        assert config.crypto.signature_algorithm == "dilithium3"

    def test_load_nonexistent_file(self, temp_dir: Path):
        """Test loading non-existent configuration file."""
        with pytest.raises(FileNotFoundError):
            load_config(temp_dir / "nonexistent.yaml")


class TestSaveConfig:
    """Tests for save_config function."""

    def test_save_yaml_config(self, temp_dir: Path):
        """Test saving YAML configuration."""
        config = ProvisioningConfig(manufacturer_id="TEST")
        output_path = temp_dir / "output.yaml"
        save_config(config, output_path)

        assert output_path.exists()
        loaded = load_config(output_path)
        assert loaded.manufacturer_id == "TEST"

    def test_save_json_config(self, temp_dir: Path):
        """Test saving JSON configuration."""
        config = ProvisioningConfig(product_id="PROD001")
        output_path = temp_dir / "output.json"
        save_config(config, output_path)

        assert output_path.exists()
        content = json.loads(output_path.read_text())
        assert content["product_id"] == "PROD001"


class TestGenerateDefaultConfig:
    """Tests for generate_default_config function."""

    def test_generate_yaml(self):
        """Test generating default YAML config."""
        yaml_config = generate_default_config("yaml")
        assert "kem_algorithm" in yaml_config
        assert "kyber768" in yaml_config

    def test_generate_json(self):
        """Test generating default JSON config."""
        json_config = generate_default_config("json")
        parsed = json.loads(json_config)
        assert "crypto" in parsed
        assert parsed["crypto"]["kem_algorithm"] == "kyber768"


class TestPredefinedConfigs:
    """Tests for predefined configuration instances."""

    def test_development_config(self):
        """Test development configuration."""
        assert DEVELOPMENT_CONFIG.security.enable_debug_lock is False

    def test_staging_config(self):
        """Test staging configuration."""
        assert isinstance(STAGING_CONFIG, ProvisioningConfig)

    def test_production_config(self):
        """Test production configuration."""
        assert PRODUCTION_CONFIG.security.enable_secure_boot is True
