"""Qbitel EdgeOS Firmware Signing Tool.

This package provides tools for signing Qbitel EdgeOS firmware images,
including:
- Post-quantum signature generation (ML-DSA/Dilithium, FN-DSA/Falcon)
- Firmware manifest creation
- Update package building
- Signature verification
"""

__version__ = "0.1.0"
__author__ = "Qbitel EdgeOS Team"

from .signer import FirmwareSigner, SigningKey, SignatureAlgorithm
from .manifest import FirmwareManifest, ManifestBuilder
from .verify import SignatureVerifier

__all__ = [
    "FirmwareSigner",
    "SigningKey",
    "SignatureAlgorithm",
    "FirmwareManifest",
    "ManifestBuilder",
    "SignatureVerifier",
]
