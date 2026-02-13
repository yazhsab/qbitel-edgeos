"""Qbitel EdgeOS Factory Provisioning Tool.

This package provides tools for factory provisioning of Qbitel EdgeOS devices,
including:
- Post-quantum key generation (ML-KEM/Kyber, ML-DSA/Dilithium)
- Device identity creation and hardware binding
- Secure flash programming
- Provisioning verification
"""

__version__ = "0.1.0"
__author__ = "Qbitel EdgeOS Team"

from .keygen import KeyGenerator, KeyPair, KeyType
from .flash import FlashProgrammer, FlashTarget
from .verify import ProvisioningVerifier, VerificationResult

__all__ = [
    "KeyGenerator",
    "KeyPair",
    "KeyType",
    "FlashProgrammer",
    "FlashTarget",
    "ProvisioningVerifier",
    "VerificationResult",
]
