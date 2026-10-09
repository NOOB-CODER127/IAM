"""
Key management for AI Agents: Ed25519 for Identity Signatures and X25519 for Diffie-Hellman Key Exchange.
"""

from __future__ import annotations
import base64
import hashlib
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519


class AgentKeyPair:
    """
    Cryptographic keypair held by an AI Agent.
    - Ed25519: Digital Signatures & Proof-of-Possession (PoP)
    - X25519: Elliptic-Curve Diffie-Hellman (ECDH) Key Exchange
    """

    def __init__(
        self,
        signing_key: ed25519.Ed25519PrivateKey | None = None,
        dh_key: x25519.X25519PrivateKey | None = None,
    ):
        self._signing_key = signing_key or ed25519.Ed25519PrivateKey.generate()
        self._dh_key = dh_key or x25519.X25519PrivateKey.generate()

    @classmethod
    def generate(cls) -> AgentKeyPair:
        """Generate a fresh ephemeral keypair for an agent instance."""
        return cls()

    @property
    def signing_public_key(self) -> ed25519.Ed25519PublicKey:
        return self._signing_key.public_key()

    @property
    def dh_public_key(self) -> x25519.X25519PublicKey:
        return self._dh_key.public_key()

    @property
    def signing_public_bytes(self) -> bytes:
        return self.signing_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def dh_public_bytes(self) -> bytes:
        return self.dh_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def signing_public_b64(self) -> str:
        return base64.b64encode(self.signing_public_bytes).decode("utf-8")

    @property
    def dh_public_b64(self) -> str:
        return base64.b64encode(self.dh_public_bytes).decode("utf-8")

    @property
    def fingerprint(self) -> str:
        """Hex-encoded SHA-256 fingerprint of the agent's identity public key."""
        return hashlib.sha256(self.signing_public_bytes).hexdigest()

    def sign(self, data: bytes) -> bytes:
        """Sign arbitrary bytes with the agent's Ed25519 private key."""
        return self._signing_key.sign(data)

    def sign_b64(self, data: bytes) -> str:
        """Sign arbitrary bytes and return Base64-encoded signature."""
        return base64.b64encode(self.sign(data)).decode("utf-8")

    @property
    def dh_private_key(self) -> x25519.X25519PrivateKey:
        return self._dh_key

    @staticmethod
    def verify(public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
        """Verify an Ed25519 signature given raw public key bytes."""
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub_key.verify(signature, data)
            return True
        except (InvalidSignature, ValueError):
            return False

    @staticmethod
    def verify_b64(public_key_b64: str, signature_b64: str, data: bytes) -> bool:
        """Verify an Ed25519 signature given Base64-encoded public key and signature."""
        try:
            pub_bytes = base64.b64decode(public_key_b64)
            sig_bytes = base64.b64decode(signature_b64)
            return AgentKeyPair.verify(pub_bytes, sig_bytes, data)
        except Exception:
            return False
