"""
Diffie-Hellman (ECDH) session negotiation, HKDF key derivation, and AES-256-GCM AEAD encryption.
Provides Perfect Forward Secrecy (PFS) and Zero Trust channel encryption for agents.
"""

from __future__ import annotations
import base64
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecureSession:
    """
    Encrypted, authenticated channel established via ECDH (X25519) + AES-GCM.
    Protects tool calls, parameters, and inter-agent messages against eavesdropping and tampering.
    """

    def __init__(self, symmetric_key: bytes):
        if len(symmetric_key) != 32:
            raise ValueError("Symmetric key must be 32 bytes (256-bit)")
        self._key = symmetric_key
        self._aesgcm = AESGCM(self._key)

    @classmethod
    def establish(
        cls,
        our_dh_private: x25519.X25519PrivateKey,
        their_dh_public_bytes: bytes,
        info: bytes = b"agent-iam-secure-session-v1",
        salt: bytes | None = None,
    ) -> SecureSession:
        """
        Derives an AES-256 symmetric session key via ECDH + HKDF.
        """
        their_public_key = x25519.X25519PublicKey.from_public_bytes(their_dh_public_bytes)
        shared_secret = our_dh_private.exchange(their_public_key)

        # HKDF expansion to 32 bytes (256 bits)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        ).derive(shared_secret)

        return cls(derived_key)

    @classmethod
    def establish_from_b64(
        cls,
        our_dh_private: x25519.X25519PrivateKey,
        their_dh_public_b64: str,
        info: bytes = b"agent-iam-secure-session-v1",
    ) -> SecureSession:
        their_public_bytes = base64.b64decode(their_dh_public_b64)
        return cls.establish(our_dh_private, their_public_bytes, info=info)

    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> Tuple[bytes, bytes]:
        """
        Encrypts plaintext with AES-GCM.
        Returns: (ciphertext_with_tag, nonce)
        """
        nonce = os.urandom(12)  # Standard 96-bit nonce for AES-GCM
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return ciphertext, nonce

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """
        Decrypts and verifies authentication tag with AES-GCM.
        Raises InvalidTag if tampered with.
        """
        return self._aesgcm.decrypt(nonce, ciphertext, associated_data)

    def encrypt_to_envelope(self, plaintext: bytes, associated_data: bytes | None = None) -> dict:
        """Convenience method returning a JSON-serializable envelope with base64 strings."""
        ciphertext, nonce = self.encrypt(plaintext, associated_data)
        return {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "aad": base64.b64encode(associated_data).decode("utf-8") if associated_data else None,
        }

    def decrypt_envelope(self, envelope: dict) -> bytes:
        """Decrypts a base64 envelope."""
        ciphertext = base64.b64decode(envelope["ciphertext"])
        nonce = base64.b64decode(envelope["nonce"])
        aad = base64.b64decode(envelope["aad"]) if envelope.get("aad") else None
        return self.decrypt(ciphertext, nonce, aad)
