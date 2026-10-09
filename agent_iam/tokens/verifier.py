"""
Capability Token Verifier: Validates cryptographic delegation chains and token attenuation.
"""

from __future__ import annotations
import time
from typing import Optional, Set

from agent_iam.crypto.keys import AgentKeyPair
from agent_iam.tokens.capability import CapabilityToken


class CapabilityTokenVerifier:
    """
    Verifies capability tokens and attenuation chains without contacting a central database.
    """

    def __init__(self, authority_public_key_b64: str):
        self.authority_public_key_b64 = authority_public_key_b64

    def verify_token(
        self,
        token: CapabilityToken,
        expected_holder_public_key_b64: Optional[str] = None,
        required_capability: Optional[str] = None,
    ) -> bool:
        """
        Validates the entire cryptographic chain of custody:
        1. Root signature from Authority
        2. Temporal validity (not expired)
        3. Each attenuation block signature and subset containment
        4. Proof-of-Possession binding (expected holder matches token holder)
        5. Required capability presence
        """
        # 1. Root signature check
        if not token.root_signature:
            return False

        if not AgentKeyPair.verify_b64(
            self.authority_public_key_b64,
            token.root_signature,
            token.canonical_root_bytes(),
        ):
            return False

        # 2. Expiration check
        if token.is_expired():
            return False

        # 3. Chain verification
        previous_signer_pubkey = token.root_public_key_b64
        current_capabilities = set(token.root_capabilities)
        max_time = token.root_expires_at

        for block in token.attenuation_chain:
            # Check block signature from the parent who delegated it
            if not block.delegator_signature:
                return False

            if not AgentKeyPair.verify_b64(
                previous_signer_pubkey,
                block.delegator_signature,
                block.canonical_bytes(),
            ):
                return False

            # Check capability containment (strict subset)
            block_caps = set(block.allowed_capabilities)
            if not block_caps.issubset(current_capabilities):
                return False  # Privilege escalation detected!

            # Check expiration monotonicity
            if block.max_expires_at > max_time:
                return False

            # Advance chain pointer
            previous_signer_pubkey = block.child_public_key_b64
            current_capabilities = block_caps
            max_time = block.max_expires_at

        # 4. Proof-of-Possession binding check
        if expected_holder_public_key_b64:
            if token.current_holder_public_key_b64 != expected_holder_public_key_b64:
                return False

        # 5. Required capability check
        if required_capability:
            if required_capability not in current_capabilities:
                return False

        return True
