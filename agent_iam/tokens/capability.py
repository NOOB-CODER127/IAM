"""
Cryptographic Capability Tokens with Token Attenuation (Hierarchical Downscoping).
Enforces least-privilege delegation across multi-agent chains without a central database lookup.
"""

from __future__ import annotations
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from agent_iam.crypto.keys import AgentKeyPair


class AttenuationBlock(BaseModel):
    """
    An attenuation block appended by an agent during sub-delegation.
    Restricts capabilities and bounds the child agent's identity.
    """
    block_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    child_agent_id: str
    child_public_key_b64: str
    allowed_capabilities: List[str]
    max_expires_at: float
    delegator_signature: Optional[str] = None  # Signed by the delegating parent's private key

    def canonical_bytes(self) -> bytes:
        data = {
            "block_id": self.block_id,
            "child_agent_id": self.child_agent_id,
            "child_public_key_b64": self.child_public_key_b64,
            "allowed_capabilities": sorted(self.allowed_capabilities),
            "max_expires_at": self.max_expires_at,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class CapabilityToken(BaseModel):
    """
    Cryptographic capability token that can be attenuated down an agent delegation chain.
    """
    token_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    root_issuer: str
    root_agent_id: str
    root_public_key_b64: str
    root_capabilities: List[str]
    root_expires_at: float
    root_signature: Optional[str] = None
    attenuation_chain: List[AttenuationBlock] = Field(default_factory=list)

    def canonical_root_bytes(self) -> bytes:
        data = {
            "token_id": self.token_id,
            "root_issuer": self.root_issuer,
            "root_agent_id": self.root_agent_id,
            "root_public_key_b64": self.root_public_key_b64,
            "root_capabilities": sorted(self.root_capabilities),
            "root_expires_at": self.root_expires_at,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def current_holder_public_key_b64(self) -> str:
        if self.attenuation_chain:
            return self.attenuation_chain[-1].child_public_key_b64
        return self.root_public_key_b64

    @property
    def current_holder_agent_id(self) -> str:
        if self.attenuation_chain:
            return self.attenuation_chain[-1].child_agent_id
        return self.root_agent_id

    @property
    def effective_capabilities(self) -> Set[str]:
        if not self.attenuation_chain:
            return set(self.root_capabilities)
        return set(self.attenuation_chain[-1].allowed_capabilities)

    @property
    def effective_expires_at(self) -> float:
        exp = self.root_expires_at
        for block in self.attenuation_chain:
            if block.max_expires_at < exp:
                exp = block.max_expires_at
        return exp

    def is_expired(self) -> bool:
        return time.time() > self.effective_expires_at

    def has_capability(self, capability: str) -> bool:
        """Checks if the token currently possesses the given capability."""
        if self.is_expired():
            return False
        return capability in self.effective_capabilities

    def attenuate(
        self,
        delegator_keypair: AgentKeyPair,
        child_agent_id: str,
        child_public_key_b64: str,
        restricted_capabilities: List[str],
        max_validity_seconds: Optional[float] = None,
    ) -> CapabilityToken:
        """
        Derives an attenuated child token.
        Enforces that child capabilities must be a strict subset of delegator's current capabilities.
        """
        # Validate that delegator currently holds this token
        if delegator_keypair.signing_public_b64 != self.current_holder_public_key_b64:
            raise PermissionError("Only the current token holder can attenuate this token")

        # Validate capabilities cannot be expanded
        requested_set = set(restricted_capabilities)
        current_set = self.effective_capabilities
        if not requested_set.issubset(current_set):
            unauthorized = requested_set - current_set
            raise ValueError(f"Privilege escalation attempt: Cannot grant unauthorized capabilities: {unauthorized}")

        # Compute expiration
        child_expires_at = self.effective_expires_at
        if max_validity_seconds is not None:
            potential_exp = time.time() + max_validity_seconds
            if potential_exp < child_expires_at:
                child_expires_at = potential_exp

        new_block = AttenuationBlock(
            child_agent_id=child_agent_id,
            child_public_key_b64=child_public_key_b64,
            allowed_capabilities=sorted(list(requested_set)),
            max_expires_at=child_expires_at,
        )

        # Delegator signs the new block
        new_block.delegator_signature = delegator_keypair.sign_b64(new_block.canonical_bytes())

        # Return new cloned token with extended chain
        cloned = self.model_copy(deep=True)
        cloned.attenuation_chain.append(new_block)
        return cloned
