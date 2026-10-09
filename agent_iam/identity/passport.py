"""
Agent Passport: Cryptographically signed identity document for AI Agents.
Contains attestation, public keys, capabilities, and provenance.
"""

from __future__ import annotations
import hashlib
import json
import time
from typing import List, Optional
from pydantic import BaseModel, Field

from agent_iam.crypto.keys import AgentKeyPair


class AgentPassport(BaseModel):
    """
    Cryptographic identity document for an AI agent instance.
    Signed by the Agent Identity Authority.
    """
    agent_id: str = Field(description="Unique Agent URI (e.g. agent://mesh/role/uuid)")
    role: str = Field(description="Agent role or specialization")
    ed25519_public_key: str = Field(description="Base64 Ed25519 public signing key")
    x25519_public_key: str = Field(description="Base64 X25519 public DH key")
    model_id: str = Field(description="AI model identifier (e.g. gemini-1.5-pro)")
    prompt_hash: str = Field(description="SHA-256 hash of the agent's system prompt")
    capabilities: List[str] = Field(default_factory=list, description="Base capability scopes")
    delegated_by: str = Field(description="Parent delegator (user or parent agent URI)")
    created_at: float = Field(default_factory=time.time)
    expires_at: float = Field(description="Expiration timestamp")
    authority_signature: Optional[str] = Field(default=None, description="Signature from Identity Authority")

    def canonical_bytes(self) -> bytes:
        """Returns canonical JSON bytes of passport fields excluding the authority signature."""
        data = {
            "agent_id": self.agent_id,
            "role": self.role,
            "ed25519_public_key": self.ed25519_public_key,
            "x25519_public_key": self.x25519_public_key,
            "model_id": self.model_id,
            "prompt_hash": self.prompt_hash,
            "capabilities": sorted(self.capabilities),
            "delegated_by": self.delegated_by,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @staticmethod
    def compute_prompt_hash(system_prompt: str) -> str:
        """Compute SHA-256 attestation hash of a system prompt."""
        return hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()
