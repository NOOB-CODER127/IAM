"""
Agent Identity Authority (CA): Issues, signs, verifies, and revokes Agent Passports.
Functions as the Zero Trust Identity Provider (IdP) for autonomous agents.
"""

from __future__ import annotations
import time
import uuid
from typing import Dict, List, Optional, Set

from agent_iam.crypto.keys import AgentKeyPair
from agent_iam.identity.passport import AgentPassport


class AgentIdentityAuthority:
    """
    Root Certificate Authority (CA) for Agent Passports.
    Signs passports with its master Ed25519 key and manages an active revocation list.
    """

    def __init__(self, ca_keypair: Optional[AgentKeyPair] = None, mesh_domain: str = "agent-mesh.local"):
        self._ca_keypair = ca_keypair or AgentKeyPair.generate()
        self.mesh_domain = mesh_domain
        self._revoked_agents: Dict[str, str] = {}  # agent_id -> revocation_reason

    @property
    def ca_public_key_b64(self) -> str:
        return self._ca_keypair.signing_public_b64

    def issue_passport(
        self,
        role: str,
        agent_keys: AgentKeyPair,
        model_id: str,
        system_prompt: str,
        delegated_by: str,
        capabilities: List[str],
        validity_seconds: float = 3600.0,
        custom_id: Optional[str] = None,
    ) -> AgentPassport:
        """
        Mints and cryptographically signs a new AgentPassport.
        """
        agent_uuid = custom_id or uuid.uuid4().hex[:12]
        agent_id = f"agent://{self.mesh_domain}/{role}/{agent_uuid}"
        now = time.time()

        passport = AgentPassport(
            agent_id=agent_id,
            role=role,
            ed25519_public_key=agent_keys.signing_public_b64,
            x25519_public_key=agent_keys.dh_public_b64,
            model_id=model_id,
            prompt_hash=AgentPassport.compute_prompt_hash(system_prompt),
            capabilities=capabilities,
            delegated_by=delegated_by,
            created_at=now,
            expires_at=now + validity_seconds,
        )

        # Authority signs canonical bytes
        signature = self._ca_keypair.sign_b64(passport.canonical_bytes())
        passport.authority_signature = signature
        return passport

    def verify_passport(self, passport: AgentPassport) -> bool:
        """
        Verifies:
        1. CA signature validity
        2. Passport expiration
        3. Passport is not on revocation list
        """
        if not passport.authority_signature:
            return False

        if passport.is_expired:
            return False

        if self.is_revoked(passport.agent_id):
            return False

        canonical_bytes = passport.canonical_bytes()
        return AgentKeyPair.verify_b64(
            self.ca_public_key_b64,
            passport.authority_signature,
            canonical_bytes,
        )

    def revoke_agent(self, agent_id: str, reason: str = "revoked by admin / security policy") -> None:
        """Kill switch: Instantly revoke an agent's identity."""
        self._revoked_agents[agent_id] = reason

    def is_revoked(self, agent_id: str) -> bool:
        return agent_id in self._revoked_agents

    def get_revocation_reason(self, agent_id: str) -> Optional[str]:
        return self._revoked_agents.get(agent_id)
