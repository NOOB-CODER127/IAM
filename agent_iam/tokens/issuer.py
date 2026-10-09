"""
Token Issuer: Mints root capability tokens for agents based on human authorization.
"""

from __future__ import annotations
import time
from typing import List, Optional

from agent_iam.crypto.keys import AgentKeyPair
from agent_iam.identity.authority import AgentIdentityAuthority
from agent_iam.tokens.capability import CapabilityToken


class CapabilityTokenIssuer:
    """
    Issues root capability tokens signed by the Identity Authority.
    """

    def __init__(self, authority: AgentIdentityAuthority):
        self.authority = authority

    def issue_root_token(
        self,
        agent_id: str,
        agent_public_key_b64: str,
        capabilities: List[str],
        validity_seconds: float = 3600.0,
    ) -> CapabilityToken:
        now = time.time()
        token = CapabilityToken(
            root_issuer=f"ca://{self.authority.mesh_domain}",
            root_agent_id=agent_id,
            root_public_key_b64=agent_public_key_b64,
            root_capabilities=sorted(capabilities),
            root_expires_at=now + validity_seconds,
        )

        # Authority signs root token
        token.root_signature = self.authority._ca_keypair.sign_b64(token.canonical_root_bytes())
        return token
