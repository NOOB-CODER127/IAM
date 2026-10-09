"""
Zero Trust Policy Enforcement Point (PEP) Gateway.
Intercepts all agent tool calls, enforcing cryptographic proof-of-possession,
agent passport validity, and token capabilities before granting access.
"""

from __future__ import annotations
import logging
from typing import Any, Callable, Dict, Optional, Set

from agent_iam.crypto.signatures import SignedToolRequest
from agent_iam.identity.authority import AgentIdentityAuthority
from agent_iam.identity.passport import AgentPassport
from agent_iam.tokens.capability import CapabilityToken
from agent_iam.tokens.verifier import CapabilityTokenVerifier

logger = logging.getLogger("agent_iam.gateway")


class SecurityViolation(Exception):
    """Raised when an agent tool invocation fails Zero Trust policy checks."""
    pass


class ZeroTrustGateway:
    """
    Policy Enforcement Point (PEP) that validates cryptographic signatures,
    passports, and attenuated capability tokens for every tool execution.
    """

    def __init__(self, authority: AgentIdentityAuthority):
        self.authority = authority
        self.token_verifier = CapabilityTokenVerifier(authority.ca_public_key_b64)
        self._seen_nonces: Set[str] = set()
        self._registered_tools: Dict[str, Callable[..., Any]] = {}

    def register_tool(self, tool_name: str, handler: Callable[..., Any]) -> None:
        """Register a protected tool function with the gateway."""
        self._registered_tools[tool_name] = handler

    def invoke(
        self,
        passport: AgentPassport,
        token: CapabilityToken,
        signed_request: Dict[str, Any],
    ) -> Any:
        """
        Zero Trust verification and invocation pipeline:
        1. Verify Agent Passport (CA signature, expiration, revocation)
        2. Verify Proof-of-Possession signature and anti-replay
        3. Verify Capability Token chain and permissions
        4. Execute tool
        """
        # 1. Verify Passport
        if not self.authority.verify_passport(passport):
            reason = self.authority.get_revocation_reason(passport.agent_id) or "Invalid or expired passport"
            raise SecurityViolation(f"Agent Passport rejected: {reason}")

        # 2. Verify Signed Request (Proof of Possession & Anti-Replay)
        is_sig_valid = SignedToolRequest.verify(
            signed_request=signed_request,
            agent_public_key_b64=passport.ed25519_public_key,
            seen_nonces=self._seen_nonces,
            max_clock_skew_seconds=60.0,
        )
        if not is_sig_valid:
            raise SecurityViolation("Tool request signature verification failed or replay detected")

        payload = signed_request["payload"]
        tool_name = payload["tool_name"]
        parameters = payload.get("parameters", {})

        # Ensure agent_id in request matches passport
        if payload.get("agent_id") != passport.agent_id:
            raise SecurityViolation(
                f"Agent ID mismatch: payload specifies {payload.get('agent_id')} but passport is {passport.agent_id}"
            )

        # 3. Verify Capability Token
        required_capability = f"tool:{tool_name}"
        is_token_valid = self.token_verifier.verify_token(
            token=token,
            expected_holder_public_key_b64=passport.ed25519_public_key,
            required_capability=required_capability,
        )
        if not is_token_valid:
            raise SecurityViolation(
                f"Unauthorized capability: Agent {passport.agent_id} lacks valid capability for '{required_capability}'"
            )

        # 4. Tool Execution
        if tool_name not in self._registered_tools:
            raise ValueError(f"Tool '{tool_name}' is not registered with the gateway")

        handler = self._registered_tools[tool_name]
        return handler(**parameters)
