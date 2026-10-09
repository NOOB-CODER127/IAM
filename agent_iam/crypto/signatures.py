"""
Cryptographic request signing and anti-replay verification for Agent tool calls.
Enforces Proof-of-Possession (PoP).
"""

from __future__ import annotations
import json
import time
import uuid
from typing import Any, Dict, Set

from agent_iam.crypto.keys import AgentKeyPair


def canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    """Produces deterministic, canonical JSON bytes for signature generation."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SignedToolRequest:
    """
    Represents a signed tool call from an agent.
    Includes anti-replay nonce and timestamp.
    """

    @staticmethod
    def create(
        agent_keypair: AgentKeyPair,
        agent_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        capability_token_id: str | None = None,
    ) -> Dict[str, Any]:
        """
        Signs a tool execution request with the agent's Ed25519 private key.
        """
        payload = {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "parameters": parameters,
            "capability_token_id": capability_token_id,
            "timestamp": time.time(),
            "nonce": uuid.uuid4().hex,
        }
        canonical_bytes = canonical_json_bytes(payload)
        signature = agent_keypair.sign_b64(canonical_bytes)

        return {
            "payload": payload,
            "signature": signature,
        }

    @staticmethod
    def verify(
        signed_request: Dict[str, Any],
        agent_public_key_b64: str,
        seen_nonces: Set[str] | None = None,
        max_clock_skew_seconds: float = 60.0,
    ) -> bool:
        """
        Verifies the request signature, timestamp, and replay-prevention nonce.
        """
        payload = signed_request.get("payload")
        signature = signed_request.get("signature")
        if not payload or not signature:
            return False

        # Anti-replay check 1: Clock skew / expiration
        req_timestamp = payload.get("timestamp", 0)
        current_time = time.time()
        if abs(current_time - req_timestamp) > max_clock_skew_seconds:
            return False

        # Anti-replay check 2: Nonce reuse
        nonce = payload.get("nonce")
        if not nonce:
            return False
        if seen_nonces is not None:
            if nonce in seen_nonces:
                return False
            seen_nonces.add(nonce)

        # Cryptographic verification
        canonical_bytes = canonical_json_bytes(payload)
        return AgentKeyPair.verify_b64(agent_public_key_b64, signature, canonical_bytes)
