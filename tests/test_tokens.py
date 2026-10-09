import time
import pytest
from agent_iam.crypto import AgentKeyPair
from agent_iam.identity import AgentIdentityAuthority
from agent_iam.tokens import CapabilityTokenIssuer, CapabilityTokenVerifier


def test_root_token_issuance_and_verification():
    authority = AgentIdentityAuthority()
    issuer = CapabilityTokenIssuer(authority)
    verifier = CapabilityTokenVerifier(authority.ca_public_key_b64)

    agent_keys = AgentKeyPair.generate()
    agent_id = "agent://mesh/orchestrator/01"

    root_caps = ["tool:sql:read", "tool:sql:write", "tool:web:search"]
    token = issuer.issue_root_token(
        agent_id=agent_id,
        agent_public_key_b64=agent_keys.signing_public_b64,
        capabilities=root_caps,
        validity_seconds=300,
    )

    # Valid token verification
    assert verifier.verify_token(token, expected_holder_public_key_b64=agent_keys.signing_public_b64) is True
    assert token.has_capability("tool:sql:read") is True
    assert token.has_capability("tool:admin:drop_db") is False


def test_token_attenuation_downscoping():
    authority = AgentIdentityAuthority()
    issuer = CapabilityTokenIssuer(authority)
    verifier = CapabilityTokenVerifier(authority.ca_public_key_b64)

    # Orchestrator agent
    orch_keys = AgentKeyPair.generate()
    orch_id = "agent://mesh/orchestrator/01"
    root_token = issuer.issue_root_token(
        agent_id=orch_id,
        agent_public_key_b64=orch_keys.signing_public_b64,
        capabilities=["tool:sql:read", "tool:sql:write", "tool:web:search"],
        validity_seconds=300,
    )

    # Sub-agent (Read-only worker)
    worker_keys = AgentKeyPair.generate()
    worker_id = "agent://mesh/worker/sql_readonly_01"

    # Orchestrator attenuates token to ONLY allow sql:read
    worker_token = root_token.attenuate(
        delegator_keypair=orch_keys,
        child_agent_id=worker_id,
        child_public_key_b64=worker_keys.signing_public_b64,
        restricted_capabilities=["tool:sql:read"],
        max_validity_seconds=60,
    )

    # Verifier checks worker's token bound to worker's key
    assert verifier.verify_token(
        worker_token,
        expected_holder_public_key_b64=worker_keys.signing_public_b64,
        required_capability="tool:sql:read",
    ) is True

    # Worker no longer has write or search capabilities
    assert worker_token.has_capability("tool:sql:write") is False
    assert worker_token.has_capability("tool:web:search") is False

    # Proof-of-Possession check: Orchestrator cannot use worker's attenuated token as self
    assert verifier.verify_token(
        worker_token,
        expected_holder_public_key_b64=orch_keys.signing_public_b64,
    ) is False


def test_privilege_escalation_blocked():
    authority = AgentIdentityAuthority()
    issuer = CapabilityTokenIssuer(authority)

    orch_keys = AgentKeyPair.generate()
    root_token = issuer.issue_root_token(
        agent_id="agent://mesh/orch",
        agent_public_key_b64=orch_keys.signing_public_b64,
        capabilities=["tool:sql:read"],
    )

    worker_keys = AgentKeyPair.generate()

    # Attempting to grant a capability not held by delegator raises ValueError
    with pytest.raises(ValueError, match="Privilege escalation attempt"):
        root_token.attenuate(
            delegator_keypair=orch_keys,
            child_agent_id="agent://mesh/worker",
            child_public_key_b64=worker_keys.signing_public_b64,
            restricted_capabilities=["tool:sql:read", "tool:sql:write"],
        )


def test_non_holder_cannot_attenuate():
    authority = AgentIdentityAuthority()
    issuer = CapabilityTokenIssuer(authority)

    orch_keys = AgentKeyPair.generate()
    imposter_keys = AgentKeyPair.generate()

    root_token = issuer.issue_root_token(
        agent_id="agent://mesh/orch",
        agent_public_key_b64=orch_keys.signing_public_b64,
        capabilities=["tool:sql:read"],
    )

    worker_keys = AgentKeyPair.generate()

    # Imposter trying to attenuate someone else's token fails
    with pytest.raises(PermissionError, match="Only the current token holder"):
        root_token.attenuate(
            delegator_keypair=imposter_keys,
            child_agent_id="agent://mesh/worker",
            child_public_key_b64=worker_keys.signing_public_b64,
            restricted_capabilities=["tool:sql:read"],
        )
