import pytest
from agent_iam.crypto import AgentKeyPair, SignedToolRequest
from agent_iam.identity import AgentIdentityAuthority
from agent_iam.tokens import CapabilityTokenIssuer
from agent_iam.gateway import ZeroTrustGateway, SecurityViolation


@pytest.fixture
def test_setup():
    authority = AgentIdentityAuthority()
    issuer = CapabilityTokenIssuer(authority)
    gateway = ZeroTrustGateway(authority)

    # Register sample tools
    def search_db(query: str):
        return f"Results for: {query}"

    def drop_table(table_name: str):
        return f"Dropped {table_name}"

    gateway.register_tool("search_db", search_db)
    gateway.register_tool("drop_table", drop_table)

    return authority, issuer, gateway


def test_successful_tool_invocation(test_setup):
    authority, issuer, gateway = test_setup
    agent_keys = AgentKeyPair.generate()

    passport = authority.issue_passport(
        role="analyst",
        agent_keys=agent_keys,
        model_id="gemini-1.5-pro",
        system_prompt="Search database",
        delegated_by="user:alice@company.com",
        capabilities=["tool:search_db"],
    )

    token = issuer.issue_root_token(
        agent_id=passport.agent_id,
        agent_public_key_b64=agent_keys.signing_public_b64,
        capabilities=["tool:search_db"],
    )

    signed_req = SignedToolRequest.create(
        agent_keypair=agent_keys,
        agent_id=passport.agent_id,
        tool_name="search_db",
        parameters={"query": "active_users"},
    )

    result = gateway.invoke(passport, token, signed_req)
    assert result == "Results for: active_users"


def test_unauthorized_tool_call_blocked(test_setup):
    authority, issuer, gateway = test_setup
    agent_keys = AgentKeyPair.generate()

    passport = authority.issue_passport(
        role="analyst",
        agent_keys=agent_keys,
        model_id="gemini-1.5-pro",
        system_prompt="Search only",
        delegated_by="user:alice@company.com",
        capabilities=["tool:search_db"],
    )

    token = issuer.issue_root_token(
        agent_id=passport.agent_id,
        agent_public_key_b64=agent_keys.signing_public_b64,
        capabilities=["tool:search_db"],
    )

    # Agent attempts to call drop_table (which it does not have capability for)
    signed_req = SignedToolRequest.create(
        agent_keypair=agent_keys,
        agent_id=passport.agent_id,
        tool_name="drop_table",
        parameters={"table_name": "users"},
    )

    with pytest.raises(SecurityViolation, match="Unauthorized capability"):
        gateway.invoke(passport, token, signed_req)


def test_revoked_agent_blocked_immediately(test_setup):
    authority, issuer, gateway = test_setup
    agent_keys = AgentKeyPair.generate()

    passport = authority.issue_passport(
        role="analyst",
        agent_keys=agent_keys,
        model_id="gemini-1.5-pro",
        system_prompt="Search only",
        delegated_by="user:alice@company.com",
        capabilities=["tool:search_db"],
    )

    token = issuer.issue_root_token(
        agent_id=passport.agent_id,
        agent_public_key_b64=agent_keys.signing_public_b64,
        capabilities=["tool:search_db"],
    )

    signed_req = SignedToolRequest.create(
        agent_keypair=agent_keys,
        agent_id=passport.agent_id,
        tool_name="search_db",
        parameters={"query": "active_users"},
    )

    # Security team trips the kill switch
    authority.revoke_agent(passport.agent_id, reason="Compromised via prompt injection")

    with pytest.raises(SecurityViolation, match="Agent Passport rejected"):
        gateway.invoke(passport, token, signed_req)


def test_subagent_attenuated_delegation(test_setup):
    authority, issuer, gateway = test_setup

    # Orchestrator has search and drop capabilities
    orch_keys = AgentKeyPair.generate()
    orch_passport = authority.issue_passport(
        role="orchestrator",
        agent_keys=orch_keys,
        model_id="gemini-1.5-pro",
        system_prompt="Plan tasks",
        delegated_by="user:alice@company.com",
        capabilities=["tool:search_db", "tool:drop_table"],
    )

    orch_token = issuer.issue_root_token(
        agent_id=orch_passport.agent_id,
        agent_public_key_b64=orch_keys.signing_public_b64,
        capabilities=["tool:search_db", "tool:drop_table"],
    )

    # Worker subagent
    worker_keys = AgentKeyPair.generate()
    worker_passport = authority.issue_passport(
        role="worker",
        agent_keys=worker_keys,
        model_id="gemini-1.5-pro",
        system_prompt="Search worker",
        delegated_by=orch_passport.agent_id,
        capabilities=["tool:search_db"],
    )

    # Orchestrator attenuates token to ONLY allow search_db
    worker_token = orch_token.attenuate(
        delegator_keypair=orch_keys,
        child_agent_id=worker_passport.agent_id,
        child_public_key_b64=worker_keys.signing_public_b64,
        restricted_capabilities=["tool:search_db"],
    )

    # Worker successfully calls search_db
    valid_req = SignedToolRequest.create(
        agent_keypair=worker_keys,
        agent_id=worker_passport.agent_id,
        tool_name="search_db",
        parameters={"query": "items"},
    )
    result = gateway.invoke(worker_passport, worker_token, valid_req)
    assert result == "Results for: items"

    # Worker attempts to call drop_table using its attenuated token
    invalid_req = SignedToolRequest.create(
        agent_keypair=worker_keys,
        agent_id=worker_passport.agent_id,
        tool_name="drop_table",
        parameters={"table_name": "items"},
    )
    with pytest.raises(SecurityViolation, match="Unauthorized capability"):
        gateway.invoke(worker_passport, worker_token, invalid_req)
