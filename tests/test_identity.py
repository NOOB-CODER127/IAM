import time
import pytest
from agent_iam.crypto import AgentKeyPair
from agent_iam.identity import AgentIdentityAuthority, AgentPassport


def test_passport_issuance_and_verification():
    authority = AgentIdentityAuthority()
    agent_keys = AgentKeyPair.generate()

    prompt = "You are a read-only database query assistant. Only execute SELECT queries."
    passport = authority.issue_passport(
        role="db_analyst",
        agent_keys=agent_keys,
        model_id="gemini-1.5-pro",
        system_prompt=prompt,
        delegated_by="user:alice@company.com",
        capabilities=["tool:sql_read", "tool:schema_inspect"],
        validity_seconds=120.0,
    )

    assert passport.agent_id.startswith("agent://agent-mesh.local/db_analyst/")
    assert passport.prompt_hash == AgentPassport.compute_prompt_hash(prompt)
    assert authority.verify_passport(passport) is True


def test_passport_tampering_detection():
    authority = AgentIdentityAuthority()
    agent_keys = AgentKeyPair.generate()

    passport = authority.issue_passport(
        role="db_analyst",
        agent_keys=agent_keys,
        model_id="gemini-1.5-pro",
        system_prompt="Analyze logs",
        delegated_by="user:alice@company.com",
        capabilities=["tool:read_logs"],
    )

    # An attacker tries to escalate capabilities in the passport
    tampered_passport = passport.model_copy(deep=True)
    tampered_passport.capabilities.append("tool:drop_database")

    # Verification must fail
    assert authority.verify_passport(tampered_passport) is False


def test_passport_revocation_kill_switch():
    authority = AgentIdentityAuthority()
    agent_keys = AgentKeyPair.generate()

    passport = authority.issue_passport(
        role="worker",
        agent_keys=agent_keys,
        model_id="gpt-4o",
        system_prompt="Do tasks",
        delegated_by="user:alice@company.com",
        capabilities=["tool:search"],
    )

    assert authority.verify_passport(passport) is True

    # Security team detects anomaly and trips the kill switch
    authority.revoke_agent(passport.agent_id, reason="Prompt injection attempt detected")

    # Immediate rejection
    assert authority.is_revoked(passport.agent_id) is True
    assert authority.verify_passport(passport) is False
    assert "Prompt injection" in authority.get_revocation_reason(passport.agent_id)


def test_passport_expiration():
    authority = AgentIdentityAuthority()
    agent_keys = AgentKeyPair.generate()

    passport = authority.issue_passport(
        role="worker",
        agent_keys=agent_keys,
        model_id="gpt-4o",
        system_prompt="Do tasks",
        delegated_by="user:alice@company.com",
        capabilities=["tool:search"],
        validity_seconds=0.01,
    )

    time.sleep(0.05)
    assert passport.is_expired is True
    assert authority.verify_passport(passport) is False
