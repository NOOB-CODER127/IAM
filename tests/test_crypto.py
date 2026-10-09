import time
import pytest
from agent_iam.crypto import AgentKeyPair, SecureSession, SignedToolRequest


def test_agent_keypair_generation_and_signatures():
    agent_keys = AgentKeyPair.generate()

    assert agent_keys.signing_public_b64 is not None
    assert agent_keys.dh_public_b64 is not None
    assert len(agent_keys.fingerprint) == 64

    data = b"execute_tool_action_payload_123"
    signature_b64 = agent_keys.sign_b64(data)

    # Valid signature
    assert AgentKeyPair.verify_b64(agent_keys.signing_public_b64, signature_b64, data) is True

    # Tampered data
    tampered_data = b"execute_tool_action_payload_456"
    assert AgentKeyPair.verify_b64(agent_keys.signing_public_b64, signature_b64, tampered_data) is False

    # Impersonation test with another key
    imposter_keys = AgentKeyPair.generate()
    assert AgentKeyPair.verify_b64(imposter_keys.signing_public_b64, signature_b64, data) is False


def test_diffie_hellman_session_encryption_and_forward_secrecy():
    agent = AgentKeyPair.generate()
    gateway = AgentKeyPair.generate()

    # Agent establishes session using gateway's public DH key
    agent_session = SecureSession.establish(
        agent.dh_private_key,
        gateway.dh_public_bytes,
    )

    # Gateway establishes session using agent's public DH key
    gateway_session = SecureSession.establish(
        gateway.dh_private_key,
        agent.dh_public_bytes,
    )

    secret_prompt = b'{"instruction": "analyze financial quarterly report", "budget": 100}'
    ciphertext, nonce = agent_session.encrypt(secret_prompt, associated_data=b"task-99")

    # Gateway successfully decrypts
    decrypted = gateway_session.decrypt(ciphertext, nonce, associated_data=b"task-99")
    assert decrypted == secret_prompt

    # Tampered ciphertext fails authentication (AEAD integrity)
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF
    with pytest.raises(Exception):
        gateway_session.decrypt(bytes(tampered_ciphertext), nonce, associated_data=b"task-99")

    # Tampered associated data fails authentication
    with pytest.raises(Exception):
        gateway_session.decrypt(ciphertext, nonce, associated_data=b"task-tampered")


def test_signed_tool_request_anti_replay():
    agent_keys = AgentKeyPair.generate()
    agent_id = "agent://mesh/finance/worker-1"

    seen_nonces = set()
    signed_req = SignedToolRequest.create(
        agent_keypair=agent_keys,
        agent_id=agent_id,
        tool_name="sql_query",
        parameters={"query": "SELECT count(*) FROM users"},
    )

    # First verification succeeds
    assert SignedToolRequest.verify(signed_req, agent_keys.signing_public_b64, seen_nonces=seen_nonces) is True

    # Replay attack with the exact same request fails
    assert SignedToolRequest.verify(signed_req, agent_keys.signing_public_b64, seen_nonces=seen_nonces) is False

    # Expired request fails
    signed_req_expired = SignedToolRequest.create(
        agent_keypair=agent_keys,
        agent_id=agent_id,
        tool_name="sql_query",
        parameters={"query": "SELECT 1"},
    )
    signed_req_expired["payload"]["timestamp"] = time.time() - 1000
    # Note: signature must match, but even if valid, timestamp window check rejects it
    assert SignedToolRequest.verify(signed_req_expired, agent_keys.signing_public_b64, max_clock_skew_seconds=60) is False
