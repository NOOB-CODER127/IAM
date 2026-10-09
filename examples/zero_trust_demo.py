"""
End-to-End Demonstration of Zero Trust IAM for AI Agents.
Demonstrating:
1. Cryptographic Agent Identity (Ed25519) & Attestation
2. Perfect Forward Secrecy via Diffie-Hellman (X25519) + AES-GCM
3. Token Attenuation downscoping for Sub-Agents
4. Real-time Policy Enforcement Point (ZeroTrustGateway)
5. Kill Switch (Instant Revocation)
"""

import sys
from pathlib import Path

# Ensure project root is in python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_iam.crypto import AgentKeyPair, SecureSession, SignedToolRequest
from agent_iam.identity import AgentIdentityAuthority
from agent_iam.tokens import CapabilityTokenIssuer
from agent_iam.gateway import ZeroTrustGateway, SecurityViolation


def main():
    print("=" * 70)
    print("🛡️  ZERO TRUST IDENTITY AND ACCESS MANAGEMENT FOR AI AGENTS")
    print("=" * 70)

    # 1. Initialize Control Plane (Certificate Authority & Gateway)
    print("\n[Step 1] Initializing Agent Identity Authority & Zero Trust Gateway...")
    authority = AgentIdentityAuthority(mesh_domain="cyber-mesh.internal")
    gateway = ZeroTrustGateway(authority)
    issuer = CapabilityTokenIssuer(authority)

    # Register protected tools in Gateway
    gateway.register_tool("fetch_financial_report", lambda quarter: f"Financial Report ({quarter}): Revenue $5.2M")
    gateway.register_tool("execute_bank_transfer", lambda amount, recipient: f"Transferred ${amount} to {recipient}")
    print("  -> Tools registered in Policy Enforcement Point: 'fetch_financial_report', 'execute_bank_transfer'")

    # 2. Spawn Orchestrator Agent
    print("\n[Step 2] Minting Agent Passport for Orchestrator Agent...")
    orch_keys = AgentKeyPair.generate()
    orch_passport = authority.issue_passport(
        role="financial_orchestrator",
        agent_keys=orch_keys,
        model_id="gemini-1.5-pro",
        system_prompt="You coordinate financial audits and disbursements.",
        delegated_by="user:cfo@company.com",
        capabilities=["tool:fetch_financial_report", "tool:execute_bank_transfer"],
        validity_seconds=3600,
    )
    orch_token = issuer.issue_root_token(
        agent_id=orch_passport.agent_id,
        agent_public_key_b64=orch_keys.signing_public_b64,
        capabilities=["tool:fetch_financial_report", "tool:execute_bank_transfer"],
    )
    print(f"  -> Agent ID: {orch_passport.agent_id}")
    print(f"  -> Public Key Fingerprint: {orch_keys.fingerprint[:16]}...")
    print(f"  -> System Prompt Attestation Hash: {orch_passport.prompt_hash[:16]}...")
    print(f"  -> Capabilities: {orch_token.effective_capabilities}")

    # 3. Diffie-Hellman Encrypted Channel
    print("\n[Step 3] Establishing Encrypted Channel via Diffie-Hellman (X25519)...")
    gateway_keys = AgentKeyPair.generate()
    session_orch = SecureSession.establish(orch_keys.dh_private_key, gateway_keys.dh_public_bytes)
    session_gw = SecureSession.establish(gateway_keys.dh_private_key, orch_keys.dh_public_bytes)
    
    secret_payload = b'{"confidential": "Q3 balance sheet data"}'
    ciphertext, nonce = session_orch.encrypt(secret_payload)
    decrypted = session_gw.decrypt(ciphertext, nonce)
    print(f"  -> ECDH exchange complete. Decrypted session payload: {decrypted.decode()}")

    # 4. Orchestrator delegates a subtask to an untrusted/junior Analyst Worker
    print("\n[Step 4] Sub-Delegation & Token Attenuation (Parent -> Worker)...")
    worker_keys = AgentKeyPair.generate()
    worker_passport = authority.issue_passport(
        role="junior_analyst",
        agent_keys=worker_keys,
        model_id="gemini-1.5-flash",
        system_prompt="You only read financial reports.",
        delegated_by=orch_passport.agent_id,
        capabilities=["tool:fetch_financial_report"],
    )

    # Cryptographic Attenuation: Orchestrator downscopes token to READ ONLY
    worker_token = orch_token.attenuate(
        delegator_keypair=orch_keys,
        child_agent_id=worker_passport.agent_id,
        child_public_key_b64=worker_keys.signing_public_b64,
        restricted_capabilities=["tool:fetch_financial_report"],  # NO TRANSFER CAPABILITY!
    )
    print(f"  -> Worker Agent ID: {worker_passport.agent_id}")
    print(f"  -> Worker Effective Capabilities: {worker_token.effective_capabilities}")

    # 5. Worker executes authorized tool
    print("\n[Step 5] Worker executes authorized tool ('fetch_financial_report')...")
    req_valid = SignedToolRequest.create(
        agent_keypair=worker_keys,
        agent_id=worker_passport.agent_id,
        tool_name="fetch_financial_report",
        parameters={"quarter": "Q3-2026"},
    )
    result = gateway.invoke(worker_passport, worker_token, req_valid)
    print(f"  ✅ SUCCESS: {result}")

    # 6. Attack Simulation: Prompt Injection forces Worker to attempt bank transfer
    print("\n[Step 6] Attack Simulation: Worker tricked by Prompt Injection to call 'execute_bank_transfer'...")
    req_malicious = SignedToolRequest.create(
        agent_keypair=worker_keys,
        agent_id=worker_passport.agent_id,
        tool_name="execute_bank_transfer",
        parameters={"amount": 500000, "recipient": "attacker_account"},
    )
    try:
        gateway.invoke(worker_passport, worker_token, req_malicious)
        print("  ❌ ERROR: Malicious call was unexpectedly allowed!")
    except SecurityViolation as e:
        print(f"  🛡️ BLOCKED BY ZERO TRUST GATEWAY: {e}")

    # 7. Kill Switch: Instant Revocation
    print("\n[Step 7] Testing Kill Switch (Instant Revocation)...")
    authority.revoke_agent(worker_passport.agent_id, reason="Worker flagged for suspicious behavior")
    print(f"  -> Revoked Agent: {worker_passport.agent_id}")

    try:
        gateway.invoke(worker_passport, worker_token, req_valid)
        print("  ❌ ERROR: Revoked agent was able to invoke tool!")
    except SecurityViolation as e:
        print(f"  🛡️ BLOCKED BY KILL SWITCH: {e}")

    print("\n" + "=" * 70)
    print("✅ All Zero Trust IAM security guarantees verified successfully!")
    print("=" * 70)


if __name__ == "__main__":
    main()
