# Agent IAM: Zero Trust Identity and Access Management for AI Agents

> **"Never Trust, Always Verify" applied to Autonomous AI Agents.**

[![Tests](https://img.shields.io/badge/pytest-15%20passed-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/crypto-Ed25519%20%7C%20X25519%20%7C%20AES--GCM-blue.svg)]()
[![Zero Trust](https://img.shields.io/badge/architecture-NIST%20SP%20800--207-orange.svg)]()

## Overview

Traditional IAM (OAuth, SAML, static API keys) is broken for AI agents:
1. **Confused Deputy Attacks:** When an agent is manipulated via prompt injection, it misuses its high-privilege credentials.
2. **Uncontrolled Delegation:** Multi-agent workflows delegate tasks across agent swarms without cryptographic downscoping or provenance tracking.
3. **Lack of Proof-of-Possession:** Bearer tokens leaked into LLM context can be stolen and reused by anyone.

**Agent IAM** implements a mathematically verifiable **Zero Trust Architecture** tailored specifically for autonomous AI agents.

---

## Core Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CONTROL PLANE: Identity Authority                    │
│   - Issues Agent Passports (Ed25519 Public Key + Prompt Attestation)   │
│   - Mints Root Capability Tokens                                       │
│   - Maintains Active Revocation List (Instant Kill Switch)             │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    EXECUTION PLANE: Agent Mesh                         │
│   - Parent Agent (Orchestrator) holds Keypair & Root Token             │
│   - Attenuates token downscope (Hierarchical Least Privilege)          │
│   - Sub-Agents receive restricted tokens bound to their own public key │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│               ENFORCEMENT PLANE: Zero Trust Gateway (PEP)              │
│   1. Verifies Agent Passport & CA Signature                            │
│   2. Enforces Proof-of-Possession (PoP) & Anti-Replay Nonce            │
│   3. Verifies Cryptographic Attenuation Chain                          │
│   4. Checks Instant Revocation Status                                  │
│   5. Executes Tool only upon full cryptographic authorization          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Key Cryptographic Primitives

1. **Digital Signatures (Ed25519):**
   * Every agent generates an ephemeral Ed25519 keypair at initialization.
   * Every tool call must be cryptographically signed by the agent (Proof-of-Possession). Leaking a token string alone is completely harmless.
2. **Key Agreement & Perfect Forward Secrecy (X25519 / Diffie-Hellman):**
   * Negotiates ephemeral AES-256-GCM session keys between agents and the Gateway.
   * Compromise of an agent's current state does not expose historical tool calls or messages.
3. **Token Attenuation (Hierarchical Downscoping):**
   * Parent agents can append cryptographic attenuation blocks to downscope capabilities before delegating to child agents.
   * Cryptographically prevents privilege escalation: child agents cannot add capabilities or extend token lifetimes.
4. **Attestation & Prompt Integrity:**
   * Passports include a SHA-256 hash of the agent's system prompt and model metadata to prevent prompt tampering or unauthorized drift.
5. **Instant Kill Switch:**
   * Revocation at the CA level immediately halts any further tool executions for compromised agents.

---

## Directory Structure

```
IAM/
├── agent_iam/
│   ├── crypto/
│   │   ├── keys.py          # Ed25519 signing & X25519 Diffie-Hellman keys
│   │   ├── session.py       # ECDH shared secret derivation + HKDF + AES-GCM
│   │   └── signatures.py    # Request signing, PoP & anti-replay verification
│   ├── identity/
│   │   ├── passport.py      # AgentPassport data model & prompt hash attestation
│   │   └── authority.py     # Agent Identity Authority (CA) & Kill Switch
│   ├── tokens/
│   │   ├── capability.py    # CapabilityToken & AttenuationBlock (downscoping)
│   │   ├── issuer.py        # Minting root capability tokens
│   │   └── verifier.py      # Cryptographic attenuation chain verification
│   └── gateway/
│       └── interceptor.py   # ZeroTrustGateway Policy Enforcement Point (PEP)
├── tests/
│   ├── test_crypto.py       # Key generation, signatures, and ECDH tests
│   ├── test_identity.py     # Passport issuance, tampering, and revocation tests
│   ├── test_tokens.py       # Token attenuation and escalation prevention tests
│   └── test_gateway.py      # End-to-end policy enforcement & attack tests
├── examples/
│   └── zero_trust_demo.py   # Complete end-to-end demo scenario
├── pyproject.toml
└── README.md
```

---

## Quickstart

### 1. Run Unit Tests
```bash
pytest -v
```

### 2. Run the End-to-End Zero Trust Demo
```bash
python3 examples/zero_trust_demo.py
```