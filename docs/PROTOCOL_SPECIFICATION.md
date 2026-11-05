# MedPQC Protocol Specification (v2.5)

**Protocol Name**: Authenticated Hybrid Post-Quantum Medical Key Exchange (MedPQC-v2.5)  
**Suite Identifier**: `ECDH-P256+ML-KEM-768+Ed25519+AES-256-GCM`  
**Authors**: Muhammad Khubaib Ahmad, Muzammil Shadab (INFERENCE Lab)  
**Date**: November 2026  

---

## 1. Protocol Architecture and Participants

The MedPQC protocol operates between two authenticated entities using dedicated context classes:
- **Initiator (Alice)**: Clinical workstation or client imaging system (managed via `InitiatorContext`), identified by `sender_id` (e.g., `"hospital-a-pacs"`).
- **Responder (Bob)**: Hospital PACS archive or vendor-neutral archive (VNA) (managed via `ResponderContext`), identified by `receiver_id` (e.g., `"hospital-b-pacs"`).

### 1.1 Long-Term Cryptographic Identities
Each entity possesses a long-term Ed25519 signing keypair (`IdentityKeyPair`):
- Alice: Private signing key $sk_A$, Public identity key $pk_A \in \{0,1\}^{32}$.
- Bob: Private signing key $sk_B$, Public identity key $pk_B \in \{0,1\}^{32}$.

Both nodes maintain an authorized peer identity registry via `TrustStore`.

### 1.2 Context API Interface
The protocol enforces role separation using distinct contexts:
- `InitiatorContext(node_id, identity, trust_store)`:
  - `initiate(peer_node_id, offered_suites=...) -> dict[str, Any]`: Samples ephemeral keys and outputs signed initiation message.
  - `finalize(response_message) -> Session`: Verifies responder signature and derives directional session keys.
- `ResponderContext(node_id, identity, trust_store, replay_store, allow_non_durable_replay_store=False)`:
  - `respond(init_message) -> tuple[dict[str, Any], Session]`: Validates recipient binding, checks peer authorization, consumes replay token, encapsulates hybrid secrets, signs response, and derives directional session keys.

---

## 2. Protocol Execution Flow

```
Alice (InitiatorContext)                                         Bob (ResponderContext)
========================                                         ======================
1. Generate ephemeral P-256 (sk_eA, pk_eA)
2. Generate ML-KEM-768 (dk_pqA, ek_pqA)
3. Build T_init = CanonicalInit(...)
4. Compute Sig_A = Ed25519_Sign(sk_A, T_init)
5. Send InitMessage --------------------------------------------->
                                               1. Verify recipient binding (receiver_id == self.node_id)
                                               2. Verify pk_A in TrustStore (Mandatory)
                                               3. Verify Sig_A over T_init
                                               4. Freshness check & atomic ReplayStore consumption
                                               5. Generate ephemeral P-256 (sk_eB, pk_eB)
                                               6. (ct_pq, ss_pqB) = ML-KEM-768.Encap(ek_pqA)
                                               7. ss_ecdhB = ECDH(sk_eB, pk_eA)
                                               8. Build T_resp = CanonicalResp(H(T_init), ct_pq, ...)
                                               9. Compute Sig_B = Ed25519_Sign(sk_B, T_resp)
                                              10. Derive Keys: HKDF(ss_ecdhB || ss_pqB, Context)
                       <-------------------------------- Send RespMessage
1. Verify recipient binding (receiver_id == self.node_id)
2. Verify pk_B in TrustStore (Mandatory)
3. Verify Sig_B over T_resp
4. ss_pqA = ML-KEM-768.Decap(dk_pqA, ct_pq)
5. ss_ecdhA = ECDH(sk_eA, pk_eB)
6. Derive Keys: HKDF(ss_ecdhA || ss_pqA, Context)
```

---

## 3. Detailed Protocol Phases

### 3.1 Phase 1: Initiation Handshake (`InitiatorContext.initiate`)
1. **Timestamp**: Record current epoch time $t_{\text{init}}$ in milliseconds.
2. **Ephemeral Keys**:
   - Classical ephemeral keypair: $(sk_{eA}, pk_{eA}) \leftarrow \text{ECDH-P256.KeyGen}()$.
   - Post-quantum keypair: $(dk_{pqA}, ek_{pqA}) \leftarrow \text{ML-KEM-768.KeyGen}()$.
3. **Canonical Initiation Transcript ($T_{\text{init}}$)**:
   Construct length-prefixed byte framing:
   $$T_{\text{init}} = \text{Frame}\big(\text{"MedPQC-Canonical-Init-v2.4"}, v_{\text{proto}}, \text{suite\_id}, \text{sender\_id}, \text{receiver\_id}, \text{session\_id}, t_{\text{init}}, pk_A, pk_{eA}, ek_{pqA}\big)$$
4. **Signature**:
   $$\sigma_A = \text{Ed25519.Sign}(sk_A, T_{\text{init}})$$
5. **Dispatch**: Transmit `InitMessage = {protocol_version, suite_id, sender_id, receiver_id, session_id, timestamp, alice_id_pub, ecdh_pub, pq_pub, signature}`.

### 3.2 Phase 2: Response & Key Derivation (`ResponderContext.respond`)
1. **Recipient Binding**: Check that `receiver_id` matches local `node_id`. If mismatched, terminate with `WrongRecipientError`.
2. **Peer Verification**: Verify $pk_A$ against `TrustStore`. If untrusted or revoked, terminate with `AuthenticationError`.
3. **Transcript Verification**: Reconstruct $T_{\text{init}}$ and verify:
   $$\text{Ed25519.Verify}(pk_A, \sigma_A, T_{\text{init}}) \stackrel{?}{=} \text{True}$$
4. **Replay & Freshness Check**:
   - Verify $|t_{\text{current}} - t_{\text{init}}| \le \Delta_{\text{skew}}$ (default $300\text{ s}$).
   - Atomically consume `sender_id:session_id` in `ReplayStore`. If previously recorded, terminate with `ReplayDetectedError`.
5. **Encapsulation**:
   - Classical: $(sk_{eB}, pk_{eB}) \leftarrow \text{ECDH-P256.KeyGen}()$, $K_{\text{ecdh}} = \text{ECDH}(sk_{eB}, pk_{eA})$.
   - Post-Quantum: $(C_{\text{pq}}, K_{\text{pq}}) \leftarrow \text{ML-KEM-768.Encaps}(ek_{pqA})$.
6. **Canonical Response Transcript ($T_{\text{resp}}$)**:
   Compute initiation hash $H_{\text{init}} = \text{SHA-512}(T_{\text{init}})$.
   $$T_{\text{resp}} = \text{Frame}\big(\text{"MedPQC-Canonical-Resp-v2.4"}, v_{\text{proto}}, \text{suite\_id}, \text{sender\_id}, \text{receiver\_id}, \text{session\_id}, t_{\text{resp}}, H_{\text{init}}, pk_B, pk_{eB}, C_{\text{pq}}\big)$$
7. **Signature**:
   $$\sigma_B = \text{Ed25519.Sign}(sk_B, T_{\text{resp}})$$
8. **Directional Key Derivation**:
   Compute transcript binding hash $H_{\text{resp}} = \text{SHA-512}(T_{\text{resp}})$.
   Derive directional session keys via HKDF-SHA-512:
   $$\text{PRK} = \text{HMAC-SHA-512}(\text{salt}=\text{"MedPQC-v2.4-Strict-Salt"}, K_{\text{ecdh}} \parallel K_{\text{pq}})$$
   Derive 96 bytes:
   $$k_{\text{enc\_i2r}} = \text{OKM}[0:32], \quad k_{\text{enc\_r2i}} = \text{OKM}[32:64], \quad ID_{\text{session\_key}} = \text{OKM}[64:96]$$

### 3.3 Phase 3: Finalization (`InitiatorContext.finalize`)
1. **Peer Verification**: Verify $pk_B$ in `TrustStore`.
2. **Transcript Verification**: Reconstruct $T_{\text{resp}}$ and verify:
   $$\text{Ed25519.Verify}(pk_B, \sigma_B, T_{\text{resp}}) \stackrel{?}{=} \text{True}$$
3. **Decapsulation**:
   - Classical: $K_{\text{ecdh}} = \text{ECDH}(sk_{eA}, pk_{eB})$.
   - Post-Quantum: $K_{\text{pq}} = \text{ML-KEM-768.Decaps}(dk_{pqA}, C_{\text{pq}})$.
4. **Key Derivation**: Apply identical HKDF expansion using $K_{\text{ecdh}}$, $K_{\text{pq}}$, and session context parameters.
   Output established `Session` with matching directional traffic keys.

---

## 4. Security Properties and Limitations

1. **Hybrid Key Agreement**: Combines classical ephemeral ECDH (P-256) with post-quantum ML-KEM-768. Protects against retrospective decryption by future quantum adversaries. Unqualified forward secrecy is not claimed against endpoint compromise.
2. **Mutual Authenticity & MITM Resistance**: Transcripts explicitly bind sender, receiver, timestamps, and ephemeral parameters under Ed25519 signatures.
3. **Replay Protection**: Atomic consumption of session identifiers in `ReplayStore` prevents handshake replaying.

---

## 5. Canonical Handshake Test Vectors

The canonical byte framing and fixed-byte test vectors are pinned against standard reference vectors in `tests/vectors/transcripts.json`.

- **Initiator Transcript SHA3-512 Hash**:
  `72960e6a54c29f906cadf60d9bc7a8912509b739a154cbffdabe7e765ea91b49b851314e12da2ad71e1f00efa80c9352574018cbd91474a52b444839c3884577`

- **Responder Transcript SHA3-512 Hash**:
  `703938ce05e4080ca64d00b026a908675bce10d5040dab1d165cceef775f541743b6472318b24f0eff811dab37d7aa9c289a984f5dea1c8d564a56204f5e56d6`
