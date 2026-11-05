# MedPQC Security Model and Design Rationale (v2.3)

**Status**: Research Prototype Implementation  
**Date**: November 2026  

---

## 1. Security Goals and Objectives

MedPQC v2.3 is designed around four primary security objectives for medical imaging transmission:

1. **Confidentiality Against Classical and Quantum Adversaries**:
   Medical pixel rasters and sensitive patient attributes remain confidential against eavesdroppers. Combining ephemeral classical ECDH (P-256) and post-quantum lattice-based key encapsulation (NIST FIPS 203 ML-KEM-768) provides dual-system protection against retroactive decryption.
2. **Integrity and Authenticity of Image and Metadata (INT-CTXT / INT-AD)**:
   Ciphertext and associated DICOM headers are protected by AES-256-GCM authenticated encryption. Any modification to ciphertext, headers, or metadata causes immediate verification failure prior to any memory allocation.
3. **Mutual Identity Authentication**:
   Handshake messages are signed with Ed25519 digital signatures and verified against a pre-configured `TrustStore`.
4. **Replay and Reflection Resistance**:
   Handshake nonces and session identifiers are tracked using millisecond-precision stores (`SqliteReplayStore` or `MemoryReplayStore`). Deriving separate directional keys (`k_enc_i2r` and `k_enc_r2i`) prevents reflection attacks.

> [!NOTE]
> MedPQC is an exploratory research prototype. The security guarantees described herein reflect intended cryptographic design objectives. No formal machine-checked reduction proof is claimed.

---

## 2. Adversarial Model

### 2.1 Network Adversary (Dolev-Yao Model)
The adversary $\mathcal{A}$ controls the network medium connecting clinical workstations, modalities, and PACS servers:
- $\mathcal{A}$ can eavesdrop, intercept, modify, drop, replay, or inject arbitrary packets.
- $\mathcal{A}$ can initiate sessions under rogue identities or attempt identity misbinding.
- $\mathcal{A}$ does not possess the long-term private signing keys of authorized nodes registered in the target `TrustStore`.

### 2.2 Quantum Adversary (Harvest-Now-Decrypt-Later)
- $\mathcal{A}$ records encrypted network traffic today.
- In the future, $\mathcal{A}$ gains access to a Cryptanalytically Relevant Quantum Computer (CRQC) capable of executing Shor's algorithm, breaking classical discrete logarithm schemes (P-256 and Ed25519 retroactively).
- Under the post-quantum confidentiality goal, past session traffic remains secure provided the lattice-based Module Learning With Errors (MLWE) problem underlying ML-KEM-768 remains intractable.

---

## 3. Design Arguments

### 3.1 Hybrid Combiner Construction
The hybrid combiner employs RFC 5869 HKDF-SHA-512 in an extract-and-expand construction:
$$\text{PRK} = \text{HKDF-Extract}(\text{salt}=\text{transcript\_hash}, \text{IKM}=K_{\text{ecdh}} \parallel K_{\text{pq}})$$
$$\text{OKM} = \text{HKDF-Expand}(\text{PRK}, \text{info}=\text{session\_context}, L=96)$$
The extracted pseudorandom key $\text{PRK}$ depends on both classical and post-quantum shared secrets. If an adversary cannot determine either $K_{\text{ecdh}}$ or $K_{\text{pq}}$, the resulting $\text{PRK}$ remains computationally indistinguishable from random under the random oracle model.

### 3.2 Directional Key Separation
To prevent reflection attacks where an adversary redirects an initiator's ciphertext back to the initiator:
- Initiator-to-Responder: $K_{\text{enc, i2r}} = \text{OKM}[0:32]$
- Responder-to-Initiator: $K_{\text{enc, r2i}} = \text{OKM}[32:64]$
- Session Key Identifier: $\text{ID}_{\text{session}} = \text{OKM}[64:96]$

Each communicating endpoint uses distinct keys for transmission and reception.

### 3.3 Context-Bound Associated Authenticated Data
In the single encrypted object architecture, AES-256-GCM AEAD takes Associated Authenticated Data (AAD) formatted as canonical JSON:
$$\text{AAD} = \text{CanonicalJSON}(\{\text{envelope\_id}, \text{dataset\_hash}, \text{suite\_id}, \text{transfer\_syntax\_uid}\})$$
Any unauthorized alteration to routing headers, study identifiers, or transfer syntax UIDs invalidates the 128-bit authentication tag, causing atomic decryption abort and immediate cleanup.
