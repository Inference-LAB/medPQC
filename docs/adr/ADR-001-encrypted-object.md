# ADR-001: Single Authenticated Encrypted Object Architecture and Dataset Hash Binding

## Status
Accepted

## Date
2026-11-01

## Context
In hospital and PACS network deployments, medical imaging files formatted per DICOM PS 3.10 are routed through intermediate vendor neutral archives (VNAs), storage caches, and workflow orchestrators. In prior versions of MedPQC (v2.2 and earlier):
1. Cleartext routing headers (e.g. Modality, Rows, Columns, PatientID, StudyDate) were left unauthenticated or only partially bound via a static Associated Authenticated Data (AAD) dictionary.
2. The encrypted Protected Health Information (PHI) blob was stored in a private DICOM tag using static AAD string constants (`MedPQC-PHI-Metadata-v2.2`), which permitted an adversary to transplant an encrypted PHI payload from Patient B's file into Patient A's file without triggering an authentication or integrity violation.
3. Modification of cleartext attributes on an encrypted container was not detected during decryption, permitting unauthorized manipulation of clinical metadata.

## Decision
We implement a Single Authenticated Encrypted Object architecture with the following cryptographic guarantees:

1. **Unique Envelope Binding (`envelope_id`)**:
   Every encryption operation generates a cryptographically secure 128-bit random `envelope_id`. This identifier is embedded in both the image AEAD AAD and the PHI AEAD AAD (`MedPQC-PHI-v2.3|<envelope_id>`). A PHI payload transplanted from another container will fail GCM authentication and abort decryption.

2. **Dataset Hash Binding (`dataset_hash`)**:
   Before payload encryption, a canonical SHA-256 digest is computed across all DICOM header attributes (excluding PixelData and MedPQC private payload blocks):
   $$\text{dataset\_hash} = \text{SHA-256}\left(\bigoplus_{i} \left(\text{tag}_i \parallel \text{value}_i\right)\right)$$
   This hash is cryptographically bound into the AES-256-GCM Associated Authenticated Data (AAD). Upon decryption, the recipient re-computes the dataset hash across the ingested container. If any cleartext tag has been modified, the computed hash mismatches the authenticated metadata, raising an immediate `AuthenticationError`.

3. **Mandatory Keyed Site Pseudonymization (`site_key`)**:
   Default hardcoded salts (`DEFAULT_SITE_SALT`) are deleted. Site pseudonymization requires an explicit `SitePseudonymizationKey` of at least 32 bytes with domain separation via HMAC-SHA-256:
   $$\text{PSN} = \text{HMAC-SHA-256}(\text{site\_key}, \text{"PatientID:"} \parallel \text{PatientID})[0..16]$$

4. **Atomic Decryption Cleanup**:
   If authentication or decryption fails at any stage (AEAD tag mismatch, dataset hash mismatch, or manifest corruption), any intermediate files are removed from the filesystem, ensuring zero release of partial plaintext.

## Consequences
- **Positive**: Eliminates cross-object PHI transplantation attacks (F-DICOM-02).
- **Positive**: Guarantees bit-level integrity protection for all cleartext routing metadata without breaking standard DICOM viewer parsing.
- **Positive**: Follows DICOM PS 3.15 Annex E and standard de-identification recommendations.
- **Trade-offs**: Decryption requires a two-pass operation across the header to verify dataset hash before reconstructing pixel data.
