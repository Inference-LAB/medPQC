# MedPQC Encrypted DICOM PACS Object Specification (v2.2)

**Document**: Encrypted DICOM Container & PACS Envelope Specification  
**Standard Compliance**: DICOM PS 3.10, PS 3.12, PS 3.15 Annex E  
**Authors**: Muhammad Khubaib Ahmad, Muzammil Shadab (INFERENCE Lab)  
**Date**: November 2026  

---

## 1. Overview and Architecture

The MedPQC Encrypted DICOM Object represents a dual-container medical imaging file formatted in strict accordance with the DICOM Part 10 file format standard. It satisfies two concurrent operational requirements:

1. **PACS Interoperability**: Standard PACS storage archives, Vendor Neutral Archives (VNAs), and DICOM viewers can ingest, route, index, and render the object without crashing or reporting corrupted byte encodings.
2. **Cryptographic Confidentiality**: Complete image pixel data and Protected Health Information (PHI) are encrypted under standards-conformant post-quantum hybrid keys (ML-KEM-768 + P-256 + AES-256-GCM), with all retained routing headers bound to AEAD integrity tags.

---

## 2. Tag Layout & Data Elements

| Tag | Keyword | VR | Description & Encrypted Handling |
| :--- | :--- | :--- | :--- |
| `(0x0008, 0x0016)` | SOPClassUID | UI | Retained intact; bound into AES-256-GCM AAD. |
| `(0x0008, 0x0018)` | SOPInstanceUID | UI | Retained intact; bound into AES-256-GCM AAD. |
| `(0x0008, 0x0060)` | Modality | CS | Retained intact (e.g. `"CT"`, `"MR"`); bound into AAD. |
| `(0x0010, 0x0010)` | PatientName | PN | Scrubbed to `"ANONYMIZED^MEDPQC"`; plaintext encrypted in private tag. |
| `(0x0010, 0x0020)` | PatientID | LO | Pseudonymized to `"MEDPQC-PSN-<hex>"`; plaintext encrypted in private tag. |
| `(0x0028, 0x0010)` | Rows | US | Retained intact; bound into AAD. |
| `(0x0028, 0x0011)` | Columns | US | Retained intact; bound into AAD. |
| `(0x0028, 0x0100)` | BitsAllocated | US | Retained intact (8, 16); bound into AAD. |
| `(0x0028, 0x0101)` | BitsStored | US | Retained intact; bound into AAD. |
| `(0x0028, 0x0103)` | PixelRepresentation | US | Retained intact (0 = unsigned, 1 = signed); bound into AAD. |
| `(0x0029, 0x0010)` | PrivateCreator | LO | Set to `"MEDPQC_SECURITY_V2.2"`. |
| `(0x0029, 0x1010)` | PrivatePayload | OB | Complete self-contained cryptographic manifest and untruncated ciphertext. |
| `(0x7FE0, 0x0010)` | PixelData | OB/OW | Deterministic synthetic noise raster matching exact original dimensions. |

---

## 3. PixelData Non-Truncation Architecture (SEC-03)

In early cryptographic medical prototypes, storing ciphertexts inside standard DICOM files frequently resulted in byte truncation because symmetric encryption bundles (ciphertext + IV + auth tag + framing headers) are larger than raw pixel arrays. Truncating ciphertext destroys cryptographic integrity.

MedPQC v2.2 completely eliminates ciphertext truncation:
1. **Private Container Ingestion**: The full, untruncated authenticated ciphertext bundle is preserved exclusively inside Private Tag `(0x0029, 0x1010)`.
2. **Synthetic Noise Raster**: `ds.PixelData` is populated with a high-entropy synthetic noise raster matching the exact uncompressed byte length:
   $$L_{\text{raw}} = \text{Rows} \times \text{Columns} \times \text{SamplesPerPixel} \times \left(\frac{\text{BitsAllocated}}{8}\right)$$
   The noise stream is generated deterministically via `ChaoticEntropySponge` seeded by the first 32 bytes of the image ciphertext.
3. **PACS Viewing Safety**: When opened in standard PACS viewers (e.g., Horos, OsiriX, Orthanc, MicroDicom), the image displays uniform high-entropy visual noise without throwing dimension mismatch or unexpected EOF errors.
4. **Lossless Recovery**: Authorized MedPQC decoders extract the full untruncated ciphertext from Private Tag `(0x0029, 0x1010)` and decrypt with full cryptographic integrity ($\text{MSE} \equiv 0.0$).

---

## 4. Protected Health Information (PHI) De-Identification (SEC-04, SEC-05)

### 4.1 Recursive Sequence Scrubbing
In accordance with DICOM PS 3.15 Annex E de-identification profiles:
- The de-identification engine recursively traverses all top-level attributes and nested `Sequence` (`VR == 'SQ'`) elements (such as `RequestAttributesSequence`, `SpecimenDescriptionSequence`, and `ProcedureCodeSequence`).
- All direct and indirect patient identifiers are extracted and preserved in the encrypted PHI payload.
- In the public DICOM dataset, identified fields are replaced or scrubbed:
  - `PatientName`: `"ANONYMIZED^MEDPQC"`
  - `PatientID`: Keyed salted pseudonymized string `MEDPQC-PSN-<hmac16>`
  - `InstitutionName`: `"PROTECTED_HEALTHCARE_FACILITY"`
  - `PatientBirthDate`, `PatientBirthTime`, `PatientAddress`, `PatientTelephoneNumbers`: Cleared to empty strings.

### 4.2 Keyed Salted Pseudonymization
Pseudonymization uses HMAC-SHA256 keyed with a mandatory site salt:
$$\text{PSN} = \text{HMAC-SHA256}(\text{site\_salt}, \text{PatientID})[0:16]$$
The framework mandates a secret site salt of at least 16 bytes (`validate_site_salt`), preventing rainbow-table and correlation attacks across healthcare institutions.

---

## 5. Private Tag Cryptographic Manifest Schema

The JSON payload inside Private Tag `(0x0029, 0x1010)` adheres to the following schema:

```json
{
  "version": "2.2.0",
  "shape": [512, 512],
  "dtype": "int16",
  "n_bytes": 524288,
  "retained_headers": {
    "BitsAllocated": "16",
    "BitsStored": "16",
    "Columns": "512",
    "Modality": "CT",
    "PixelRepresentation": "1",
    "Rows": "512",
    "SOPClassUID": "1.2.840.10008.5.1.4.1.1.2",
    "SOPInstanceUID": "1.2.3.4.5.6.7.8.9"
  },
  "aead": {
    "nonce": "<base64 96-bit IV>",
    "ciphertext": "<base64 untruncated ciphertext>",
    "gcm_tag": "<base64 128-bit tag>",
    "outer_mac": "<base64 256-bit HMAC-SHA3 tag>"
  },
  "kem_ciphertext": "<base64 1088-byte ML-KEM-768 ciphertext>",
  "encrypted_phi": "<base64 encrypted PHI JSON metadata>",
  "handshake_payload": {
    "protocol_version": "MedPQC-v2.5",
    "suite_id": "ECDH-P256+ML-KEM-768+Ed25519+AES-256-GCM",
    "sender_id": "hospital-a-pacs",
    "receiver_id": "hospital-b-pacs",
    "session_id": "<base64 16-byte sid>",
    "bob_id_pub": "<base64 Ed25519 public key>",
    "ecdh_pub": "<base64 P-256 public key>",
    "signature": "<base64 Ed25519 response signature>",
    "timestamp": 1730420000.0000
  }
}
```

---

## 6. Format Matrix & Transfer Syntax Conformance

The MedPQC encrypted container mandates uncompressed Native PixelData with explicit Little Endian transfer syntax. Unsupported syntaxes or encapsulated formats are rejected explicitly with `UnsupportedDICOMError`.

### Format Matrix

| Transfer Syntax UID | Transfer Syntax Name | Support Status | Rejection Behavior |
| :--- | :--- | :--- | :--- |
| `1.2.840.10008.1.2.1` | Explicit VR Little Endian | Supported | Ingested, sealed, and processed |
| `1.2.840.10008.1.2` | Implicit VR Little Endian | Supported | Ingested, sealed, and processed |
| `1.2.840.10008.1.2.2` | Explicit VR Big Endian | Rejected | `UnsupportedDICOMError` raised |
| `1.2.840.10008.1.2.4.50` | JPEG Baseline (Process 1) | Rejected | `UnsupportedDICOMError` raised |
| `1.2.840.10008.1.2.4.70` | JPEG Lossless (Process 14) | Rejected | `UnsupportedDICOMError` raised |
| `1.2.840.10008.1.2.4.90` | JPEG 2000 Lossless | Rejected | `UnsupportedDICOMError` raised |
| `1.2.840.10008.1.2.4.91` | JPEG 2000 Part 1 | Rejected | `UnsupportedDICOMError` raised |
| `1.2.840.10008.1.2.5` | RLE Lossless | Rejected | `UnsupportedDICOMError` raised |

