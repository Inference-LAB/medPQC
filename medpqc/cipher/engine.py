"""
medpqc.cipher.engine
====================
Unified Medical Image Encryption & Decryption Engine (MedPQC v2.3).

Coordinates:
  1. Hybrid KEM (ECDH P-256 + NIST FIPS 203 ML-KEM-768)
  2. Optional Experimental Chaos Scrambling & Diffusion
  3. AES-256-GCM AEAD Authenticated Encryption (NIST SP 800-38D)
  4. Strict Associated Authenticated Data (AAD) Metadata Authentication
  5. Strict Memory, Dimension, and Invocations Caps (DoS & Decompression Bomb Defense)

Preserves 8-bit and native 16-bit medical data with zero numerical loss (MSE = 0.0).
Strictly validates all metadata types, ranges, and byte-depths before reconstruction.
"""

import hashlib
import json
from typing import Any

import numpy as np

from ..kem.combiner import HybridKeyCombiner
from ..utils.canonical import canonical_json_dumps
from ..utils.limits import (
    MAX_CIPHERTEXTS_PER_KEY,
    KeyExhaustionError,
    MissingOptionalDependencyError,
)
from ..utils.validation import ALLOWED_DTYPES, validate_metadata
from .aead import AuthenticatedCipher

MEDPQC_PROTOCOL_VERSION = "2.4.0"


def serialize_metadata_aad(
    shape: tuple[int, ...],
    dtype: str,
    n_bytes: int,
    enable_scrambling: bool = False,
    version: str = MEDPQC_PROTOCOL_VERSION,
    retained_headers: dict[str, Any] | None = None,
    envelope_id: str | None = None,
    session_key_id: str | None = None,
    suite_id: str | None = None,
    transfer_syntax_uid: str | None = None,
    dataset_hash: str | None = None,
) -> bytes:
    """
    Constructs canonical JSON bytes representing envelope metadata, identifiers,
    and retained headers. Passed as Associated Authenticated Data (AAD) to AES-256-GCM
    to guarantee tamper-resistance against header manipulation attacks.
    """
    payload: dict[str, Any] = {
        "dtype": str(dtype),
        "enable_scrambling": bool(enable_scrambling),
        "n_bytes": int(n_bytes),
        "shape": list(shape),
        "version": str(version),
    }
    if envelope_id is not None:
        payload["envelope_id"] = str(envelope_id)
    if session_key_id is not None:
        payload["session_key_id"] = str(session_key_id)
    if suite_id is not None:
        payload["suite_id"] = str(suite_id)
    if transfer_syntax_uid is not None:
        payload["transfer_syntax_uid"] = str(transfer_syntax_uid)
    if dataset_hash is not None:
        payload["dataset_hash"] = str(dataset_hash)
    if retained_headers:
        payload["retained_headers"] = {k: str(v) for k, v in sorted(retained_headers.items())}

    return canonical_json_dumps(payload)


class MedPQCCipher:
    """
    High-Performance Medical Image Encryption Engine with AAD Metadata Binding.
    Enforces per-key invocation limits and memory safety bounds.
    """

    def __init__(
        self,
        k_aes: bytes | None = None,
        k_mac: bytes | None = None,
        s_chaos: bytes | None = None,
        okm: bytes | None = None,
        session_context: bytes | None = None,
        session_key_id: str | None = None,
        suite_id: str | None = None,
    ):
        if k_aes is None:
            k_aes = b"\x00" * 32
        elif not isinstance(k_aes, (bytes, bytearray)) or len(k_aes) != 32:
            raise ValueError(f"Invalid AES key length: {len(k_aes)}. Expected 32 bytes.")
        if k_mac is not None and (not isinstance(k_mac, (bytes, bytearray)) or len(k_mac) != 32):
            raise ValueError(f"Invalid MAC key length: {len(k_mac)}. Expected 32 bytes.")

        self.k_aes = bytes(k_aes)
        self.k_mac = bytes(k_mac) if k_mac is not None else b"\x00" * 32
        self.session_key_id = session_key_id
        self.suite_id = suite_id
        self._enc_count: int = 0

        if s_chaos is not None:
            if len(s_chaos) == 96 and okm is None:
                # Caller passed 96-byte okm positionally
                self.okm = bytes(s_chaos)
                self.s_chaos = bytes(s_chaos[64:96])
            elif len(s_chaos) == 32:
                self.s_chaos = bytes(s_chaos)
                self.okm = bytes(okm) if okm is not None else (self.k_aes + self.k_mac)
            else:
                raise ValueError(f"Invalid s_chaos length: {len(s_chaos)}. Expected 32 bytes.")
        elif okm is not None:
            self.okm = bytes(okm)
            self.s_chaos = bytes(okm[64:96]) if len(okm) >= 96 else hashlib.sha3_256(self.okm + b"|s_chaos").digest()
        else:
            self.okm = self.k_aes + self.k_mac
            self.s_chaos = hashlib.sha3_256(self.okm + b"|s_chaos").digest()

        self.session_context = session_context

    @classmethod
    def from_shared_secrets(
        cls,
        k_ecdh: bytes,
        k_pq: bytes,
        session_context: bytes | None = None,
    ) -> "MedPQCCipher":
        """Instantiate cipher directly from classical and post-quantum shared secrets."""
        k_aes, k_mac, s_chaos = HybridKeyCombiner.derive_all_keys(
            k_ecdh, k_pq, session_context=session_context if session_context is not None else b""
        )
        okm = k_aes + k_mac + s_chaos
        return cls(k_aes, k_mac, s_chaos=s_chaos, okm=okm, session_context=session_context)

    @staticmethod
    def build_strict_aad(metadata: dict[str, Any]) -> bytes:
        """
        Builds strict canonical Associated Authenticated Data (AAD) binding all 16
        technical attributes plus dataset_hash to prevent manifest/header tampering.
        """
        fields = [
            "envelope_version",
            "suite_id",
            "session_key_id",
            "envelope_id",
            "payload_type",
            "pipeline_id",
            "shape",
            "dtype",
            "endianness",
            "frame_count",
            "samples_per_pixel",
            "planar_configuration",
            "photometric_interpretation",
            "pixel_representation",
            "transfer_syntax_uid",
            "original_byte_count",
            "dataset_hash",
        ]
        payload: dict[str, Any] = {}
        for f in fields:
            val = metadata.get(f)
            if isinstance(val, (list, tuple)):
                payload[f] = list(val)
            elif isinstance(val, bytes):
                payload[f] = val.hex()
            elif val is not None:
                payload[f] = str(val)
            else:
                payload[f] = ""
        return canonical_json_dumps(payload)

    def encrypt(
        self,
        image_array: np.ndarray,
        enable_scrambling: bool = False,
        retained_headers: dict[str, Any] | None = None,
        envelope_id: str | None = None,
        transfer_syntax_uid: str | None = None,
        dataset_hash: str | None = None,
    ) -> dict[str, Any]:
        """
        Encrypt a NumPy image array (uint8, uint16, int16; 2D or 3D).
        Returns an authenticated bundle where all metadata is cryptographically bound via AAD.
        Enforces maximum ciphertext count per key (F-ENV-02).
        """
        if self._enc_count >= MAX_CIPHERTEXTS_PER_KEY:
            raise KeyExhaustionError(
                f"KEY_EXHAUSTION: Invocations ({self._enc_count}) reached maximum permitted {MAX_CIPHERTEXTS_PER_KEY}. Rekeying required."
            )
        self._enc_count += 1

        orig_shape = image_array.shape
        orig_dtype = str(image_array.dtype)

        # Raw bytes view preserving exact native bit-depth and Hounsfield representations
        flat_bytes = np.frombuffer(image_array.tobytes(), dtype=np.uint8).copy()
        n_bytes = flat_bytes.size

        # Pre-validate metadata before processing
        validate_metadata(orig_shape, orig_dtype, n_bytes, MEDPQC_PROTOCOL_VERSION)

        if enable_scrambling:
            try:
                from ..experimental.chaos.permutation import ChaoticPermuter
                from ..experimental.chaos.sponge import ChaoticEntropySponge
                from ..experimental.diffusion import ChaoticDiffusion
            except ImportError as e:
                raise MissingOptionalDependencyError(
                    "Experimental chaos/diffusion transforms require optional dependencies. "
                    "Install with: pip install 'medpqc[chaos]'"
                ) from e

            # 1. Derive domain-separated sub-seeds from s_chaos
            chaos_seed = hashlib.sha3_512(self.s_chaos + b"chaos-sponge-v2.1").digest()
            perm_seed = hashlib.sha3_512(self.s_chaos + b"perm-shuffle-v2.1").digest()

            # 2. Chaotic Permutation (Pixel Scrambling)
            scrambled, _ = ChaoticPermuter.permute(flat_bytes, perm_seed)

            # 3. Generate chaotic keystream bytes via SHA3 Entropy Sponge
            keystream = ChaoticEntropySponge.extract_uint8_stream(chaos_seed, n_bytes * 3)

            # 4. Bit-plane XOR diffusion
            bp_diffused = ChaoticDiffusion.bitplane_diffuse(scrambled, keystream[:n_bytes])

            # 5. 3-round Chaotic Chained Diffusion (CCD)
            processed_bytes = ChaoticDiffusion.cbc_mix(bp_diffused, keystream, rounds=3).tobytes()
        else:
            processed_bytes = flat_bytes.tobytes()

        # 6. Canonical AAD Construction
        aad = serialize_metadata_aad(
            shape=orig_shape,
            dtype=orig_dtype,
            n_bytes=n_bytes,
            enable_scrambling=enable_scrambling,
            version=MEDPQC_PROTOCOL_VERSION,
            retained_headers=retained_headers,
            envelope_id=envelope_id,
            session_key_id=self.session_key_id,
            suite_id=self.suite_id,
            transfer_syntax_uid=transfer_syntax_uid,
            dataset_hash=dataset_hash,
        )

        # 7. AES-256-GCM AEAD with AAD Binding
        aead_bundle = AuthenticatedCipher.encrypt(processed_bytes, self.k_aes, self.k_mac, aad=aad)

        bundle: dict[str, Any] = {
            "aead": aead_bundle,
            "shape": orig_shape,
            "dtype": orig_dtype,
            "enable_scrambling": enable_scrambling,
            "n_bytes": n_bytes,
            "version": MEDPQC_PROTOCOL_VERSION,
        }
        if retained_headers:
            bundle["retained_headers"] = retained_headers
        if envelope_id:
            bundle["envelope_id"] = envelope_id
        if self.session_key_id:
            bundle["session_key_id"] = self.session_key_id
        if self.suite_id:
            bundle["suite_id"] = self.suite_id
        if transfer_syntax_uid:
            bundle["transfer_syntax_uid"] = transfer_syntax_uid
        if dataset_hash:
            bundle["dataset_hash"] = dataset_hash

        return bundle

    def decrypt(self, encrypted_data: dict[str, Any] | bytes | bytearray) -> np.ndarray:
        """
        Decrypt the ciphertext bundle and reconstruct the original image losslessly.
        Validates both ciphertext and metadata integrity via AAD.
        Rigorously validates metadata before any allocation.
        """
        if isinstance(encrypted_data, (bytes, bytearray)):
            # Parse leading JSON header
            text = bytes(encrypted_data).decode("utf-8", errors="replace")
            decoder = json.JSONDecoder()
            try:
                header, end_idx = decoder.raw_decode(text)
            except (json.JSONDecodeError, ValueError) as e:
                raise ValueError(f"Failed to decode JSON header from ciphertext: {e}") from e

            # Validate header metadata immediately BEFORE allocating anything
            shape = tuple(header.get("shape", ()))
            dtype_str = str(header.get("dtype", "uint8"))
            n_bytes = header.get("n_bytes", 0)
            version = str(header.get("version", MEDPQC_PROTOCOL_VERSION))
            validate_metadata(shape, dtype_str, n_bytes, version)

            # Reconstruct bundle
            header_bytes = text[:end_idx].encode("utf-8")
            raw_payload = bytes(encrypted_data)[len(header_bytes) :]
            if len(raw_payload) < 28:  # 12 bytes nonce + 16 bytes tag
                raise ValueError("Ciphertext payload too short for AEAD bundle.")

            nonce = raw_payload[:12]
            tag = raw_payload[-16:]
            ct = raw_payload[12:-16]
            encrypted_bundle = {
                "aead": {"nonce": nonce, "ciphertext": ct, "gcm_tag": tag},
                "shape": shape,
                "dtype": dtype_str,
                "enable_scrambling": header.get("scrambled", header.get("enable_scrambling", False)),
                "n_bytes": n_bytes,
                "version": version,
            }
        elif isinstance(encrypted_data, dict):
            encrypted_bundle = encrypted_data
        else:
            raise TypeError(f"Expected dict or bytes for encrypted_data, got {type(encrypted_data).__name__}")

        aead_bundle = encrypted_bundle["aead"]
        orig_shape = tuple(encrypted_bundle["shape"])
        orig_dtype_str = str(encrypted_bundle["dtype"])
        enable_scrambling = encrypted_bundle.get("enable_scrambling", False)
        n_bytes = encrypted_bundle["n_bytes"]
        version = str(encrypted_bundle.get("version", MEDPQC_PROTOCOL_VERSION))
        retained_headers = encrypted_bundle.get("retained_headers")
        envelope_id = encrypted_bundle.get("envelope_id")
        session_key_id = encrypted_bundle.get("session_key_id", self.session_key_id)
        suite_id = encrypted_bundle.get("suite_id", self.suite_id)
        transfer_syntax_uid = encrypted_bundle.get("transfer_syntax_uid")
        dataset_hash = encrypted_bundle.get("dataset_hash")

        # 1. Strict metadata validation
        validate_metadata(orig_shape, orig_dtype_str, n_bytes, version)
        orig_dtype = np.dtype(orig_dtype_str)

        # 2. Reconstruct canonical AAD
        aad = serialize_metadata_aad(
            shape=orig_shape,
            dtype=orig_dtype_str,
            n_bytes=n_bytes,
            enable_scrambling=enable_scrambling,
            version=version,
            retained_headers=retained_headers,
            envelope_id=envelope_id,
            session_key_id=session_key_id,
            suite_id=suite_id,
            transfer_syntax_uid=transfer_syntax_uid,
            dataset_hash=dataset_hash,
        )

        # 3. Verify AEAD and decrypt AES ciphertext with AAD validation
        raw_decrypted = AuthenticatedCipher.decrypt(aead_bundle, self.k_aes, self.k_mac, aad=aad)

        if enable_scrambling:
            try:
                from ..experimental.chaos.permutation import ChaoticPermuter
                from ..experimental.chaos.sponge import ChaoticEntropySponge
                from ..experimental.diffusion import ChaoticDiffusion
            except ImportError as e:
                raise MissingOptionalDependencyError(
                    "Experimental chaos/diffusion transforms require optional dependencies. "
                    "Install with: pip install 'medpqc[chaos]'"
                ) from e

            cbc_mixed = np.frombuffer(raw_decrypted, dtype=np.uint8)

            # 4. Derive domain-separated chaotic seeds from s_chaos
            chaos_seed = hashlib.sha3_512(self.s_chaos + b"chaos-sponge-v2.1").digest()
            perm_seed = hashlib.sha3_512(self.s_chaos + b"perm-shuffle-v2.1").digest()

            # Keystream via Entropy Sponge
            keystream = ChaoticEntropySponge.extract_uint8_stream(chaos_seed, n_bytes * 3)

            # 5. Inverse 3-round Chaotic Chained Diffusion (CCD)
            bp_diffused = ChaoticDiffusion.cbc_unmix(cbc_mixed, keystream, rounds=3)

            # 6. Inverse Bit-plane XOR undiffusion
            scrambled = ChaoticDiffusion.bitplane_undiffuse(bp_diffused, keystream[:n_bytes])

            # 7. Inverse Chaotic Permutation
            recovered_bytes = ChaoticPermuter.inverse_permute(scrambled, perm_seed)
        else:
            recovered_bytes = np.frombuffer(raw_decrypted, dtype=np.uint8)

        # 8. Reconstruct original typed array and shape universally
        reconstructed = np.frombuffer(recovered_bytes.tobytes(), dtype=orig_dtype).reshape(orig_shape)
        return reconstructed


__all__ = [
    "ALLOWED_DTYPES",
    "MEDPQC_PROTOCOL_VERSION",
    "MedPQCCipher",
    "serialize_metadata_aad",
    "validate_metadata",
]
