"""
medpqc.kem.rlwe
================
Post-Quantum Key Encapsulation Mechanism (KEM).

Implements standards-compliant NIST FIPS 203 ML-KEM-768:
  - Security Level: NIST Category 3
  - Public Encapsulation Key (ek) length: 1,184 bytes (Module-LWE, rank k=3)
  - Ciphertext (c) length: 1,088 bytes
  - Decapsulation Key (dk) length: 2,400 bytes
  - Shared Secret (K) length: 32 bytes

Backends:
  1. `mlkem` (FIPS 203 standard provider)
  2. `liboqs` (Open Quantum Safe, if installed)
"""

from typing import Any

# Check for standard FIPS 203 ML-KEM providers
HAS_MLKEM = False
try:
    import mlkem
    from mlkem import rust as mlkem_backend

    HAS_MLKEM = True
except ImportError:
    HAS_MLKEM = False

HAS_LIBOQS = False
try:
    import oqs

    HAS_LIBOQS = True  # pragma: no cover - justification: optional liboqs dependency
except ImportError:
    HAS_LIBOQS = False

# Standard NIST FIPS 203 ML-KEM-768 parameters
MLKEM768_EK_LEN = 1184
MLKEM768_DK_LEN = 2400
MLKEM768_CT_LEN = 1088
MLKEM768_SS_LEN = 32


class KEMError(Exception):
    """Raised for any key encapsulation or decapsulation failure."""


class PostQuantumKEM:
    """
    Standards-Compliant NIST FIPS 203 ML-KEM-768 Key Encapsulation.
    Never performs silent insecure fallbacks.
    """

    def __init__(self, alg_name: str = "ML-KEM-768", prefer_liboqs: bool = False) -> None:
        self.alg_name = alg_name
        self._backend_type: str | None = None
        self._mlkem_instance: Any = None
        self._dk: Any = None
        self._ek: Any = None
        self.public_key_bytes: bytes = b""

        # 1. Try liboqs if preferred and available
        if prefer_liboqs and HAS_LIBOQS:  # pragma: no cover - justification: optional liboqs not installed
            if alg_name in oqs.get_enabled_KEM_mechanisms():
                self._backend_type = "liboqs"
                self._oqs_kem = oqs.KeyEncapsulation(alg_name)
                self.public_key_bytes = self._oqs_kem.generate_keypair()
                return

        # 2. Standard FIPS 203 mlkem provider
        if HAS_MLKEM and alg_name == "ML-KEM-768":
            self._backend_type = "fips-203-mlkem"
            try:
                self._mlkem_instance = mlkem_backend.ML_KEM(mlkem_backend.ParameterSet.ML_KEM_768)
                ek, dk = self._mlkem_instance.key_gen()
                self._ek = ek
                self._dk = dk
                self.public_key_bytes = bytes(ek)
            except (TypeError, ValueError, RuntimeError) as e:
                raise KEMError("ML-KEM-768 key generation failed.") from e

            if len(self.public_key_bytes) != MLKEM768_EK_LEN:
                raise KEMError(f"Unexpected ML-KEM-768 public key size: {len(self.public_key_bytes)}")
            return

        # 3. Fallback to liboqs if available
        if (
            HAS_LIBOQS and alg_name in oqs.get_enabled_KEM_mechanisms()
        ):  # pragma: no cover - justification: optional liboqs not installed
            self._backend_type = "liboqs"
            self._oqs_kem = oqs.KeyEncapsulation(alg_name)
            self.public_key_bytes = self._oqs_kem.generate_keypair()
            return

        # Explicit failure: No silent toy fallback
        raise KEMError(
            f"FIPS 203 compliant {alg_name} backend not available. "
            "Please ensure 'mlkem' is installed: pip install mlkem"
        )

    @property
    def backend(self) -> str:
        """Returns the active post-quantum provider backend."""
        return self._backend_type or "none"

    @property
    def provider_info(self) -> dict[str, str]:
        """Metadata regarding provider backend and NIST specification."""
        provider_version = "unknown"
        if HAS_MLKEM:
            provider_version = getattr(mlkem, "__version__", "0.2.0")
        return {
            "algorithm": self.alg_name,
            "backend": self._backend_type or "none",
            "provider_package": "mlkem" if self._backend_type == "fips-203-mlkem" else "liboqs",
            "provider_version": str(provider_version),
            "standard": "NIST FIPS 203 (Final August 2024)",
            "module_rank_k": "3",
            "public_key_len": str(MLKEM768_EK_LEN),
            "ciphertext_len": str(MLKEM768_CT_LEN),
            "shared_secret_len": str(MLKEM768_SS_LEN),
        }

    @classmethod
    def encapsulate_to_peer(cls, peer_pub_bytes: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulates a shared secret to peer's ML-KEM-768 public key without generating
        a local throwaway keypair.
        Returns: (ciphertext_bytes [1,088 bytes], shared_secret_bytes [32 bytes])
        """
        if not isinstance(peer_pub_bytes, (bytes, bytearray)):
            raise TypeError(f"Expected bytes for peer_pub_bytes, got {type(peer_pub_bytes).__name__}")
        if len(peer_pub_bytes) != MLKEM768_EK_LEN:
            raise KEMError(
                f"Invalid ML-KEM-768 public key length: {len(peer_pub_bytes)} bytes. "
                f"Expected exactly {MLKEM768_EK_LEN} bytes according to NIST FIPS 203."
            )

        if HAS_MLKEM:
            try:
                ek_obj = mlkem_backend.EncapsKey.from_bytes(bytes(peer_pub_bytes))
                inst = mlkem_backend.ML_KEM(mlkem_backend.ParameterSet.ML_KEM_768)
                shared_secret, ciphertext = inst.encaps(ek_obj)
            except (TypeError, ValueError, RuntimeError) as e:
                raise KEMError("ML-KEM-768 encapsulation failed.") from e

            if len(ciphertext) != MLKEM768_CT_LEN or len(shared_secret) != MLKEM768_SS_LEN:
                raise KEMError("ML-KEM-768 encapsulation produced invalid byte lengths.")
            return bytes(ciphertext), bytes(shared_secret)

        if HAS_LIBOQS:  # pragma: no cover - justification: optional liboqs not installed
            try:
                client = oqs.KeyEncapsulation("ML-KEM-768")
                ct, ss = client.encap_secret(bytes(peer_pub_bytes))
                return ct, ss
            except (TypeError, ValueError, RuntimeError) as e:
                raise KEMError("liboqs ML-KEM-768 encapsulation failed.") from e

        raise KEMError("No standard FIPS 203 ML-KEM backend available for encapsulation.")

    def encapsulate(self, peer_pub_bytes: bytes) -> tuple[bytes, bytes]:
        """Instance encapsulation delegating to validate peer public key."""
        return self.encapsulate_to_peer(peer_pub_bytes)

    def decapsulate(self, ciphertext: bytes, dk: bytes | None = None) -> bytes:
        """
        Decapsulate ciphertext to recover the 32-byte shared secret.
        """
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError(f"Expected bytes for ciphertext, got {type(ciphertext).__name__}")
        if len(ciphertext) != MLKEM768_CT_LEN:
            raise KEMError(
                f"Invalid ML-KEM-768 ciphertext length: {len(ciphertext)} bytes. "
                f"Expected exactly {MLKEM768_CT_LEN} bytes according to NIST FIPS 203."
            )

        decaps_key = self._dk
        if dk is not None:
            if not isinstance(dk, (bytes, bytearray)) or len(dk) != MLKEM768_DK_LEN:
                raise KEMError(
                    f"Invalid ML-KEM-768 decapsulation key length: {len(dk) if isinstance(dk, (bytes, bytearray)) else 'invalid'} bytes. "
                    f"Expected exactly {MLKEM768_DK_LEN} bytes."
                )
            if HAS_MLKEM:
                try:
                    decaps_key = mlkem_backend.DecapsKey.from_bytes(bytes(dk))
                except (TypeError, ValueError, RuntimeError) as e:
                    raise KEMError("Invalid ML-KEM-768 decapsulation key format.") from e

        if self._backend_type == "fips-203-mlkem" or (HAS_MLKEM and dk is not None):
            try:
                inst = self._mlkem_instance or mlkem_backend.ML_KEM(mlkem_backend.ParameterSet.ML_KEM_768)
                shared_secret = inst.decaps(decaps_key, bytes(ciphertext))
                return bytes(shared_secret)
            except (TypeError, ValueError, RuntimeError) as e:
                raise KEMError("ML-KEM-768 decapsulation failed.") from e

        if self._backend_type == "liboqs":  # pragma: no cover - justification: optional liboqs not installed
            try:
                return bytes(self._oqs_kem.decap_secret(bytes(ciphertext)))
            except (TypeError, ValueError, RuntimeError) as e:
                raise KEMError("liboqs ML-KEM-768 decapsulation failed.") from e

        raise KEMError("No standard FIPS 203 ML-KEM backend available for decapsulation.")
