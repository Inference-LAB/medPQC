"""
medpqc.kem.ecdh
================
Classical Elliptic-Curve Diffie-Hellman (ECDH) over NIST P-256 curve (secp256r1).
Generates 32-byte shared secret with strict point validation.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .rlwe import KEMError


class ECDHKeyExchange:
    """NIST P-256 (secp256r1) ephemeral ECDH key agreement."""

    P256_UNCOMPRESSED_LEN = 65

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        if private_key is None:
            self._private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            self._private_key = private_key
        self._public_key = self._private_key.public_key()

    @property
    def public_bytes(self) -> bytes:
        """Export uncompressed public key bytes (65 bytes, starting with 0x04)."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

    @classmethod
    def from_public_bytes(cls, pub_bytes: bytes) -> ec.EllipticCurvePublicKey:
        """
        Loads and validates peer public key from raw uncompressed X9.62 point bytes.
        Rejects non-bytes, wrong lengths, compressed points, and off-curve points.
        """
        if not isinstance(pub_bytes, (bytes, bytearray)):
            raise TypeError(f"Expected bytes for ECDH public key, got {type(pub_bytes).__name__}")
        if len(pub_bytes) != cls.P256_UNCOMPRESSED_LEN:
            raise KEMError(
                f"Invalid P-256 public key length: {len(pub_bytes)} bytes. "
                f"Expected exactly {cls.P256_UNCOMPRESSED_LEN} bytes."
            )
        if pub_bytes[0] != 0x04:
            raise KEMError("Invalid P-256 point encoding: expected uncompressed point prefix 0x04.")

        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(pub_bytes))
        except (ValueError, TypeError) as e:
            raise KEMError("Invalid P-256 elliptic curve point.") from e

    def exchange(self, peer_public_bytes: bytes) -> bytes:
        """
        Derives 32-byte raw ECDH shared secret from peer public key bytes.
        Rejects all-zero or identity shared secrets.
        """
        peer_pub = self.from_public_bytes(peer_public_bytes)
        try:
            shared_secret = self._private_key.exchange(ec.ECDH(), peer_pub)
        except (ValueError, TypeError) as e:
            raise KEMError("ECDH exchange computation failed.") from e

        if len(shared_secret) != 32 or shared_secret == b"\x00" * 32:
            raise KEMError("All-zero or invalid ECDH shared secret rejected.")

        return shared_secret

    def compute_shared_secret(self, peer_public_bytes: bytes) -> bytes:
        """Alias for exchange() providing explicit method name."""
        return self.exchange(peer_public_bytes)


def generate_ecdh_keypair() -> tuple[ECDHKeyExchange, bytes]:
    """Helper to generate local party instance and its uncompressed public key bytes."""
    party = ECDHKeyExchange()
    return party, party.public_bytes
