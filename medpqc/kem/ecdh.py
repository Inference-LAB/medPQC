"""
medpqc.kem.ecdh
================
Classical Elliptic-Curve Diffie-Hellman (ECDH) over NIST P-256 curve (secp256r1).
Generates 32-byte shared secret.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from typing import Tuple

class ECDHKeyExchange:
    """NIST P-256 (secp256r1) ECDH key agreement."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey = None):
        if private_key is None:
            self._private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            self._private_key = private_key
        self._public_key = self._private_key.public_key()

    @property
    def public_bytes(self) -> bytes:
        """Export uncompressed public key bytes (65 bytes)."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    @classmethod
    def from_public_bytes(cls, pub_bytes: bytes) -> ec.EllipticCurvePublicKey:
        """Load peer public key from X9.62 raw bytes."""
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)

    def exchange(self, peer_public_bytes: bytes) -> bytes:
        """
        Derive 32-byte raw ECDH shared secret from peer public key bytes.
        """
        peer_pub = self.from_public_bytes(peer_public_bytes)
        shared_secret = self._private_key.exchange(ec.ECDH(), peer_pub)
        return shared_secret

def generate_ecdh_keypair() -> Tuple[ECDHKeyExchange, bytes]:
    """Helper to generate local party instance and its public key bytes."""
    party = ECDHKeyExchange()
    return party, party.public_bytes
