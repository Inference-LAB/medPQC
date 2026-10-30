"""
tests.test_kem_ecdh
===================
Unit tests for medpqc.kem.ecdh module.
"""

import pytest
from medpqc.kem.ecdh import ECDHKeyExchange, generate_ecdh_keypair

def test_ecdh_keypair_generation():
    party, pub_bytes = generate_ecdh_keypair()
    assert isinstance(party, ECDHKeyExchange)
    assert isinstance(pub_bytes, bytes)
    assert len(pub_bytes) == 65  # Uncompressed SECP256R1 public key point

def test_ecdh_key_agreement_symmetry():
    alice = ECDHKeyExchange()
    bob = ECDHKeyExchange()

    alice_pub = alice.public_bytes
    bob_pub = bob.public_bytes

    alice_secret = alice.exchange(bob_pub)
    bob_secret = bob.exchange(alice_pub)

    assert isinstance(alice_secret, bytes)
    assert len(alice_secret) == 32
    assert alice_secret == bob_secret

def test_ecdh_distinct_keys_different_secrets():
    alice = ECDHKeyExchange()
    bob = ECDHKeyExchange()
    charlie = ECDHKeyExchange()

    secret_ab = alice.exchange(bob.public_bytes)
    secret_ac = alice.exchange(charlie.public_bytes)

    assert secret_ab != secret_ac

def test_ecdh_custom_private_key_initialization():
    from cryptography.hazmat.primitives.asymmetric import ec
    custom_priv = ec.generate_private_key(ec.SECP256R1())
    party = ECDHKeyExchange(private_key=custom_priv)
    assert party._private_key is custom_priv
    assert len(party.public_bytes) == 65

def test_ecdh_invalid_public_key_rejection():
    alice = ECDHKeyExchange()
    invalid_pub = b"\x00" * 65
    with pytest.raises(Exception):
        alice.exchange(invalid_pub)
