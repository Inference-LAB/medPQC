"""
tests.test_kem_rlwe
===================
Unit tests for medpqc.kem.rlwe module.
"""

import numpy as np
import pytest
from medpqc.kem.rlwe import (
    _poly_mul_negacyclic,
    _sample_cbd,
    NativeRLWEKEM,
    PostQuantumKEM,
    Q_PRIME,
    N_DEG
)

def test_cbd_sampling():
    samples = _sample_cbd(eta=2)
    assert len(samples) == N_DEG
    assert samples.dtype == np.int32
    assert np.all(samples >= 0) and np.all(samples < Q_PRIME)

def test_poly_mul_negacyclic():
    # Multiply x by x^(n-1) -> should be -1 mod (x^n + 1)
    a = np.zeros(N_DEG, dtype=np.int32)
    b = np.zeros(N_DEG, dtype=np.int32)
    a[1] = 1          # x
    b[N_DEG - 1] = 1  # x^(n-1)
    prod = _poly_mul_negacyclic(a, b)
    # Result degree is 0 with value -1 mod Q_PRIME
    assert prod[0] == (Q_PRIME - 1)
    assert np.all(prod[1:] == 0)

def test_native_rlwe_encapsulate_decapsulate():
    server = NativeRLWEKEM()
    pub_bytes = server.public_key_bytes
    assert len(pub_bytes) == 32 + N_DEG * 2

    # Client encapsulates
    ct_bytes, client_secret = NativeRLWEKEM.encapsulate(pub_bytes)
    assert len(client_secret) == 32

    # Server decapsulates
    server_secret = server.decapsulate(ct_bytes)
    assert len(server_secret) == 32

    assert client_secret == server_secret

def test_post_quantum_kem_wrapper():
    alice = PostQuantumKEM()
    bob = PostQuantumKEM()

    ct, bob_secret = bob.encapsulate(alice.public_key_bytes)
    alice_secret = alice.decapsulate(ct)

    assert bob_secret == alice_secret
    assert len(bob_secret) == 32
