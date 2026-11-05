"""
tests.unit.test_experimental_toy_rlwe
=====================================
Unit tests for medpqc.experimental.toy_rlwe.
"""
import numpy as np
from medpqc.experimental.toy_rlwe import ExperimentalToyRLWE


def test_experimental_toy_rlwe_polynomial_math():
    samples = ExperimentalToyRLWE._sample_cbd(eta=2)
    assert len(samples) == ExperimentalToyRLWE.N_DEG
    assert samples.dtype == np.int32
    assert np.all(samples >= 0) and np.all(samples < ExperimentalToyRLWE.Q_PRIME)

    # Multiply x by x^(n-1) -> should be -1 mod (x^n + 1)
    n = ExperimentalToyRLWE.N_DEG
    q = ExperimentalToyRLWE.Q_PRIME
    a = np.zeros(n, dtype=np.int32)
    b = np.zeros(n, dtype=np.int32)
    a[1] = 1
    b[n - 1] = 1
    prod = ExperimentalToyRLWE._poly_mul(a, b)
    assert prod[0] == (q - 1)
    assert np.all(prod[1:] == 0)


def test_experimental_toy_rlwe_encapsulate_decapsulate():
    server = ExperimentalToyRLWE()
    pub_bytes = server.public_key_bytes
    assert len(pub_bytes) == 32 + ExperimentalToyRLWE.N_DEG * 2

    ct_bytes, client_secret = ExperimentalToyRLWE.encapsulate(pub_bytes)
    assert len(client_secret) == 32

    server_secret = server.decapsulate(ct_bytes)
    assert len(server_secret) == 32
    assert client_secret == server_secret
