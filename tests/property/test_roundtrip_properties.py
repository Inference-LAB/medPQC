"""
tests.property.test_roundtrip_properties
========================================
Property-based lossless roundtrip verification for MedPQCCipher.
Tests multiple dimensionalities, medical dtypes, and scrambling configurations.
"""

import numpy as np
import pytest
from medpqc.cipher.engine import MedPQCCipher


@pytest.mark.parametrize("shape", [(16, 16), (32, 24), (8, 8, 3)])
@pytest.mark.parametrize("dtype", [np.uint8, np.uint16, np.int16])
@pytest.mark.parametrize("scrambling", [True, False])
def test_cipher_lossless_roundtrip_properties(shape, dtype, scrambling):
    cipher = MedPQCCipher(k_aes=b"K" * 32, k_mac=b"M" * 32, s_chaos=b"S" * 32)

    if dtype == np.int16:
        data = np.random.randint(-1000, 2000, size=shape, dtype=dtype)
    elif dtype == np.uint16:
        data = np.random.randint(0, 60000, size=shape, dtype=dtype)
    else:
        data = np.random.randint(0, 255, size=shape, dtype=dtype)

    retained = {"Modality": "CT", "Rows": str(shape[0]), "Columns": str(shape[1])}
    encrypted = cipher.encrypt(data, enable_scrambling=scrambling, retained_headers=retained)

    restored = cipher.decrypt(encrypted)
    assert restored.shape == shape
    assert restored.dtype == dtype
    assert np.array_equal(data, restored)
    mse = float(np.mean((data.astype(float) - restored.astype(float)) ** 2))
    assert mse == 0.0
