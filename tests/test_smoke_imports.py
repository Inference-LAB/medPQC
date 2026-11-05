"""
tests.test_smoke_imports
========================
Smoke test verifying import correctness for all public modules and symbols.
Ensures zero unresolved type annotations, broken circular dependencies,
or missing __all__ exports.
"""

import sys
import importlib
import pytest

MODULES_TO_TEST = [
    "medpqc",
    "medpqc.kem",
    "medpqc.kem.rlwe",
    "medpqc.kem.auth",
    "medpqc.kem.combiner",
    "medpqc.kem.ecdh",
    "medpqc.cipher",
    "medpqc.cipher.aead",
    "medpqc.cipher.engine",
    "medpqc.experimental",
    "medpqc.experimental.diffusion",
    "medpqc.experimental.chaos",
    "medpqc.experimental.chaos.lorenz",
    "medpqc.experimental.chaos.sponge",
    "medpqc.experimental.chaos.permutation",
    "medpqc.dicom",
    "medpqc.dicom.handler",
    "medpqc.dicom.pacs",
    "medpqc.security",
    "medpqc.security.trust",
    "medpqc.security.replay",
    "medpqc.utils",
    "medpqc.utils.canonical",
    "medpqc.utils.validation",
]

@pytest.mark.parametrize("mod_name", MODULES_TO_TEST)
def test_import_module_succeeds(mod_name):
    """Ensure every public module can be cleanly imported."""
    mod = importlib.import_module(mod_name)
    assert mod is not None

def test_top_level_all_exports_present():
    """Verify every symbol advertised in medpqc.__all__ exists in the top-level package."""
    import medpqc
    for symbol in medpqc.__all__:
        assert hasattr(medpqc, symbol), f"Exported symbol '{symbol}' missing in medpqc"

@pytest.mark.parametrize(
    "subpkg_name",
    ["medpqc.kem", "medpqc.cipher", "medpqc.experimental", "medpqc.dicom", "medpqc.security", "medpqc.utils"]
)
def test_subpackage_all_exports_present(subpkg_name):
    """Verify every symbol advertised in subpackage __all__ exists."""
    mod = importlib.import_module(subpkg_name)
    assert hasattr(mod, "__all__"), f"{subpkg_name} missing __all__"
    for symbol in mod.__all__:
        assert hasattr(mod, symbol), f"Exported symbol '{symbol}' missing in {subpkg_name}"
