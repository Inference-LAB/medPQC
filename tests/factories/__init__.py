"""
tests.factories
===============
Synthetic factories for tests without clinical PHI or external test data.
"""
from .dicom_factory import create_synthetic_dicom, get_all_canary_strings

__all__ = ["create_synthetic_dicom", "get_all_canary_strings"]
