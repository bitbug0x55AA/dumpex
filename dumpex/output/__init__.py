"""Versioned structured-output types and serialization helpers.

Records retain forensic distinctions such as absent, empty, failed, partial, and
unknown. Addresses use normalized hex strings where specified; dump offsets,
counts, handles, and bitfields remain integers. Envelope construction and schema
validation preserve deterministic ordering and public wire contracts.
"""
from dumpex.output.collector import V2Output

__all__ = ["V2Output"]
