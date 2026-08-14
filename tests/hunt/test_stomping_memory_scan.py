"""Direct unit tests for dumpex.hunt.stomping.memory_scan.read_module_header()
-- specifically pinning that a short module-header read reaches
dumpex.core.pe_utils.parse_pe_header()'s current wording, so a future
change to that wording (issue #40 changed the < 0x40-byte case from
'no MZ signature' to 'truncated DOS header') is caught here rather than
relying on no other test happening to assert the old text.
"""
from tests.fixtures.fakes import FakeMF, Module, mem_reader

from dumpex.hunt.stomping.config import PE_VALIDATE_READ_MAX
from dumpex.hunt.stomping.memory_scan import read_module_header


def test_short_mz_header_reason_is_truncated_dos_header():
    """A module header short-read (< 0x40 bytes, but starting with the
    real 'MZ' signature) reaches stomping's own ParseFailedEvidence.reason
    -- pinned to parse_pe_header()'s current wording and insufficient_data
    signal."""
    module_base = 0x7ff600000000
    module = Module(module_base, 0x10, r"C:\Windows\System32\legit.dll")
    read_region = mem_reader({module_base: b"MZ" + b"\x00" * 8})   # 10 bytes, real MZ prefix

    pe, read_failed = read_module_header(FakeMF(), read_region, module, PE_VALIDATE_READ_MAX)
    assert read_failed is False
    assert pe["valid"] is False
    assert pe["reason"] == "truncated DOS header"
    assert pe["insufficient_data"] is True


def test_short_non_mz_header_reason_is_no_mz_signature():
    """A short read whose first two bytes are already conclusively NOT
    'MZ' is a deterministic rejection, not a capture-length gap -- reason
    stays 'no MZ signature' and insufficient_data is False regardless of
    how short the read was."""
    module_base = 0x7ff600000000
    module = Module(module_base, 0x10, r"C:\Windows\System32\legit.dll")
    read_region = mem_reader({module_base: b"XX" + b"\x00" * 8})

    pe, read_failed = read_module_header(FakeMF(), read_region, module, PE_VALIDATE_READ_MAX)
    assert read_failed is False
    assert pe["valid"] is False
    assert pe["reason"] == "no MZ signature"
    assert pe["insufficient_data"] is False
