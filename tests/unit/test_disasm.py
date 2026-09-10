"""The isolated disassembler seam: bounded decoding, branch-operand
resolution, and the graceful state when capstone is not installed."""
import sys

import pytest

from dumpex.core import disasm
from dumpex.core.disasm import (
    BranchKind, DisasmAvailability, MAX_DECODE_INSNS, decode_window,
    disasm_available,
)

pytestmark = pytest.mark.skipif(not disasm_available(),
                                reason="capstone not installed")

# x64 machine code fragments, each assembled by hand at a known base.
BASE = 0x140001000

# call rel32 -> absolute 0x140002000  (E8, then 0x140002000 - (BASE+5))
_CALL_DIRECT = b"\xe8\xfb\x0f\x00\x00"
# jmp qword [rip + 0x200]  (FF /4 with ModRM 25)  -> slot at BASE+6+0x200
_JMP_RIP_SLOT = b"\xff\x25\x00\x02\x00\x00"
# call qword [0x1234]  absolute disp32 slot
_CALL_ABS_SLOT = b"\xff\x14\x25\x34\x12\x00\x00"
_CALL_REG = b"\xff\xd0"          # call rax
_RET = b"\xc3"


def test_direct_call_target_is_absolute():
    result = decode_window(code=_CALL_DIRECT, base_va=BASE, architecture="x64")
    assert result.decoded_ok
    (insn,) = result.instructions
    assert insn.is_call and insn.branch_kind is BranchKind.DIRECT
    assert insn.direct_target_va == 0x140002000
    assert insn.slot_target_va is None


def test_rip_relative_indirect_resolves_the_slot_not_the_target():
    result = decode_window(code=_JMP_RIP_SLOT, base_va=BASE, architecture="x64")
    (insn,) = result.instructions
    assert insn.is_jump and insn.branch_kind is BranchKind.INDIRECT_SLOT
    assert insn.slot_is_rip_relative
    assert insn.slot_target_va == BASE + 6 + 0x200
    assert insn.direct_target_va is None


def test_absolute_memory_indirect_resolves_the_slot():
    result = decode_window(code=_CALL_ABS_SLOT, base_va=BASE, architecture="x64")
    (insn,) = result.instructions
    assert insn.branch_kind is BranchKind.INDIRECT_SLOT
    assert not insn.slot_is_rip_relative
    assert insn.slot_target_va == 0x1234


def test_register_indirect_is_not_resolvable():
    result = decode_window(code=_CALL_REG, base_va=BASE, architecture="x64")
    (insn,) = result.instructions
    assert insn.branch_kind is BranchKind.INDIRECT_REGISTER
    assert insn.slot_target_va is None and insn.direct_target_va is None


def test_ret_is_not_a_branch():
    result = decode_window(code=_RET, base_va=BASE, architecture="x64")
    (insn,) = result.instructions
    assert insn.is_return and insn.branch_kind is BranchKind.NONE


def test_instruction_cap_stops_the_window():
    code = _RET * (MAX_DECODE_INSNS + 20)
    result = decode_window(code=code, base_va=BASE, architecture="x64",
                           max_insns=4)
    assert len(result.instructions) == 4
    assert result.stopped_reason == "insn_cap"


def test_byte_cap_stops_the_window():
    code = _RET * 40
    result = decode_window(code=code, base_va=BASE, architecture="x64",
                           max_bytes=8)
    assert result.window_bytes == 8
    assert result.stopped_reason == "byte_cap"
    assert result.decoded_ok


def test_a_mid_stream_invalid_opcode_is_a_decode_error():
    # A valid ret, then a long run of 0x06 (invalid in 64-bit mode) --
    # more than one instruction's worth, so it is corruption, not a tail.
    result = decode_window(code=_RET + b"\x06" * 20, base_va=BASE, architecture="x64")
    assert len(result.instructions) == 1
    assert result.stopped_reason == "decode_error"
    assert not result.decoded_ok


def test_a_short_undecoded_tail_is_invalid_or_incomplete_not_a_clean_decode():
    # A valid ret, then bytes that do not decode with too few left to tell
    # a cut-short instruction from an invalid opcode.
    for tail in (_CALL_DIRECT[:2], b"\x06"):
        result = decode_window(code=_RET + tail, base_va=BASE, architecture="x64")
        assert len(result.instructions) == 1
        assert result.stopped_reason == "undecoded_tail"
        assert not result.decoded_ok
        assert result.window_truncated


def test_a_legit_instruction_the_byte_cap_cut_is_reported_as_a_byte_cap():
    # Six ret, then a seven-byte `call [disp32]` that the max_bytes=8
    # window cuts; the lookahead past the cap completes it.
    code = _RET * 6 + b"\xff\x14\x25\x11\x22\x33\x44" + b"\x90" * 8
    result = decode_window(code=code, base_va=BASE, architecture="x64", max_bytes=8)
    assert len(result.instructions) == 6
    assert result.stopped_reason == "byte_cap"
    assert result.decoded_ok


def test_an_invalid_opcode_with_a_full_lookahead_is_a_decode_error():
    code = _RET * 6 + b"\x06" + b"\x90" * 15
    result = decode_window(code=code, base_va=BASE, architecture="x64", max_bytes=8)
    assert result.stopped_reason == "decode_error"
    assert not result.decoded_ok


def test_a_short_tail_with_too_little_lookahead_stays_undecoded_tail():
    # An eleven-byte NOP begins two bytes before the cap and the capture
    # ends five bytes into it -- not enough to prove invalid vs cut.
    nop11 = b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00"
    code = _RET * 6 + nop11[:5]
    result = decode_window(code=code, base_va=BASE, architecture="x64", max_bytes=8,
                           input_truncated=True)
    assert len(result.instructions) == 6
    assert result.stopped_reason == "undecoded_tail"
    assert not result.decoded_ok


def test_a_64_bit_absolute_slot_with_the_high_bit_set_still_resolves():
    # call qword [0x00000000ffff0000]  (FF 14 25 <disp32>) -- disp32 with
    # the high bit set sign-extends; the slot is the unsigned 64-bit form.
    code = b"\xff\x14\x25\x00\x00\xff\xff"
    result = decode_window(code=code, base_va=BASE, architecture="x64")
    (insn,) = result.instructions
    assert insn.branch_kind is BranchKind.INDIRECT_SLOT
    assert insn.slot_target_va == 0xFFFFFFFFFFFF0000


def test_unsupported_architecture_is_explicit():
    result = decode_window(code=_RET, base_va=BASE, architecture="arm64")
    assert result.availability is DisasmAvailability.AVAILABLE
    assert not result.arch_supported
    assert result.instructions == ()


def test_x86_mode_decodes_32_bit():
    result = decode_window(code=_CALL_DIRECT, base_va=0x401000, architecture="x86")
    (insn,) = result.instructions
    assert insn.branch_kind is BranchKind.DIRECT
    assert insn.direct_target_va == 0x401000 + 5 + 0x0ffb


def test_missing_capstone_yields_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "capstone", None)
    assert not disasm.disasm_available()
    result = decode_window(code=_CALL_DIRECT, base_va=BASE, architecture="x64")
    assert result.availability is DisasmAvailability.UNAVAILABLE
    assert result.instructions == ()
    assert not result.decoded_ok
