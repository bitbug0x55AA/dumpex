"""The isolated disassembler seam: bounded decoding, branch-operand
resolution, and the graceful state when the backend does not answer.

capstone is a base dependency, so these decodes run unconditionally. A
skip would turn the one environment this suite must reject -- a dumpex
that cannot decode -- into a silent pass."""
import sys

from dumpex.core import disasm
from dumpex.core.disasm import (
    BranchKind, DisasmAvailability, MAX_DECODE_INSNS, decode_window,
    disasm_available, is_full_width_register, register_family,
)


def test_the_declared_decoder_answers_in_this_environment():
    assert disasm_available(), (
        "capstone is a base dependency of dumpex: an environment that can "
        "import dumpex must be able to decode")

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


def test_a_store_into_an_explicit_memory_operand_is_reported():
    # xor byte ptr [rax], 0x41
    result = decode_window(code=b"\x80\x30\x41", base_va=BASE, architecture="x64")
    (insn,) = result.instructions
    assert insn.writes_memory


def test_a_read_only_memory_operand_is_not_a_write():
    # cmp byte ptr [rax], 0x41 -- the same operand shape, read only
    result = decode_window(code=b"\x80\x38\x41", base_va=BASE, architecture="x64")
    (insn,) = result.instructions
    assert not insn.writes_memory


def test_a_register_only_instruction_is_not_a_memory_write():
    # xor eax, eax names no memory operand at all
    result = decode_window(code=b"\x31\xc0", base_va=BASE, architecture="x64")
    (insn,) = result.instructions
    assert not insn.writes_memory


def test_an_implicit_stack_write_is_not_an_explicit_memory_operand():
    # push rax stores to the stack, but the instruction names no memory
    # operand, so nothing mechanically determinable is reported.
    result = decode_window(code=b"\x50", base_va=BASE, architecture="x64")
    (insn,) = result.instructions
    assert not insn.writes_memory


def test_register_names_resolve_to_the_register_they_share():
    """One register has up to five names. A consumer tracking a value
    between instructions has to see them as one thing."""
    for name in ("rax", "eax", "ax", "al", "ah", "RAX"):
        assert register_family(name) == "rax"
    for name in ("r8", "r8d", "r8w", "r8b"):
        assert register_family(name) == "r8"
    assert register_family("sil") == "rsi"
    # A name with no family is its own, so it is never merged with another.
    assert register_family("xmm0") == "xmm0"
    assert register_family(None) is None


def test_full_width_is_read_against_the_architecture():
    """`eax` is the whole register in 32-bit code and half of one in
    64-bit code, so the question cannot be answered by the name alone."""
    assert is_full_width_register("rax", "x64")
    assert not is_full_width_register("eax", "x64")
    assert is_full_width_register("eax", "x86")
    assert not is_full_width_register("rax", "x86")
    for narrow in ("ax", "al", "ah", "r8b"):
        assert not is_full_width_register(narrow, "x64")
    # An architecture this module does not decode answers False rather
    # than letting a caller conclude a value survived.
    assert not is_full_width_register("rax", "arm64")
    assert not is_full_width_register("rax", None)


def test_falls_through_is_decided_by_instruction_id_not_mnemonic():
    """`jmp` and `ljmp` are one control-flow fact under two spellings and
    two capstone ids, and `retf`/`iret` are returns that do not spell
    themselves `ret`. A consumer comparing mnemonic text would find only
    some of them."""
    def only(hexs, architecture="x86"):
        (insn,) = decode_window(code=bytes.fromhex(hexs), base_va=BASE,
                                architecture=architecture).instructions
        return insn

    for hexs, mnemonic in (("ea785634120800", "ljmp"),   # far jump
                           ("ebfe", "jmp"),              # near relative jump
                           ("ffe0", "jmp"),              # register-indirect jump
                           ("c3", "ret"),
                           ("cb", "retf"),
                           ("cf", "iretd")):
        insn = only(hexs)
        assert insn.mnemonic == mnemonic
        assert not insn.falls_through, mnemonic

    # A conditional branch, a call, and an ordinary instruction all
    # continue at the next instruction.
    for hexs in ("75f3", "e8fbffffff", "803041", "90"):
        assert only(hexs).falls_through


def test_an_instruction_that_never_reaches_its_successor_does_not_fall_through():
    """An undefined opcode raises #UD every time it runs. Reading the
    bytes below it as the continuation would assume a handler exists and
    resumes there, which no byte window shows. The same goes for the
    other instructions that do not return to their successor."""
    def only(hexs):
        (insn,) = decode_window(code=bytes.fromhex(hexs), base_va=BASE,
                                architecture="x86").instructions
        return insn

    for hexs, mnemonic in (("0f0b", "ud2"),
                           ("0fff", "ud0"),
                           ("0fb9c0", "ud1"),
                           ("f4", "hlt"),
                           ("0f07", "sysret"),
                           ("0f35", "sysexit"),
                           ("0f34", "sysenter"),
                           ("0faa", "rsm"),
                           ("c6f800", "xabort")):
        insn = only(hexs)
        assert insn.mnemonic == mnemonic
        assert not insn.falls_through, mnemonic

    # `syscall` is the contrast: it records the address to come back to,
    # so its successor IS a continuation the architecture supports.
    (syscall,) = decode_window(code=bytes.fromhex("0f05"), base_va=BASE,
                               architecture="x64").instructions
    assert syscall.mnemonic == "syscall"
    assert syscall.falls_through


def test_implicit_register_writes_are_reported_as_clobbers():
    """`mul` overwrites rax and rdx without naming either as an operand.
    A consumer asking whether a register still holds what it held has to
    be told about those, so they are separate from the operand writes."""
    (mul_insn,) = decode_window(code=bytes.fromhex("48f7e3"), base_va=BASE,
                                architecture="x64").instructions
    assert mul_insn.register_writes == ()
    assert set(mul_insn.clobbered_registers) >= {"rax", "rdx"}
    # An operand write is a clobber too -- the two never disagree about a
    # register the instruction spells out.
    (add_insn,) = decode_window(code=bytes.fromhex("4883c010"), base_va=BASE,
                                architecture="x64").instructions
    assert add_insn.register_writes == ("rax",)
    assert "rax" in add_insn.clobbered_registers


def test_a_written_memory_operand_reports_its_base_register():
    # xor byte ptr [rax], 0x41 -- rax is read to compute the address and
    # is not itself written.
    result = decode_window(code=b"\x80\x30\x41", base_va=BASE, architecture="x64")
    (insn,) = result.instructions
    assert insn.write_base_register == "rax"
    assert insn.register_reads == ("rax",)
    assert insn.register_writes == ()


def test_register_reads_and_writes_follow_capstone_access():
    # add rax, 0x10 reads and writes rax; mov rbx, qword ptr [rax] writes
    # rbx and reads rax for the address only.
    (add,) = decode_window(code=b"\x48\x83\xc0\x10", base_va=BASE,
                           architecture="x64").instructions
    assert add.register_reads == ("rax",) and add.register_writes == ("rax",)
    (mov,) = decode_window(code=b"\x48\x8b\x18", base_va=BASE,
                           architecture="x64").instructions
    assert mov.register_writes == ("rbx",) and mov.register_reads == ("rax",)
    assert not mov.writes_memory


def test_ordered_register_operands_separate_the_zero_idiom_from_an_immediate():
    """`xor eax, eax` names one register twice and `sub rcx, 1` names one
    once. The deduplicated read/write tuples cannot tell them apart, so
    the ordered operand list is what a consumer checks."""
    (zeroed,) = decode_window(code=b"\x31\xc0", base_va=BASE,
                              architecture="x64").instructions
    (subtracted,) = decode_window(code=b"\x48\x83\xe9\x01", base_va=BASE,
                                  architecture="x64").instructions
    assert zeroed.register_operands == ("eax", "eax")
    assert subtracted.register_operands == ("rcx",)
    assert zeroed.register_reads == zeroed.register_writes == ("eax",)
    assert subtracted.register_reads == subtracted.register_writes == ("rcx",)


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
