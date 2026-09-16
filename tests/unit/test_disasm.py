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


def _only(code, architecture="x64"):
    (insn,) = decode_window(code=code, base_va=BASE,
                            architecture=architecture).instructions
    return insn


def test_a_memory_operand_reports_every_part_of_its_address_expression():
    """`[rbx + rcx*4 + 0x10]` is five separate facts, and a consumer
    proving two accesses reach the same bytes compares all of them. A
    subset that happened to match would be a different address read as
    the same one."""
    # mov r8d, dword ptr [rbx + rcx*4 + 0x10]
    (operand,) = _only(b"\x44\x8b\x44\x8b\x10").memory_operands
    assert operand.base == "rbx"
    assert operand.index == "rcx"
    assert operand.scale == 4
    assert operand.displacement == 0x10
    assert operand.width == 4
    assert operand.segment is None
    assert operand.reads and not operand.writes
    assert operand.address_registers == ("rbx", "rcx")


def test_an_operand_with_no_index_reports_a_scale_of_one():
    """A binding reports no scale for an operand with no index. One is
    the identity the expression actually has; zero would read as a
    multiplication by nothing."""
    (operand,) = _only(b"\x8b\x55\x00").memory_operands       # mov edx, [rbp]
    assert (operand.base, operand.index, operand.scale) == ("rbp", None, 1)
    assert operand.displacement == 0
    assert operand.address_registers == ("rbp",)


def test_an_absence_the_expression_states_is_not_an_unknown_component():
    """`scale` of one where there is no index, `None` where there is no
    base or segment, and a zero displacement are what the expression
    itself says. Only a part the binding named and this record could not
    represent is an unknown, so an ordinary operand carries no flag and
    stays comparable with another."""
    (indexed,) = _only(b"\x44\x8b\x44\x8b\x10").memory_operands
    (plain,) = _only(b"\x8b\x55\x00").memory_operands
    (absolute,) = _only(b"\x8b\x14\x25\x00\x10\x00\x00").memory_operands
    assert not indexed.components_unknown
    assert not plain.components_unknown
    assert (absolute.base, absolute.index) == (None, None)
    assert not absolute.components_unknown


def test_a_read_modify_write_operand_reports_both_accesses():
    # xor byte ptr [rax], 0x41 -- one operand, read and written, one byte.
    (operand,) = _only(b"\x80\x30\x41").memory_operands
    assert operand.reads and operand.writes
    assert operand.width == 1


def test_a_store_operand_is_written_and_not_read():
    (operand,) = _only(b"\x89\x55\x00").memory_operands       # mov [rbp], edx
    assert operand.writes and not operand.reads
    assert operand.width == 4


def test_an_operand_with_no_access_bit_says_its_access_is_unknown():
    """A string instruction's implied destination arrives as a named
    memory operand with neither a read nor a write reported. That is not
    "left alone": `insb` writes to `[rdi]` every time it runs. A consumer
    that must rule out a write has to be able to see that it cannot."""
    (operand,) = _only(b"\x6c").memory_operands          # insb
    assert operand.base == "rdi"
    assert not operand.reads and not operand.writes
    assert operand.access_unknown

    # The contrast: capstone does report the access for `stosd`, and an
    # ordinary read-modify-write is known in both directions.
    (stored,) = _only(b"\xab").memory_operands           # stosd
    assert stored.writes and not stored.access_unknown
    (rmw,) = _only(b"\x80\x30\x41").memory_operands      # xor byte [rax], 0x41
    assert not rmw.access_unknown


def test_a_relative_call_is_in_the_jump_group_as_well_as_the_call_group():
    """capstone reports a relative `call` in its relative-branch group,
    so `is_jump` is True for one. Anything deciding whether a backward
    branch closes a loop -- where a backward `call` is recursion instead
    -- has to read `is_call` as well."""
    (call,) = decode_window(code=_CALL_DIRECT, base_va=BASE,
                            architecture="x64").instructions
    assert call.is_call and call.is_jump
    (jump,) = decode_window(code=b"\xeb\xfe", base_va=BASE,
                            architecture="x64").instructions
    assert jump.is_jump and not jump.is_call


def test_the_interrupt_group_is_read_as_one_fact():
    """`int3`, `int n`, `int1` and `syscall` each leave for a handler or
    the kernel, and each pushes state it names no operand for. They are
    one capstone group, not four spellings."""
    for code in (b"\xcc", b"\xcd\x80", b"\xf1", b"\x0f\x05"):
        assert _only(code).is_interrupt, code
    assert not _only(b"\x55").is_interrupt               # push rbp
    assert not _only(b"\x90").is_interrupt


def test_leaving_for_outside_code_is_read_from_the_groups_that_name_it():
    """A VM entry falls through to its successor, clobbers no register
    capstone reports, and names no memory operand -- nothing about it
    says a hypervisor ran except the group it is in."""
    for code, label in ((b"\x0f\x01\xc1", "vmcall"), (b"\x0f\x01\xd9", "vmmcall"),
                        (b"\x0f\x01\xc2", "vmlaunch"), (b"\x0f\x01\xc3", "vmresume"),
                        (b"\x0f\x01\xd4", "vmfunc"), (b"\x0f\x01\xd8", "vmrun"),
                        (b"\x0f\x37", "getsec"), (b"\x0f\x05", "syscall"),
                        (b"\xcc", "int3"), (b"\xe8\x00\x00\x00\x00", "call")):
        insn = _only(code)
        assert insn.leaves_analysis_context, label
    for code, label in ((b"\x90", "nop"), (b"\x31\xc2", "xor edx, eax"),
                        (b"\xeb\xfe", "jmp"), (b"\xc3", "ret"),
                        (b"\x8b\x55\x00", "mov edx, [rbp]")):
        assert not _only(code).leaves_analysis_context, label


def test_a_privileged_instruction_is_not_read_as_leaving_by_itself():
    """capstone's `privilege` group is broader than the claim: loading a
    segment register is in it and hands control to nobody. A group whose
    membership exceeds the fact is not a basis for stating the fact, so
    the address-version set handles a segment write instead."""
    (mov_seg,) = decode_window(code=b"\x8e\xc1", base_va=BASE,
                               architecture="x86").instructions
    assert mov_seg.mnemonic == "mov"
    assert not mov_seg.leaves_analysis_context


def test_reporting_nothing_is_not_the_same_as_doing_nothing():
    """The encoding spaces the system instructions live in are full of
    instructions capstone reports no operand, no clobber and no group
    for, and almost none of them are inert: `aaa` and `das` change AL,
    `xlatb` reads through `[rbx + al]` and writes AL, `rdpkru` writes EAX
    and EDX, and every SGX and virtualisation leaf dispatcher selects its
    behaviour from a register this module does not track.

    So the rule is an ALLOWLIST. Only the instructions known to do
    nothing answer False; forgetting an entry costs a proof, where
    forgetting one on a list of dangerous instructions would cost the
    truth of a proof."""
    for code, label in ((b"\x0f\x01\xcf", "encls"), (b"\x0f\x01\xc0", "enclv"),
                        (b"\x0f\x01\xc5", "pconfig"), (b"\xd7", "xlatb"),
                        (b"\x0f\x01\xee", "rdpkru"), (b"\x0f\x01\xc9", "mwait"),
                        (b"\x0f\x01\xd5", "xend"), (b"\x0f\x09", "wbinvd"),
                        (b"\x0f\x06", "clts"), (b"\x0f\x01\xef", "wrpkru")):
        insn = _only(code)
        assert insn.effects_unknown, label
        assert insn.may_write_memory, label
    for code, label in ((b"\x37", "aaa"), (b"\x2f", "das")):
        assert _only(code, "x86").effects_unknown, label
    # The whole allowlist, and nothing else in these spaces is on it.
    for code, label in ((b"\x90", "nop"), (b"\x0f\x77", "emms"),
                        (b"\x0f\x0e", "femms")):
        assert not _only(code).effects_unknown, label
        assert not _only(code).may_write_memory, label
    # An instruction that reports something is judged on what it reports,
    # never on this flag.
    for code, label in ((b"\x31\xc2", "xor edx, eax"), (b"\x8b\x55\x00", "mov"),
                        (b"\xc3", "ret"), (b"\xeb\xfe", "jmp")):
        assert not _only(code).effects_unknown, label


def test_lea_is_an_address_computation_and_not_an_access():
    """capstone describes `lea`'s operand exactly as it describes
    `movnti`'s -- read-only -- so this is not a decision to believe the
    report. `lea` is architecturally guaranteed never to dereference the
    address it computes, which is a fact about the instruction rather
    than about what was said of it."""
    lea = _only(b"\x48\x8d\x4e\x01")                 # lea rcx, [rsi + 1]
    assert lea.memory_operands and lea.memory_operands[0].reads
    assert not lea.may_write_memory
    # The instruction it is otherwise indistinguishable from.
    movnti = _only(b"\x0f\xc3\x08")
    assert movnti.memory_operands[0].reads
    assert movnti.may_write_memory


def test_the_inert_allowlist_covers_the_fences_and_pause():
    """These report no operand, no clobber and no group, and each is
    provably inert for an analysis following memory and general
    registers: `pause` is architecturally `rep nop`, and the fences order
    accesses without performing any."""
    for code, label in ((b"\xf3\x90", "pause"), (b"\x0f\xae\xe8", "lfence"),
                        (b"\x0f\xae\xf0", "mfence"), (b"\x0f\xae\xf8", "sfence")):
        insn = _only(code)
        assert insn.mnemonic == label
        assert not insn.effects_unknown, label
        assert not insn.may_write_memory, label


def test_a_report_that_contradicts_the_architecture_is_not_relied_on():
    """Reporting something is not the same as reporting everything.
    Executing a `push` MUST change the stack pointer and an `aam` MUST
    change the accumulator; when the report names neither, it is short of
    what the architecture requires, and nothing else in it can be relied
    on either.

    This is a self-consistency check, not a list of instructions to
    distrust -- which is why the same instruction id answers both ways
    depending on what capstone actually said about the encoding."""
    for code, arch, label in ((b"\x0f\xa0", "x64", "push fs"),
                              (b"\x0f\xa1", "x64", "pop fs"),
                              (b"\x1e", "x86", "push ds"),
                              (b"\x1f", "x86", "pop ds"),
                              (b"\xc8\x00\x00\x00", "x64", "enter"),
                              (b"\xd4\x0a", "x86", "aam"),
                              (b"\xd5\x0a", "x86", "aad")):
        insn = _only(code, arch)
        assert not insn.implicit_clobbers_known, label
        assert insn.effects_unknown, label
        assert insn.may_write_memory, label
        # Not a transfer: this contract is separate from that one.
        assert not insn.leaves_analysis_context, label

    # The same ids, on encodings capstone does account for.
    for code, arch, label in ((b"\x55", "x64", "push rbp"),
                              (b"\x5d", "x64", "pop rbp"),
                              (b"\xc9", "x64", "leave"),
                              (b"\x9c", "x64", "pushfq"),
                              (b"\x9d", "x64", "popfq"),
                              (b"\x60", "x86", "pushal"),
                              (b"\x61", "x86", "popal")):
        insn = _only(code, arch)
        assert insn.implicit_clobbers_known, label
        assert not insn.effects_unknown, label


def test_the_all_register_push_is_matched_by_id_not_by_spelling():
    """capstone spells this `pushal` and `pushaw`, never `pusha` or
    `pushad`. A rule keyed on the spelling matched neither, and eight
    stack writes reported no memory operand at all."""
    for code, label in ((b"\x60", "pushal"), (b"\x66\x60", "pushaw")):
        insn = _only(code, "x86")
        assert insn.mnemonic == label
        assert not insn.memory_operands
        assert insn.writes_memory_implicitly, label
        assert insn.may_write_memory, label
    # `popal` reads the stack rather than writing it.
    assert not _only(b"\x61", "x86").writes_memory_implicitly


def test_enclu_is_read_as_leaving_for_outside_code():
    """`enclu` dispatches on EAX, and EENTER, ERESUME and EEXIT transfer
    into or out of an enclave. This module does not track EAX, so it
    cannot tell those leaves from the ones that stay put."""
    insn = _only(b"\x0f\x01\xd7")
    assert insn.mnemonic == "enclu"
    assert insn.leaves_analysis_context
    assert insn.may_write_memory


def test_may_write_memory_does_not_trust_a_claimed_read():
    """capstone reports the memory operands of `movnti`, `stmxcsr` and
    `cmpxchg16b` as read-only, and every one of those writes. A claimed
    access therefore cannot prove a pure read, so ANY memory operand
    counts -- and an instruction that writes memory it names no operand
    for is carried by mnemonic or by group."""
    # Operands capstone calls read-only, which nonetheless write.
    for code, label in ((b"\x0f\xc3\x00", "movnti"), (b"\x0f\xae\x18", "stmxcsr"),
                        (b"\x48\x0f\xc7\x08", "cmpxchg16b"),
                        (b"\x66\x0f\x38\xf8\x00", "movdir64b")):
        insn = _only(code)
        assert not insn.writes_memory, label
        assert insn.may_write_memory, label
    # No memory operand at all: the mnemonic or the group is the fact.
    for code, label in ((b"\x0f\x01\xfc", "clzero"), (b"\x66\x0f\xf7\xc1", "maskmovdqu"),
                        (b"\x0f\xf7\xc1", "maskmovq"), (b"\x55", "push"),
                        (b"\xcc", "int3"), (b"\xe8\x00\x00\x00\x00", "call")):
        insn = _only(code)
        assert not insn.memory_operands, label
        assert insn.may_write_memory, label
    # An instruction with no memory operand and no implicit access.
    for code, label in ((b"\x90", "nop"), (b"\x31\xc2", "xor edx, eax"),
                        (b"\xeb\xfe", "jmp")):
        assert not _only(code).may_write_memory, label
    # The cost, stated: an unambiguous load answers True as well.
    assert _only(b"\x8b\x0e").may_write_memory                # mov ecx, [rsi]


def test_a_call_reports_how_many_bytes_of_return_address_it_pushes():
    """The operand size decides it, so a `callw` in 32-bit code pushes
    two bytes where a plain `call` pushes four. That is the difference
    between a `pop` that recovers the whole of what was pushed and one
    that recovers part of it."""
    assert _only(_CALL_DIRECT).return_address_width == 8            # x64
    assert _only(b"\xe8\x00\x00\x00\x00", "x86").return_address_width == 4
    assert _only(b"\x66\xe8\x00\x00", "x86").return_address_width == 2
    # Nothing else pushes a return address, so nothing else reports one.
    assert _only(b"\xeb\xfe").return_address_width == 0             # jmp
    assert _only(b"\x5d").return_address_width == 0                 # pop rbp


def test_a_segment_override_is_part_of_the_address():
    (operand,) = _only(b"\x64\x8b\x55\x00").memory_operands   # mov edx, fs:[rbp]
    assert operand.segment == "fs"
    assert operand.base == "rbp"


def test_a_rip_relative_operand_says_so():
    """`[rip + disp]` resolves against the address of the NEXT
    instruction, so the same text at two instructions is two addresses --
    a consumer comparing operands has to be able to see that."""
    (operand,) = _only(b"\x8b\x15\x00\x00\x00\x00").memory_operands
    assert operand.rip_relative
    assert not _only(b"\x8b\x55\x00").memory_operands[0].rip_relative


def test_an_absolute_operand_has_no_address_register():
    # mov edx, dword ptr [0x1234]
    (operand,) = _only(b"\x8b\x14\x25\x34\x12\x00\x00").memory_operands
    assert operand.base is None and operand.index is None
    assert operand.displacement == 0x1234
    assert operand.address_registers == ()


def test_data_reads_separate_a_value_from_a_way_to_reach_one():
    """`mov edx, dword ptr [rbp]` reads `rbp` to FORM an address and
    consumes no register's contents at all; `add rax, qword ptr [rax]`
    does both with one register, so it is in both sets."""
    load = _only(b"\x8b\x55\x00")
    assert load.register_reads == ("rbp",)
    assert load.data_register_reads == ()

    store = _only(b"\x89\x55\x00")                            # mov [rbp], edx
    assert store.data_register_reads == ("edx",)
    assert set(store.register_reads) == {"rbp", "edx"}

    both = _only(b"\x48\x03\x00")                             # add rax, [rax]
    assert both.register_reads == ("rax",)
    assert both.data_register_reads == ("rax",)


def test_immediates_are_reported_as_the_binding_gives_them():
    """An identity and a transform have the same shape and differ only in
    this value.

    The value is capstone's own and is NOT normalized here: a
    sign-extended `imm8` of -1 against a 32-bit destination arrives as
    the unsigned all-ones, so a consumer deciding whether `and edx, -1`
    is the identity has to mask to the destination's width rather than
    compare against -1."""
    assert _only(b"\x83\xc2\x00").immediates == (0,)          # add edx, 0
    assert _only(b"\x83\xc2\x07").immediates == (7,)          # add edx, 7
    assert _only(b"\x83\xe2\xff").immediates == (0xFFFFFFFF,)  # and edx, -1
    assert _only(b"\x31\xc2").immediates == ()                # xor edx, eax


def test_register_width_is_reported_for_every_name_of_a_register():
    """`rax`, `eax`, `ax`, `al` and `ah` are one register at five widths.
    A value read from a 4-byte slot lives in `edx`, and telling that from
    a later write to `dl` is what the width is for."""
    assert [disasm.register_width(name) for name in ("rax", "eax", "ax", "al", "ah")] \
        == [8, 4, 2, 1, 1]
    assert disasm.register_width("r8d") == 4
    assert disasm.register_width("EAX") == 4
    assert disasm.register_width("xmm0") is None
    assert disasm.register_width(None) is None


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
