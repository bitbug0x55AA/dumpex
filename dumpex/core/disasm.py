"""The isolated disassembler seam.

`capstone` is a base dependency of dumpex and an unconditional part of
the official Windows executable, so a successful installation of either
kind arrives with a decoder. This module is the only place it is
imported, and every entry point still works when the backend does not
answer: a decode request then returns a result whose `availability` is
`"unavailable"` and whose instruction tuple is empty, never an exception
and never a partial guess. That state describes a damaged installation
or a development tree, never the expected shape of a supported install.

A decoder that does not answer has two distinct causes and this module
keeps them apart. `module_absent` is the declared dependency not being
present at all. `load_failure` is the backend being importable by name
and still unusable -- capstone resolves its native library through
`ctypes.CDLL()` at import time, so a missing, misplaced, or incompatible
`capstone.dll` raises `ImportError`/`OSError`, not `ModuleNotFoundError`.
The two have different remedies, and a packaged executable can act on
neither. Every failure reason is carried as bounded, path-redacted,
printable-ASCII text; a traceback never reaches a caller.

What this module decodes is a bounded byte window at a known virtual
address. It resolves the mechanically determinable operands of each
instruction -- the absolute target of a direct `call`/`jmp`, the slot
address of an indirect `call`/`jmp` through a RIP-relative or absolute
memory operand, which explicit register operands are read and written,
each explicit memory operand's whole effective-address expression and
access width, and whether execution continues at the instruction after
this one -- and nothing else. An indirect branch through a register, function
boundaries, call arguments, and stack state are not mechanically
determinable from a byte window and are never reported.

Register names are capstone's own, at the width the instruction names
them: `rax`, `eax`, `ax`, `al` and `ah` are five names one instruction
or another calls a single piece of hardware. :func:`register_family`
maps every one of them to the register they share, and
:func:`is_full_width_register` says whether a name is that register at
its architecture's full width -- what a consumer tracking a value
between instructions needs in order to tell a write that preserves it
from one that does not.
"""
import re
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "DisasmAvailability",
    "DisasmBackendStatus",
    "DisasmBackend",
    "BranchKind",
    "MemoryOperand",
    "DecodedInsn",
    "DecodeResult",
    "SUPPORTED_ARCHITECTURES",
    "MAX_DECODE_BYTES",
    "MAX_DECODE_INSNS",
    "MAX_INSTRUCTION_LENGTH",
    "MAX_MNEMONIC_CHARS",
    "MAX_OPERANDS_CHARS",
    "MAX_REGISTER_OPERANDS",
    "MAX_MEMORY_OPERANDS",
    "MAX_IMMEDIATES",
    "register_family",
    "register_width",
    "is_full_width_register",
    "MAX_BACKEND_REASON_CHARS",
    "backend_status",
    "disasm_available",
    "decode_window",
]

# ── Caps ───────────────────────────────────────────────────────────────
# A decode window is bounded by both a byte ceiling and an instruction
# count. The byte ceiling bounds one read; the instruction count bounds
# the decode of a window that is all one-byte instructions.
MAX_DECODE_BYTES = 512
MAX_DECODE_INSNS = 48

# The longest a single x86/x64 instruction can be. A caller reads this
# many bytes past the window as lookahead so a legitimate instruction the
# byte cap cut can be told apart from an invalid opcode.
MAX_INSTRUCTION_LENGTH = 15

# One decoded instruction's text is capped so a hostile byte stream that
# decodes to an enormous operand string cannot inflate a record. capstone
# never emits a mnemonic near this length; a value at the cap is a signal
# in itself.
MAX_MNEMONIC_CHARS = 32
MAX_OPERANDS_CHARS = 160

# Register operand names kept per instruction per direction. An x86
# instruction names at most a handful; this bounds a decoded record
# against a binding that reports more than it should.
MAX_REGISTER_OPERANDS = 8

# Explicit memory operands kept per instruction. An x86 instruction names
# at most two (a string operation's source and destination), so this is
# slack over the architecture rather than a cut through it.
MAX_MEMORY_OPERANDS = 4

# Immediate values kept per instruction. One is the normal case; the
# cap bounds a binding that reports more.
MAX_IMMEDIATES = 4

# A backend failure reason comes from a third-party exception, so it is
# bounded the same way dump-derived text is: one line, this many
# characters, and no room for a message that fills a log.
MAX_BACKEND_REASON_CHARS = 120

#: The architecture tokens this module decodes. Anything else leaves a
#: decode result `arch_supported` False with an empty instruction tuple --
#: an explicit unsupported state, never a wrong-width decode.
SUPPORTED_ARCHITECTURES = ("x86", "x64")


# Instructions that hand control to code outside this window without
# capstone placing them in a group that says so. `getsec` enters an
# authenticated code module and capstone reports no group for it at all;
# every other form this module knows of is carried by a group below, so
# this list stays as short as the binding allows.
_CONTEXT_LEAVING_MNEMONICS = frozenset((
    # Enters an authenticated code module.
    "getsec",
    # `enclu` dispatches on EAX, and three of its leaves -- EENTER,
    # ERESUME and EEXIT -- transfer into or out of an SGX enclave. This
    # module does not track EAX, so it cannot tell those leaves from the
    # ones that stay put, and treats every `enclu` as the transfer.
    "enclu",
))

# The few instructions that report nothing because they genuinely DO
# nothing this analysis has to account for -- no memory, no general
# register, no transfer. Everything else that reports nothing is covered
# by :attr:`DecodedInsn.effects_unknown`, so this list is an ALLOWLIST:
# forgetting an entry costs a proof, where forgetting an entry on a list
# of dangerous instructions would cost the truth of one.
_NO_EFFECT_MNEMONICS = frozenset((
    "nop",                          # including the multi-byte forms
    "emms", "femms",                # clear the MMX/x87 tag word only
    "pause",                        # architecturally `rep nop`
    "lfence", "mfence", "sfence",   # order accesses; perform none
))

# The one instruction whose memory operand is not an access. `lea`
# computes an effective address and is architecturally guaranteed never
# to dereference it, so its operand says nothing about memory being
# touched. This is not a decision to trust capstone's reported access --
# capstone reports `lea` exactly as it reports `movnti`, read-only -- it
# is a fact about what the instruction does.
_ADDRESS_ONLY_MNEMONICS = frozenset(("lea",))

# Instruction ids whose execution MUST change the stack pointer, and the
# one pair that must change the accumulator. They are the basis of a
# self-consistency check rather than a list of dangerous instructions:
# capstone models most of these fully -- `push rbp` reports `rsp`, `leave`
# reports `rbp` and `rsp` -- and under-reports a few. `push fs`, `pop fs`
# and `enter` name no stack pointer at all, and `aam`/`aad` name no
# accumulator, so for those the report is demonstrably short of what the
# architecture requires, and nothing else it says can be relied on
# either.
#
# Keyed on capstone's instruction ids, not its mnemonics: one id covers
# `push rbp` and `push fs` together, and a spelling that moves between
# binding versions (`pusha` became `pushal`) cannot silently empty the
# set.
_STACK_POINTER_INSN_NAMES = (
    "X86_INS_PUSH", "X86_INS_POP",
    "X86_INS_PUSHAW", "X86_INS_PUSHAL", "X86_INS_POPAW", "X86_INS_POPAL",
    "X86_INS_PUSHF", "X86_INS_PUSHFD", "X86_INS_PUSHFQ",
    "X86_INS_POPF", "X86_INS_POPFD", "X86_INS_POPFQ",
    "X86_INS_ENTER", "X86_INS_LEAVE",
)
_ACCUMULATOR_INSN_NAMES = ("X86_INS_AAM", "X86_INS_AAD")

# Instruction ids that write memory while naming no memory operand,
# replacing what was a list of mnemonics -- capstone spells the
# all-register push `pushal` and `pushaw`, not `pusha`/`pushad`, and a
# set keyed on the spelling silently matched neither.
_IMPLICIT_MEMORY_WRITE_INSN_NAMES = (
    # A stack frame pushed below the stack pointer.
    "X86_INS_PUSH", "X86_INS_PUSHAW", "X86_INS_PUSHAL",
    "X86_INS_PUSHF", "X86_INS_PUSHFD", "X86_INS_PUSHFQ", "X86_INS_ENTER",
    # A masked store through `[rdi]`/`[edi]`, named by no operand.
    "X86_INS_MASKMOVQ", "X86_INS_MASKMOVDQU", "X86_INS_VMASKMOVDQU",
    # A cache line zeroed at the address in `rax`, named by no operand.
    "X86_INS_CLZERO",
    # SGX and MKTME leaf dispatchers. Each selects its function from EAX,
    # which this module does not track, and several of those functions
    # write memory through a register: `encls[EDBGWR]` writes RBX's data
    # to the EPC page at RCX, `enclv[ESETCONTEXT]` writes EPC, and
    # `pconfig` programs a key table. None of it reaches an operand.
    "X86_INS_ENCLS", "X86_INS_ENCLV", "X86_INS_PCONFIG",
)



# ── Register families ──────────────────────────────────────────────────
# One x86/x64 register under every name an instruction can call it by.
# Writing ANY of those names changes the register: in 64-bit mode a
# 32-bit write additionally zeroes the upper half, and an 8- or 16-bit
# write leaves the rest stale. Either way a 64-bit value someone was
# following through that register is no longer intact, which is why the
# family -- not the name -- is the unit a consumer tracks.
#
# Each row is (64-bit, 32-bit, 16-bit, low 8-bit, high 8-bit); a register
# with no name at a width carries None there.
_REGISTER_WIDTH_ROWS = (
    ("rax", "eax", "ax", "al", "ah"),
    ("rbx", "ebx", "bx", "bl", "bh"),
    ("rcx", "ecx", "cx", "cl", "ch"),
    ("rdx", "edx", "dx", "dl", "dh"),
    ("rsi", "esi", "si", "sil", None),
    ("rdi", "edi", "di", "dil", None),
    ("rbp", "ebp", "bp", "bpl", None),
    ("rsp", "esp", "sp", "spl", None),
    ("rip", "eip", "ip", None, None),
) + tuple((f"r{n}", f"r{n}d", f"r{n}w", f"r{n}b", None) for n in range(8, 16))

# The width in bytes of each column of ``_REGISTER_WIDTH_ROWS``. The two
# 8-bit columns are the low and high halves of one 16-bit register, so
# they share a width and are still distinct names.
_REGISTER_WIDTH_BYTES = (8, 4, 2, 1, 1)

_REGISTER_FAMILY = {}
_REGISTER_WIDTH = {}
_FULL_WIDTH_BY_ARCH = {"x64": set(), "x86": set()}
for _row in _REGISTER_WIDTH_ROWS:
    for _column, _name in enumerate(_row):
        if _name:
            _REGISTER_FAMILY[_name] = _row[0]
            _REGISTER_WIDTH[_name] = _REGISTER_WIDTH_BYTES[_column]
    _FULL_WIDTH_BY_ARCH["x64"].add(_row[0])
    if _row[1]:
        _FULL_WIDTH_BY_ARCH["x86"].add(_row[1])


def register_family(name) -> "str | None":
    """The register ``name`` names, as its 64-bit name.

    ``eax``, ``ax``, ``al`` and ``ah`` all answer ``rax``. A name this
    module has no family for -- a vector or segment register, or anything
    a future binding invents -- answers itself, so it is its own family
    and is never merged with another."""
    if not isinstance(name, str) or not name:
        return None
    lowered = name.lower()
    return _REGISTER_FAMILY.get(lowered, lowered)


def register_width(name) -> "int | None":
    """How many bytes of its register ``name`` names -- 8 for ``rax``, 4
    for ``eax``, 2 for ``ax``, 1 for ``al`` and ``ah``.

    A name this module has no width for -- a vector or segment register,
    or anything a future binding invents -- answers None, so a consumer
    comparing the width of a value against the width of a memory slot is
    told it cannot, rather than being given a wrong number."""
    if not isinstance(name, str) or not name:
        return None
    return _REGISTER_WIDTH.get(name.lower())


def is_full_width_register(name, architecture) -> bool:
    """Whether ``name`` is its register at the full width of
    ``architecture`` -- ``rax`` on x64, ``eax`` on x86.

    A write to a full-width register replaces the whole of it, so a value
    computed into one is intact. A write to any narrower name is not: the
    register still holds something afterwards, but not a 64-bit value a
    caller was following. An unknown architecture answers False, which
    keeps a caller from concluding a value survived."""
    if not isinstance(name, str) or not name:
        return False
    return name.lower() in _FULL_WIDTH_BY_ARCH.get(architecture, ())


class DisasmAvailability(str, Enum):
    """Whether a decoder backend is installed."""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class DisasmBackendStatus(str, Enum):
    """Why the decoder backend is or is not usable.

    ``MODULE_ABSENT`` -- the declared `capstone` dependency is not
    present. ``LOAD_FAILURE`` -- it is present and did not load: its
    native library is missing, misplaced, or incompatible, or its own
    import raised. The two are never merged: the first is an incomplete
    installation, the second an installed backend that does not work,
    and each is repaired differently.
    """
    AVAILABLE = "available"
    MODULE_ABSENT = "module_absent"
    LOAD_FAILURE = "load_failure"


@dataclass(frozen=True)
class DisasmBackend:
    """One attempt to load the decoder backend.

    ``version`` is the loaded binding's own version string, read from the
    module that answered rather than from installed metadata, so it
    describes the code that is actually running. ``exception_type`` is
    the raising class's bare name and ``reason`` its message reduced by
    :func:`_sanitize_reason` to one bounded, path-free, printable-ASCII
    line; both are None when the backend loaded, and neither ever carries
    a traceback.
    """
    status: DisasmBackendStatus
    version: "str | None" = None
    exception_type: "str | None" = None
    reason: "str | None" = None
    reason_truncated: bool = False

    @property
    def available(self) -> bool:
        """The backend loaded and can decode."""
        return self.status is DisasmBackendStatus.AVAILABLE


class BranchKind(str, Enum):
    """The mechanically determinable shape of one instruction's branch
    operand.

    ``DIRECT`` -- a `call`/`jmp` to an immediate: `direct_target_va` is the
    absolute destination.

    ``INDIRECT_SLOT`` -- a `call`/`jmp` through a memory operand whose
    address is fixed by the instruction itself (`[rip + disp]` or an
    absolute `[disp]`): `slot_target_va` is the address of the pointer
    slot, not the destination. Reading the slot is a separate step.

    ``INDIRECT_REGISTER`` -- a `call`/`jmp` through a register, or through
    a memory operand indexed by a register. The destination is a function
    of run-time state and is not reported.

    ``NONE`` -- not a branch, or a branch this module does not classify
    (`ret`, conditional relative jumps are ``DIRECT``).
    """
    DIRECT = "direct"
    INDIRECT_SLOT = "indirect_slot"
    INDIRECT_REGISTER = "indirect_register"
    NONE = "none"


class _StopReason(str, Enum):
    END_OF_INPUT = "end_of_input"
    INSN_CAP = "insn_cap"
    BYTE_CAP = "byte_cap"
    DECODE_ERROR = "decode_error"
    UNDECODED_TAIL = "undecoded_tail"


# When a decode stops with fewer than one instruction's worth of bytes
# left and no more bytes are available, an invalid opcode and a final
# instruction the capture cut short are indistinguishable -- the result
# is ``undecoded_tail``, an explicit "invalid-or-incomplete", not a clean
# decode.
_MAX_X86_INSN_LEN = MAX_INSTRUCTION_LENGTH


@dataclass(frozen=True)
class MemoryOperand:
    """One explicit memory operand of one instruction, normalized.

    The address is the x86 effective-address expression the instruction
    itself spells out: ``segment:[base + index*scale + displacement]``.
    ``base`` and ``index`` are register names at the width the
    instruction names them (an address-size override makes ``ebp`` and
    ``rbp`` different address expressions, and they stay different names
    here), ``scale`` is 1 when there is no index, and ``displacement`` is
    capstone's own signed value. ``segment`` is the segment register the
    instruction names, or None for the default -- two operands under
    different segments are different addresses however alike the rest
    reads.

    ``width`` is the access width in bytes, so a 4-byte load and a 1-byte
    store through one address are not confused for each other; it is 0
    when the binding does not report a size. ``reads`` and ``writes`` are
    capstone's own access bits for this operand: a read-modify-write
    operand has both.

    ``components_unknown`` says the binding named a component this record
    could not represent -- a register id it would not name, a
    displacement that is not an integer, a scale that is not a positive
    one. The field is then holding its own default rather than the
    operand's value, so the normalized expression is a shape and not this
    address; an operand carrying the flag is equivalent to no other
    operand, itself included.

    Two operands are the same effective address only when every one of
    these matches AND nothing wrote the base or index register in
    between; equality of this record alone says the expressions agree,
    not that they evaluate alike. :func:`rip_relative` marks the one
    expression that cannot agree across two addresses even when it does:
    ``[rip + disp]`` resolves against the *next* instruction's address,
    so the same text at two instructions is two addresses."""
    base: "str | None" = None
    index: "str | None" = None
    scale: int = 1
    displacement: int = 0
    width: int = 0
    segment: "str | None" = None
    reads: bool = False
    writes: bool = False
    components_unknown: bool = False

    @property
    def address_registers(self) -> tuple:
        """The registers this address expression reads, base then index,
        each once and only when it has one."""
        names = []
        for name in (self.base, self.index):
            if name and name not in names:
                names.append(name)
        return tuple(names)

    @property
    def rip_relative(self) -> bool:
        """The address is computed from the instruction pointer."""
        return register_family(self.base) == "rip"

    @property
    def access_unknown(self) -> bool:
        """The binding named this memory operand and reported neither a
        read nor a write on it.

        An operand that reports no access is not an operand that is left
        alone: a string instruction's implied destination is the common
        case -- `insb` names `[rdi]` and capstone reports no access bit
        for it -- and the instruction writes there every time it runs.
        The honest reading is "this instruction touches memory here and
        the direction is not stated", so a consumer that must rule out a
        write cannot rule this one out."""
        return not self.reads and not self.writes


@dataclass(frozen=True)
class DecodedInsn:
    """One decoded instruction and its resolved branch operand.

    ``address`` is the instruction's own virtual address, ``size`` its
    length in bytes. ``mnemonic`` and ``operands`` are capstone's text,
    each cut to this module's cap with a ``*_truncated`` flag. ``is_call``
    / ``is_jump`` / ``is_return`` / ``is_interrupt`` are read from
    capstone's instruction groups so no consumer repeats the opcode test.
    ``is_interrupt`` covers `int3`, `int n`, `int1` and `into` as one
    group rather than as four spellings: each pushes a stack frame it
    names no operand for, so a consumer tracking memory has to see them,
    and a list of names would have to stay complete to stay safe.

    ``is_call`` and ``is_jump`` are not exclusive. A relative `call` is
    in capstone's relative-branch group as well as its call group, so
    both are True for one: ``is_jump`` answers "this instruction branches
    to a relative or computed destination", not "this instruction is a
    `jmp`". A consumer that means the second -- anything deciding whether
    a backward branch closes a loop, where a backward `call` is recursion
    instead -- reads ``is_call`` as well.

    ``falls_through`` is whether execution continues at the instruction
    after this one: False for a return of any width, for `iret`, for an
    unconditional jump near or far, and for an instruction that does not
    return to its successor at all -- an undefined opcode, `hlt`, a
    kernel-to-user return, a transactional abort. It is decided by
    capstone's own instruction id and groups, never by the text; see
    :data:`_NON_FALLTHROUGH_INSN_NAMES` for the whole list and why each
    entry is on it.

    ``writes_memory`` is capstone's own write access on an explicit
    memory operand: this instruction stores into memory the instruction
    itself names. An implicit stack write (`push`, `call`) and a string
    operation's implied destination are not explicit operands and are not
    reported. ``write_base_register`` is that written operand's base
    register, or None when it has none (an absolute or RIP-relative
    address) or nothing is written.

    ``memory_operands`` is every explicit memory operand as a normalized
    :class:`MemoryOperand` -- the whole effective-address expression and
    the access width, which is what proving two accesses reach the same
    address needs. ``writes_memory`` and ``write_base_register`` are the
    summary of the same facts and stay for callers that need no more.

    ``register_reads`` and ``register_writes`` name the explicit register
    operands this instruction reads and writes, capstone's own access
    bits again, plus the base and index registers of every memory operand
    in ``register_reads`` -- computing an address reads those registers.
    Each name appears once. ``data_register_reads`` is the same read set
    with the address registers left out: the registers whose CONTENTS
    this instruction consumes, as opposed to the ones it consumes only to
    reach a memory slot. `mov edx, dword ptr [rbp]` reads `rbp` to form
    an address and reads no register's contents at all, so its
    ``data_register_reads`` is empty while its ``register_reads`` names
    `rbp`. ``register_operands`` is the register operands in the order
    the instruction names them, repeats kept, so `xor eax, eax` is
    distinguishable from `xor eax, 1`.

    ``immediates`` is every immediate operand's signed value, in operand
    order. It is what tells an identity from a transform: `xor edx, 0`
    and `and edx, 0` have the same shape as `xor edx, 0x41` and leave the
    register unchanged and constant respectively.

    ``leaves_analysis_context`` is whether control may continue in code
    this window does not contain before reaching the next instruction: a
    `call`, an interrupt or `syscall`, a VM entry or exit (`vmcall`,
    `vmmcall`, `vmlaunch`, `vmresume`, `vmfunc`, `vmrun`, and the rest of
    capstone's ``vm`` group), and `getsec`.
    Most of those fall through to their successor and clobber no register
    capstone reports, so nothing else about them says that a hypervisor,
    a kernel or an authenticated code module ran in between. A consumer
    following a value across one of these is following it across code it
    never saw, which is why this is one fact rather than a test each
    consumer repeats.

    ``effects_unknown`` is the backstop under all of this: capstone
    reports no operand, no register write, no clobber and no group for
    this instruction, and it is not one of the few in
    :data:`_NO_EFFECT_MNEMONICS` that genuinely do nothing. Reporting
    nothing is not the same as doing nothing, and the encoding spaces
    these live in are full of the difference -- `aaa` and `das` change
    AL, `xlatb` reads memory through `[rbx + al]` and writes AL,
    `rdpkru` writes EAX and EDX, and every SGX and virtualisation leaf
    dispatcher selects its behaviour from a register. A consumer that
    treated "nothing reported" as "nothing happened" would be trusting
    the decoder's silence, which is what this flag exists to stop.

    ``may_write_memory`` is the conservative answer to "could this
    instruction have written memory". It is True for ANY explicit memory
    operand, whatever access capstone claims for it, because that claim
    is not reliable enough to prove a pure read: capstone reports the
    memory operands of `movnti`, `cmpxchg16b` and `stmxcsr` as read-only,
    and every one of those writes. It is also True for a `call`, an
    interrupt, and the instructions in
    ``writes_memory_implicitly`` instructions -- those writing memory
    they name no operand for. A consumer that must rule out a write reads this;
    one that wants the narrower "capstone reports an explicit written
    operand" reads ``writes_memory``.

    ``return_address_width`` is how many bytes of return address a `call`
    pushes, and 0 for everything else. It is the instruction's own
    operand size, so a `callw` in 32-bit code answers 2 where a plain
    `call` answers 4 -- the difference between a `pop` that recovers the
    whole of what was pushed and one that recovers part of it, which is
    the difference between having the code's own address and having some
    of its bits.

    ``clobbered_registers`` is every register capstone says the
    instruction writes, the ones it names and the ones it does not: the
    flags, the stack pointer a `push` moves, the `rax`/`rdx` pair a `mul`
    overwrites without mentioning. It is what a consumer asking "does
    this register still hold what it held" must read -- `register_writes`
    answers only for registers the instruction spells out. All four
    tuples are capped at :data:`MAX_REGISTER_OPERANDS` names.
    """
    address: int
    size: int
    mnemonic: str
    mnemonic_truncated: bool
    operands: str
    operands_truncated: bool
    is_call: bool
    is_jump: bool
    is_return: bool
    branch_kind: BranchKind
    is_interrupt: bool = False
    falls_through: bool = True
    direct_target_va: "int | None" = None
    slot_target_va: "int | None" = None
    slot_is_rip_relative: bool = False
    writes_memory: bool = False
    write_base_register: "str | None" = None
    memory_operands: tuple = ()
    register_reads: tuple = ()
    data_register_reads: tuple = ()
    register_writes: tuple = ()
    register_operands: tuple = ()
    clobbered_registers: tuple = ()
    immediates: tuple = ()
    return_address_width: int = 0
    leaves_analysis_context: bool = False
    implicit_clobbers_known: bool = True
    writes_memory_implicitly: bool = False

    @property
    def effects_unknown(self) -> bool:
        """Whether the decoder reported nothing about this instruction
        and it is not known to be inert.

        Two ways to be unknown, and both are here because reporting
        something is not the same as reporting everything.
        ``implicit_clobbers_known`` False is a report that contradicts
        the architecture -- a `push` that names no stack pointer, an
        `aam` that names no accumulator -- and a report short in one
        place is not trustworthy in another. Otherwise it is a report
        with nothing in it at all, from an instruction not known to be
        inert.

        The allowlist is deliberately tiny and the rule deliberately
        wide: an instruction this answers True for ends any analysis that
        was following state through it, which costs a proof, while the
        opposite mistake costs the truth of one."""
        if not self.implicit_clobbers_known:
            return True
        if (self.memory_operands or self.register_operands
                or self.clobbered_registers or self.immediates):
            return False
        if (self.is_call or self.is_jump or self.is_return
                or self.is_interrupt or self.leaves_analysis_context
                or not self.falls_through):
            return False
        return self.mnemonic.lower() not in _NO_EFFECT_MNEMONICS

    @property
    def may_write_memory(self) -> bool:
        """Whether this instruction could have written memory.

        Deliberately wider than :attr:`writes_memory`: an operand's
        claimed access does not prove a pure read, so any memory operand
        counts. `lea` is the one exception, and not because its report is
        believed -- capstone describes its operand exactly as it
        describes `movnti`'s, read-only -- but because the instruction is
        architecturally guaranteed never to dereference the address it
        computes. Anything that leaves for code this window does not show
        counts too -- what a callee, a kernel or a hypervisor wrote is
        not visible here. The cost is that an unambiguous load answers
        True as well, which under-reports for a caller ruling writes out
        -- the direction to be wrong in here."""
        if self.mnemonic.lower() in _ADDRESS_ONLY_MNEMONICS:
            return False
        return bool(self.memory_operands
                    or self.leaves_analysis_context
                    or self.effects_unknown
                    or self.writes_memory_implicitly)


@dataclass(frozen=True)
class DecodeResult:
    """The outcome of one bounded decode window.

    ``availability`` is whether a decoder backend was importable at all.
    ``arch_supported`` is whether the requested architecture is one this
    module decodes; both must hold for ``instructions`` to be non-empty.
    ``bytes_decoded`` is how far into ``code`` decoding reached, and
    ``stopped_reason`` says why it stopped there: ``end_of_input`` /
    ``insn_cap`` / ``byte_cap`` (bounded stops with sound output),
    ``undecoded_tail`` (a few trailing bytes did not decode and too few
    remain to tell an invalid opcode from a cut-short instruction), or
    ``decode_error`` (an invalid opcode with room for a whole instruction
    after it). The instructions before any stop are sound.

    ``backend`` is the :class:`DisasmBackend` this decode ran against. It
    says why an ``unavailable`` result is unavailable; a caller phrasing
    guidance reads it rather than assuming an absent dependency.
    """
    availability: DisasmAvailability
    arch_supported: bool
    architecture: str
    base_va: int
    window_bytes: int
    bytes_decoded: int
    stopped_reason: str
    instructions: tuple = field(default_factory=tuple)
    backend: "DisasmBackend | None" = None

    @property
    def decoded_ok(self) -> bool:
        """Decoding reached a clean end or a bounded cap with every byte
        accounted for. False for both ``decode_error`` and
        ``undecoded_tail`` -- in each case some bytes did not decode."""
        return (self.availability is DisasmAvailability.AVAILABLE
                and self.arch_supported
                and self.stopped_reason not in (_StopReason.DECODE_ERROR.value,
                                                _StopReason.UNDECODED_TAIL.value))

    @property
    def window_truncated(self) -> bool:
        """The window did not cover every byte available -- a byte cap, or
        a final run of bytes that did not decode. Instructions past it
        were not evaluated."""
        return self.stopped_reason in (_StopReason.BYTE_CAP.value,
                                       _StopReason.UNDECODED_TAIL.value)


def _bounded(text: str, cap: int) -> "tuple[str, bool]":
    if not isinstance(text, str):
        return "", False
    if len(text) > cap:
        return text[:cap], True
    return text, False


# A filesystem path in an exception message names the machine it came
# from, so it is removed rather than escaped. An unquoted path has no
# reliable end -- a profile directory named after a person, and the
# standard program directory, both carry a space inside a directory
# name, and no rule tells that space apart from the one before the next
# word of prose. A path opener therefore redacts everything from itself
# to the next quote or the end of the message: a quoted path gives its
# own terminator back, and an unquoted one gives up the rest of the line
# rather than a surname.
#
# An opener is a drive letter, a UNC prefix, or a complete POSIX
# `/segment/`. Requiring that whole segment keeps ordinary prose such as
# "and/or" prose.
_PATH_RE = re.compile(
    r"""(?:[A-Za-z]:[\\/]"""                # a drive-letter path
    r"""|\\\\"""                            # a UNC share path
    r"""|/(?:[^\s'"/]+/)+)"""               # a POSIX path
    r"""[^'"]*""")
_NON_PRINTABLE_RE = re.compile(r"[^\x20-\x7e]")


def _sanitize_reason(text) -> "tuple[str, bool]":
    """``(reason, truncated)`` for one exception message: a single line of
    printable ASCII, with filesystem paths replaced by ``<path>`` and the
    whole cut to :data:`MAX_BACKEND_REASON_CHARS`.

    The text is third-party and may be hostile, so it is treated like
    dump-derived text. Line breaks are folded first, so no reason can
    forge a second line of a release log or a console report; anything
    outside printable ASCII becomes ``.``, so no escape sequence survives
    to act on a terminal. A drive-letter, UNC, or POSIX path takes the
    rest of the message with it (see :data:`_PATH_RE`), so a user name or
    an install directory cannot reach a log through a path whose spaces
    hid its end."""
    if not isinstance(text, str):
        text = str(text)
    one_line = " ".join(text.split())
    redacted = _PATH_RE.sub("<path>", one_line)
    printable = _NON_PRINTABLE_RE.sub(".", redacted)
    return _bounded(printable, MAX_BACKEND_REASON_CHARS)


def _failed_backend(status: DisasmBackendStatus, exc: BaseException) -> DisasmBackend:
    """A :class:`DisasmBackend` recording ``exc`` as the reason ``status``
    was reached."""
    reason, cut = _sanitize_reason(str(exc))
    return DisasmBackend(status=status, exception_type=type(exc).__name__,
                         reason=reason, reason_truncated=cut)


def _backend_version(capstone) -> "str | None":
    """The loaded backend's version, or ``None`` when it cannot be read.
    ``cs_version()`` is answered by the native library, so a version read
    from it is also evidence that the library responded."""
    version = getattr(capstone, "__version__", None)
    if isinstance(version, str) and version:
        return _sanitize_reason(version)[0]
    try:
        major, minor, extra = capstone.cs_version()
    except Exception:
        return None
    return f"{major}.{minor}.{extra}"


def _load_backend() -> "tuple[object | None, DisasmBackend]":
    """``(module, backend)`` for the one import of ``capstone`` in dumpex.

    Performed on every call so a test can remove the module from
    ``sys.modules`` and see the unavailable path. Never raises: every
    failure becomes a :class:`DisasmBackend` whose status says whether
    the declared dependency is absent or present and unusable."""
    try:
        import capstone
    except ModuleNotFoundError as exc:
        # The dependency is absent only when ``capstone`` itself is
        # exactly the name that could not be found. A missing
        # ``capstone.x86`` -- a damaged install, or a submodule packaging
        # left behind -- means the distribution IS there and is
        # incomplete, and so does a missing module capstone imports. An
        # error that names nothing is read the same way: an installed
        # backend that failed, never advice to install what is present.
        if exc.name == "capstone":
            return None, _failed_backend(DisasmBackendStatus.MODULE_ABSENT, exc)
        return None, _failed_backend(DisasmBackendStatus.LOAD_FAILURE, exc)
    except Exception as exc:
        # capstone's own ``ctypes.CDLL()`` search raising ``ImportError``,
        # an ``OSError`` from an unreadable or incompatible native
        # library, and anything else its import raises all land here.
        return None, _failed_backend(DisasmBackendStatus.LOAD_FAILURE, exc)
    return capstone, DisasmBackend(status=DisasmBackendStatus.AVAILABLE,
                                   version=_backend_version(capstone))


def backend_status() -> DisasmBackend:
    """The decoder backend's state right now, with a bounded sanitized
    reason when it is not usable. Import-safe and never raises."""
    return _load_backend()[1]


def disasm_available() -> bool:
    """Whether a decoder backend is installed and loaded right now."""
    return backend_status().available


def _mode_for(capstone, architecture: str):
    if architecture == "x64":
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64
    if architecture == "x86":
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32
    return None


def _classify_branch(capstone, insn, address_mask: int
                     ) -> "tuple[BranchKind, int | None, int | None, bool]":
    """One instruction's branch operand as
    ``(kind, direct_target_va, slot_target_va, slot_is_rip_relative)``.

    Only a `call` or `jmp` is classified. capstone resolves a relative
    immediate branch to its absolute target in ``op.imm`` already; a
    memory operand's slot address is ``insn.address + insn.size +
    disp`` for a RIP-relative operand and ``disp`` for an absolute one.
    A displacement capstone reports sign-extended is brought back into the
    unsigned address space with ``address_mask`` (0xFFFFFFFF for 32-bit,
    0xFFFFFFFFFFFFFFFF for 64-bit). Any register in the operand makes the
    destination run-time state.
    """
    x86 = capstone.x86
    groups = set(getattr(insn, "groups", ()) or ())
    is_branch = (x86.X86_GRP_CALL in groups or x86.X86_GRP_JUMP in groups
                 or x86.X86_GRP_BRANCH_RELATIVE in groups)
    if not is_branch:
        return BranchKind.NONE, None, None, False
    operands = [op for op in (getattr(insn, "operands", ()) or ())]
    # A `call`/`jmp` names exactly one operand; a decoded instruction with
    # a different shape is not one this module resolves.
    target_ops = [op for op in operands if op.type in
                  (x86.X86_OP_IMM, x86.X86_OP_MEM, x86.X86_OP_REG)]
    if len(target_ops) != 1:
        return BranchKind.NONE, None, None, False
    op = target_ops[0]
    if op.type == x86.X86_OP_IMM:
        target = op.imm
        if isinstance(target, int) and 0 <= target < (1 << 64):
            return BranchKind.DIRECT, target, None, False
        return BranchKind.NONE, None, None, False
    if op.type == x86.X86_OP_REG:
        return BranchKind.INDIRECT_REGISTER, None, None, False
    mem = op.mem
    if mem.index != 0:
        return BranchKind.INDIRECT_REGISTER, None, None, False
    if not isinstance(mem.disp, int):
        return BranchKind.INDIRECT_REGISTER, None, None, False
    if mem.base == 0:
        slot = mem.disp & address_mask
        return BranchKind.INDIRECT_SLOT, None, slot, False
    if mem.base == x86.X86_REG_RIP:
        slot = (insn.address + insn.size + mem.disp) & address_mask
        return BranchKind.INDIRECT_SLOT, None, slot, True
    return BranchKind.INDIRECT_REGISTER, None, None, False


# Instruction groups and ids whose execution does not continue at the
# instruction after them. Named rather than matched on mnemonic text:
# `jmp` and `ljmp` are one control-flow fact under two spellings and two
# ids, and `retf`/`iret` are returns that do not spell themselves `ret`.
#
# A name a binding does not define drops out of the comparison, which
# reports a fall-through. That is the direction to be wrong in here: a
# consumer using this to END a run is told of fewer stops than exist,
# never more.
_NON_FALLTHROUGH_GROUP_NAMES = (
    "X86_GRP_RET",     # ret, retf, and every other return width
    "X86_GRP_IRET",    # iret/iretd/iretq -- a return that is not in the ret group
)
_NON_FALLTHROUGH_INSN_NAMES = (
    # An unconditional jump, near or far. A conditional jump is a
    # different id and is absent from this list, because its
    # fall-through IS the next instruction.
    "X86_INS_JMP", "X86_INS_LJMP",
    # An undefined opcode raises #UD every time it executes. Reading the
    # bytes below it as the continuation would assume a handler exists
    # and resumes there, which no byte window shows.
    "X86_INS_UD0", "X86_INS_UD1", "X86_INS_UD2",
    # `hlt` faults in user mode. In ring 0 it resumes on an interrupt, so
    # this is the one entry that can be wrong -- and it is wrong in the
    # direction that reports a stop, which only ever withholds a claim.
    "X86_INS_HLT",
    # Returns to another context: the next instruction is not where they
    # go. `rsm` resumes the state System Management Mode interrupted, and
    # raises #UD anywhere else -- neither outcome reaches its successor.
    "X86_INS_SYSRET", "X86_INS_SYSRETQ", "X86_INS_SYSEXIT", "X86_INS_SYSEXITQ",
    "X86_INS_RSM",
    # `sysenter` records no return address at all: it is not one half of
    # a call/return pair with `sysexit`, and where control comes back to
    # -- if anywhere -- is an operating-system convention no byte window
    # states. Its successor is therefore not a continuation this module
    # can claim.
    "X86_INS_SYSENTER",
    # A transactional abort transfers to the fallback path.
    "X86_INS_XABORT",
)
# Deliberately absent, and each for its own reason: `syscall` DOES record
# where to come back to (the instruction after it, in `rcx`), so its
# successor is a continuation the architecture itself supports;
# `int`/`int3` return to their successor; and a VM entry
# (`vmlaunch`/`vmresume`) falls through precisely when it fails.


def _control_flow_stops(capstone) -> "tuple[frozenset, frozenset]":
    """``(instruction_ids, groups)`` that end a linear run, resolved once
    against the loaded binding so an id it does not define is simply
    absent."""
    x86 = capstone.x86
    ids = {getattr(x86, name, None) for name in _NON_FALLTHROUGH_INSN_NAMES}
    groups = {getattr(x86, name, None) for name in _NON_FALLTHROUGH_GROUP_NAMES}
    ids.discard(None)
    groups.discard(None)
    return frozenset(ids), frozenset(groups)


def _effect_tables(capstone) -> tuple:
    """``(stack_ids, accumulator_ids, implicit_write_ids)`` resolved once
    against the loaded binding, so an id it does not define is simply
    absent rather than an AttributeError."""
    x86 = capstone.x86
    tables = []
    for names in (_STACK_POINTER_INSN_NAMES, _ACCUMULATOR_INSN_NAMES,
                  _IMPLICIT_MEMORY_WRITE_INSN_NAMES):
        ids = {getattr(x86, name, None) for name in names}
        ids.discard(None)
        tables.append(frozenset(ids))
    return tuple(tables)


def _implicit_clobbers_known(insn, clobbered: tuple, tables: tuple) -> bool:
    """Whether capstone's register-write report for ``insn`` accounts for
    the effect its instruction class requires.

    A self-consistency check, not a list of instructions to distrust.
    Executing a `push` MUST change the stack pointer and an `aam` MUST
    change the accumulator; when the report names neither, it is short of
    what the architecture requires and nothing else in it can be relied
    on either. capstone models most of these fully -- `push rbp` names
    `rsp`, `leave` names `rbp` and `rsp` -- so the check costs nothing
    there, and it is exactly the segment-register `push`/`pop`, `enter`
    and `aam`/`aad` forms that it catches."""
    stack_ids, accumulator_ids, _writes = tables
    insn_id = getattr(insn, "id", None)
    if insn_id is None:
        return True
    families = {register_family(name) for name in clobbered}
    if insn_id in stack_ids and "rsp" not in families:
        return False
    if insn_id in accumulator_ids and "rax" not in families:
        return False
    return True


def _leaves_analysis_context(capstone, mnemonic: str, groups: set) -> bool:
    """Whether control may continue in code outside this window before
    reaching the instruction after ``insn``.

    Read from capstone's own groups wherever one names the class
    precisely: ``call``, ``int`` (which carries `syscall` too), and ``vm``
    for every VM entry and exit. A group is preferred over a name for the
    reason every list of names is a liability, and
    :data:`_CONTEXT_LEAVING_MNEMONICS` carries only what no group names --
    `getsec`, which enters an authenticated code module, and `enclu`,
    whose EENTER, ERESUME and EEXIT leaves transfer into and out of an
    SGX enclave (EAX selects which, and this module does not track EAX,
    so every `enclu` is read as the transfer).

    capstone's ``privilege`` group is deliberately NOT read here. It is
    broader than this claim -- `mov es, ecx` is in it, and loading a
    segment register does not hand control to anyone -- and a group whose
    membership exceeds the fact being stated is not a mechanical basis
    for stating it. What a privileged instruction can still do to an
    address is handled where it belongs: a segment selector through the
    address-version set, and a segment base through
    `insn_flow._SEGMENT_BASE_WRITES`."""
    x86 = capstone.x86
    for name in ("X86_GRP_CALL", "X86_GRP_INT", "X86_GRP_VM"):
        group = getattr(x86, name, None)
        if group is not None and group in groups:
            return True
    return mnemonic.lower() in _CONTEXT_LEAVING_MNEMONICS


def _falls_through(insn, groups, stops) -> bool:
    """Whether execution continues at the instruction after ``insn``,
    against the ``stops`` :func:`_control_flow_stops` resolved."""
    stop_ids, stop_groups = stops
    if groups & stop_groups:
        return False
    return getattr(insn, "id", None) not in stop_ids


def _register_name(insn, reg) -> "str | None":
    """One capstone register id as its own lowercase name, or None when
    the id is absent or the binding cannot name it."""
    if not reg:
        return None
    try:
        name = insn.reg_name(reg)
    except Exception:
        return None
    return name.lower() if isinstance(name, str) and name else None


@dataclass(frozen=True)
class _OperandFacts:
    """What one instruction's explicit operands say, before the record is
    built. A container rather than a tuple because there are now more of
    these than a positional result can be read at a glance."""
    writes_memory: bool = False
    write_base_register: "str | None" = None
    memory_operands: tuple = ()
    register_reads: tuple = ()
    data_register_reads: tuple = ()
    register_writes: tuple = ()
    register_operands: tuple = ()
    immediates: tuple = ()
    immediate_width: int = 0


def _memory_operand(capstone, insn, op) -> MemoryOperand:
    """One capstone memory operand as a :class:`MemoryOperand`.

    A scale the binding reports as 0 -- which an operand with no index
    does -- is normalized to 1, so the expression reads as the identity
    it is rather than as a multiplication by nothing, and an operand that
    names no base or index register carries None for it. Those are the
    absences the expression itself states.

    Everything else is a component the binding named and this record
    cannot represent: a register id it would not name, a displacement
    that is not an integer, a scale on a real index that is not a
    positive one. The field then falls back to its default and
    ``components_unknown`` is set, because a default is indistinguishable
    from a real `[base + 0]` and an unknown component must never be read
    as agreement with one."""
    read_bit = getattr(capstone, "CS_AC_READ", 0)
    write_bit = getattr(capstone, "CS_AC_WRITE", 0)
    access = getattr(op, "access", 0)
    mem = op.mem
    base_id = getattr(mem, "base", 0)
    index_id = getattr(mem, "index", 0)
    segment_id = getattr(mem, "segment", 0)
    base = _register_name(insn, base_id)
    index = _register_name(insn, index_id)
    segment = _register_name(insn, segment_id)
    scale = getattr(mem, "scale", 1)
    disp = getattr(mem, "disp", 0)
    size = getattr(op, "size", 0)
    unknown = ((bool(base_id) and base is None)
               or (bool(index_id) and index is None)
               or (bool(segment_id) and segment is None)
               or not isinstance(disp, int)
               or (index is not None
                   and not (isinstance(scale, int) and scale > 0)))
    return MemoryOperand(
        base=base, index=index,
        scale=(scale if isinstance(scale, int) and scale > 0 and index else 1),
        displacement=(disp if isinstance(disp, int) else 0),
        width=(size if isinstance(size, int) and size > 0 else 0),
        segment=segment,
        reads=bool(read_bit and (access & read_bit)),
        writes=bool(write_bit and (access & write_bit)),
        components_unknown=unknown)


def _operand_facts(capstone, insn) -> _OperandFacts:
    """One instruction's explicit operands, from capstone's own
    per-operand access bits.

    An operand that reports no access contributes nothing, so an unknown
    is never an assertion that a store or a register write happened. A
    memory operand's base and index are register READS whatever the
    operand's own access is: computing the address reads them, and
    writing through `[rax]` does not write `rax`. Those same registers
    are kept OUT of ``data_register_reads``, which names only the
    registers whose contents the instruction consumes -- the distinction
    between a register that reaches a value and a register that is one.
    A register that is both, as in `add rax, qword ptr [rax]`, is in
    both."""
    x86 = capstone.x86
    read_bit = getattr(capstone, "CS_AC_READ", 0)
    write_bit = getattr(capstone, "CS_AC_WRITE", 0)
    writes_memory = False
    write_base = None
    immediate_width = 0
    reads, data_reads, writes, named = [], [], [], []
    memory, immediates = [], []
    for op in (getattr(insn, "operands", ()) or ()):
        access = getattr(op, "access", 0)
        if op.type == x86.X86_OP_REG:
            name = _register_name(insn, op.reg)
            if name is None:
                continue
            named.append(name)
            if read_bit and (access & read_bit):
                if name not in reads:
                    reads.append(name)
                if name not in data_reads:
                    data_reads.append(name)
            if write_bit and (access & write_bit) and name not in writes:
                writes.append(name)
        elif op.type == x86.X86_OP_IMM:
            value = getattr(op, "imm", None)
            immediates.append(value if isinstance(value, int) else 0)
            size = getattr(op, "size", 0)
            if immediate_width == 0 and isinstance(size, int) and size > 0:
                immediate_width = size
        elif op.type == x86.X86_OP_MEM:
            operand = _memory_operand(capstone, insn, op)
            memory.append(operand)
            for name in operand.address_registers:
                if name not in reads:
                    reads.append(name)
            if operand.writes:
                writes_memory = True
                if write_base is None:
                    write_base = operand.base
    return _OperandFacts(
        writes_memory=writes_memory, write_base_register=write_base,
        memory_operands=tuple(memory[:MAX_MEMORY_OPERANDS]),
        register_reads=tuple(reads[:MAX_REGISTER_OPERANDS]),
        data_register_reads=tuple(data_reads[:MAX_REGISTER_OPERANDS]),
        register_writes=tuple(writes[:MAX_REGISTER_OPERANDS]),
        register_operands=tuple(named[:MAX_REGISTER_OPERANDS]),
        immediates=tuple(immediates[:MAX_IMMEDIATES]),
        immediate_width=immediate_width)


def _clobbered_registers(insn, explicit_writes: tuple) -> tuple:
    """Every register ``insn`` writes, implicit ones included.

    ``regs_access()`` is capstone's own full answer and is preferred. A
    binding that does not provide it, or that raises, falls back to the
    explicit operand writes -- less than the truth, so a caller relying
    on this to invalidate state is told about fewer writes than happen,
    never more."""
    try:
        _reads, writes = insn.regs_access()
    except Exception:
        return explicit_writes
    names = []
    for reg in writes or ():
        name = _register_name(insn, reg)
        if name is not None and name not in names:
            names.append(name)
    for name in explicit_writes:
        if name not in names:
            names.append(name)
    return tuple(names[:MAX_REGISTER_OPERANDS])


def _tail_completes_with_lookahead(md, lookahead: bytes, offset: int, base_va: int,
                                   window_len: int) -> bool:
    """Whether the bytes at ``offset`` begin an instruction that decodes
    once the lookahead past ``window_len`` is available and that ends past
    the window -- i.e. the window cut a real instruction rather than
    stopping on an invalid opcode."""
    try:
        for insn in md.disasm(lookahead[offset:], base_va + offset):
            return (insn.address - base_va) + insn.size > window_len
    except Exception:
        return False
    return False


def decode_window(*, code: bytes, base_va: int, architecture: str,
                  max_insns: int = MAX_DECODE_INSNS,
                  max_bytes: int = MAX_DECODE_BYTES,
                  input_truncated: bool = False) -> DecodeResult:
    """Decode a bounded instruction window.

    ``code`` is the captured bytes, ``base_va`` the virtual address of
    ``code[0]``, ``architecture`` one of :data:`SUPPORTED_ARCHITECTURES`.
    Decoding stops at ``max_insns`` instructions, ``max_bytes`` consumed,
    the end of ``code``, or the first byte capstone cannot decode --
    ``stopped_reason`` says which. Never raises: a decoder that is not
    installed yields ``availability='unavailable'``; a capstone failure
    yields ``stopped_reason='decode_error'`` over whatever decoded before
    it.

    ``input_truncated`` tells the decoder that ``code`` is itself a prefix
    of a longer captured region even when it is not longer than
    ``max_bytes``. When ``code`` runs past ``max_bytes`` those extra bytes
    are lookahead: a short undecoded tail that a legitimate instruction
    completes once the lookahead is added is a byte-cap cut, not an error.
    A short undecoded tail with no more bytes to consult is
    ``undecoded_tail`` (invalid-or-incomplete); one that the lookahead
    still cannot complete is a ``decode_error``.
    """
    window = bytes(code[:max_bytes]) if code else b""
    lookahead = bytes(code[:max_bytes + _MAX_X86_INSN_LEN]) if code else b""
    capstone, backend = _load_backend()
    if capstone is None:
        return DecodeResult(
            availability=DisasmAvailability.UNAVAILABLE, arch_supported=False,
            architecture=architecture, base_va=base_va, window_bytes=len(window),
            bytes_decoded=0, stopped_reason=_StopReason.END_OF_INPUT.value,
            backend=backend)

    mode = _mode_for(capstone, architecture)
    if mode is None:
        return DecodeResult(
            availability=DisasmAvailability.AVAILABLE, arch_supported=False,
            architecture=architecture, base_va=base_va, window_bytes=len(window),
            bytes_decoded=0, stopped_reason=_StopReason.END_OF_INPUT.value,
            backend=backend)

    address_mask = 0xFFFFFFFF if architecture == "x86" else 0xFFFFFFFFFFFFFFFF
    truncated_input = input_truncated or (bool(code) and len(code) > len(window))
    has_lookahead = len(lookahead) > len(window)
    instructions = []
    bytes_decoded = 0
    stopped = _StopReason.END_OF_INPUT
    try:
        md = capstone.Cs(*mode)
        md.detail = True
        stops = _control_flow_stops(capstone)
        effects = _effect_tables(capstone)
        for insn in md.disasm(window, base_va):
            if len(instructions) >= max_insns:
                stopped = _StopReason.INSN_CAP
                break
            kind, direct, slot, rip_rel = _classify_branch(capstone, insn, address_mask)
            facts = _operand_facts(capstone, insn)
            groups = set(getattr(insn, "groups", ()) or ())
            mnemonic, mn_cut = _bounded(insn.mnemonic or "", MAX_MNEMONIC_CHARS)
            operands, op_cut = _bounded(insn.op_str or "", MAX_OPERANDS_CHARS)
            instructions.append(DecodedInsn(
                address=insn.address, size=insn.size,
                mnemonic=mnemonic, mnemonic_truncated=mn_cut,
                operands=operands, operands_truncated=op_cut,
                is_call=capstone.x86.X86_GRP_CALL in groups,
                is_jump=(capstone.x86.X86_GRP_JUMP in groups
                         or capstone.x86.X86_GRP_BRANCH_RELATIVE in groups),
                is_return=capstone.x86.X86_GRP_RET in groups,
                is_interrupt=getattr(capstone.x86, "X86_GRP_INT", None) in groups,
                falls_through=_falls_through(insn, groups, stops),
                branch_kind=kind, direct_target_va=direct,
                slot_target_va=slot, slot_is_rip_relative=rip_rel,
                writes_memory=facts.writes_memory,
                write_base_register=facts.write_base_register,
                memory_operands=facts.memory_operands,
                register_reads=facts.register_reads,
                data_register_reads=facts.data_register_reads,
                register_writes=facts.register_writes,
                register_operands=facts.register_operands,
                clobbered_registers=_clobbered_registers(
                    insn, facts.register_writes),
                immediates=facts.immediates,
                return_address_width=(
                    facts.immediate_width
                    if capstone.x86.X86_GRP_CALL in groups else 0),
                leaves_analysis_context=_leaves_analysis_context(
                    capstone, insn.mnemonic or "", groups),
                implicit_clobbers_known=_implicit_clobbers_known(
                    insn, _clobbered_registers(insn, facts.register_writes),
                    effects),
                writes_memory_implicitly=(
                    getattr(insn, "id", None) in effects[2])))
            bytes_decoded = (insn.address - base_va) + insn.size
        else:
            remaining = len(window) - bytes_decoded
            # Bytes available from the failure point, window plus lookahead.
            available = len(lookahead) - bytes_decoded
            if remaining <= 0:
                stopped = _StopReason.BYTE_CAP if truncated_input else _StopReason.END_OF_INPUT
            elif remaining >= _MAX_X86_INSN_LEN:
                # A whole instruction could have fitted -- a genuine
                # invalid opcode well inside the window.
                stopped = _StopReason.DECODE_ERROR
            elif has_lookahead and _tail_completes_with_lookahead(
                    md, lookahead, bytes_decoded, base_va, len(window)):
                # The window cut a legitimate instruction that the
                # lookahead completes -- a byte-cap truncation.
                stopped = _StopReason.BYTE_CAP
            elif available >= _MAX_X86_INSN_LEN:
                # A full instruction's worth of bytes at the failure point
                # and it still does not decode -- a genuine invalid opcode.
                stopped = _StopReason.DECODE_ERROR
            else:
                # Not enough bytes past the failure point to rule out an
                # instruction the capture cut short: invalid-or-incomplete.
                stopped = _StopReason.UNDECODED_TAIL
    except Exception:
        stopped = _StopReason.DECODE_ERROR

    return DecodeResult(
        availability=DisasmAvailability.AVAILABLE, arch_supported=True,
        architecture=architecture, base_va=base_va, window_bytes=len(window),
        bytes_decoded=bytes_decoded, stopped_reason=stopped.value,
        instructions=tuple(instructions), backend=backend)
