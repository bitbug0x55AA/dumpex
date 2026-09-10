"""The isolated disassembler seam.

`capstone` is an optional dependency (`pip install dumpex[disasm]`). This
module is the only place it is imported, and every entry point works
whether or not it is installed: with no decoder, a decode request returns
a result whose `availability` is `"unavailable"` and whose instruction
tuple is empty, never an exception and never a partial guess.

What this module decodes is a bounded byte window at a known virtual
address. It resolves the mechanically determinable branch operand of each
instruction -- the absolute target of a direct `call`/`jmp`, and the
slot address of an indirect `call`/`jmp` through a RIP-relative or
absolute memory operand -- and nothing else. An indirect branch through a
register, function boundaries, call arguments, and stack state are not
mechanically determinable from a byte window and are never reported.
"""
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "DisasmAvailability",
    "BranchKind",
    "DecodedInsn",
    "DecodeResult",
    "SUPPORTED_ARCHITECTURES",
    "MAX_DECODE_BYTES",
    "MAX_DECODE_INSNS",
    "MAX_INSTRUCTION_LENGTH",
    "MAX_MNEMONIC_CHARS",
    "MAX_OPERANDS_CHARS",
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

#: The architecture tokens this module decodes. Anything else leaves a
#: decode result `arch_supported` False with an empty instruction tuple --
#: an explicit unsupported state, never a wrong-width decode.
SUPPORTED_ARCHITECTURES = ("x86", "x64")


class DisasmAvailability(str, Enum):
    """Whether a decoder backend is installed."""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


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
class DecodedInsn:
    """One decoded instruction and its resolved branch operand.

    ``address`` is the instruction's own virtual address, ``size`` its
    length in bytes. ``mnemonic`` and ``operands`` are capstone's text,
    each cut to this module's cap with a ``*_truncated`` flag. ``is_call``
    / ``is_jump`` / ``is_return`` are read from capstone's instruction
    groups so no consumer repeats the opcode test.
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
    direct_target_va: "int | None" = None
    slot_target_va: "int | None" = None
    slot_is_rip_relative: bool = False


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
    """
    availability: DisasmAvailability
    arch_supported: bool
    architecture: str
    base_va: int
    window_bytes: int
    bytes_decoded: int
    stopped_reason: str
    instructions: tuple = field(default_factory=tuple)

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


def _import_capstone():
    """The one import of ``capstone`` in dumpex. Returns the module or
    ``None``; performed on every call so a test can remove it from
    ``sys.modules`` and see the unavailable path."""
    try:
        import capstone
    except Exception:
        return None
    return capstone


def disasm_available() -> bool:
    """Whether a decoder backend is installed right now."""
    return _import_capstone() is not None


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
    capstone = _import_capstone()
    if capstone is None:
        return DecodeResult(
            availability=DisasmAvailability.UNAVAILABLE, arch_supported=False,
            architecture=architecture, base_va=base_va, window_bytes=len(window),
            bytes_decoded=0, stopped_reason=_StopReason.END_OF_INPUT.value)

    mode = _mode_for(capstone, architecture)
    if mode is None:
        return DecodeResult(
            availability=DisasmAvailability.AVAILABLE, arch_supported=False,
            architecture=architecture, base_va=base_va, window_bytes=len(window),
            bytes_decoded=0, stopped_reason=_StopReason.END_OF_INPUT.value)

    address_mask = 0xFFFFFFFF if architecture == "x86" else 0xFFFFFFFFFFFFFFFF
    truncated_input = input_truncated or (bool(code) and len(code) > len(window))
    has_lookahead = len(lookahead) > len(window)
    instructions = []
    bytes_decoded = 0
    stopped = _StopReason.END_OF_INPUT
    try:
        md = capstone.Cs(*mode)
        md.detail = True
        for insn in md.disasm(window, base_va):
            if len(instructions) >= max_insns:
                stopped = _StopReason.INSN_CAP
                break
            kind, direct, slot, rip_rel = _classify_branch(capstone, insn, address_mask)
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
                branch_kind=kind, direct_target_va=direct,
                slot_target_va=slot, slot_is_rip_relative=rip_rel))
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
        instructions=tuple(instructions))
