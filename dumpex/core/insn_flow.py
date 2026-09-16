"""Bounded local control and data flow over one decoded instruction window.

A decoded window is a list of instructions in byte order. Byte order is
not a path: the instruction after a branch may be the branch's successor,
another branch's destination, or data the code reads. This module is
where that difference is made explicit, so nothing above it has to reason
about instruction text or about linear adjacency again.

It answers three questions and no others.

**Which instruction can reach which.** :class:`LocalCfg` is a graph over
the instruction boundaries THIS decode produced, with one edge per
control transfer the instruction itself states: a fall-through, a direct
conditional branch's taken edge, a direct unconditional branch, and a
direct call. An unconditional branch has no fall-through edge, so the
bytes below one are reachable only when something branches to them. A
branch whose destination is outside the window contributes no edge at
all -- a path that leaves is a path this module cannot follow, and it
reports less rather than guessing.

**Whether a loop transforms memory in place.** :class:`TransformLoop` is
a proof, not a pattern match, and there are exactly two shapes it
accepts. A direct read-modify-write (`xor dword ptr [rbp], eax`) is one
instruction. The register-mediated form is three -- a load, a
non-identity transform of the loaded value, and a store of that same
surviving value back to the same effective address -- and every step of
it is checked: the two accesses must name the same
segment/base/index/scale/displacement/width with every component
resolved, the load must not write a register its own address reads, no
instruction between them may write the base or index register, the value
must survive every explicit and implicit clobber to reach the store, and
no branch may fork or join the span and bring a different value in with
it. Non-identity is asked of the VALUE and not of the register name: two
registers a `mov` made equal are one value, and `xor` between them
leaves zero however differently they are spelled.

**Where the code's own address came from.** A direct `call` whose target
is a `pop` leaves a return address in a register. That is evidence about
a transform loop only when the value is followed, register family by
register family, from that `pop` to the very address register the proven
access uses -- and arithmetic between two registers carrying it leaves a
displacement or a doubling, which is no longer an address in this code.

Everything here under-reports on purpose. A form it does not model, an
operand it cannot normalize, a clobber it cannot rule out and a path it
cannot join all end a candidate rather than weaken a claim, and no result
this module returns asserts that any instruction executed.
"""
from dataclasses import dataclass
from enum import Enum

from dumpex.core.disasm import (
    BranchKind, DecodedInsn, MemoryOperand, is_full_width_register,
    register_family, register_width,
)

__all__ = [
    "EdgeKind",
    "LocalCfg",
    "build_local_cfg",
    "linear_run_is_uninterrupted",
    "same_effective_address",
    "effective_segment",
    "registers_holding",
    "is_zero_idiom",
    "GetPcPair",
    "ExitTransfer",
    "TransformLoop",
    "DIRECT_WRITE_BACK",
    "LOAD_TRANSFORM_STORE",
    "TRANSFORM_MNEMONICS",
    "find_transform_loop",
    "transform_loop_withheld",
    "WITHHELD_UNREACHABLE",
    "WITHHELD_UNPROVEN",
    "MAX_TRACKED_VALUES",
    "MAX_PROOF_ATTEMPTS",
]

# ── Caps ───────────────────────────────────────────────────────────────
# Register values followed through one span at once. A modelled flow
# names one destination per instruction, so this is slack over the
# analysis rather than a cut through it; a span that reaches the cap is
# one this module has stopped being able to account for, and the
# candidate ends there.
MAX_TRACKED_VALUES = 8

# Candidate (loop, access) pairs one window's proof search evaluates. The
# decode cap already bounds a window to 48 instructions, so this is
# reached only by a window that is almost entirely branches and accesses;
# past it the search stops with whatever it has proven, which is a
# smaller claim and never a wrong one.
MAX_PROOF_ATTEMPTS = 256


# ── control flow ───────────────────────────────────────────────────────

class EdgeKind(str, Enum):
    """One control transfer between two decoded instructions.

    ``FALL_THROUGH`` -- execution continues at the next instruction.
    Present only when `DecodedInsn.falls_through` says so, which is how
    an unconditional branch ends up with no fall-through edge: nothing
    reaches the bytes below a `jmp` by falling into them.

    ``CONDITIONAL`` -- a direct conditional branch's taken edge. The
    instruction also has a ``FALL_THROUGH`` edge; both are real.

    ``UNCONDITIONAL`` -- a direct `jmp` to an instruction in this window.

    ``CALL`` -- a direct `call` to an instruction in this window. It is
    kept apart from the other two because control also continues below
    the call, and because a `call` whose target is a `pop` is a way of
    reading an address rather than of invoking a function.
    """
    FALL_THROUGH = "fall_through"
    CONDITIONAL = "conditional"
    UNCONDITIONAL = "unconditional"
    CALL = "call"


class LocalCfg:
    """The control-flow graph of one decoded window.

    Nodes are the instruction addresses this decode produced, so a branch
    into the middle of a decoded instruction reaches no node and is
    simply not an edge. Edges are the transfers each instruction states
    for itself; a destination outside the window is not one, because a
    path that leaves the window is a path this graph cannot follow.
    """

    def __init__(self, instructions):
        self.instructions = tuple(instructions)
        self.by_address = {insn.address: insn for insn in self.instructions}
        edges = {}
        for insn in self.instructions:
            out = []
            target = insn.direct_target_va
            if (insn.branch_kind is BranchKind.DIRECT and target is not None
                    and target in self.by_address):
                if insn.is_call:
                    kind = EdgeKind.CALL
                elif insn.falls_through:
                    kind = EdgeKind.CONDITIONAL
                else:
                    kind = EdgeKind.UNCONDITIONAL
                out.append((kind, target))
            if insn.falls_through:
                successor = insn.address + insn.size
                if successor in self.by_address:
                    out.append((EdgeKind.FALL_THROUGH, successor))
            edges[insn.address] = tuple(out)
        self._edges = edges
        self._reachable_memo = {}

    def successors(self, address: int) -> tuple:
        """``((EdgeKind, target_address), ...)`` leaving ``address``."""
        return self._edges.get(address, ())

    def reachable_from(self, start: int) -> frozenset:
        """Every instruction address reachable from ``start``, ``start``
        itself included when it is a decoded boundary.

        The walk is bounded by the node count, so it terminates on a
        window that is one cycle, and each start is walked once per
        graph."""
        cached = self._reachable_memo.get(start)
        if cached is not None:
            return cached
        seen = set()
        pending = [start] if start in self.by_address else []
        seen.update(pending)
        while pending:
            address = pending.pop()
            for _kind, target in self.successors(address):
                if target not in seen:
                    seen.add(target)
                    pending.append(target)
        result = frozenset(seen)
        self._reachable_memo[start] = result
        return result


def build_local_cfg(instructions) -> LocalCfg:
    """The :class:`LocalCfg` over one decoded window."""
    return LocalCfg(instructions)


def linear_run_is_uninterrupted(instructions, start_va: int, end_va: int) -> bool:
    """Whether every instruction in the half-open range ``[start_va,
    end_va)`` leaves the linear path intact -- no return and no
    unconditional branch.

    The range is half-open so a caller can state exactly which endpoints
    it means: an instruction AT ``start_va`` is examined, one at
    ``end_va`` is not. A caller that means "after this instruction"
    passes ``insn.address + insn.size`` rather than ``insn.address``,
    because the instruction sitting on an endpoint is often the very one
    that ends the run.

    Whether an instruction ends the run is `DecodedInsn.falls_through`,
    decided at the decode layer from capstone's instruction id -- so a
    far `ljmp` ends it exactly as a near `jmp` does, which comparing
    mnemonic text would miss.

    This is the weakest honest statement that one linear run can cover
    the range; it proves no run was taken."""
    return all(insn.falls_through for insn in instructions
               if start_va <= insn.address < end_va)


# ── memory operands ────────────────────────────────────────────────────

def effective_segment(operand: MemoryOperand,
                      architecture: "str | None") -> "str | None":
    """The segment register ``operand``'s address actually resolves
    through, named or implied, or None when no segment can move it.

    An operand that names one answers that. An operand that names none
    still HAS one: in 32-bit code an address based on `ebp` or `esp` goes
    through SS and everything else through DS, and writing either
    register moves every address that resolves through it. In 64-bit code
    the CS/DS/ES/SS bases are forced to zero and cannot be moved at all,
    so an unnamed segment there answers None -- only an explicit FS or GS
    carries a base worth tracking."""
    if operand.segment:
        return operand.segment
    if architecture != "x86":
        return None
    return "ss" if register_family(operand.base) in ("rbp", "rsp") else "ds"


def same_effective_address(first: MemoryOperand, second: MemoryOperand) -> bool:
    """Whether two memory operands name one address expression.

    Every normalized component has to agree -- segment, base, index,
    scale, displacement and access width -- because each of them is a way
    for two accesses that look alike to reach different bytes: a
    different segment is a different region, a different width is a
    different number of bytes at the same start, and an address-size
    override makes `[ebp]` and `[rbp]` two expressions that print almost
    identically.

    A width the decoder did not report is not a match: an unknown is
    never evidence of agreement. Neither is any other component the
    decoder named and could not resolve -- `MemoryOperand.components_
    unknown` marks an operand whose base, index, scale, displacement or
    segment fell back to a default, and a default that happens to read
    like a real `[base + 0]` is not a statement that the two addresses
    meet. A RIP-relative operand never matches anything, its own text
    included -- `[rip + disp]` resolves against the address of the
    instruction AFTER it, so the same displacement at two instructions is
    two addresses.

    Agreement of the expressions is only half of address equivalence. The
    registers in them must also still hold what they held; that is the
    caller's to establish, and :func:`find_transform_loop` does it by
    rejecting any write to a base or index register in between."""
    if first.rip_relative or second.rip_relative:
        return False
    if first.components_unknown or second.components_unknown:
        return False
    if first.width <= 0 or second.width <= 0:
        return False
    return (first.base == second.base
            and first.index == second.index
            and first.scale == second.scale
            and first.displacement == second.displacement
            and first.width == second.width
            and first.segment == second.segment)


# Instructions that change a segment BASE without writing the segment
# selector a memory operand names, and WHICH segment each one moves. A
# `wrfsbase` moves the whole of the FS-relative address space without
# touching `fs`, so two `fs:[eax]` operands either side of one are two
# addresses -- and two `gs:[eax]` operands either side of it are still
# one, because the FS base is not where a GS-relative address resolves.
# There is no capstone group for these; the table is checked beside the
# selector clobbers.
#
# `wrmsr` is the one entry that names more than it is known to move: the
# MSR it writes is chosen by ECX at run time, and this module does not
# resolve that, so both bases it COULD write are given up. What it cannot
# write is the CS/DS/ES/SS base in 64-bit code, which the architecture
# forces to zero, or a 32-bit descriptor base, which lives in a
# descriptor table rather than in an MSR -- so an ordinary address is
# unaffected by it.
_SEGMENT_BASE_WRITES = {
    "wrfsbase": frozenset(("fs",)),
    "wrgsbase": frozenset(("gs",)),
    "swapgs":   frozenset(("gs",)),
    "wrmsr":    frozenset(("fs", "gs")),
}


def _address_version_survives(insn: DecodedInsn, address_registers: set,
                              segment: "str | None") -> bool:
    """Whether ``insn`` leaves every register ``address`` resolves
    through holding what it held.

    The base, the index and the segment selector -- named or implied --
    are one set, and a write to any of them at any width makes the next
    access a different address however identical its text. A segment BASE
    moves without the selector being touched, so
    :data:`_SEGMENT_BASE_WRITES` is asked alongside -- about the segment
    THIS address resolves through, which :func:`effective_segment` names.
    A base write to a segment the address does not go through moves some
    other region and leaves this one where it was."""
    moved = _SEGMENT_BASE_WRITES.get(insn.mnemonic)
    if moved is not None and segment is not None and segment.lower() in moved:
        return False
    clobbered = {register_family(name) for name in insn.clobbered_registers}
    return not (clobbered & address_registers)


def _address_registers_of(address: MemoryOperand,
                          architecture: "str | None") -> set:
    """Every register family ``address`` resolves through -- base, index,
    and the segment selector :func:`effective_segment` names or
    implies."""
    families = {register_family(name) for name in address.address_registers}
    segment = effective_segment(address, architecture)
    if segment is not None:
        families.add(register_family(segment))
    return families


# ── value flow ─────────────────────────────────────────────────────────

# The arithmetic and logic mnemonics that transform a value already in
# their destination. Each reads that destination and writes it back, so
# the result still derives from what was there -- which is what separates
# a transform from a replacement.
#
# One set serves both accepted forms, because they are one operation
# written two ways: the destination is an explicit memory operand in the
# direct form and a register in the register-mediated one. Neither form
# accepts a mnemonic this does not name, and `mov` is deliberately absent
# from both -- it carries a value rather than changing it, so a load and
# a store with only `mov` between them stays an ordinary memory copy. The
# set is written out here rather than derived from an instruction group,
# so the rule a lead is emitted under is readable in one place.
TRANSFORM_MNEMONICS = frozenset((
    "xor", "add", "sub", "adc", "sbb", "and", "or", "not", "neg",
    "inc", "dec", "rol", "ror", "shl", "shr", "sal", "sar", "rcl", "rcr",
))

# The load forms this module reads as loads. A `mov`/`movzx`/`movsx`
# whose single memory operand is a source and whose destination is a
# register does not write memory, and that is the same trust the proof
# already places in the `mov` mnemonic at both ends of it -- the load it
# anchors on and the store it proves. Without this a key-table read
# inside the body ends the candidate, and reading a key from a table is
# what the canonical decoder loop does.
_PURE_LOAD_MNEMONICS = frozenset(("mov", "movzx", "movsx", "movsxd"))

_COPY_MNEMONIC = "mov"
_ADDRESS_MNEMONIC = "lea"
_SELF_ARITHMETIC_MNEMONICS = frozenset(("add", "sub", "inc", "dec"))

# The only coefficient at which this code's own address is still this
# code's own address. Anything else -- a doubling, a scaled index, a
# difference -- is a number computed FROM where the code sits rather than
# a place in it, and an access through it lands wherever that arithmetic
# put it.
_CARRIED_ONCE = 1

# Mnemonics whose result is the destination unchanged when the immediate
# is zero, and the two `and`/`or` values that replace the destination
# with a constant. Neither is a transform: the first leaves the value as
# it was, the second discards it. The immediate is compared at the
# destination's width, so an `and` against all-ones reads as the identity
# it is whether the binding reports it as -1 or as the unsigned mask.
_IDENTITY_AT_ZERO_MNEMONICS = frozenset((
    "add", "sub", "xor", "or",
    "rol", "ror", "shl", "shr", "sal", "sar", "rcl", "rcr",
))
_SHIFT_MNEMONICS = frozenset(("rol", "ror", "shl", "shr", "sal", "sar", "rcl", "rcr"))

# The mnemonics that take a third input this module does not track. `adc`
# and `sbb` read the carry flag, so `adc edx, i` is `edx + i + CF` and
# `sbb edx, i` is `edx - i - CF`, and which value the destination holds
# afterwards is decided by an instruction that may be anywhere above --
# or outside the window entirely.
#
# Either leaves the destination alone exactly when `i + CF` is zero at
# that destination's width, so the immediates that can be an identity are
# zero (with the carry clear) and the all-ones mask (with it set), and
# no others. Both are given up rather than called transforms. The two
# answers are wrong in one direction each, and this is the direction that
# costs a proof instead of the truth of one: calling either a transform
# would assert a non-identity result on a run where the instruction wrote
# back precisely what it read.
#
# No other immediate is affected. `adc edx, 5` still transforms -- the
# result is `edx + 5 + CF`, which is not `edx` under either flag -- and
# so does `adc edx, ecx`, which has no immediate at all.
_CARRY_DEPENDENT_MNEMONICS = frozenset(("adc", "sbb"))

# The mnemonics whose result does not depend on the operand when both
# operands hold one VALUE -- the same register named twice, or two
# registers a `mov` made equal. They split by what the destination is
# left holding, which is not the same question as whether a transform
# happened: `xor`/`sub` leave zero and `sbb reg, reg` leaves 0 or -1
# decided by the carry flag alone, so the value is gone; `and`/`or` leave
# the register exactly as it was -- the canonical flag-test idiom -- so
# the value is still there and still untransformed. `add`/`adc` are
# absent from both: doubling a value is a transform of it.
_SAME_VALUE_ZEROES = frozenset(("xor", "sub", "sbb"))
_SAME_VALUE_IS_IDENTITY = frozenset(("and", "or"))

# What one instruction leaves in a register that held a tracked value.
# Three answers are needed and not two, because "this is not a transform"
# and "the value is no longer here" are different facts about the rows:
# `or edx, edx` sets flags and leaves the loaded bytes in place, so a
# later `xor edx, eax` transforms the value that was LOADED, while
# `xor edx, edx` leaves a constant and the same later instruction
# transforms something else entirely.
_VALUE_TRANSFORMED = "transformed"
_VALUE_UNCHANGED = "unchanged"
_VALUE_LOST = "lost"


def is_zero_idiom(insn: DecodedInsn) -> bool:
    """Whether ``insn`` is the `xor reg, reg` / `sub reg, reg` zeroing
    idiom. It is recognised by the instruction naming one register twice,
    so `sub rcx, 1` -- which reads and writes rcx just as `sub rcx, rcx`
    does -- is not mistaken for it."""
    return insn.mnemonic in ("xor", "sub") and _names_one_register_twice(insn)


def _names_one_register_twice(insn: DecodedInsn) -> bool:
    """Whether ``insn``'s two register operands are the same register."""
    return (len(insn.register_operands) == 2
            and insn.register_operands[0] == insn.register_operands[1])


@dataclass(frozen=True)
class _TrackedValue:
    """One register's share of a loaded value, and what has happened to
    it.

    ``origin`` names the VALUE rather than the register. A
    register-to-register `mov` copies it, so two registers carrying one
    origin hold one value; a transform issues a fresh origin, because
    what it leaves is a different value from the one it read.

    ``transformed`` is whether that value still derives from the loaded
    bytes through at least one non-identity operation. A store of a value
    that is merely a copy is a memory copy and proves nothing.

    ``path`` is the instructions that carried the value here from the
    load, in the order they were walked. A proof names them, because the
    relationship between the load and the register a store reads is only
    as visible as the instructions that established it."""
    origin:      int
    transformed: bool
    path:        tuple = ()


def _same_value_verdict(insn: DecodedInsn, tracked: dict,
                        destination: str) -> "str | None":
    """What ``insn`` leaves in ``destination`` when it combines two
    copies of ONE value under a mnemonic whose result then does not
    depend on what that value was, or None when it is not that shape.

    :data:`_VALUE_LOST` for `xor`/`sub`, which leave zero, and for `sbb`,
    which leaves the carry flag alone. :data:`_VALUE_UNCHANGED` for the
    `and`/`or` flag-test idiom, which leaves the value exactly as it was
    -- the flags moved and the bytes did not, so the next instruction to
    read the register reads the value that was loaded.

    Naming one register twice is the visible case. The other is two
    registers holding one value: after `mov ecx, edx`, the instruction
    `xor edx, ecx` is `xor edx, edx` written across two instructions and
    its result is a constant that carries nothing of the loaded bytes.
    :attr:`_TrackedValue.origin` is what tells the two apart, so the
    question is asked about the value and never about the register
    name."""
    if insn.mnemonic in _SAME_VALUE_ZEROES:
        verdict = _VALUE_LOST
    elif insn.mnemonic in _SAME_VALUE_IS_IDENTITY:
        verdict = _VALUE_UNCHANGED
    else:
        return None
    return verdict if _combines_one_value(insn, tracked, destination) else None


def _combines_one_value(insn: DecodedInsn, tracked: dict,
                        destination: str) -> bool:
    """Whether ``insn``'s two inputs are two copies of one value --
    the same register named twice, or two registers a `mov` made
    equal."""
    if _names_one_register_twice(insn):
        return True
    origin = tracked[destination].origin
    by_family = {register_family(name): entry for name, entry in tracked.items()}
    destination_family = register_family(destination)
    for name in insn.data_register_reads:
        family = register_family(name)
        if family == destination_family:
            continue
        entry = by_family.get(family)
        if entry is not None and entry.origin == origin:
            return True
    return False


def _immediate_verdict(insn: DecodedInsn, width: "int | None") -> str:
    """What ``insn``'s immediate operand leaves in a destination of
    ``width`` bytes that held a tracked value.

    An instruction with no immediate is :data:`_VALUE_TRANSFORMED`: its
    other input is a register, and whatever that register holds, the
    result depends on the destination as well. More than one immediate is
    a form this does not model and is :data:`_VALUE_LOST`, as is an
    immediate on a destination with no known width -- there is nothing to
    compare the value against.

    The three answers separate an immediate that leaves the value ALONE
    from one that DISCARDS it. `add edx, 0` and `shl edx, 0` write back
    the bytes they read, so the value is still there for a later
    instruction to transform; `and edx, 0` and `or edx, -1` write a
    constant, and it is not. The two immediates that can make a
    :data:`_CARRY_DEPENDENT_MNEMONICS` instruction an identity are
    neither: whether `adc edx, 0` or `adc edx, -1` changed the register
    is decided by a flag this module does not follow, so the value is
    given up rather than claimed either way."""
    if not insn.immediates:
        return _VALUE_TRANSFORMED
    if len(insn.immediates) != 1:
        return _VALUE_LOST
    if not width:
        return _VALUE_LOST
    mask = (1 << (width * 8)) - 1
    value = insn.immediates[0] & mask
    mnemonic = insn.mnemonic
    if mnemonic in _SHIFT_MNEMONICS:
        # x86 masks a shift count to the low 5 or 6 bits, so a count at
        # or past the operand width is not the shift the text reads as
        # and is not resolved here. Zero is the identity.
        if value == 0:
            return _VALUE_UNCHANGED
        return _VALUE_TRANSFORMED if value < width * 8 else _VALUE_LOST
    if mnemonic in _CARRY_DEPENDENT_MNEMONICS and value in (0, mask):
        # `adc x, i` is `x + i + CF` and `sbb x, i` is `x - i - CF`, so
        # either leaves x exactly when `i + CF` is zero at the
        # destination's width. CF is zero or one, so the immediates that
        # can do it are zero and the all-ones mask and there are no
        # others -- this is the whole set, not the cases seen so far.
        return _VALUE_LOST
    if mnemonic == "and":
        # All-ones leaves the destination alone; zero replaces it.
        if value == mask:
            return _VALUE_UNCHANGED
        return _VALUE_LOST if value == 0 else _VALUE_TRANSFORMED
    if mnemonic == "or" and value == mask:
        return _VALUE_LOST
    if mnemonic in _IDENTITY_AT_ZERO_MNEMONICS and value == 0:
        return _VALUE_UNCHANGED
    return _VALUE_TRANSFORMED


def _transformed_destination(insn: DecodedInsn, tracked: dict, *,
                             new_origin: int) -> "tuple | None":
    """``(register_name, _TrackedValue, transforms_here)`` for the one
    register ``insn`` leaves a tracked value in, or None when it leaves
    none there.

    Three forms carry a value, and each names exactly one register
    destination.

    A register-to-register `mov` of a tracked register at the same width
    moves the value itself -- the same origin and the same transform
    state -- so the copy and its source stay known to hold one value.

    A :data:`TRANSFORM_MNEMONICS` instruction whose destination is itself
    tracked transforms it in place under ``new_origin``, provided the
    result still depends on what was there.

    And the same instruction may instead leave the destination exactly as
    it was: `or edx, edx`, `and edx, -1`, `add edx, 0`, `shl edx, 0`.
    That is neither a transform nor a loss, and it answers with the value
    it was given -- origin, transform state and all -- and
    ``transforms_here`` False. Reading those as losses would end a flow
    the rows show continuing, and reading them as transforms would let a
    loop that writes back precisely what it read count as one that
    transformed it.

    The tracked name is the exact register name, not its family, because
    the width is part of the value: a 4-byte load lands in `edx`, and a
    later write to `dl` or to `rdx` leaves something that is no longer
    the 4 bytes that were read. The caller kills by family, so either of
    those ends the track.

    Everything else answers None, and the caller then kills whatever the
    instruction clobbers. A zeroing idiom, an annihilating immediate and
    an unmodelled form therefore each lose the value rather than carrying
    it silently."""
    writes = insn.register_writes
    if len(writes) != 1:
        return None
    destination = writes[0]
    if insn.mnemonic == _COPY_MNEMONIC:
        if len(insn.register_operands) != 2 or len(insn.data_register_reads) != 1:
            return None
        source = insn.data_register_reads[0]
        if source not in tracked:
            return None
        if register_width(source) != register_width(destination):
            return None
        carried = tracked[source]
        return destination, _TrackedValue(
            origin=carried.origin, transformed=carried.transformed,
            path=carried.path + (insn,)), False
    if insn.mnemonic not in TRANSFORM_MNEMONICS:
        return None
    if destination not in tracked or insn.memory_operands:
        return None
    verdict = _same_value_verdict(insn, tracked, destination)
    if verdict is None:
        verdict = _immediate_verdict(insn, register_width(destination))
    if verdict == _VALUE_LOST:
        return None
    carried = tracked[destination]
    if verdict == _VALUE_UNCHANGED:
        return destination, _TrackedValue(
            origin=carried.origin, transformed=carried.transformed,
            path=carried.path + (insn,)), False
    return destination, _TrackedValue(
        origin=new_origin, transformed=True,
        path=carried.path + (insn,)), True


def _address_carries_once(address: MemoryOperand, carrying: set,
                          architecture: "str | None") -> "tuple | None":
    """``(register_name, family)`` for the carried value ``address`` is
    built from, when the address IS that value plus a constant, or None.

    Two things have to hold, and a register family appearing somewhere in
    the expression is neither of them.

    The coefficient has to be exactly one. Every register in ``carrying``
    holds the value of one `pop`, so the base contributes one and a
    scaled index contributes its scale: `[rax + rbp*4]` is four times
    this code's address plus whatever `rax` holds, and `[rbp + rcx]` with
    a copy of the popped value in `rcx` is twice it. Each of those names
    a location computed FROM where the code sits rather than a location
    IN it, and an access through one lands wherever that arithmetic put
    it.

    And the register has to enter the address at the architecture's full
    address width. `[ebp]` in 64-bit code is an address-size override
    that uses the low 32 bits of `rbp` and discards the rest, and `[bp]`
    in 32-bit code uses the low 16; the popped return address is not
    what either of them resolves through, however plainly the register
    family says it is the same register. :func:`register_family` is the
    right question for a KILL -- a write to `ebp` does destroy `rbp` --
    and the wrong one for a USE."""
    if address.components_unknown:
        return None
    carried = None
    coefficient = 0
    for name, scale in ((address.base, 1), (address.index, address.scale)):
        if not name or register_family(name) not in carrying:
            continue
        if not is_full_width_register(name, architecture):
            return None
        coefficient += scale
        if carried is None:
            carried = (name, register_family(name))
    if carried is None or coefficient != _CARRIED_ONCE:
        return None
    return carried


def _carrying_destination(insn: DecodedInsn, *, architecture: "str | None",
                          carrying: set) -> "str | None":
    """The one register family ``insn`` leaves a carried ADDRESS in, or
    None.

    This is the address-value counterpart of
    :func:`_transformed_destination`, and it is stricter in the two ways
    an address needs.

    The destination has to be this architecture's full width, because a
    narrower write does not leave a whole address behind.

    And the carried value has to be CONSUMED, not merely mentioned.
    `DecodedInsn.register_reads` names a memory operand's base and index
    too -- computing an address reads those registers -- so
    `add rcx, qword ptr [rbp]` reads `rbp`, and what it adds to `rcx` is
    the memory at that address rather than the address itself. Reading it
    through `data_register_reads` is what keeps a register that merely
    supplied an address from promoting a register that holds something
    fetched with it. `lea` is the one exception and takes the wider set:
    its memory operand is never dereferenced, so there the address
    registers ARE the value.

    And the carried address has to come through with a COEFFICIENT OF
    ONE. Every register in ``carrying`` holds the value of one `pop`, so
    an instruction that consumes it more than once, or scales it, leaves
    a multiple or a difference of this code's address rather than an
    address in this code: `sub rcx, rbp` between two carrying registers
    is zero, the same after `lea rcx, [rbp + 0x20]` is the constant
    0x20 -- a displacement, which names no location -- and
    `add rbp, rbp`, `lea rbp, [rbp + rbp]` and `lea rbp, [rbp*4]` are
    each a multiple. The coefficient is summed over the instruction's
    inputs, so a register named twice counts twice however the operand
    list spells it, and an index register contributes its own scale. A
    transform through a register holding any of those must not be read
    as a stub rewriting its own bytes.

    None is the answer for every instruction this module does not model,
    and the caller kills the instruction's destinations either way -- so
    an unrecognised form loses the value rather than passing it on."""
    writes = insn.register_writes
    if len(writes) != 1 or not is_full_width_register(writes[0], architecture):
        return None
    sources = (insn.register_reads if insn.mnemonic == _ADDRESS_MNEMONIC
               else insn.data_register_reads)
    if not any(register_family(name) in carrying for name in sources):
        return None
    destination = register_family(writes[0])
    if insn.mnemonic == _COPY_MNEMONIC:
        # Two register operands and exactly one register read: a register
        # source. A load reads a memory operand's base instead, which
        # leaves only one register operand and is rejected here.
        if len(insn.register_operands) == 2 and len(insn.register_reads) == 1:
            return destination
        return None
    if insn.mnemonic == _ADDRESS_MNEMONIC:
        # `lea`'s only register operand is its destination; everything it
        # reads is the address arithmetic.
        if len(insn.register_operands) != 1 or len(insn.memory_operands) != 1:
            return None
        operand = insn.memory_operands[0]
        if _address_carries_once(operand, carrying, architecture) is None:
            return None
        return destination
    if insn.mnemonic in _SELF_ARITHMETIC_MNEMONICS:
        # A memory operand here means the second input came from memory,
        # which is a load however the mnemonic reads. `add rcx, [rbp]` is
        # not address arithmetic under any reading of it.
        if is_zero_idiom(insn) or insn.memory_operands:
            return None
        reads = {register_family(name) for name in insn.data_register_reads}
        if destination not in reads:
            return None
        operands = insn.register_operands
        if len(operands) > 2:
            return None
        coefficient = 1 if register_family(operands[0]) in carrying else 0
        if len(operands) == 2:
            second = 1 if register_family(operands[1]) in carrying else 0
            coefficient += -second if insn.mnemonic == "sub" else second
        return destination if coefficient == _CARRIED_ONCE else None
    return None


def _carrying_with_paths(instructions, *, seed: str,
                         architecture: "str | None",
                         from_va: int, to_va: int) -> tuple:
    """``(carrying, paths)`` -- the register families still holding the
    value ``seed`` held at ``from_va``, and for each of them the
    addresses of the instructions that carried it there.

    The rules are :func:`registers_holding`'s, which is this function
    with the paths dropped. A path is kept because the carry is a claim
    about instructions that name different registers at either end: a
    `pop rbp` and an `[rcx]` access say nothing to each other without the
    `mov rcx, rbp` between them, so the instructions that moved the value
    are part of what the claim rests on rather than context around it.

    A family's path is the path of the first carrying register the
    instruction consumed, in operand order, with the instruction's own
    address appended -- so one window answers the same way every run. A
    kill drops the family's path along with the family."""
    carrying = {register_family(seed)}
    paths = {register_family(seed): ()}
    for insn in instructions:
        if not from_va <= insn.address < to_va:
            continue
        if insn.leaves_analysis_context or insn.effects_unknown:
            return set(), {}
        if not insn.clobbered_registers:
            continue
        destination = _carrying_destination(
            insn, architecture=architecture, carrying=carrying)
        carried_from = ()
        if destination is not None:
            sources = (insn.register_reads if insn.mnemonic == _ADDRESS_MNEMONIC
                       else insn.data_register_reads)
            carried_from = next(
                (paths[register_family(name)] for name in sources
                 if register_family(name) in carrying), ())
        killed = {register_family(name) for name in insn.clobbered_registers}
        carrying -= killed
        for family in killed:
            paths.pop(family, None)
        if destination is not None:
            carrying.add(destination)
            paths[destination] = carried_from + (insn.address,)
    return carrying, paths


def registers_holding(instructions, *, seed: str, architecture: "str | None",
                      from_va: int, to_va: int) -> set:
    """The register families still carrying the value ``seed`` held at
    ``from_va``, walked forward over the instructions in ``[from_va,
    to_va)``.

    Tracking is per register FAMILY, not per name: `rax`, `eax`, `ax`,
    `al` and `ah` are one register, and writing any of them ends what it
    held. The kill covers every register capstone says an instruction
    writes, the implicit ones included, so a `mul` that overwrites `rax`
    without naming it does not leave a stale value behind. It is
    unconditional and it comes first -- in 64-bit mode `xor eax, eax`
    zeroes the whole of `rax`, and an 8- or 16-bit write leaves the rest
    stale, so in neither case does the address someone was following
    survive.

    A `call` ends every carry at once. What a callee writes is not in
    this window, and capstone reports a `call`'s own clobbers as the
    stack pointer and instruction pointer alone -- so treating the call
    as an ordinary instruction would leave every other register looking
    intact across a function whose body was never examined. A volatile
    register is precisely the one a callee is free to replace, and a
    resolver call between a get-PC sequence and a decode loop is an
    ordinary layout, not an exotic one.

    So does an instruction the decoder reported nothing about, which is
    not the same as an instruction that does nothing: `aaa` and `das`
    change AL, `xlatb` reads memory through `[rbx + al]` and writes AL,
    and `rdpkru` writes EAX and EDX, all with capstone reporting no
    operand and no clobber. `DecodedInsn.effects_unknown` is that
    backstop.

    So does everything else that leaves for code this window does not
    contain, for the same reason and with less of the state visible:
    `int 0x80`, `int3` and `syscall` enter a handler or the kernel, and
    `vmcall`, `vmmcall`, `vmlaunch` and the rest of the VM group enter a
    hypervisor. Most of them fall through to their successor and clobber
    no register capstone reports, so nothing but
    `DecodedInsn.leaves_analysis_context` says that other code ran at
    all.

    Only then, and only for the forms :func:`_carrying_destination`
    models, does one destination take the value on. Reading a carrying
    register is not enough by itself: `and rax, 0` reads `rax` and leaves
    a constant, and `xchg rbx, rax` reads one carrying register and
    writes two destinations that are not interchangeable.

    Everything this cannot model under-reports, which is the direction to
    err in: a flow it cannot follow yields no claim that the flow
    exists."""
    carrying, _paths = _carrying_with_paths(
        instructions, seed=seed, architecture=architecture,
        from_va=from_va, to_va=to_va)
    return carrying


# ── proofs ─────────────────────────────────────────────────────────────

#: A transform whose input and output are one explicit memory operand of
#: one arithmetic or logic instruction.
DIRECT_WRITE_BACK = "direct_write_back"

#: A transform mediated by a register: a load, a non-identity transform
#: of the loaded value, and a store of the surviving result back to the
#: same effective address.
LOAD_TRANSFORM_STORE = "load_transform_store"


@dataclass(frozen=True)
class GetPcPair:
    """A direct `call` whose target is a `pop`, and whose popped value
    reaches the address register of a proven access.

    The `call` records its own return address; the `pop` reads it. That
    is the position-independent way code learns where it is, and it is
    evidence about a particular loop only because ``register`` was
    followed from the `pop` to that loop's address register.

    ``path`` is the addresses of the instructions that carried the value
    along that way -- the `mov`, `lea` and `add` that moved it between
    register families. Without them the claim rests on two instructions
    that name different registers, so they are part of the proof and not
    background."""
    call:     DecodedInsn
    pop:      DecodedInsn
    register: str
    path:     tuple = ()


@dataclass(frozen=True)
class ExitTransfer:
    """A register-indirect `call`/`jmp` reachable from an edge that
    leaves a loop.

    ``exit_branch`` is the instruction whose edge leaves the loop body --
    the closing branch when it is conditional and falls through, or a
    conditional branch before it. It is always one or the other: see
    :func:`_find_exit_transfer` for why no other edge can leave a proven
    loop, which is the rule that keeps an unconditional backward `jmp`
    from being read as reaching whatever follows it.

    ``path`` names every instruction that BRANCHES along the walked route
    from the exit edge's destination to ``transfer``, ``transfer``
    included and ``exit_branch`` -- which has a field of its own -- not.
    A fall-through run between two of them is the instruction rows read
    downwards and is not named; a branch is, because which instruction
    left the run and where it went is the part of the route the rows do
    not show.

    The destination of ``transfer`` is run-time state and is not reported
    anywhere. That a path exists is a property of the decoded graph, not
    a statement that the path was taken."""
    exit_branch: DecodedInsn
    transfer:    DecodedInsn
    path:        tuple = ()


@dataclass(frozen=True)
class TransformLoop:
    """One bounded proof that a loop in this window transforms memory in
    place.

    ``form`` is :data:`DIRECT_WRITE_BACK` or
    :data:`LOAD_TRANSFORM_STORE`; ``load`` and ``transform`` are set only
    for the second, where they are the instruction that read the value
    and the first instruction that changed it.

    ``address`` is the proven effective address, ``entry_va`` the loop
    entry ``branch`` closes back to, and ``access_va`` the address of the
    first instruction that touches ``address`` -- which is where an
    address register has to still carry what a `call`/`pop` left in it
    for ``get_pc`` to be set.

    ``value_path`` is the addresses of the instructions that carried the
    transformed value from ``transform`` to the register ``store``
    reads -- empty when the store reads the transform's own destination.

    Nothing here says the loop ran. It says these instructions are
    connected to each other in the decoded graph in the stated way."""
    form:       str
    branch:     DecodedInsn
    entry_va:   int
    store:      DecodedInsn
    address:    MemoryOperand
    access_va:  int
    load:       "DecodedInsn | None" = None
    transform:  "DecodedInsn | None" = None
    get_pc:     "GetPcPair | None" = None
    exit:       "ExitTransfer | None" = None
    value_path: tuple = ()

    @property
    def instruction_addresses(self) -> tuple:
        """Every instruction this proof rests on, ascending and without
        repeats -- what a reader re-checks the claim against.

        It is the whole of the proof and not its endpoints: the copies
        that carried the transformed value to the register the store
        reads, the `mov`/`lea`/`add` chain that carried a get-PC value to
        the address register, and the control-flow path from the exit
        branch to the transfer are each a step the claim depends on, and
        each is here. A consumer that shows fewer of them is showing a
        cut of this list and says so for itself."""
        addresses = {self.branch.address, self.store.address}
        addresses.update(self.value_path)
        for insn in (self.load, self.transform):
            if insn is not None:
                addresses.add(insn.address)
        if self.get_pc is not None:
            addresses.update((self.get_pc.call.address, self.get_pc.pop.address))
            addresses.update(self.get_pc.path)
        if self.exit is not None:
            addresses.update((self.exit.exit_branch.address,
                              self.exit.transfer.address))
            addresses.update(self.exit.path)
        return tuple(sorted(addresses))


def _loop_body_holds(instructions, by_address, insn, branch) -> bool:
    """Whether the loop ``branch`` closes actually runs ``insn``.

    An address between the branch's target and the branch itself is not
    enough: a `ret` or an unconditional branch inside that span ends the
    run before ``insn`` is reached, or before the closing branch is, and
    ``insn`` is then simply bytes that happen to lie in the interval.
    Three things are required, and each is an endpoint the range
    arithmetic has to include on purpose:

    * the branch target is an instruction boundary THIS decode produced,
      so the loop entry is a real instruction and not the middle of one;
    * nothing from the loop entry up to ``insn`` ends the run -- the
      instruction AT the target is part of that check, and a `ret`
      sitting exactly there is the case this exists to reject;
    * nothing after ``insn`` ends the run before the closing branch.

    It says the loop can run ``insn``, never that it did."""
    target = branch.direct_target_va
    if target not in by_address:
        return False
    if not target <= insn.address <= branch.address:
        return False
    return (linear_run_is_uninterrupted(instructions, target, insn.address)
            and linear_run_is_uninterrupted(
                instructions, insn.address + insn.size, branch.address))


def _direct_write_back_operand(insn: DecodedInsn) -> "MemoryOperand | None":
    """The memory operand ``insn`` transforms in place, or None.

    One explicit memory operand that the instruction both READS and
    writes, under a mnemonic in :data:`TRANSFORM_MNEMONICS`, whose result
    still derives from what that memory held. The read is what makes the
    operand the instruction's own input as well as its output: a store
    that only writes is not a transform of anything.

    The non-identity rule is the same one the register-mediated form
    applies, at the memory operand's width rather than a register's.
    `add dword ptr [rax], 0` and `and dword ptr [rax], -1` leave the
    bytes exactly as they were, and `and dword ptr [rax], 0` replaces
    them with a constant -- a scrub, which is a different thing from a
    transform and must not be named as one."""
    if insn.mnemonic not in TRANSFORM_MNEMONICS or not insn.writes_memory:
        return None
    if len(insn.memory_operands) != 1:
        return None
    operand = insn.memory_operands[0]
    if not (operand.reads and operand.writes):
        return None
    if _immediate_verdict(insn, operand.width) != _VALUE_TRANSFORMED:
        return None
    # The value written must not be the address it is written to. Zero
    # bytes decode to `add byte ptr [rax], al` -- a read-modify-write
    # under a transform mnemonic, whose source is the low byte of its own
    # address register -- and a stray branch byte above it closes a
    # "loop" around padding. Folding an address into the value at it is
    # not a shape any transform loop has.
    address_families = {register_family(name)
                        for name in operand.address_registers}
    if any(register_family(name) in address_families
           for name in insn.data_register_reads):
        return None
    return operand


def _is_pure_load(insn: DecodedInsn) -> bool:
    """Whether ``insn`` reads memory into a register and writes none.

    Strict about the shape as well as the mnemonic: exactly one memory
    operand, which is read and not written, at least one register
    destination, and nothing about the instruction that the decoder could
    not account for. A `mov` that stores, or one whose effects are
    unknown, is not this."""
    if insn.mnemonic not in _PURE_LOAD_MNEMONICS:
        return False
    if len(insn.memory_operands) != 1 or insn.writes_memory:
        return False
    operand = insn.memory_operands[0]
    if operand.writes or not operand.reads:
        return False
    if not insn.register_writes:
        return False
    return not (insn.leaves_analysis_context or insn.effects_unknown)


def _load_operand(insn: DecodedInsn) -> "MemoryOperand | None":
    """The effective address ``insn`` loads from into one register, or
    None.

    The instruction has to be a `mov` with exactly one memory operand it
    only reads, exactly one register destination, and no register whose
    CONTENTS it consumes -- so a read-modify-write, a store, and a
    two-source form are all rejected. The destination's width has to
    equal the access width, because a value that arrives narrower or
    wider than the slot is not the slot's contents.

    The destination must also lie outside the address expression itself.
    `mov eax, dword ptr [rax]` computes its address from the `rax` it
    then overwrites -- in 64-bit mode a 32-bit write clears the upper
    half outright -- so a later `[rax]` is a second address that merely
    spells the same. An index register is the same case
    (`mov ecx, dword ptr [rax + rcx*4]`), and a load that consumes the
    register version it destroys is not an anchor any same-address proof
    can be built on."""
    if insn.mnemonic != _COPY_MNEMONIC or len(insn.memory_operands) != 1:
        return None
    operand = insn.memory_operands[0]
    if not operand.reads or operand.writes:
        return None
    if len(insn.register_writes) != 1 or insn.data_register_reads:
        return None
    destination = insn.register_writes[0]
    if not operand.width or register_width(destination) != operand.width:
        return None
    if register_family(destination) in {register_family(name)
                                        for name in operand.address_registers}:
        return None
    return operand


def _store_operand(insn: DecodedInsn) -> "tuple | None":
    """``(MemoryOperand, source_register)`` for a `mov` that stores one
    register into one memory operand, or None. A read-modify-write and an
    immediate store are both rejected: neither states that a value
    carried in a register is what reached memory."""
    if insn.mnemonic != _COPY_MNEMONIC or len(insn.memory_operands) != 1:
        return None
    operand = insn.memory_operands[0]
    if not operand.writes or operand.reads:
        return None
    if len(insn.data_register_reads) != 1 or insn.register_writes:
        return None
    return operand, insn.data_register_reads[0]


def _no_inbound_join(instructions, *, start: int, end: int) -> bool:
    """Whether the span ``(start, end]`` is entered only through
    ``start``.

    A direct branch from outside into the middle of the span reaches the
    store along a path on which the tracked register holds something this
    walk never saw. The span is half-open at ``start`` on purpose: the
    loop's own back edge targets the load, which is the entry, and that
    is the one inbound edge the proof is built on."""
    for insn in instructions:
        if insn.branch_kind is not BranchKind.DIRECT:
            continue
        target = insn.direct_target_va
        if target is None or not start < target <= end:
            continue
        if not start <= insn.address <= end:
            return False
    return True


def _prove_load_transform_store(instructions, *, load: DecodedInsn,
                                address: MemoryOperand, branch: DecodedInsn,
                                architecture: "str | None") -> "tuple | None":
    """``(store, transform, carriers)`` proving the value ``load`` read
    is transformed and stored back to the same effective address before
    ``branch``, or None. ``carriers`` are the instructions that moved the
    transformed value between the transform and the store, so the proof
    can name every instruction it rests on and not only its endpoints.

    The walk is linear and forward from the instruction after the load,
    and every one of these ends it without a proof:

    * a `call`, whose callee clobbers registers this window does not
      show;
    * any instruction that leaves for code this window does not contain
      -- a `call`, an interrupt, a system call, a VM entry -- after which
      neither the tracked value nor the memory it came from is something
      these bytes still account for. `DecodedInsn.may_write_memory`
      covers this case as well as the next one;
    * any instruction `DecodedInsn.may_write_memory` cannot rule out,
      unless :func:`_is_pure_load` shows it to be a plain register load
      from memory --
      one memory-safety question asked once, rather than a list of write
      forms this walk would have to keep complete on its own. It may
      alias the address under analysis: `[rdi]` and `[rbp]` are different
      expressions and nothing here says the registers differ at run time,
      and an access that cannot be shown to be a read is not an access
      known to be elsewhere;
    * a write to the base or index register of the address, which makes
      the store's address expression a different address however
      identical its text;
    * losing the loaded value to a clobber, an unmodelled form, or a
      redefinition;
    * an instruction that does not fall through, which ends the path
      before the store is reached;
    * a conditional branch, whose taken edge reaches the store along a
      path this walk did not follow. The value the store reads there is
      whatever the skipped instructions left, and an untransformed value
      arriving at the store is exactly the case the proof exists to rule
      out. The store must have ONE reaching definition and this walk is
      how it is established, so a fork inside the span ends the
      candidate;
    * a store whose address differs, or whose source register does not
      hold the surviving transformed value at the access width;
    * a branch from outside the span into the middle of it, which joins a
      path on which the tracked register holds something else.

    The transform itself has to be non-identity: the first instruction
    that turns the tracked value into something that still derives from
    it is recorded, and a store reached with no such instruction is an
    ordinary memory copy and proves nothing."""
    tracked = {load.register_writes[0]: _TrackedValue(origin=0,
                                                      transformed=False)}
    origins = 0
    # The segment the address resolves through is part of the address.
    # Writing its selector moves every operand that names it, so it is
    # tracked exactly as a base or index register is -- named or implied.
    address_registers = _address_registers_of(address, architecture)
    address_segment = effective_segment(address, architecture)
    transform = None
    for insn in instructions:
        if not load.address < insn.address <= branch.address:
            continue
        store = _store_operand(insn)
        if store is not None:
            operand, source = store
            carried = tracked.get(source)
            if (transform is not None
                    and same_effective_address(address, operand)
                    and carried is not None and carried.transformed
                    and register_width(source) == operand.width
                    and _no_inbound_join(instructions, start=load.address,
                                         end=insn.address)):
                return insn, transform, carried.path
            return None
        if insn.may_write_memory and not _is_pure_load(insn):
            return None
        if insn.is_jump and insn.falls_through:
            # A conditional branch: both of its edges are real, and the
            # one this walk does not take rejoins below. Nothing here
            # establishes what the tracked register holds on that path.
            return None
        if not _address_version_survives(insn, address_registers,
                                         address_segment):
            return None
        clobbered = {register_family(name) for name in insn.clobbered_registers}
        origins += 1
        destination = _transformed_destination(insn, tracked, new_origin=origins)
        for name in [name for name in tracked
                     if register_family(name) in clobbered]:
            del tracked[name]
        if destination is not None:
            name, carried, transforms_here = destination
            if transforms_here:
                # Exactly one transform is allowed. Two of them compose,
                # and composition is where a non-identity claim stops
                # being checkable without symbolic evaluation --
                # `xor edx, eax` twice, `not` twice, and `add 1` then
                # `sub 1` all write back precisely what was read. Proving
                # which compositions cancel is out of scope, so a second
                # transform ends the candidate and a composite transform
                # under-reports. A copy and an identity operation are
                # neither, and pass through without spending it.
                if transform is not None:
                    return None
                transform = insn
            tracked[name] = carried
        if not tracked or len(tracked) > MAX_TRACKED_VALUES:
            return None
        if not insn.falls_through:
            return None
    return None


#: How many bytes of address each architecture pushes and pops.
_ADDRESS_WIDTH = {"x64": 8, "x86": 4}


def _get_pc_pairs(instructions, by_address, base_va: int, window_end: int,
                  reachable, architecture: "str | None") -> list:
    """``[(call, pop)]`` for each direct `call` in this window whose
    target is a `pop` that recovers the whole of what it pushed -- the
    position-independent way code leaves its own address in a register.

    The widths have to agree, all three of them, because a partial
    recovery is not the address. `call` pushes at its own operand size:
    a `callw` in 32-bit code pushes two bytes where a plain `call`
    pushes four, and in 64-bit code a call pushes eight. A `pop` takes
    at ITS operand size: `pop bp` recovers sixteen bits of a
    sixty-four-bit return address and leaves the rest of `rbp` holding
    whatever it held before, so `[rbp]` is not an address this code
    computed. Requiring the push width, the pop width and the
    architecture's own address width to be one number rejects every
    mismatch without enumerating them.

    The `call` itself has to be reachable. A `call` that nothing arrives
    at did not put anything on the stack, so the `pop` below it read a
    value that came from somewhere this window does not show, and
    attributing the code's own address to it would be attributing a
    write to an instruction that no path executes. A `jmp` over a
    `call`, straight to the `pop` it targets, is exactly that shape.
    ``reachable`` None skips the check, which only the
    withheld-shape query does."""
    width = _ADDRESS_WIDTH.get(architecture)
    if width is None:
        return []
    pairs = []
    for insn in instructions:
        if not (insn.is_call and insn.branch_kind is BranchKind.DIRECT):
            continue
        if reachable is not None and insn.address not in reachable:
            continue
        if insn.return_address_width != width:
            continue
        target = insn.direct_target_va
        if target is None or not base_va <= target < window_end:
            continue
        popped = by_address.get(target)
        if popped is None or popped.mnemonic != "pop" or not popped.register_writes:
            continue
        destination = popped.register_writes[0]
        if not is_full_width_register(destination, architecture):
            continue
        if register_width(destination) != width:
            continue
        pairs.append((insn, popped))
    return pairs


def _get_pc_reaching(instructions, pairs, *, address: MemoryOperand,
                     access_va: int, entry_va: int,
                     architecture: "str | None") -> "GetPcPair | None":
    """The `call`/`pop` pair whose popped value is what ``address``
    resolves through at ``access_va``, on a linear run that also reaches
    the loop entry, or None.

    Either register the effective address reads is a candidate, base or
    index alike: which of the two the compiler chose says nothing about
    the relationship. What the address has to be is this code's own
    address plus a constant -- one whole copy of the popped value, at
    the architecture's address width -- which is
    :func:`_address_carries_once`. An address built from four times it,
    or from the low half of it, is a place this code computed rather than
    a place inside this code, and a loop transforming what is there is
    not a loop transforming itself.

    The `pop` has to end before the loop entry and before the access: a
    pair inside or after the loop says nothing about the address the
    loop's first access uses, and a pair elsewhere in the same 512-byte
    window is not evidence about this loop at all. The value is followed
    per register family, so a write at any width to any name of that
    register ends the carry, and the instructions that carried it are
    kept on the pair: a `pop` and an access naming different registers
    state nothing to each other without them."""
    for call, popped in pairs:
        pop_end = popped.address + popped.size
        if pop_end > entry_va or popped.address >= access_va:
            continue
        # The walk starts AFTER the pop: the pop is what seeded the
        # register, and a walk that included it would read its own write
        # as a kill.
        carrying, paths = _carrying_with_paths(
            instructions, seed=popped.register_writes[0],
            architecture=architecture, from_va=pop_end, to_va=access_va)
        if not linear_run_is_uninterrupted(instructions, pop_end, entry_va):
            continue
        carried = _address_carries_once(address, carrying, architecture)
        if carried is None:
            continue
        register, family = carried
        return GetPcPair(call=call, pop=popped, register=register,
                         path=paths.get(family, ()))
    return None


def _reachable_without_re_entering(cfg: LocalCfg, start: int, body: set) -> dict:
    """``{address: (predecessor, edge_kind)}`` for every instruction
    reachable from ``start`` along paths that never enter ``body``,
    ``start`` itself included and mapped to ``(None, None)``.

    A path that returns to the loop body is a path back INTO the loop,
    and everything it reaches from there is loop body rather than
    anything after the loop. Cutting the walk at the body is what makes
    "after the loop" a statement about control flow instead of about
    which addresses happen to be numerically outside the span.

    The predecessor each address was first reached from, and the edge it
    was reached over, are kept so the caller can name the branches its
    claim rests on rather than only its two endpoints. The walk is
    breadth-first over edges in the order :class:`LocalCfg` states them,
    so one window answers the same way every run; it is bounded by the
    node count and expands each node once, so a window that is one cycle
    terminates."""
    if start in body or start not in cfg.by_address:
        return {}
    reached = {start: (None, None)}
    pending = [start]
    at = 0
    while at < len(pending):
        address = pending[at]
        at += 1
        for kind, target in cfg.successors(address):
            if target in body or target in reached:
                continue
            reached[target] = (address, kind)
            pending.append(target)
    return reached


def _branches_along(reached: dict, target: int) -> tuple:
    """The addresses of the instructions that BRANCH along the walked
    route to ``target``, ``target`` itself included, ascending.

    ``reached`` is a :func:`_reachable_without_re_entering` result, so
    following predecessors terminates at the start, whose predecessor is
    None.

    A fall-through run is the instruction rows read downwards and needs
    no address to state it. What a reader cannot recover from the rows is
    which instruction left that run and where it went, so an instruction
    is named here exactly when the route leaves it over an edge that is
    not a fall-through."""
    route = []
    address = target
    while address is not None:
        route.append(address)
        address, _kind = reached[address]
    route.reverse()
    named = [target]
    for position, address in enumerate(route[:-1]):
        _predecessor, kind = reached[route[position + 1]]
        if kind is not EdgeKind.FALL_THROUGH:
            named.append(address)
    return tuple(sorted(named))


def _find_exit_transfer(cfg: LocalCfg, *, entry_va: int,
                        branch: DecodedInsn) -> "ExitTransfer | None":
    """A register-indirect `call`/`jmp` reachable from an edge that
    leaves this loop's body, or None.

    Only a CONDITIONAL branch's edge leaves a loop, and the rule is
    applied here rather than inferred afterwards. Three things can carry
    control out of the body and exactly one of them qualifies:

    * a conditional branch's taken edge, or the closing branch's own
      fall-through -- both belong to a conditional branch, and both are
      exits. This is the whole of the set: an unconditional backward
      `jmp` has no fall-through edge, so nothing is "after" one, and
      when such a loop is left it is left through a conditional branch
      INSIDE the body;
    * a `call` edge, which is not an exit at all. Control comes back
      below the call and carries on round the loop, so reading one as an
      exit would report a transfer on a path that returns;
    * an unconditional branch out of the body, which cannot occur in a
      proven loop -- :func:`_loop_body_holds` requires an uninterrupted
      run from the entry to the access and from the access to the closing
      branch, and an unconditional branch anywhere in the body would have
      ended one of them.

    Because every accepted exit belongs to a conditional branch, the
    record carries no flag saying so; the type of ``exit_branch`` is the
    statement.

    The reachable set is walked over the decoded graph, so bytes below an
    unconditional branch that nothing targets are not reached and cannot
    supply the transfer. It also STOPS at the body: an edge that leaves
    the numeric span and comes straight back round the loop has not left
    the loop, and a transfer the walk finds after re-entering is inside
    the loop rather than after it. Only a transfer the walk reaches
    without touching the body is one this record is about."""
    body = {address for address in cfg.by_address
            if entry_va <= address <= branch.address}
    for address in sorted(body):
        source = cfg.by_address[address]
        for kind, target in cfg.successors(address):
            if target in body:
                continue
            if not (kind is EdgeKind.CONDITIONAL
                    or (kind is EdgeKind.FALL_THROUGH
                        and source.is_jump and not source.is_call)):
                continue
            reachable = _reachable_without_re_entering(cfg, target, body)
            transfer = next(
                (insn for insn in cfg.instructions
                 if insn.address in reachable
                 and insn.branch_kind is BranchKind.INDIRECT_REGISTER
                 and (insn.is_call or insn.is_jump)), None)
            if transfer is None:
                continue
            return ExitTransfer(
                exit_branch=source, transfer=transfer,
                path=_branches_along(reachable, transfer.address))
    return None


def _candidate_loops(instructions, by_address, cfg: LocalCfg, base_va: int, *,
                     architecture: "str | None", require_reachable: bool = True):
    """``(form, branch, access, address, transform, store, value_path)``
    for every transform shape a backward branch in this window closes a
    loop around, in closing-branch order and then in address order.
    ``value_path`` is the instructions that carried the transformed value
    to the store, and is empty for the direct form, which has none.

    A loop whose entry nothing in the decoded graph reaches is not a
    candidate. Zero padding decodes to `add byte ptr [rax], al` and a
    data table decodes to whatever its bytes spell, and either can sit
    inside the span of a backward branch that is itself decoded from
    data. What separates an instruction from a byte that decodes like one
    is that something reaches it: the entry has to be reachable from the
    window's first instruction over :class:`LocalCfg`. Code reached only
    through a branch this module cannot resolve -- an indirect one, or
    one from before the window -- is not reached here either, and
    under-reports.

    Both accepted forms are produced here, so the caller ranks proofs
    rather than repeating the loop-membership rules for each shape. The
    search stops at :data:`MAX_PROOF_ATTEMPTS` evaluated candidates."""
    reachable = (cfg.reachable_from(instructions[0].address)
                 if require_reachable else None)
    # A relative `call` is in capstone's relative-branch group as well as
    # its call group, so `DecodedInsn.is_jump` is True for one -- and a
    # backward direct `call` is recursion, which pushes a return address
    # every time round and is not the loop this analysis is about.
    # `is_call` is what separates them.
    backward = [insn for insn in instructions
                if (insn.is_jump and not insn.is_call
                    and insn.branch_kind is BranchKind.DIRECT
                    and insn.direct_target_va is not None
                    and base_va <= insn.direct_target_va <= insn.address
                    and (reachable is None
                         or insn.direct_target_va in reachable))]
    attempts = 0
    for branch in backward:
        for insn in instructions:
            if attempts >= MAX_PROOF_ATTEMPTS:
                return
            address = _direct_write_back_operand(insn)
            if address is not None:
                if not _loop_body_holds(instructions, by_address, insn, branch):
                    continue
                attempts += 1
                yield DIRECT_WRITE_BACK, branch, insn, address, None, insn, ()
                continue
            address = _load_operand(insn)
            if address is None:
                continue
            if not _loop_body_holds(instructions, by_address, insn, branch):
                continue
            attempts += 1
            proof = _prove_load_transform_store(
                instructions, load=insn, address=address, branch=branch,
                architecture=architecture)
            if proof is None:
                continue
            store, transform, carriers = proof
            yield (LOAD_TRANSFORM_STORE, branch, insn, address, transform,
                   store, tuple(carrier.address for carrier in carriers))


def _strongest_proof(instructions, *, base_va: int, window_len: int,
                     architecture: "str | None",
                     require_reachable: bool) -> "TransformLoop | None":
    """The chosen proof, without an exit transfer attached.

    ``require_reachable`` is the loop-entry reachability gate. It is a
    parameter only so that :func:`transform_loop_withheld_as_unreachable`
    can ask what the same bytes would have proven without it; every
    caller that produces a lead passes True."""
    if not instructions:
        return None
    by_address = {insn.address: insn for insn in instructions}
    cfg = build_local_cfg(instructions)
    reachable = (cfg.reachable_from(instructions[0].address)
                 if require_reachable else None)
    pairs = _get_pc_pairs(instructions, by_address, base_va,
                          base_va + window_len, reachable, architecture)

    chosen = None
    for (form, branch, access, address, transform, store,
         value_path) in _candidate_loops(
            instructions, by_address, cfg, base_va,
            architecture=architecture, require_reachable=require_reachable):
        get_pc = _get_pc_reaching(
            instructions, pairs, address=address,
            access_va=access.address, entry_va=branch.direct_target_va,
            architecture=architecture)
        loop = TransformLoop(
            form=form, branch=branch, entry_va=branch.direct_target_va,
            store=store, address=address, access_va=access.address,
            load=(access if form == LOAD_TRANSFORM_STORE else None),
            transform=transform, get_pc=get_pc, value_path=value_path)
        if chosen is None or get_pc is not None:
            chosen = loop
        if get_pc is not None:
            break
    return chosen


#: The loop entry is reached by no edge in the decoded graph, so a proof
#: that otherwise stands was withheld. The reason is about where the
#: decode began rather than about the instructions.
WITHHELD_UNREACHABLE = "unreachable"

#: A load and a store over one effective address sit inside a reachable
#: loop, and the value between them could not be proven to be the same
#: transformed value. The reason is about what the analysis cannot show,
#: which the instruction rows do not reveal on their own.
WITHHELD_UNPROVEN = "unproven"


def _attempted_transform_reaches_store(instructions, *, load: DecodedInsn,
                                       address: MemoryOperand,
                                       branch: DecodedInsn,
                                       architecture: "str | None") -> bool:
    """Whether a value ``load`` read reaches a store to the SAME address
    having been through at least one non-identity transform.

    This is :func:`_prove_load_transform_store` with the survival half
    removed and nothing else. The value rules are the proof's own, called
    through :func:`_transformed_destination`, so a zeroing idiom, an
    identity or annihilating immediate, and an operation between two
    copies of one value are each no transform here either -- those
    instructions SAY the result stopped deriving from what was read, and
    an analyst reads that off the rows.

    What is dropped is everything about whether a TRANSFORMED value
    survives: once an entry carries one, no clobber of it ends the walk,
    no memory write, no call, no control-flow stop, no join. That is the
    half the proof declined on and the half the rows do not show.

    For an entry that carries no transform yet, nothing is dropped. A
    `mov edx, eax` over the loaded value, a `xor edx, edx` that zeroes
    it, a narrow `mov dl, al` over part of it -- each of those SAYS on
    its own row that what reaches a later transform is not what was
    loaded, so that transform transforms something else and there is no
    declined proof to report.

    The relaxation is decided PER TRACKED VALUE and never for the walk as
    a whole. One loaded value can sit in several registers at once, and
    what happened to one copy says nothing about another: after
    `mov ecx, edx` and `xor ecx, eax`, the copy in `ecx` carries a
    transform and the copy in `edx` does not, so a `mov edx, ebx` below
    them still ends `edx` while `ecx` carries on. A walk-wide flag would
    let the transformed sibling shelter every untransformed one, and a
    store reading a register the rows show being overwritten would
    produce a note about a proof that was never close.

    The address half is not dropped either. A write to the base, the
    index or the effective segment between the two accesses makes them
    two addresses, and that is as readable in the rows as a store to a
    different register -- so it ends the candidate rather than becoming a
    note."""
    tracked = {load.register_writes[0]: _TrackedValue(origin=0,
                                                      transformed=False)}
    address_registers = _address_registers_of(address, architecture)
    address_segment = effective_segment(address, architecture)
    origins = 0
    for insn in instructions:
        if not load.address < insn.address <= branch.address:
            continue
        store = _store_operand(insn)
        if store is not None:
            operand, source = store
            carried = tracked.get(source)
            if (carried is not None and carried.transformed
                    and register_width(source) == operand.width
                    and same_effective_address(address, operand)):
                return True
            continue
        if not _address_version_survives(insn, address_registers,
                                         address_segment):
            return False
        origins += 1
        destination = _transformed_destination(insn, tracked,
                                               new_origin=origins)
        clobbered = {register_family(name)
                     for name in insn.clobbered_registers}
        # The entry's own state at the moment of the write decides it,
        # which is why this is read before the new value is installed: an
        # instruction that transforms the register it clobbers ends the
        # untransformed entry and puts its own result back.
        for name in [name for name, entry in tracked.items()
                     if register_family(name) in clobbered
                     and not entry.transformed]:
            del tracked[name]
        if destination is not None:
            name, carried, _ = destination
            tracked[name] = carried
        if not tracked or len(tracked) > MAX_TRACKED_VALUES:
            return False
    return False


def _same_address_shape_present(instructions, base_va: int,
                                architecture: "str | None") -> bool:
    """Whether a reachable loop in this window holds a load, an attempted
    transform, and a later store over ONE effective address.

    An "attempted transform" is one the proof's own non-identity rules
    accept, applied to the loaded value and carried to the register the
    store reads. A copy loop is not one, and neither is a copy loop with
    an unrelated `xor eax, ecx` beside it, a `xor edx, edx` that zeroes
    what was read, an `add edx, 0` that changes nothing, or a transform
    of one copy when a different copy is what reaches memory. Each of
    those instructions states its own result, so an analyst reading the
    rows sees the negative and needs no note about it.

    What this IS blind to is whether the transformed value survives to
    the store -- that is the half the proof declined on, and the half the
    rows do not reveal.

    This answers "was the shape there", so a caller can say a proof was
    declined rather than leaving the window looking like one that held
    nothing."""
    by_address = {insn.address: insn for insn in instructions}
    cfg = build_local_cfg(instructions)
    reachable = cfg.reachable_from(instructions[0].address)
    attempts = 0
    for branch in instructions:
        if not (branch.is_jump and not branch.is_call
                and branch.branch_kind is BranchKind.DIRECT
                and branch.direct_target_va is not None
                and base_va <= branch.direct_target_va <= branch.address
                and branch.direct_target_va in reachable):
            continue
        for load in instructions:
            address = _load_operand(load)
            if address is None:
                continue
            if not _loop_body_holds(instructions, by_address, load, branch):
                continue
            attempts += 1
            if attempts > MAX_PROOF_ATTEMPTS:
                return False
            if _attempted_transform_reaches_store(
                    instructions, load=load, address=address, branch=branch,
                    architecture=architecture):
                return True
    return False


def transform_loop_withheld(instructions, *, base_va: int, window_len: int,
                            architecture: "str | None") -> "str | None":
    """Why these bytes held a transform-loop shape that no lead was read
    from, or None when they held none or a lead was read.

    Two rejections are worth saying out loud, and both for the same
    reason: an analyst reading the instruction rows cannot see either of
    them. Every other rejection is visible in the rows themselves -- a
    copy loop writes back what it read, a store lands at a different
    address -- and needs no note.

    :data:`WITHHELD_UNREACHABLE` is about where the decode BEGAN. An
    anchor that does not fall through (a thread whose start address is a
    jump thunk, an explicit address landing on a `ret` or
    mid-instruction, a card anchored in data) leaves the window with no
    edges out of its first instruction, and an otherwise whole proof is
    withheld.

    :data:`WITHHELD_UNPROVEN` is about what the analysis cannot show. The
    load and the store are there, over one address held under one
    register version, inside a reachable loop -- and the value between
    them was not provably the same transformed value: a composite
    transform this module will not compose, a clobber OF THAT VALUE it
    cannot rule out, an access it cannot account for.

    Neither is a lead and neither names an address: the proof was not
    established, and pointing at the bytes that nearly carried one would
    assert the thing the gate declined to assert."""
    if not instructions:
        return None
    if _strongest_proof(instructions, base_va=base_va, window_len=window_len,
                        architecture=architecture, require_reachable=True):
        return None
    if _strongest_proof(instructions, base_va=base_va, window_len=window_len,
                        architecture=architecture, require_reachable=False):
        return WITHHELD_UNREACHABLE
    if _same_address_shape_present(instructions, base_va, architecture):
        return WITHHELD_UNPROVEN
    return None


def find_transform_loop(instructions, *, base_va: int, window_len: int,
                        architecture: "str | None") -> "TransformLoop | None":
    """The strongest bounded transform-loop proof this window supports,
    or None.

    Candidates are produced in a fixed order -- by closing branch, then
    by the address of the instruction that first touches the transformed
    memory -- and the first one that additionally correlates a
    `call`/`pop` address acquisition wins. A window with several loops
    therefore yields the same proof every run, and the `call`/`pop`
    correlation decides only between proofs that already stand on their
    own.

    The reachable register-indirect transfer is attached to whichever
    proof is chosen. It is supporting context and never a gate: a loop
    with no transfer after it is still a proven loop, and a transfer with
    no loop is not a lead at all.

    A window that holds a shape this returns nothing for BECAUSE its loop
    entry is unreachable is a coverage gap rather than a clean negative;
    :func:`transform_loop_withheld_as_unreachable` is how a caller asks
    about that and reports it."""
    chosen = _strongest_proof(instructions, base_va=base_va,
                              window_len=window_len, architecture=architecture,
                              require_reachable=True)
    if chosen is None:
        return None
    cfg = build_local_cfg(instructions)
    exit_transfer = _find_exit_transfer(cfg, entry_va=chosen.entry_va,
                                        branch=chosen.branch)
    if exit_transfer is None:
        return chosen
    return TransformLoop(
        form=chosen.form, branch=chosen.branch, entry_va=chosen.entry_va,
        store=chosen.store, address=chosen.address, access_va=chosen.access_va,
        load=chosen.load, transform=chosen.transform, get_pc=chosen.get_pc,
        exit=exit_transfer, value_path=chosen.value_path)
