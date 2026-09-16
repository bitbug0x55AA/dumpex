"""What the bounded local flow analysis proves about one decoded window,
and the far longer list of shapes it refuses to prove anything about.

Every fixture here is a synthetic byte sequence decoded at a fixed base.
They are written to differ from each other in one relationship at a time,
so a result is attributable to that difference and not to the rest of the
window: most negative cases are a positive case with a single
instruction replaced, and the positive control for each is named beside
it.

The two shapes a transform loop can take are the point of the module. A
direct read-modify-write is one instruction. The register-mediated form
is a load, a transform of the loaded value, and a store back to the same
effective address, which is the same operation written across three
instructions -- and the form a compiler and a real sample both emit far
more often than the first.

Nothing asserted here is a claim that any instruction executed. A proof
says these instructions are connected to each other in the decoded graph
in a stated way, and the tests are written in those terms.
"""
import pytest

from dumpex.core.disasm import MemoryOperand, decode_window, disasm_available
from dumpex.core.insn_flow import (
    DIRECT_WRITE_BACK, LOAD_TRANSFORM_STORE, EdgeKind, build_local_cfg,
    find_transform_loop, same_effective_address,
    WITHHELD_UNPROVEN, WITHHELD_UNREACHABLE, transform_loop_withheld,
)

BASE_VA = 0x1000

_needs_capstone = pytest.mark.skipif(not disasm_available(),
                                     reason="capstone not installed")

# ── assembling fixtures ────────────────────────────────────────────────
# A multi-byte NOP, so padding a window out to a chosen offset costs one
# instruction per four bytes rather than one per byte. A window is capped
# at 48 instructions, and a fixture that spends them on padding runs out
# before it reaches the shape under test.
NOP4 = b"\x0f\x1f\x40\x00"
NOP1 = b"\x90"
RET = b"\xc3"

DEC_RCX = b"\x48\x83\xe9\x01"        # sub rcx, 1
LOAD_EDX_RBP = b"\x8b\x55\x00"       # mov edx, dword ptr [rbp]
STORE_RBP_EDX = b"\x89\x55\x00"      # mov dword ptr [rbp], edx
XOR_EDX_EAX = b"\x31\xc2"            # xor edx, eax


def _pad(length: int) -> bytes:
    """``length`` bytes of NOP, as few instructions as it takes."""
    return NOP4 * (length // 4) + NOP1 * (length % 4)


def _conditional_loop(body: bytes, *, tail: bytes = RET) -> bytes:
    """``body``, a counter decrement, and a `jne` back to the first byte
    of ``body`` -- a loop whose closing branch is conditional, so it also
    falls through to ``tail``."""
    span = len(body) + len(DEC_RCX) + 2
    return body + DEC_RCX + b"\x75" + bytes([-span & 0xFF]) + tail


def _decode(code: bytes, *, architecture: str = "x64"):
    result = decode_window(code=code, base_va=BASE_VA, architecture=architecture)
    return result.instructions, result


def _proof(code: bytes, *, architecture: str = "x64"):
    instructions, result = _decode(code, architecture=architecture)
    return find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture=architecture)


def _offsets(loop) -> tuple:
    """A proof's evidence as offsets from the window base, which is how
    the fixtures above are written."""
    return tuple(address - BASE_VA for address in loop.instruction_addresses)


def _get_pc_then_loop(insn: bytes) -> bytes:
    """`call`/`pop rbp`, then ``insn`` at offset 0x06, then a loop that
    transforms memory at `[rbp]`. The one instruction under test sits
    between the get-PC sequence and the loop's first access."""
    tail = b"\x31\x45\x00" + DEC_RCX
    return (b"\xe8\x00\x00\x00\x00" + b"\x5d" + insn + tail
            + b"\x75" + bytes([-(len(tail) + 2) & 0xFF]) + RET)


# ── the shape the requirement was written from ─────────────────────────
# A direct call/pop leaves this code's own address in rbp; a loop loads
# from that address, transforms the loaded value in a register, and
# stores it back to the same address; an unconditional backward jmp
# closes the loop and a conditional branch before it provides the exit;
# the exit path reaches a call through a register.
#
#   0x05  jmp  0x3a
#   0x07  pop  rbp
#   0x18  push rbp
#   0x19  mov  edx, dword ptr [rbp]
#   0x1c  xor  edx, eax
#   0x1e  mov  dword ptr [rbp], edx
#   0x2e  je   0x32
#   0x30  jmp  0x19
#   0x32  pop  rax
#   0x38  call rax
#   0x3a  call 0x07
REGISTER_MEDIATED_STUB = bytes.fromhex(
    "0f1f400090" "eb33" "5d" "0f1f40000f1f40000f1f40000f1f4000"
    "55" "8b5500" "31c2" "895500" "90" "0f1f40000f1f40000f1f4000"
    "7402" "ebe7" "58" "90" "0f1f4000" "ffd0" "e8c8ffffff" "c3")
_STUB_POP_PC = 0x07
_STUB_LOAD = 0x19
_STUB_TRANSFORM = 0x1c
_STUB_STORE = 0x1e
_STUB_CONDITIONAL_EXIT = 0x2e
_STUB_BACK_JUMP = 0x30
_STUB_INDIRECT_CALL = 0x38
_STUB_CALL_PC = 0x3a


@_needs_capstone
def test_the_register_mediated_sample_proves_a_load_transform_store_loop():
    """The store is a `mov` and the transform happens in a register, so
    no single instruction both reads and writes the memory. The proof is
    the three of them together over one effective address."""
    loop = _proof(REGISTER_MEDIATED_STUB)
    assert loop is not None
    assert loop.form == LOAD_TRANSFORM_STORE
    assert loop.load.address - BASE_VA == _STUB_LOAD
    assert loop.transform.mnemonic == "xor"
    assert loop.transform.address - BASE_VA == _STUB_TRANSFORM
    assert loop.store.address - BASE_VA == _STUB_STORE
    assert loop.entry_va - BASE_VA == _STUB_LOAD
    assert loop.address.base == "rbp"
    assert loop.address.width == 4


@_needs_capstone
def test_the_get_pc_pair_is_correlated_through_the_address_register():
    """The `call` sits after the `pop` it targets, which is the whole
    point of the sequence: the call's own return address is what the pop
    reads. It is evidence about this loop because `rbp` still carries it
    where the loop first touches the address."""
    loop = _proof(REGISTER_MEDIATED_STUB)
    assert loop.get_pc is not None
    assert loop.get_pc.call.address - BASE_VA == _STUB_CALL_PC
    assert loop.get_pc.pop.address - BASE_VA == _STUB_POP_PC
    assert loop.get_pc.register == "rbp"


@_needs_capstone
def test_the_exit_is_the_conditional_branch_and_not_the_backward_jump():
    """The loop closes with an unconditional `jmp`, which reaches its
    successor on no run at all. The edge that leaves is the `je` before
    it, and the register-indirect `call` is reachable from there."""
    loop = _proof(REGISTER_MEDIATED_STUB)
    assert loop.branch.mnemonic == "jmp"
    assert loop.branch.address - BASE_VA == _STUB_BACK_JUMP
    assert loop.branch.falls_through is False
    assert loop.exit is not None
    assert loop.exit.exit_branch.address - BASE_VA == _STUB_CONDITIONAL_EXIT
    assert loop.exit.exit_branch.mnemonic == "je"
    assert loop.exit.transfer.address - BASE_VA == _STUB_INDIRECT_CALL
    assert loop.exit.transfer.is_call


@_needs_capstone
def test_the_whole_proof_is_the_evidence_and_nothing_else_is():
    """Every instruction the proof rests on, and no instruction it does
    not. The padding between them is in the window and in none of this."""
    loop = _proof(REGISTER_MEDIATED_STUB)
    assert _offsets(loop) == (
        _STUB_POP_PC, _STUB_LOAD, _STUB_TRANSFORM, _STUB_STORE,
        _STUB_CONDITIONAL_EXIT, _STUB_BACK_JUMP, _STUB_INDIRECT_CALL, _STUB_CALL_PC)


@_needs_capstone
def test_the_instructions_that_carried_a_value_are_part_of_the_evidence():
    """A proof rests on the instructions that established its
    relationships, not only on the ones it is named for. The `mov` that
    carried the popped address to the loop's address register and the
    `mov` that carried the transformed value to the store's source
    register are each a step the claim depends on, so each is named.

        0x00  call 0x05
        0x05  pop rbp
        0x06  mov rcx, rbp      -- carries the code's own address
        0x09  mov edx, [rcx]
        0x0b  xor edx, eax
        0x0d  mov esi, edx      -- carries the transformed value
        0x0f  mov [rcx], esi
        0x11  sub rbx, 1
        0x15  jne 0x09
    """
    code = (bytes.fromhex("e800000000") + bytes.fromhex("5d")
            + bytes.fromhex("4889e9")
            + bytes.fromhex("8b11" "31c2" "89d6" "8931" "4883eb01" "75f2")
            + RET)
    loop = _proof(code)
    assert loop is not None
    assert loop.get_pc is not None
    assert loop.get_pc.path == (BASE_VA + 0x06,)
    assert loop.value_path == (BASE_VA + 0x0b, BASE_VA + 0x0d)
    assert _offsets(loop) == (0x00, 0x05, 0x06, 0x09, 0x0b, 0x0d, 0x0f, 0x15)


# ── the direct form still proves itself ────────────────────────────────

@_needs_capstone
def test_an_address_folded_into_its_own_value_is_not_a_transform():
    """A run of zero bytes decodes to `add byte ptr [rax], al` -- a
    read-modify-write under a transform mnemonic, whose source is the low
    byte of its own address register -- and a stray branch byte above it
    closes a "loop" around the padding. Writing an address into the bytes
    at that address is not a shape any transform loop has.

        0x00  add byte ptr [rax], al   (x3, from six zero bytes)
        0x06  jne 0x00
    """
    code = b"\x00\x00" * 3 + b"\x75\xf8" + RET
    instructions, _result = _decode(code)
    assert any(insn.mnemonic == "add" and insn.writes_memory
               for insn in instructions)
    assert _proof(code) is None


@_needs_capstone
def test_a_write_back_of_an_unrelated_register_is_still_a_transform():
    """The control, and the reason the rule is about the VALUE rather
    than about the mnemonic: `xor dword ptr [rbp], eax` has the same
    shape and writes something that is not its own address."""
    loop = _proof(b"\x31\x45\x00" + DEC_RCX + b"\x75\xf7" + RET)
    assert loop is not None
    assert loop.form == DIRECT_WRITE_BACK
    assert loop.store.mnemonic == "xor"


@_needs_capstone
def test_a_direct_read_modify_write_is_still_one_instruction():
    """`xor byte ptr [rax], 0x41` is its own load, transform and store.
    Recognising the three-instruction form does not cost the one-
    instruction form its proof."""
    #   xor byte ptr [rax], 0x41 / inc rax / sub rcx, 1 / jne back / ret
    loop = _proof(_conditional_loop(b"\x80\x30\x41" + b"\x48\xff\xc0"))
    assert loop is not None
    assert loop.form == DIRECT_WRITE_BACK
    assert loop.load is None and loop.transform is None
    assert loop.store.mnemonic == "xor"
    assert loop.address.base == "rax"


# ── address components and register families ───────────────────────────

@_needs_capstone
@pytest.mark.parametrize("code, description", [
    # mov r8d, [rbx + rcx*4 + 0x10] / xor r8d, eax / mov [rbx+rcx*4+0x10], r8d
    (b"\x44\x8b\x44\x8b\x10" + b"\x41\x31\xc0" + b"\x44\x89\x44\x8b\x10",
     "base + index*scale + displacement, extended register family"),
    # mov dl, byte ptr [rsi] / xor dl, cl / mov byte ptr [rsi], dl
    (b"\x8a\x16" + b"\x30\xca" + b"\x88\x16",
     "an 8-bit value, where the register name is the low half of a family"),
    # mov edx, [rbp] / xor edx, eax / mov ecx, edx / mov [rbp], ecx
    (LOAD_EDX_RBP + XOR_EDX_EAX + b"\x89\xd1" + b"\x89\x4d\x00",
     "the transformed value copied to another register before the store"),
    # mov edx, [rbp] / not edx / mov [rbp], edx
    (LOAD_EDX_RBP + b"\xf7\xd2" + STORE_RBP_EDX,
     "a single-operand transform"),
])
def test_supported_address_and_register_forms_still_prove_the_loop(code, description):
    loop = _proof(_conditional_loop(code))
    assert loop is not None, description
    assert loop.form == LOAD_TRANSFORM_STORE, description


@_needs_capstone
def test_the_register_mediated_form_proves_itself_in_32_bit_code_too():
    """The same three instructions decoded 32-bit. `eax` is the full
    width there rather than a narrowing write, and the address register
    is `ebp` rather than `rbp`."""
    #   mov edx, [ebp] / xor edx, eax / mov [ebp], edx / dec ecx / jne back
    code = LOAD_EDX_RBP + XOR_EDX_EAX + STORE_RBP_EDX + b"\x49" + b"\x75\xf5" + RET
    loop = _proof(code, architecture="x86")
    assert loop is not None
    assert loop.form == LOAD_TRANSFORM_STORE
    assert loop.address.base == "ebp"


@_needs_capstone
def test_a_32_bit_get_pc_pair_correlates_through_the_full_width_register():
    """`eax` IS the whole register on x86, so a call/pop value survives a
    32-bit write to it -- the same shape that would be a narrowing write
    on x64.

        0x00  call 0x05
        0x05  pop ebp
        0x06  mov edx, [ebp]
        0x09  xor edx, eax
        0x0b  mov [ebp], edx
        0x0e  dec ecx
        0x0f  jne 0x06
    """
    code = (b"\xe8\x00\x00\x00\x00" + b"\x5d"
            + LOAD_EDX_RBP + XOR_EDX_EAX + STORE_RBP_EDX + b"\x49"
            + b"\x75\xf5" + RET)
    loop = _proof(code, architecture="x86")
    assert loop is not None
    assert loop.get_pc is not None
    assert loop.get_pc.register == "ebp"


@_needs_capstone
@pytest.mark.parametrize("pair, description", [
    (XOR_EDX_EAX + XOR_EDX_EAX, "xor against the same register twice"),
    (b"\xf7\xd2" + b"\xf7\xd2", "not twice"),
    (b"\x83\xc2\x01" + b"\x83\xea\x01", "add 1 then sub 1"),
    (XOR_EDX_EAX + b"\x83\xc2\x07", "xor then add 7, which does NOT cancel"),
])
def test_two_transforms_compose_and_end_the_candidate(pair, description):
    """Exactly one transform is allowed. Two of them compose, and the
    first three of these write back precisely what was read -- a copy
    loop wearing a transform's shape, which the tracker's own
    "transformed" flag cannot see because it never goes back to False.
    Deciding which compositions cancel needs symbolic evaluation this
    module does not do, so every composition ends the candidate. The
    fourth case is the cost of that: a real composite transform
    under-reports, which is the direction to err in."""
    assert _proof(_conditional_loop(
        LOAD_EDX_RBP + pair + STORE_RBP_EDX)) is None, description


@_needs_capstone
def test_the_single_transform_is_the_one_the_proof_names():
    """With one transform and a copy after it, the transform recorded is
    the instruction that made the value stop being what memory held."""
    loop = _proof(_conditional_loop(
        LOAD_EDX_RBP + XOR_EDX_EAX + b"\x89\xd1" + b"\x89\x4d\x00"))
    assert loop is not None
    assert loop.transform.mnemonic == "xor"


@_needs_capstone
def test_a_transfer_through_a_register_jump_counts_as_much_as_a_call():
    """`jmp rax` leaves through a register exactly as `call rax` does.
    Neither destination is reported, and neither is a gate."""
    #   xor byte ptr [rax], 0x41 / sub rcx, 1 / jne back / jmp rax
    loop = _proof(_conditional_loop(b"\x80\x30\x41", tail=b"\xff\xe0"))
    assert loop.exit is not None
    assert loop.exit.transfer.is_jump
    assert loop.exit.exit_branch is loop.branch


# ── an ordinary copy is not a transform ────────────────────────────────

@_needs_capstone
def test_a_copy_loop_over_one_address_proves_nothing():
    """A load and a store to the same address with nothing between them
    is a read followed by a write of what was read. It changes no byte,
    and the difference from the positive case is the one missing
    transform."""
    assert _proof(_conditional_loop(LOAD_EDX_RBP + STORE_RBP_EDX)) is None


@_needs_capstone
def test_an_ordinary_buffer_copy_loop_proves_nothing():
    """The shape most loops in most programs are: read here, write
    there, advance, repeat."""
    #   mov edx, [rsi] / mov [rdi], edx / add rsi, 4 / add rdi, 4
    code = (b"\x8b\x16" + b"\x89\x17"
            + b"\x48\x83\xc6\x04" + b"\x48\x83\xc7\x04")
    assert _proof(_conditional_loop(code)) is None


@_needs_capstone
@pytest.mark.parametrize("code, description", [
    # mov edx, [rbp] / xor edx, eax / mov [rbx], edx
    (LOAD_EDX_RBP + XOR_EDX_EAX + b"\x89\x13",
     "a store through a different base register"),
    # mov edx, [rbp] / xor edx, eax / mov [rbp+4], edx
    (LOAD_EDX_RBP + XOR_EDX_EAX + b"\x89\x55\x04",
     "a store at a different displacement"),
    # mov edx, [rbp] / xor edx, eax / mov byte ptr [rbp], dl
    (LOAD_EDX_RBP + XOR_EDX_EAX + b"\x88\x55\x00",
     "a store of a different width at the same start"),
    # mov edx, fs:[rbp] / xor edx, eax / mov [rbp], edx
    (b"\x64" + LOAD_EDX_RBP + XOR_EDX_EAX + STORE_RBP_EDX,
     "a load under a segment override the store does not carry"),
    # mov edx, [rip+0] / xor edx, eax / mov [rip-9], edx
    (b"\x8b\x15\x00\x00\x00\x00" + XOR_EDX_EAX + b"\x89\x15\xf7\xff\xff\xff",
     "two RIP-relative operands, which resolve against different addresses"),
])
def test_a_store_to_a_different_effective_address_proves_nothing(code, description):
    assert _proof(_conditional_loop(code)) is None, description


@_needs_capstone
def test_a_write_to_the_base_register_makes_the_store_a_different_address():
    """The two operands read identically and are not the same address: an
    instruction between them changed what `rbp` holds, so the store
    lands somewhere the load never read."""
    #   mov edx, [rbp] / xor edx, eax / add rbp, 4 / mov [rbp], edx
    code = LOAD_EDX_RBP + XOR_EDX_EAX + b"\x48\x83\xc5\x04" + STORE_RBP_EDX
    assert _proof(_conditional_loop(code)) is None


@_needs_capstone
def test_a_write_to_the_index_register_does_the_same():
    #   mov r8d, [rbx+rcx*4+0x10] / xor r8d, eax / inc rcx
    #   / mov [rbx+rcx*4+0x10], r8d
    code = (b"\x44\x8b\x44\x8b\x10" + b"\x41\x31\xc0" + b"\x48\xff\xc1"
            + b"\x44\x89\x44\x8b\x10")
    assert _proof(_conditional_loop(code)) is None


# ── an operation that changes nothing changes nothing ──────────────────

_IDENTITY_OPERATIONS = [
    (b"\x09\xd2", "or edx, edx"),
    (b"\x21\xd2", "and edx, edx"),
    (b"\x83\xc2\x00", "add edx, 0"),
    (b"\x83\xea\x00", "sub edx, 0"),
    (b"\x83\xf2\x00", "xor edx, 0"),
    (b"\x83\xca\x00", "or edx, 0"),
    (b"\x83\xe2\xff", "and edx, -1"),
    (b"\xc1\xe2\x00", "shl edx, 0"),
    (b"\xc1\xea\x00", "shr edx, 0"),
    (b"\xc1\xfa\x00", "sar edx, 0"),
    (b"\xc1\xc2\x00", "rol edx, 0"),
    (b"\xc1\xca\x00", "ror edx, 0"),
]


@_needs_capstone
@pytest.mark.parametrize("operation, text", _IDENTITY_OPERATIONS)
def test_an_identity_operation_carries_the_loaded_value_to_the_transform(
        operation, text):
    """An operation whose result is its input writes back the bytes it
    read. The value in the register afterwards IS the loaded value, so
    the transform below it transforms what was loaded and the loop is
    the same loop it would be without the instruction.

        mov edx, [rbp] / <identity> / xor edx, eax / mov [rbp], edx
    """
    loop = _proof(_conditional_loop(
        LOAD_EDX_RBP + operation + XOR_EDX_EAX + STORE_RBP_EDX))
    assert loop is not None, text
    assert loop.form == LOAD_TRANSFORM_STORE


@_needs_capstone
@pytest.mark.parametrize("operation, text", _IDENTITY_OPERATIONS)
def test_an_identity_operation_is_not_itself_the_transform(operation, text):
    """The same instruction does not satisfy the transform the proof
    requires. Carrying a value and changing it are separate facts, and a
    loop whose only arithmetic leaves every byte where it was is a copy
    loop -- which the rows show, so there is nothing withheld either."""
    code = _conditional_loop(LOAD_EDX_RBP + operation + STORE_RBP_EDX)
    instructions, result = _decode(code)
    assert find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture="x64") is None, text
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture="x64") is None, text


@_needs_capstone
def test_an_identity_operation_after_the_transform_does_not_spend_it():
    """One transform is the budget. An identity operation below it is
    neither a second transform nor a loss, so the value reaching the
    store is still the one transform's result."""
    #   mov edx, [rbp] / xor edx, eax / or edx, edx / mov [rbp], edx
    loop = _proof(_conditional_loop(
        LOAD_EDX_RBP + XOR_EDX_EAX + b"\x09\xd2" + STORE_RBP_EDX))
    assert loop is not None


@_needs_capstone
def test_the_and_idiom_between_two_proved_equal_copies_carries_the_value():
    """`and ecx, edx` after `mov ecx, edx` is `and ecx, ecx` written
    across two instructions: the flag-test idiom, which sets flags and
    leaves the register alone. The copy still holds the loaded value, so
    the transform below it is a transform OF that value.

        mov edx, [rbp] / mov ecx, edx / and ecx, edx
        / xor ecx, eax / mov [rbp], ecx
    """
    code = (LOAD_EDX_RBP + b"\x89\xd1" + b"\x21\xd1" + b"\x31\xc1"
            + b"\x89\x4d\x00")
    assert _proof(_conditional_loop(code)) is not None


@_needs_capstone
@pytest.mark.parametrize("operation, text", [
    (b"\x83\xe2\x00", "and edx, 0 replaces the value with zero"),
    (b"\x83\xca\xff", "or edx, -1 replaces it with all ones"),
    (b"\x31\xd2", "xor edx, edx zeroes it"),
    (b"\x29\xd2", "sub edx, edx zeroes it"),
    (b"\x19\xd2", "sbb edx, edx leaves the carry flag alone"),
])
def test_an_annihilating_operation_still_loses_the_loaded_value(
        operation, text):
    """The companion negative: these write a constant, and the transform
    below them transforms that constant rather than anything that was
    read. Separating "unchanged" from "lost" is what keeps the identity
    cases above from admitting these."""
    assert _proof(_conditional_loop(
        LOAD_EDX_RBP + operation + XOR_EDX_EAX + STORE_RBP_EDX)) is None, text


@_needs_capstone
@pytest.mark.parametrize("load, code, store, description", [
    # mov edx, [rbp] / stc / adc edx, 0 / sub edx, 1 / mov [rbp], edx
    (LOAD_EDX_RBP, bytes.fromhex("f9" "83d200" "83ea01"), STORE_RBP_EDX,
     "adc edx, 0 then sub edx, 1, which cancel when the carry is set"),
    (LOAD_EDX_RBP, bytes.fromhex("f9" "83da00" "83c201"), STORE_RBP_EDX,
     "sbb edx, 0 then add edx, 1, the same the other way round"),
    (LOAD_EDX_RBP, bytes.fromhex("83d200"), STORE_RBP_EDX,
     "adc edx, 0 alone"),
    # the same at every width the register family offers
    (bytes.fromhex("8a5500"), bytes.fromhex("80d200" "80ea01"),
     bytes.fromhex("885500"), "adc dl, 0, 8-bit"),
    (bytes.fromhex("668b5500"), bytes.fromhex("6683d200" "6683ea01"),
     bytes.fromhex("66895500"), "adc dx, 0, 16-bit"),
    (bytes.fromhex("488b5500"), bytes.fromhex("4883d200" "4883ea01"),
     bytes.fromhex("48895500"), "adc rdx, 0, 64-bit"),
    # and after the value has been copied to another register
    (LOAD_EDX_RBP, bytes.fromhex("89d1" "83d100" "83e901"),
     bytes.fromhex("894d00"), "adc ecx, 0 over a copy of the loaded value"),
    # The all-ones immediate, the other half of the same rule. With the
    # carry SET, `x + (2**n - 1) + 1` and `x - (2**n - 1) - 1` are both x
    # at n bits.
    (LOAD_EDX_RBP, bytes.fromhex("f9" "83d2ff"), STORE_RBP_EDX,
     "adc edx, -1 under a set carry"),
    (LOAD_EDX_RBP, bytes.fromhex("f9" "83daff"), STORE_RBP_EDX,
     "sbb edx, -1 under a set carry"),
    (bytes.fromhex("8a5500"), bytes.fromhex("80d2ff"),
     bytes.fromhex("885500"), "adc dl, -1, 8-bit"),
    (bytes.fromhex("8a5500"), bytes.fromhex("80daff"),
     bytes.fromhex("885500"), "sbb dl, -1, 8-bit"),
    (bytes.fromhex("668b5500"), bytes.fromhex("6683d2ff"),
     bytes.fromhex("66895500"), "adc dx, -1, 16-bit"),
    (bytes.fromhex("488b5500"), bytes.fromhex("4883d2ff"),
     bytes.fromhex("48895500"), "adc rdx, -1, 64-bit"),
    # the imm32 spelling of the same value, which the binding reports as
    # the unsigned mask rather than as -1
    (LOAD_EDX_RBP, bytes.fromhex("81d2ffffffff"), STORE_RBP_EDX,
     "adc edx, 0xffffffff, the imm32 encoding"),
    (LOAD_EDX_RBP, bytes.fromhex("81daffffffff"), STORE_RBP_EDX,
     "sbb edx, 0xffffffff, likewise"),
    (LOAD_EDX_RBP, bytes.fromhex("89d1" "83d1ff"),
     bytes.fromhex("894d00"), "adc ecx, -1 over a copy of the loaded value"),
])
def test_a_carry_dependent_identity_immediate_loses_the_value(
        load, code, store, description):
    """`adc x, i` is `x + i + CF` and `sbb x, i` is `x - i - CF`, so
    either leaves x exactly when `i + CF` is zero at the destination's
    width. The carry is zero or one, so the immediates that can do it are
    zero and the all-ones mask -- and no others.

    Which one applies is decided by a flag this module does not follow,
    and the instruction that set it may be anywhere above or outside the
    window. Reading such an instruction as UNCHANGED lets a pair that
    cancel under a set carry reach the store as a "transform" of a value
    they returned to exactly what was loaded; reading it as a transform
    asserts a non-identity result on the run where it was not one. The
    value is given up instead, which costs a proof rather than the truth
    of one."""
    assert _proof(_conditional_loop(load + code + store)) is None, description


@_needs_capstone
@pytest.mark.parametrize("code, description", [
    (bytes.fromhex("f9" "835500ff"), "adc dword ptr [rbp], -1"),
    (bytes.fromhex("f9" "835d00ff"), "sbb dword ptr [rbp], -1"),
    (bytes.fromhex("f9" "83550000"), "adc dword ptr [rbp], 0"),
    (bytes.fromhex("f9" "835d0000"), "sbb dword ptr [rbp], 0"),
    (bytes.fromhex("805500ff"), "adc byte ptr [rbp], -1, 8-bit"),
    (bytes.fromhex("805d00ff"), "sbb byte ptr [rbp], -1, 8-bit"),
    (bytes.fromhex("66835500ff"), "adc word ptr [rbp], -1, 16-bit"),
    (bytes.fromhex("48835500ff"), "adc qword ptr [rbp], -1, 64-bit"),
])
def test_the_direct_form_applies_the_same_carry_rule(code, description):
    """The one-instruction form asks the same question of the same
    immediate, at the memory operand's width rather than a register's --
    so a read-modify-write that may write back exactly what it read is
    not named a transform in either spelling."""
    assert _proof(_conditional_loop(code)) is None, description


@_needs_capstone
@pytest.mark.parametrize("operation, text", [
    (bytes.fromhex("83d205"), "adc edx, 5, whose result is edx + 5 + CF"),
    (bytes.fromhex("83da05"), "sbb edx, 5, likewise"),
    (bytes.fromhex("83d2fe"), "adc edx, -2, one short of the identity"),
    (bytes.fromhex("83dafe"), "sbb edx, -2, likewise"),
    (bytes.fromhex("11ca"), "adc edx, ecx, which has no immediate at all"),
    (bytes.fromhex("19ca"), "sbb edx, ecx, likewise"),
    (bytes.fromhex("83c2ff"), "add edx, -1, which reads no carry"),
    (bytes.fromhex("83eaff"), "sub edx, -1, likewise"),
])
def test_a_carry_dependent_operation_that_cannot_be_identity_transforms(
        operation, text):
    """The control, so the rule above is attributable to the two
    immediates and not to the mnemonic. `edx + 5 + CF` and `edx - 2 + CF`
    are not `edx` under either value of the flag, so the carry costs
    nothing there; `add edx, -1` reads no carry at all and is an ordinary
    transform."""
    assert _proof(_conditional_loop(
        LOAD_EDX_RBP + operation + STORE_RBP_EDX)) is not None, text


@_needs_capstone
@pytest.mark.parametrize("load, code, store, description", [
    (bytes.fromhex("8a5500"), bytes.fromhex("c0d209"), bytes.fromhex("885500"),
     "rcl dl, 9 -- a 9-bit rotate by 9"),
    (bytes.fromhex("8a5500"), bytes.fromhex("c0da09"), bytes.fromhex("885500"),
     "rcr dl, 9 -- likewise"),
    (bytes.fromhex("668b5500"), bytes.fromhex("66c1d211"),
     bytes.fromhex("66895500"), "rcl dx, 17 -- a 17-bit rotate by 17"),
    (LOAD_EDX_RBP, bytes.fromhex("c1d221"), STORE_RBP_EDX,
     "rcl edx, 33 -- a count past the operand width"),
    (LOAD_EDX_RBP, bytes.fromhex("c1d200"), STORE_RBP_EDX,
     "rcl edx, 0 -- the count the processor performs no rotation for"),
])
def test_a_rotate_through_carry_that_could_be_identity_is_not_a_transform(
        load, code, store, description):
    """`rcl` and `rcr` read the carry flag too: they rotate an
    (n+1)-bit quantity, so a count of n+1 returns every bit to where it
    started. x86 reaches that count for the narrow operands -- a count
    is masked to five bits and then taken modulo 9 for a byte and modulo
    17 for a word -- so `rcl dl, 9` and `rcl dx, 17` write back exactly
    what they read.

    No separate rule is needed: requiring the count to lie strictly
    between zero and the operand's bit width already refuses every one of
    them, and that requirement exists because a count outside it is not
    the shift its text reads as. This pins the consequence, so the range
    is not later widened to admit counts whose result is a no-op."""
    assert _proof(_conditional_loop(load + code + store)) is None, description


@_needs_capstone
@pytest.mark.parametrize("operation, text", [
    (bytes.fromhex("c1d203"), "rcl edx, 3"),
    (bytes.fromhex("c1da03"), "rcr edx, 3"),
])
def test_a_rotate_through_carry_inside_the_width_still_transforms(
        operation, text):
    """The control. A count strictly inside the operand width moves every
    bit, whichever way the carry fell, so reading the flag costs nothing
    and the result is a transform of what was loaded."""
    assert _proof(_conditional_loop(
        LOAD_EDX_RBP + operation + STORE_RBP_EDX)) is not None, text


# ── the value has to survive to the store ──────────────────────────────

@_needs_capstone
@pytest.mark.parametrize("code, description", [
    # mov edx, [rbp] / xor edx, eax / mov edx, ecx / mov [rbp], edx
    (LOAD_EDX_RBP + XOR_EDX_EAX + b"\x89\xca" + STORE_RBP_EDX,
     "the transformed value replaced by an unrelated register"),
    # mov edx, [rbp] / xor edx, eax / mov [rbp], ecx
    (LOAD_EDX_RBP + XOR_EDX_EAX + b"\x89\x4d\x00",
     "the store takes a register the load never filled"),
    # mov edx, [rbp] / xor edx, edx / mov [rbp], edx
    (LOAD_EDX_RBP + b"\x31\xd2" + STORE_RBP_EDX,
     "the zeroing idiom, which discards the loaded value"),
    # mov edx, [rbp] / or edx, edx / mov [rbp], edx
    (LOAD_EDX_RBP + b"\x09\xd2" + STORE_RBP_EDX,
     "the `or` flag-test idiom, which leaves the value exactly as it was"),
    # mov edx, [rbp] / and edx, edx / mov [rbp], edx
    (LOAD_EDX_RBP + b"\x21\xd2" + STORE_RBP_EDX,
     "the `and` flag-test idiom, likewise"),
    # mov edx, [rbp] / sbb edx, edx / mov [rbp], edx
    (LOAD_EDX_RBP + b"\x19\xd2" + STORE_RBP_EDX,
     "sbb against itself, whose result is the carry flag and nothing else"),
    # mov edx, [rbp] / add edx, 0 / mov [rbp], edx
    (LOAD_EDX_RBP + b"\x83\xc2\x00" + STORE_RBP_EDX,
     "an identity immediate, which leaves the value as it was"),
    # mov edx, [rbp] / and edx, 0 / mov [rbp], edx
    (LOAD_EDX_RBP + b"\x83\xe2\x00" + STORE_RBP_EDX,
     "an annihilating immediate, which leaves a constant"),
    # mov edx, [rbp] / shl edx, 0 / mov [rbp], edx
    (LOAD_EDX_RBP + b"\xc1\xe2\x00" + STORE_RBP_EDX,
     "a shift by zero"),
    # mov edx, [rbp] / mul rbx / mov [rbp], edx
    (LOAD_EDX_RBP + b"\x48\xf7\xe3" + STORE_RBP_EDX,
     "an implicit clobber of the tracked register that names it nowhere"),
    # mov edx, [rbp] / xor edx, eax / mov rcx, rdx / mov [rbp], ecx
    (LOAD_EDX_RBP + XOR_EDX_EAX + b"\x48\x89\xd1" + b"\x89\x4d\x00",
     "a copy at a different width, which is not the value that was read"),
])
def test_a_value_that_does_not_reach_the_store_proves_nothing(code, description):
    assert _proof(_conditional_loop(code)) is None, description


@_needs_capstone
@pytest.mark.parametrize("code, description", [
    # mov eax, [rax] / mov edx, eax / xor edx, ecx / mov [rax], edx
    (bytes.fromhex("8b00" "89c2" "31ca" "8910"),
     "a load into its own base register"),
    # mov ecx, [rax + rcx*4] / xor ecx, edx / mov [rax + rcx*4], ecx
    (bytes.fromhex("8b0c88" "31d1" "890c88"),
     "a load into its own index register"),
])
def test_a_load_that_destroys_its_own_address_proves_nothing(code, description):
    """The load computes its address from a register it then overwrites,
    so the store's identical text is a second address. In 64-bit mode a
    32-bit write clears the whole of the register it names, and either
    way the version the load used is gone before the store computes
    anything."""
    assert _proof(_conditional_loop(code)) is None, description


@_needs_capstone
def test_a_load_into_a_register_outside_its_address_is_the_control():
    """The same loop reading into a register the address expression does
    not name: nothing about the address changed between the two
    accesses, and the proof stands."""
    #   mov edx, [rax] / xor edx, ecx / mov [rax], edx
    loop = _proof(_conditional_loop(bytes.fromhex("8b10" "31ca" "8910")))
    assert loop is not None
    assert loop.form == LOAD_TRANSFORM_STORE


@_needs_capstone
@pytest.mark.parametrize("insn, description", [
    ("31ca", "xor, whose result is zero"),
    ("29ca", "sub, likewise"),
    ("21ca", "and, which leaves the value untouched"),
    ("09ca", "or, likewise"),
    ("19ca", "sbb, whose result is the carry flag and nothing else"),
])
def test_two_registers_holding_one_value_are_one_register(insn, description):
    """`mov ecx, edx` makes `ecx` and `edx` one value, so the instruction
    below it is the same-register idiom written across two instructions,
    and its result carries nothing of what was loaded. The names differ
    and the value does not, and the value is what the rule is about."""
    #   mov edx, [rbp] / mov ecx, edx / <insn> edx, ecx / mov [rbp], edx
    code = LOAD_EDX_RBP + bytes.fromhex("89d1" + insn) + STORE_RBP_EDX
    assert _proof(_conditional_loop(code)) is None, description


@_needs_capstone
def test_a_second_operand_holding_another_value_is_the_control():
    """The same shape with `ecx` left alone: nothing says it holds what
    the load read, so `xor edx, ecx` is an ordinary transform of the
    loaded value."""
    loop = _proof(_conditional_loop(
        LOAD_EDX_RBP + bytes.fromhex("31ca") + STORE_RBP_EDX))
    assert loop is not None
    assert loop.transform.mnemonic == "xor"


@_needs_capstone
def test_doubling_a_value_against_itself_is_a_transform():
    """The control for the same-register idioms above: `add edx, edx`
    also names one register twice, and its result does depend on what
    that register held."""
    loop = _proof(_conditional_loop(LOAD_EDX_RBP + b"\x01\xd2" + STORE_RBP_EDX))
    assert loop is not None
    assert loop.form == LOAD_TRANSFORM_STORE
    assert loop.transform.mnemonic == "add"


@_needs_capstone
@pytest.mark.parametrize("code, description", [
    (b"\x83\x00\x00", "add dword ptr [rax], 0 -- the identity"),
    (b"\x83\x20\x00", "and dword ptr [rax], 0 -- a scrub, not a transform"),
    (b"\x83\x20\xff", "and dword ptr [rax], -1 -- the identity"),
    (b"\xc1\x20\x00", "shl dword ptr [rax], 0 -- the identity"),
])
def test_the_direct_form_proves_non_identity_the_same_way(code, description):
    """The one-instruction form gets the same immediate rule as the
    three-instruction one. A loop that writes back exactly what it read
    transforms nothing however it is spelled, and a loop that replaces
    memory with a constant is a wipe -- which must not reach an analyst
    under a name that says its bytes were transformed."""
    assert _proof(_conditional_loop(code)) is None, description


@_needs_capstone
def test_a_store_that_never_reads_its_operand_is_not_a_read_modify_write():
    """`mov dword ptr [rax], 0` writes an explicit memory operand and
    never reads it, so there is no value it could have transformed."""
    assert _proof(_conditional_loop(b"\xc7\x00\x00\x00\x00\x00")) is None


@_needs_capstone
@pytest.mark.parametrize("insn, description", [
    (b"\x55", "push rbp"),
    (b"\xcc", "int3"),
    (b"\xcd\x80", "int 0x80"),
    (b"\xf1", "int1"),
])
def test_an_implicit_stack_write_between_the_load_and_the_store_ends_the_flow(
        insn, description):
    """Each of these names no memory operand and writes memory all the
    same. A stack write can land in a frame slot a tracked address points
    at, so the rule that stops at an unknown store has to see them --
    the interrupt family through its capstone group, since capstone
    reports no register write at all for `int3` and a stack-pointer rule
    would miss it."""
    code = LOAD_EDX_RBP + XOR_EDX_EAX + insn + STORE_RBP_EDX
    assert _proof(_conditional_loop(code)) is None, description


@_needs_capstone
@pytest.mark.parametrize("insn, description", [
    # An explicit written operand -- the case capstone reports plainly.
    (b"\xab", "stosd"),
    (b"\xa5", "movsd"),
    # An operand capstone names with no access bit at all.
    (b"\x6c", "insb, whose implied [rdi] reports neither read nor write"),
    # Operands capstone reports as READ-ONLY, each of which writes. These
    # are why an operand's claimed access cannot prove a pure read.
    (b"\x0f\xc3\x00", "movnti dword ptr [rax], eax"),
    (b"\x0f\xae\x18", "stmxcsr dword ptr [rax]"),
    (b"\x48\x0f\xc7\x08", "cmpxchg16b xmmword ptr [rax]"),
    (b"\x66\x0f\x38\xf8\x00", "movdir64b rax, zmmword ptr [rax]"),
    # No memory operand whatsoever: the mnemonic is the only statement.
    (b"\x66\x0f\xf7\xc1", "maskmovdqu xmm0, xmm1"),
    (b"\x0f\xf7\xc1", "maskmovq mm0, mm1"),
    (b"\x0f\x01\xfc", "clzero, which zeroes a line at the address in rax"),
    (b"\x55", "push rbp"),
    (b"\xcc", "int3"),
    # Leaf dispatchers: EAX selects what they do, and this module does
    # not track EAX.
    (b"\x0f\x01\xcf", "encls, whose EDBGWR leaf writes RBX to [RCX]"),
    (b"\x0f\x01\xc0", "enclv, whose ESETCONTEXT leaf writes EPC"),
    (b"\x0f\x01\xd7", "enclu, whose EENTER/ERESUME/EEXIT leaves transfer"),
    (b"\x0f\x01\xc5", "pconfig, which programs a key table"),
    # The decoder reports nothing at all about these.
    (b"\xd7", "xlatb, which reads [rbx + al] and writes al"),
    (b"\x0f\x01\xee", "rdpkru, which writes eax and edx"),
    (b"\x0f\x01\xc9", "mwait"),
    (b"\x0f\x01\xd5", "xend, whose abort path transfers elsewhere"),
    (b"\x0f\x09", "wbinvd"),
    # The all-register push: capstone spells it `pushal`/`pushaw`, never
    # `pusha`, so a rule keyed on the spelling matched neither and let
    # eight stack writes through.
    (b"\x60", "pushal"),
    (b"\x66\x60", "pushaw"),
    # A report that contradicts the architecture: each of these must
    # change the stack pointer or the accumulator, and names neither.
    (b"\xc8\x00\x00\x00", "enter 0, 0, which overwrites rbp and rsp"),
    (b"\x0f\xa0", "push fs, which changes rsp"),
    (b"\x0f\xa1", "pop fs, which changes rsp"),
    (b"\xd4\x0a", "aam, which changes ax"),
    (b"\xd5\x0a", "aad, which changes ax"),
])
def test_an_instruction_that_may_write_memory_ends_the_flow(insn, description):
    """One question asked once. Every one of these can write memory that
    aliases the address under analysis -- `[rdi]` and `[rbp]` are
    different expressions and nothing here says the registers differ at
    run time -- and they state it in four different ways, or in none at
    all. `DecodedInsn.may_write_memory` is where that is decided, so this
    walk carries no list of write forms it would have to keep complete by
    itself."""
    code = LOAD_EDX_RBP + XOR_EDX_EAX + insn + STORE_RBP_EDX
    assert _proof(_conditional_loop(code)) is None, description


@_needs_capstone
@pytest.mark.parametrize("insn, description", [
    (b"\x8b\x0e", "mov ecx, dword ptr [rsi] -- a key read from a table"),
    (b"\x0f\xb6\x0e", "movzx ecx, byte ptr [rsi]"),
    (b"\x48\x8d\x4e\x01", "lea rcx, [rsi + 1] -- no access at all"),
])
def test_a_read_the_module_can_place_does_not_end_the_flow(insn, description):
    """Distrusting a claimed access is the default, not an absolute. A
    `mov`/`movzx` whose one memory operand is a source and whose
    destination is a register writes no memory, and reading it that way
    is the same trust the proof already places in the `mov` mnemonic at
    both ends of it -- the load it anchors on and the store it proves.
    `lea` needs no trust at all: it is architecturally guaranteed never
    to dereference the address it computes.

    Loading a key from a table mid-loop is what the canonical decoder
    loop does, so this is the difference between recognising that shape
    and not."""
    code = LOAD_EDX_RBP + XOR_EDX_EAX + insn + STORE_RBP_EDX
    loop = _proof(_conditional_loop(code))
    assert loop is not None, description
    assert loop.form == LOAD_TRANSFORM_STORE, description


@_needs_capstone
def test_a_read_the_module_cannot_place_still_ends_the_flow():
    """The remaining cost, pinned so it stays deliberate: `cmp dword ptr
    [rsi], eax` only reads, and is not one of the forms this module reads
    as a load, so the walk stops. Widening that set is a trust decision
    per mnemonic and each one has to earn it -- capstone calls `movnti`
    and `stmxcsr` read-only too."""
    code = LOAD_EDX_RBP + XOR_EDX_EAX + b"\x39\x06" + STORE_RBP_EDX
    assert _proof(_conditional_loop(code)) is None


@_needs_capstone
@pytest.mark.parametrize("code, arch, description", [
    # x64: call pushes 8, `pop bp` recovers 2 and leaves the rest of rbp
    # holding whatever it held before.
    (b"\xe8\x00\x00\x00\x00" + b"\x66\x5d" + b"\x31\x45\x00"
     + b"\x48\x83\xe9\x01" + b"\x75\xf7" + RET, "x64", "x64 pop bp"),
    # x86: `callw` pushes 2 and `pop eax` takes 4, so the top half of the
    # register is stack bytes the call never wrote.
    (b"\x66\xe8\x00\x00" + b"\x58" + b"\x31\x18" + b"\x49" + b"\x75\xfb"
     + RET, "x86", "x86 callw + pop eax"),
    # x86: call pushes 4 and `pop ax` recovers 2.
    (b"\xe8\x00\x00\x00\x00" + b"\x66\x58" + b"\x31\x18" + b"\x49"
     + b"\x75\xfb" + RET, "x86", "x86 call + pop ax"),
])
def test_a_partial_return_address_is_not_the_code_s_own_address(
        code, arch, description):
    """Three widths have to be one number: what the `call` pushed, what
    the `pop` took, and the architecture's own address width. A partial
    recovery leaves a register that is part return address and part
    whatever was there before, which is not an address this code
    computed. The loop itself still stands; only the upgrade is refused."""
    loop = _proof(code, architecture=arch)
    assert loop is not None, description
    assert loop.get_pc is None, description


@_needs_capstone
@pytest.mark.parametrize("code, arch, description", [
    (b"\xe8\x00\x00\x00\x00" + b"\x5d" + b"\x31\x45\x00"
     + b"\x48\x83\xe9\x01" + b"\x75\xf7" + RET, "x64", "x64 call + pop rbp"),
    (b"\xe8\x00\x00\x00\x00" + b"\x58" + b"\x31\x18" + b"\x49" + b"\x75\xfb"
     + RET, "x86", "x86 call + pop eax"),
])
def test_a_whole_return_address_does_correlate(code, arch, description):
    """The controls for the three above: push width, pop width and
    address width agree, so the register holds the whole of what the call
    recorded."""
    loop = _proof(code, architecture=arch)
    assert loop is not None, description
    assert loop.get_pc is not None, description


@_needs_capstone
@pytest.mark.parametrize("code, description", [
    # mov edx, fs:[eax] / xor edx, ebx / mov fs, ecx / mov fs:[eax], edx
    (b"\x64\x8b\x10" + b"\x31\xda" + b"\x8e\xe1" + b"\x64\x89\x10",
     "an explicit fs: on both sides, with fs rewritten between"),
    # mov edx, [eax] / xor edx, ebx / mov ds, ecx / mov [eax], edx
    (b"\x8b\x10" + b"\x31\xda" + b"\x8e\xd9" + b"\x89\x10",
     "the implied DS of a 32-bit [eax], with ds rewritten between"),
    # mov edx, [ebp] / xor edx, ebx / mov ss, ecx / mov [ebp], edx
    (b"\x8b\x55\x00" + b"\x31\xda" + b"\x8e\xd1" + b"\x89\x55\x00",
     "the implied SS of a 32-bit [ebp], with ss rewritten between"),
])
def test_a_segment_written_between_the_accesses_makes_them_two_addresses(
        code, description):
    """A segment register is part of the address whether the operand
    names it or not: in 32-bit code `[ebp]` resolves through SS and
    `[eax]` through DS. Move the selector and every address that
    resolved through it moves, so two operands whose text is identical
    are two addresses."""
    span = len(code) + 3
    loop = _proof(code + b"\x4f" + b"\x75" + bytes([-span & 0xFF]) + RET,
                  architecture="x86")
    assert loop is None, description


@_needs_capstone
def test_an_unrelated_segment_write_does_not_end_the_flow():
    """The control: `mov es, ecx` between the same two accesses. ES is
    not the segment a 32-bit `[eax]` resolves through, so it moves
    nothing the address depends on."""
    #   mov edx, [eax] / xor edx, ebx / mov es, ecx / mov [eax], edx
    code = b"\x8b\x10" + b"\x31\xda" + b"\x8e\xc1" + b"\x89\x10"
    span = len(code) + 3
    loop = _proof(code + b"\x4f" + b"\x75" + bytes([-span & 0xFF]) + RET,
                  architecture="x86")
    assert loop is not None
    assert loop.form == LOAD_TRANSFORM_STORE


@_needs_capstone
@pytest.mark.parametrize("insn, description", [
    (b"\x90", "nop"),
    (b"\x0f\x77", "emms, which clears the MMX tag word only"),
    (b"\x0f\x0e", "femms"),
    (b"\xf3\x90", "pause, architecturally `rep nop`"),
    (b"\x0f\xae\xe8", "lfence, which orders accesses and performs none"),
    (b"\x0f\xae\xf0", "mfence"),
    (b"\x0f\xae\xf8", "sfence"),
])
def test_an_instruction_known_to_be_inert_does_not_end_the_flow(insn, description):
    """The control for the cases above, and the whole of the allowlist.
    Each of these reports nothing AND does nothing -- no memory content,
    no general register -- so the flow survives it. Everything else that
    reports nothing ends the candidate, which is what makes forgetting an
    entry here cost a proof rather than the truth of one."""
    code = LOAD_EDX_RBP + XOR_EDX_EAX + insn + STORE_RBP_EDX
    loop = _proof(_conditional_loop(code))
    assert loop is not None, description
    assert loop.form == LOAD_TRANSFORM_STORE, description


@_needs_capstone
def test_a_call_between_the_load_and_the_store_ends_the_flow():
    """What a callee writes is not in this window. A register that
    survives the call is not something these bytes state."""
    #   mov edx, [rbp] / xor edx, eax / call +0 / mov [rbp], edx
    code = LOAD_EDX_RBP + XOR_EDX_EAX + b"\xe8\x00\x00\x00\x00" + STORE_RBP_EDX
    assert _proof(_conditional_loop(code)) is None


@_needs_capstone
def test_a_memory_write_between_the_load_and_the_store_ends_the_flow():
    """A store to an address this module cannot place may be the very
    address under analysis. An unknown write is not a write known to be
    elsewhere."""
    #   mov edx, [rbp] / xor edx, eax / mov dword ptr [rbx], 0 / mov [rbp], edx
    code = (LOAD_EDX_RBP + XOR_EDX_EAX + b"\xc7\x03\x00\x00\x00\x00"
            + STORE_RBP_EDX)
    assert _proof(_conditional_loop(code)) is None


@_needs_capstone
def test_a_branch_between_the_load_and_the_store_ends_the_flow():
    """The proof follows one linear path, and a branch is where one path
    becomes several. Here the `jmp` does land on the store, and the
    analysis still declines: what it can state is what one run of
    straight-line instructions carries, and that is the direction to
    under-report in."""
    #   mov edx, [rbp] / xor edx, eax / jmp +0 / mov [rbp], edx
    code = LOAD_EDX_RBP + XOR_EDX_EAX + b"\xeb\x00" + STORE_RBP_EDX
    assert _proof(_conditional_loop(code)) is None


@_needs_capstone
def test_a_conditional_branch_over_the_transform_reaches_the_store_too():
    """The taken edge carries the loaded value straight to the store with
    nothing done to it, so the store has two reaching definitions and one
    of them is the value memory already held. A fork inside the span ends
    the candidate rather than being proven away.

        0x00  mov edx, [rbp]
        0x03  test eax, eax
        0x05  je 0x09
        0x07  xor edx, eax
        0x09  mov [rbp], edx
    """
    code = (LOAD_EDX_RBP + bytes.fromhex("85c0") + bytes.fromhex("7402")
            + XOR_EDX_EAX + STORE_RBP_EDX)
    assert _proof(_conditional_loop(code)) is None


@_needs_capstone
def test_a_branch_into_the_middle_of_the_span_brings_another_value_in():
    """The store is also reached on a path that skipped the transform,
    and on that path the register holds whatever it held before. A join
    this module cannot account for ends the candidate.

        0x00  jmp 0x08              -- into the middle of the span below
        0x02  mov edx, [rbp]
        0x05  xor edx, eax
        0x07  nop
        0x08  mov [rbp], edx
        0x0b  sub rcx, 1
        0x0f  jne 0x02
        0x11  ret
    """
    code = (b"\xeb\x06" + LOAD_EDX_RBP + XOR_EDX_EAX + NOP1 + STORE_RBP_EDX
            + DEC_RCX + b"\x75\xf1" + RET)
    instructions, result = _decode(code)
    assert [insn.address - BASE_VA for insn in instructions][:5] == [0, 2, 5, 7, 8]
    assert find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture="x64") is None


# ── connectivity, not coexistence ──────────────────────────────────────

@_needs_capstone
def test_a_transform_the_loop_never_reaches_proves_nothing():
    """The backward branch lands on a `ret`, so every run of the loop
    leaves at once. The three instructions below it are bytes in the
    branch's address span and nothing else.

        0x00  ret
        0x01  mov edx, [rbp]
        0x04  xor edx, eax
        0x06  mov [rbp], edx
        0x09  sub rcx, 1
        0x0d  jne 0x00
    """
    code = (RET + LOAD_EDX_RBP + XOR_EDX_EAX + STORE_RBP_EDX
            + DEC_RCX + b"\x75\xf1" + RET)
    assert _proof(code) is None


@_needs_capstone
def test_a_transform_outside_the_loop_span_proves_nothing():
    """A loop and a transform that merely share a 512-byte window are not
    a loop that runs the transform."""
    #   sub rcx, 1 / jne back to itself / mov edx,[rbp] / xor / mov / ret
    code = (DEC_RCX + b"\x75\xfa" + LOAD_EDX_RBP + XOR_EDX_EAX
            + STORE_RBP_EDX + RET)
    assert _proof(code) is None


@_needs_capstone
def test_a_loop_no_edge_reaches_is_bytes_that_decode_like_a_loop():
    """Nothing in the window targets 0x02, and 0x00 jumps past it. The
    three instructions there are inside a backward branch's span and are
    reached by no edge in the decoded graph -- which is what "bytes after
    a branch may be data" means mechanically.

        0x00  jmp 0x0d
        0x02  xor byte ptr [rax], 0x41
        0x05  sub rcx, 1
        0x09  jne 0x02
        0x0d  ret
    """
    code = (b"\xeb\x0b" + b"\x80\x30\x41" + DEC_RCX + b"\x75\xf7"
            + NOP1 * 2 + RET)
    instructions, result = _decode(code)
    assert any(insn.address - BASE_VA == 0x02 for insn in instructions)
    cfg = build_local_cfg(instructions)
    assert BASE_VA + 0x02 not in cfg.reachable_from(BASE_VA)
    assert find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture="x64") is None


@_needs_capstone
def test_the_same_loop_reached_by_the_jump_is_a_loop():
    """The control, differing in one displacement: the jump now lands on
    the loop instead of past it, so an edge arrives and the same three
    instructions are a loop."""
    code = (b"\xeb\x00" + b"\x80\x30\x41" + DEC_RCX + b"\x75\xf7"
            + NOP1 * 2 + RET)
    loop = _proof(code)
    assert loop is not None
    assert loop.form == DIRECT_WRITE_BACK
    assert loop.entry_va - BASE_VA == 0x02


@_needs_capstone
def test_zero_padding_that_decodes_like_a_write_back_is_not_a_loop():
    """A run of zero bytes decodes to `add byte ptr [rax], al`, which
    writes memory under a transform mnemonic. Below an unconditional
    branch that nothing targets, it is padding that decodes like a
    transform loop, and reachability is what tells the two apart.

        0x00  jmp 0x0b
        0x02  add byte ptr [rax], al   (x3, from six zero bytes)
        0x08  jne 0x02
        0x0b  ret
    """
    code = b"\xeb\x09" + b"\x00" * 6 + b"\x75\xf8" + NOP1 + RET
    instructions, result = _decode(code)
    assert any(insn.mnemonic == "add" and insn.writes_memory
               for insn in instructions)
    assert find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture="x64") is None


@_needs_capstone
def test_a_backward_direct_call_does_not_close_a_loop():
    """capstone puts a relative `call` in its relative-branch group as
    well as its call group, so `is_jump` is True for one. A backward
    `call` is recursion -- it pushes a return address every time round --
    and is not the loop this analysis is about.

        0x00  xor dword ptr [rbp], eax
        0x03  sub rcx, 1
        0x07  call 0x00
        0x0c  ret
    """
    code = (b"\x31\x45\x00" + DEC_RCX + b"\xe8\xf4\xff\xff\xff" + RET)
    instructions, _result = _decode(code)
    recursion = [insn for insn in instructions if insn.mnemonic == "call"]
    assert recursion and recursion[0].is_jump and recursion[0].is_call
    assert _proof(code) is None


@_needs_capstone
def test_a_backward_conditional_branch_in_the_same_shape_does_close_one():
    """The control: five bytes of `call` replaced by a two-byte `jne` to
    the same place, and nothing else changed."""
    loop = _proof(b"\x31\x45\x00" + DEC_RCX + b"\x75\xf7" + RET)
    assert loop is not None
    assert loop.branch.mnemonic == "jne"


@_needs_capstone
def test_a_get_pc_call_the_anchor_cannot_reach_does_not_upgrade_the_lead():
    """The `jmp` skips the `call` and lands on the `pop` it targets. That
    `call` pushed nothing on any path, so the value the `pop` read came
    from somewhere this window does not show -- attributing the code's
    own address to it would attribute a write to an instruction no path
    executes.

        0x00  jmp 0x07
        0x02  call 0x07        -- skipped
        0x07  pop rbp
        0x08  xor dword ptr [rbp], eax
        0x0b  sub rcx, 1
        0x0f  jne 0x08
    """
    code = (b"\xeb\x05" + b"\xe8\x00\x00\x00\x00" + b"\x5d"
            + b"\x31\x45\x00" + DEC_RCX + b"\x75\xf7" + RET)
    loop = _proof(code)
    assert loop is not None, "the loop itself is still reached and proven"
    assert loop.get_pc is None


@_needs_capstone
def test_the_same_window_with_the_call_reached_does_upgrade_it():
    """The control: the `jmp` lands on the `call` instead of past it, so
    the `call` is on the path that reaches the `pop`."""
    code = (b"\xeb\x00" + b"\xe8\x00\x00\x00\x00" + b"\x5d"
            + b"\x31\x45\x00" + DEC_RCX + b"\x75\xf7" + RET)
    loop = _proof(code)
    assert loop is not None
    assert loop.get_pc is not None
    assert loop.get_pc.register == "rbp"


@_needs_capstone
def test_an_exit_edge_that_re_enters_the_loop_reaches_nothing_after_it():
    """The conditional edge leaves the body's address span and falls
    straight back into the loop, so nothing on it is after the loop. The
    indirect `call` it would otherwise reach is inside the body, and
    reporting it would place a transfer on a path that goes round again.

        0x00  nop                  -- the edge's destination
        0x01  xor [rbp], eax       -- the loop entry
        0x04  call rdx
        0x06  je 0x00
        0x08  jmp 0x01
    """
    loop = _proof(bytes.fromhex("90" "314500" "ffd2" "74f8" "ebf7") + RET)
    assert loop is not None
    assert loop.exit is None


@_needs_capstone
def test_an_exit_edge_that_stays_out_of_the_loop_does_reach_the_transfer():
    """The control: the same loop whose conditional edge leaves forward,
    onto bytes no edge carries back into the body.

        0x00  nop
        0x01  xor [rbp], eax       -- the loop entry
        0x04  je 0x08
        0x06  jmp 0x01
        0x08  call rdx
    """
    loop = _proof(bytes.fromhex("90" "314500" "7402" "ebf9" "ffd2") + RET)
    assert loop is not None
    assert loop.exit is not None
    assert loop.exit.exit_branch.address - BASE_VA == 0x04
    assert loop.exit.transfer.address - BASE_VA == 0x08


@_needs_capstone
def test_a_call_out_of_the_loop_body_is_not_an_exit():
    """Control comes back below a `call` and carries on round the loop,
    so a call out of the body leaves nothing. Reading one as an exit
    would report a register-indirect transfer on a path that returns.

        0x00  xor byte ptr [rax], 0x41
        0x03  call 0x0a
        0x08  jmp 0x00
        0x0a  nop
        0x0b  call rdx
    """
    code = (b"\x80\x30\x41" + b"\xe8\x02\x00\x00\x00" + b"\xeb\xf6"
            + NOP1 + b"\xff\xd2" + RET)
    loop = _proof(code)
    assert loop is not None
    assert loop.exit is None


@_needs_capstone
def test_a_call_edge_is_skipped_and_the_conditional_edge_is_the_exit():
    """The call sits lower in the body than the conditional branch, so a
    scan that took the first edge out would take the call's. It is not an
    exit at all, and the `je` below it is.

        0x00  xor byte ptr [rax], 0x41
        0x03  call 0x0c
        0x08  je 0x0d
        0x0a  jmp 0x00
        0x0c  nop
        0x0d  call rdx
    """
    code = (b"\x80\x30\x41" + b"\xe8\x04\x00\x00\x00" + b"\x74\x03"
            + b"\xeb\xf4" + NOP1 + b"\xff\xd2" + RET)
    loop = _proof(code)
    assert loop is not None
    assert loop.exit is not None
    assert loop.exit.exit_branch.mnemonic == "je"


@_needs_capstone
def test_an_unconditional_backward_jump_is_given_no_fall_through():
    """Nothing follows an unconditional backward `jmp` on any run. The
    register-indirect `call` sitting after one is not reachable from the
    loop, and the loop itself is still proven.

        0x00  xor byte ptr [rax], 0x41
        0x03  jmp 0x00
        0x05  call rax
    """
    loop = _proof(b"\x80\x30\x41" + b"\xeb\xfb" + b"\xff\xd0" + RET)
    assert loop is not None
    assert loop.form == DIRECT_WRITE_BACK
    assert loop.branch.falls_through is False
    assert loop.exit is None


@_needs_capstone
def test_an_unrelated_call_and_pop_in_the_window_is_not_this_loop_s_get_pc():
    """The register-mediated loop writes through `rbp`; the call/pop pair
    fills `rax`. They are in one window and are not related.

        0x00  call 0x05
        0x05  pop rax
        0x06  mov edx, [rbp]
        0x09  xor edx, eax
        0x0b  mov [rbp], edx
        0x0e  sub rcx, 1
        0x12  jne 0x06
    """
    code = (b"\xe8\x00\x00\x00\x00" + b"\x58"
            + _conditional_loop(LOAD_EDX_RBP + XOR_EDX_EAX + STORE_RBP_EDX))
    loop = _proof(code)
    assert loop is not None
    assert loop.form == LOAD_TRANSFORM_STORE
    assert loop.get_pc is None


@_needs_capstone
def test_a_register_that_only_supplied_an_address_does_not_carry_it():
    """`add rcx, qword ptr [rbp]` reads `rbp` to FORM an address and adds
    what it found there. `rcx` ends up holding data fetched with the
    code's own address, which is not the code's own address -- a pointer
    read out of a table is the ordinary way a buffer loop gets its
    target, and calling that a self-decoding stub would be a false
    positive on the strongest name the product prints.

        0x00  call 0x05
        0x05  pop rbp                       -- rbp carries this code's address
        0x06  add rcx, qword ptr [rbp]      -- rcx gets the DATA at it
        0x0a  mov edx, dword ptr [rcx] / xor edx, eax / mov [rcx], edx
    """
    code = (b"\xe8\x00\x00\x00\x00" + b"\x5d" + b"\x48\x03\x4d\x00"
            + b"\x8b\x11" + b"\x31\xc2" + b"\x89\x11"
            + b"\x48\x83\xeb\x01" + b"\x75\xf4" + RET)
    loop = _proof(code)
    assert loop is not None, "the loop itself is still proven"
    assert loop.form == LOAD_TRANSFORM_STORE
    assert loop.get_pc is None


@_needs_capstone
@pytest.mark.parametrize("carry, description", [
    (b"\x48\x01\xe9", "add rcx, rbp"),
    (b"\x48\x8d\x4d\x20", "lea rcx, [rbp + 0x20]"),
    (b"\x48\x89\xe9", "mov rcx, rbp"),
])
def test_a_register_that_consumed_the_address_does_carry_it(carry, description):
    """The controls for the case above. Each of these takes the code's
    own address as a VALUE rather than as a way to reach one, so the
    address the loop writes through does derive from the `call`/`pop`.

        0x00  call 0x05 / 0x05 pop rbp / <carry> / loop through [rcx]
    """
    # The loop entry is the instruction after `carry`, and the body below
    # it is a fixed 12 bytes however long `carry` is, so the backward
    # displacement does not move with it.
    code = (b"\xe8\x00\x00\x00\x00" + b"\x5d" + carry
            + b"\x8b\x11" + b"\x31\xc2" + b"\x89\x11"
            + b"\x48\x83\xeb\x01" + b"\x75\xf4" + RET)
    loop = _proof(code)
    assert loop is not None, description
    assert loop.get_pc is not None, description
    assert loop.get_pc.register == "rcx", description


@_needs_capstone
@pytest.mark.parametrize("carry, description", [
    # mov rcx, rbp / sub rcx, rbp -- rcx is zero
    ("4889e9" "4829e9", "an address subtracted from a copy of itself"),
    # lea rcx, [rbp + 0x20] / sub rcx, rbp -- rcx is the constant 0x20
    ("488d4d20" "4829e9", "an address subtracted from an offset of itself"),
    # mov rcx, rbp / add rcx, rbp -- rcx is twice an address
    ("4889e9" "4801e9", "an address added to a copy of itself"),
])
def test_an_address_cancelled_against_itself_is_no_longer_one(carry, description):
    """Every carried register holds the value of one `pop`, so arithmetic
    between two of them leaves a displacement, a zero, or a doubling --
    none of which names a location in this code. The loop below is still
    a proven transform; what it is not is a stub rewriting its own bytes.

        0x00  call 0x05 / 0x05 pop rbp / <carry> / loop through [rcx]
    """
    code = (bytes.fromhex("e800000000") + bytes.fromhex("5d")
            + bytes.fromhex(carry)
            + bytes.fromhex("8b11" "31c2" "8911" "4883eb01" "75f4") + RET)
    loop = _proof(code)
    assert loop is not None, description
    assert loop.form == LOAD_TRANSFORM_STORE, description
    assert loop.get_pc is None, description


@_needs_capstone
def test_a_subtraction_of_something_else_still_leaves_an_address():
    """The control: `sub rcx, rax` moves a carried address by whatever
    `rax` holds, and nothing says `rax` holds this code's address too. A
    code-relative address minus an unrelated value is still
    code-relative.

        0x00  call 0x05 / 0x05 pop rbp / mov rcx, rbp / sub rcx, rax
    """
    code = (bytes.fromhex("e800000000") + bytes.fromhex("5d")
            + bytes.fromhex("4889e9" "4829c1")
            + bytes.fromhex("8b11" "31c2" "8911" "4883eb01" "75f4") + RET)
    loop = _proof(code)
    assert loop is not None
    assert loop.get_pc is not None
    assert loop.get_pc.register == "rcx"


# `call +0` / `pop rbp`, a carry step, then a loop that transforms
# `[rbp]`. The loop body below the carry is a fixed 14 bytes however long
# the carry is, so the backward displacement does not move with it.
_LOOP_THROUGH_RBP = bytes.fromhex("8b5500" "31c2" "895500" "4883eb01" "75f2")


def _get_pc_then_loop_through_rbp(carry: str) -> bytes:
    return (bytes.fromhex("e800000000" "5d" + carry) + _LOOP_THROUGH_RBP + RET)


@_needs_capstone
@pytest.mark.parametrize("carry, description", [
    ("4801ed", "add rbp, rbp"),
    ("488d6c2d00", "lea rbp, [rbp + rbp]"),
    ("488d2c6d00000000", "lea rbp, [rbp*2]"),
    ("488d2cad00000000", "lea rbp, [rbp*4]"),
    ("488d2ced00000000", "lea rbp, [rbp*8]"),
])
def test_a_multiple_of_this_code_s_address_is_not_this_code_s_address(
        carry, description):
    """Twice where the code sits is not where the code sits, and neither
    is four or eight times it. The carried value has to arrive with a
    coefficient of one, so an instruction that consumes it twice or
    scales it ends the carry -- whether it spells the doubling as an
    addition, as two address registers, or as a scaled index. The loop is
    still a proven transform; what it is not is a stub rewriting its own
    bytes."""
    loop = _proof(_get_pc_then_loop_through_rbp(carry))
    assert loop is not None, description
    assert loop.form == LOAD_TRANSFORM_STORE, description
    assert loop.get_pc is None, description


@_needs_capstone
def test_two_registers_carrying_one_address_are_two_of_it():
    """The two inputs are different register names and one value, so
    `lea rcx, [rcx + rbp]` after `mov rcx, rbp` doubles the address as
    plainly as `add rbp, rbp` does.

        0x00  call 0x05 / 0x05 pop rbp
        0x06  mov rcx, rbp
        0x09  lea rcx, [rcx + rbp]
        0x0d  loop through [rcx]
    """
    code = (bytes.fromhex("e800000000" "5d" "4889e9" "488d0c29")
            + bytes.fromhex("8b11" "31c2" "8911" "4883eb01" "75f4") + RET)
    loop = _proof(code)
    assert loop is not None
    assert loop.get_pc is None


@_needs_capstone
def test_a_doubled_address_is_not_an_address_in_32_bit_code_either():
    """The rule is about the value, not about the width it is carried
    at."""
    code = (bytes.fromhex("e800000000" "5d" "01ed")
            + bytes.fromhex("8b5500" "31c2" "895500" "83eb01" "75f3") + RET)
    loop = _proof(code, architecture="x86")
    assert loop is not None
    assert loop.get_pc is None


@_needs_capstone
@pytest.mark.parametrize("carry, description", [
    ("4883c510", "add rbp, 0x10, which moves the address without scaling it"),
    ("488d6d20", "lea rbp, [rbp + 0x20], likewise"),
    ("488d2c28", "lea rbp, [rax + rbp], whose other input carries nothing"),
])
def test_an_address_that_arrives_once_still_carries(carry, description):
    """The controls. Each of these consumes the carried address exactly
    once, so what it leaves is still a place in this code."""
    loop = _proof(_get_pc_then_loop_through_rbp(carry.replace(" ", "")))
    assert loop is not None, description
    assert loop.get_pc is not None, description
    assert loop.get_pc.register == "rbp", description


@_needs_capstone
def test_a_get_pc_value_reaching_the_index_register_is_correlated():
    """`[rax + rbp]` computes its address from both registers, so a
    get-PC value in the UNSCALED index contributes to the transformed
    address exactly as one in the base would. Which of the two a compiler
    chose says nothing about the relationship.

        0x00  call 0x05 / 0x05 pop rbp
        0x06  mov edx, dword ptr [rax + rbp]
        0x09  xor edx, ecx
        0x0b  mov dword ptr [rax + rbp], edx
        0x0e  sub rcx, 1 / 0x12 jne 0x06
    """
    code = (b"\xe8\x00\x00\x00\x00" + b"\x5d" + b"\x8b\x14\x28" + b"\x31\xca"
            + b"\x89\x14\x28" + DEC_RCX + b"\x75\xf2" + RET)
    loop = _proof(code)
    assert loop is not None
    assert loop.address.base == "rax" and loop.address.index == "rbp"
    assert loop.get_pc is not None
    assert loop.get_pc.register == "rbp"


@_needs_capstone
def test_a_get_pc_value_reaching_the_base_register_is_correlated():
    """The matching case, so the index result above is not an accident of
    which register the fixture happened to use: here the call/pop fills
    the BASE of a two-register address, whose scaled index holds
    something else."""
    #   call 0x05 / pop rax / mov edx, [rax + rbp*4] / xor / store / loop
    code = (b"\xe8\x00\x00\x00\x00" + b"\x58" + b"\x8b\x14\xa8" + b"\x31\xca"
            + b"\x89\x14\xa8" + DEC_RCX + b"\x75\xf2" + RET)
    loop = _proof(code)
    assert loop is not None
    assert loop.get_pc is not None
    assert loop.get_pc.register == "rax"


# The get-PC prologue every fixture below shares: call the next
# instruction, then pop the pushed return address -- this code's own
# address -- into rbp.
_CALL_POP_RBP = b"\xe8\x00\x00\x00\x00" + b"\x5d"


@_needs_capstone
@pytest.mark.parametrize("sib, description", [
    (b"\x68", "[rax + rbp*2], twice this code's address"),
    (b"\xa8", "[rax + rbp*4], four times it"),
    (b"\xe8", "[rax + rbp*8], eight times it"),
])
def test_a_scaled_get_pc_value_in_the_final_access_is_not_correlated(
        sib, description):
    """The coefficient rule is the address the loop actually touches, not
    only the registers that led to it. `rbp*4` is four times where this
    code sits: a number computed FROM the code's address, naming a
    location that is not in the code at all unless the code begins at
    zero. A loop transforming what is there is not a loop transforming
    itself, and must not be named one.

        0x00  call 0x05 / 0x05 pop rbp
        0x06  mov edx, dword ptr [rax + rbp*N]
        0x09  xor edx, ecx
        0x0b  mov dword ptr [rax + rbp*N], edx
        0x0e  sub rcx, 1 / 0x12 jne 0x06

    The loop itself still proves itself; what is refused is the get-PC
    correlation on top of it."""
    code = (_CALL_POP_RBP + b"\x8b\x14" + sib + b"\x31\xca"
            + b"\x89\x14" + sib + DEC_RCX + b"\x75\xf2" + RET)
    loop = _proof(code)
    assert loop is not None, description
    assert loop.get_pc is None, description


@_needs_capstone
@pytest.mark.parametrize("modrm, description", [
    (b"\x0d", "[rbp + rcx], the address added to a copy of itself"),
    (b"\x4d", "[rbp + rcx*2], three times it"),
])
def test_a_get_pc_value_counted_twice_in_one_address_is_not_correlated(
        modrm, description):
    """Two registers holding one popped value contribute separately. A
    copy in the index adds a second whole coefficient to the one the base
    already supplies, so the address is a multiple of this code's own
    address however plainly each half of it came from the `pop`.

        0x00  call 0x05 / 0x05 pop rbp / 0x06 mov rcx, rbp
        0x09  mov edx, dword ptr [rbp + rcx]
        0x0d  xor edx, eax
        0x0f  mov dword ptr [rbp + rcx], edx
        0x13  sub rcx, 1 / 0x17 jne 0x09
    """
    code = (_CALL_POP_RBP + b"\x48\x89\xe9"
            + b"\x8b\x54" + modrm + b"\x00" + b"\x31\xc2"
            + b"\x89\x54" + modrm + b"\x00" + DEC_RCX + b"\x75\xf0" + RET)
    loop = _proof(code)
    assert loop is not None, description
    assert loop.get_pc is None, description


@_needs_capstone
@pytest.mark.parametrize("prefix, body, span, arch, description", [
    # lea rcx, [ebp] -- an address-size override that takes the low half
    # of the popped address and zero-extends what it computed.
    (_CALL_POP_RBP + b"\x67\x48\x8d\x4d\x00",
     b"\x8b\x11" + XOR_EDX_EAX + b"\x89\x11", b"\xf4", "x64",
     "a 32-bit lea over a 64-bit popped address"),
    # the same loop reached through the whole register
    (_CALL_POP_RBP + b"\x48\x8d\x4d\x00",
     b"\x8b\x11" + XOR_EDX_EAX + b"\x89\x11", b"\xf4", "x64",
     "CONTROL: the same lea at the full width"),
    # mov edx, [ebp] -- the override on the transformed access itself
    (_CALL_POP_RBP,
     b"\x67\x8b\x55\x00" + XOR_EDX_EAX + b"\x67\x89\x55\x00", b"\xf0", "x64",
     "a 32-bit access over a 64-bit popped address"),
    (_CALL_POP_RBP,
     LOAD_EDX_RBP + XOR_EDX_EAX + STORE_RBP_EDX, b"\xf2", "x64",
     "CONTROL: the same access at the full width"),
    # mov edx, [bp] -- 16-bit addressing in 32-bit code
    (b"\xe8\x00\x00\x00\x00" + b"\x5d",
     b"\x67\x8b\x56\x00" + XOR_EDX_EAX + b"\x67\x89\x56\x00", b"\xf0", "x86",
     "a 16-bit access over a 32-bit popped address"),
    (b"\xe8\x00\x00\x00\x00" + b"\x5d",
     LOAD_EDX_RBP + XOR_EDX_EAX + STORE_RBP_EDX, b"\xf2", "x86",
     "CONTROL: the same access at the full width"),
])
def test_a_narrow_address_does_not_carry_the_whole_popped_address(
        prefix, body, span, arch, description):
    """`register_family` is the right question for a KILL and the wrong
    one for a USE. A write to `ebp` does destroy what `rbp` held, which
    is why the kill is asked by family -- but `[ebp]` in 64-bit code
    resolves through the low 32 bits of `rbp` and discards the rest, and
    `[bp]` in 32-bit code through the low 16. Neither is the address the
    `pop` recovered, however plainly the family says it is the same
    register, so neither upgrades the lead.

    Each narrow case is stated beside the full-width loop it was made
    from, so the refusal is attributable to the width and not to the rest
    of the window."""
    code = prefix + body + DEC_RCX + b"\x75" + span + RET
    loop = _proof(code, architecture=arch)
    assert loop is not None, description
    correlated = loop.get_pc is not None
    assert correlated == description.startswith("CONTROL"), description


@_needs_capstone
def test_a_call_between_the_get_pc_and_the_loop_ends_the_carry():
    """A callee's clobbers are not in this window, and capstone reports a
    `call`'s own writes as the stack and instruction pointers alone --
    so every other register would look intact across a function that was
    never examined. A volatile address register is exactly the one a
    callee may replace, and a resolver call between a get-PC sequence and
    a decode loop is an ordinary layout.

        0x00  call 0x05 / 0x05 pop rbp / 0x06 call 0x0b
        0x0b  mov edx, [rbp] / xor edx, eax / mov [rbp], edx / ... / jne 0x0b
    """
    code = (b"\xe8\x00\x00\x00\x00" + b"\x5d" + b"\xe8\x00\x00\x00\x00"
            + LOAD_EDX_RBP + XOR_EDX_EAX + STORE_RBP_EDX
            + DEC_RCX + b"\x75\xf2" + RET)
    loop = _proof(code)
    assert loop is not None, "the loop itself is still proven"
    assert loop.get_pc is None


@_needs_capstone
@pytest.mark.parametrize("insn, description", [
    (b"\xcd\x80", "int 0x80"),
    (b"\xcc", "int3"),
    (b"\x0f\x05", "syscall"),
    (b"\x0f\x01\xc1", "vmcall"),
    (b"\x0f\x01\xd9", "vmmcall"),
    (b"\x0f\x01\xc2", "vmlaunch"),
    (b"\x0f\x01\xc3", "vmresume"),
    (b"\x0f\x01\xd4", "vmfunc"),
    (b"\x0f\x01\xd8", "vmrun"),
    (b"\x0f\x37", "getsec"),
    (b"\x0f\x01\xd7", "enclu"),
])
def test_external_context_between_the_get_pc_and_the_loop_ends_the_carry(
        insn, description):
    """Control leaves for a handler, the kernel, a hypervisor or an
    authenticated code module, and whether that code saved, changed or
    restored the register is not something this window shows -- the same
    reason a `call` ends the carry, with less of the state visible. Every
    one of these falls through to its successor and clobbers no register
    capstone reports, so nothing but the group it is in says that other
    code ran at all.

        0x00  call 0x05 / 0x05 pop rbp / <insn>
        loop: xor dword ptr [rbp], eax / sub rcx, 1 / jne loop
    """
    code = _get_pc_then_loop(insn)
    loop = _proof(code)
    assert loop is not None, "the loop itself is still proven"
    assert loop.get_pc is None, description
    (subject,) = [i for i in _decode(code)[0] if i.address - BASE_VA == 0x06]
    assert subject.leaves_analysis_context, description


@_needs_capstone
@pytest.mark.parametrize("insn, description", [
    # The decoder reports nothing at all about these.
    (b"\x0f\x01\xcf", "encls, whose EDBGWR leaf writes RBX to [RCX]"),
    (b"\xd7", "xlatb, which reads [rbx + al] and writes al"),
    (b"\x0f\x01\xee", "rdpkru, which writes eax and edx"),
    # The decoder reports something, and it contradicts the architecture:
    # executing these MUST change the stack pointer or the accumulator,
    # and the report names neither.
    (b"\xc8\x00\x00\x00", "enter 0, 0, which overwrites rbp and rsp"),
    (b"\x0f\xa0", "push fs, which changes rsp"),
    (b"\x0f\xa1", "pop fs, which changes rsp"),
])
def test_unknown_or_incomplete_effects_between_the_get_pc_and_the_loop_end_it(
        insn, description):
    """A different contract from the one above, and kept apart from it:
    control does NOT leave for outside code in any of these. What fails
    is the decoder's account of what the instruction did -- either empty,
    or short of what the instruction's own class requires -- so the
    carried address cannot be shown to survive it.

    Keeping the two apart matters: a future change that mistakenly
    classified `encls` as an external transfer would still pass a test
    that accepted either answer."""
    code = _get_pc_then_loop(insn)
    loop = _proof(code)
    assert loop is not None, "the loop itself is still proven"
    assert loop.get_pc is None, description
    (subject,) = [i for i in _decode(code)[0] if i.address - BASE_VA == 0x06]
    assert subject.effects_unknown, description
    assert not subject.leaves_analysis_context, description


@_needs_capstone
def test_a_stack_push_the_decoder_accounts_for_does_not_end_the_carry():
    """The control for the `push`/`pop` cases above, and the reason the
    rule is a self-consistency check rather than a list of instructions
    to distrust: `push rbp` names `rsp` exactly as the architecture
    requires, so its report is relied on -- and it does not touch `rbp`.
    The sanitized sample this recognizer exists for has a `push rbp` in
    precisely this position."""
    loop = _proof(_get_pc_then_loop(b"\x55"))
    assert loop is not None
    assert loop.get_pc is not None
    assert loop.get_pc.register == "rbp"


@_needs_capstone
def test_the_same_window_with_no_interrupt_does_correlate():
    """The control: a `nop` in the same slot, and the carry survives."""
    tail = b"\x31\x45\x00" + DEC_RCX
    code = (b"\xe8\x00\x00\x00\x00" + b"\x5d" + NOP1 + tail
            + b"\x75" + bytes([-(len(tail) + 2) & 0xFF]) + RET)
    loop = _proof(code)
    assert loop is not None
    assert loop.get_pc is not None
    assert loop.get_pc.register == "rbp"


@_needs_capstone
def test_a_get_pc_value_the_loop_address_lost_is_not_correlated():
    """The same window with `xor rbp, rbp` after the pop: the code's own
    address is gone before the loop's first access uses it.

        0x00  call 0x05
        0x05  pop rbp
        0x06  xor rbp, rbp
        0x09  mov edx, [rbp] ...
    """
    code = (b"\xe8\x00\x00\x00\x00" + b"\x5d" + b"\x48\x31\xed"
            + _conditional_loop(LOAD_EDX_RBP + XOR_EDX_EAX + STORE_RBP_EDX))
    loop = _proof(code)
    assert loop is not None
    assert loop.get_pc is None


@_needs_capstone
def test_the_same_window_without_the_clobber_does_correlate_it():
    """The control for the case above: with the `xor` removed and
    nothing else changed, `rbp` still carries what the pop read."""
    code = (b"\xe8\x00\x00\x00\x00" + b"\x5d"
            + _conditional_loop(LOAD_EDX_RBP + XOR_EDX_EAX + STORE_RBP_EDX))
    loop = _proof(code)
    assert loop is not None
    assert loop.get_pc is not None
    assert loop.get_pc.register == "rbp"


# ── windows that establish nothing ─────────────────────────────────────

@_needs_capstone
def test_a_window_that_did_not_decode_proves_nothing():
    """0x06 is invalid in 64-bit mode. Nothing decoded, so there is no
    graph and no proof -- not a partial one."""
    _instructions, result = _decode(b"\x06" * 64)
    assert result.stopped_reason == "decode_error"
    assert _proof(b"\x06" * 64) is None


@_needs_capstone
def test_a_window_truncated_before_the_store_proves_nothing():
    """The capture ends after the transform. What is missing is the store
    that would have completed the proof, and a proof is not completed by
    the bytes that were not captured."""
    assert _proof(LOAD_EDX_RBP + XOR_EDX_EAX) is None


@_needs_capstone
def test_an_empty_window_proves_nothing():
    assert find_transform_loop((), base_va=BASE_VA, window_len=0,
                               architecture="x64") is None


# ── the reachability gate says so when it withholds ────────────────────

# The intact register-mediated loop, with nothing before it.
_BARE_LOOP = _conditional_loop(LOAD_EDX_RBP + XOR_EDX_EAX + STORE_RBP_EDX)


@_needs_capstone
@pytest.mark.parametrize("anchor, description", [
    (b"\xeb\x40", "a jump out of the window -- a thread start that is a thunk"),
    (b"\xc3", "a return -- an explicit address one instruction early"),
    (b"\xf4", "hlt -- an anchor that landed in data"),
    (b"\xff\xe0", "jmp rax -- reached only through an indirect branch"),
])
def test_an_anchor_that_does_not_fall_through_withholds_and_says_so(
        anchor, description):
    """Reachability is seeded from the decode start, which is the card's
    anchor and not an entry point. An anchor that reaches nothing leaves
    every loop in the window unreachable -- so the lead is withheld, and
    the withholding is reported rather than left to look like a window
    that simply had no shape in it.

    This is the one rejection that says something about where the decode
    began rather than about the instructions, which is why it alone is
    surfaced."""
    code = anchor + _BARE_LOOP
    instructions, result = _decode(code)
    assert find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture="x64") is None, description
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture="x64") == WITHHELD_UNREACHABLE, description


@_needs_capstone
@pytest.mark.parametrize("mid, description", [
    (XOR_EDX_EAX + b"\xc1\xc2\x03", "a composite transform, xor then rol"),
    (XOR_EDX_EAX + b"\x89\xca", "the transformed value replaced before the store"),
    (XOR_EDX_EAX + b"\x39\x06", "a read this module cannot place, cmp [rsi], eax"),
])
def test_a_shape_the_evidence_cannot_prove_is_reported_as_withheld(
        mid, description):
    """The load, an attempted transform, and a store over one address are
    all there, inside a reachable loop -- and the value between them was
    not provably the same transformed value. An analyst reading the
    instruction rows cannot see which of those steps failed, so the
    decline is said out loud rather than left looking like a window that
    held nothing."""
    code = _conditional_loop(LOAD_EDX_RBP + mid + STORE_RBP_EDX)
    instructions, result = _decode(code)
    assert find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture="x64") is None, description
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture="x64") == WITHHELD_UNPROVEN, description


@_needs_capstone
@pytest.mark.parametrize("mid, store, description", [
    (b"", STORE_RBP_EDX, "a copy loop, which transforms nothing"),
    (XOR_EDX_EAX, bytes.fromhex("8913"), "a store at a different address"),
    (bytes.fromhex("31c8"), STORE_RBP_EDX,
     "a copy loop beside an operation on registers the load never reached"),
    (XOR_EDX_EAX, bytes.fromhex("894d00"),
     "a store of a register the transformed value never reached"),
    # The same-value idioms, which state their own result.
    (bytes.fromhex("31d2"), STORE_RBP_EDX, "xor edx, edx, which zeroes it"),
    (bytes.fromhex("29d2"), STORE_RBP_EDX, "sub edx, edx, likewise"),
    (bytes.fromhex("21d2"), STORE_RBP_EDX, "and edx, edx, which changes nothing"),
    (bytes.fromhex("09d2"), STORE_RBP_EDX, "or edx, edx, likewise"),
    (bytes.fromhex("19d2"), STORE_RBP_EDX, "sbb edx, edx, which leaves the carry"),
    (bytes.fromhex("89d1" "31ca"), STORE_RBP_EDX,
     "xor between two registers a mov made equal"),
    (bytes.fromhex("89d1" "29ca"), STORE_RBP_EDX, "sub between the same two"),
    (bytes.fromhex("89d1" "21ca"), STORE_RBP_EDX, "and between the same two"),
    (bytes.fromhex("89d1" "09ca"), STORE_RBP_EDX, "or between the same two"),
    (bytes.fromhex("89d1" "19ca"), STORE_RBP_EDX, "sbb between the same two"),
    # Immediates that leave the value alone or replace it with a constant.
    (bytes.fromhex("83c200"), STORE_RBP_EDX, "add edx, 0"),
    (bytes.fromhex("83ea00"), STORE_RBP_EDX, "sub edx, 0"),
    (bytes.fromhex("83f200"), STORE_RBP_EDX, "xor edx, 0"),
    (bytes.fromhex("83ca00"), STORE_RBP_EDX, "or edx, 0"),
    (bytes.fromhex("83e200"), STORE_RBP_EDX, "and edx, 0"),
    (bytes.fromhex("83e2ff"), STORE_RBP_EDX, "and edx, -1"),
    (bytes.fromhex("83caff"), STORE_RBP_EDX, "or edx, -1"),
    (bytes.fromhex("c1e200"), STORE_RBP_EDX, "shl edx, 0"),
    (bytes.fromhex("c1ea00"), STORE_RBP_EDX, "shr edx, 0"),
    (bytes.fromhex("c1fa00"), STORE_RBP_EDX, "sar edx, 0"),
    (bytes.fromhex("c1c200"), STORE_RBP_EDX, "rol edx, 0"),
    (bytes.fromhex("c1ca00"), STORE_RBP_EDX, "ror edx, 0"),
    # A transform of one copy while a different copy reaches memory.
    (bytes.fromhex("89d1" "31c1"), STORE_RBP_EDX,
     "the transformed copy is not the one stored"),
    (bytes.fromhex("89d1" "89d6" "31c1"), STORE_RBP_EDX,
     "two copies, one transformed, the untransformed one stored"),
    # An address whose version provably changed between the accesses.
    (XOR_EDX_EAX + bytes.fromhex("48ffc5"), STORE_RBP_EDX,
     "inc rbp, which makes the store a different address"),
    (XOR_EDX_EAX + bytes.fromhex("4883c504"), STORE_RBP_EDX,
     "add rbp, 4, likewise"),
    (XOR_EDX_EAX + bytes.fromhex("4889c5"), STORE_RBP_EDX,
     "mov rbp, rax, likewise"),
])
def test_a_clean_negative_is_not_reported_as_withheld(mid, store, description):
    """The contrast, and the boundary of the note. A copy loop writes
    back what it read, a different-address store lands elsewhere, a
    zeroing operation states that its result stopped deriving from the
    loaded value, an identity operation states that it changed nothing so
    the loop is still a copy loop, and a write to the address's own base
    register makes the two accesses two addresses. Every one of those is
    in the instruction rows, so nothing was withheld and nothing is said
    -- a note on every negative would say nothing at all."""
    code = _conditional_loop(LOAD_EDX_RBP + mid + store)
    instructions, result = _decode(code)
    assert find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture="x64") is None, description
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture="x64") is None, description


@_needs_capstone
@pytest.mark.parametrize("lost, description", [
    (b"\x89\xc2", "mov edx, eax replaces the loaded value outright"),
    (b"\x31\xd2", "xor edx, edx zeroes it"),
    (b"\x29\xd2", "sub edx, edx zeroes it"),
    (b"\x19\xd2", "sbb edx, edx leaves the carry flag alone"),
    (b"\x83\xe2\x00", "and edx, 0 replaces it with zero"),
    (b"\x83\xca\xff", "or edx, -1 replaces it with all ones"),
])
def test_a_value_lost_before_the_transform_is_not_reported_as_withheld(
        lost, description):
    """A transform below an instruction that threw the loaded value away
    transforms whatever replaced it, not what was read.

        mov edx, [rbp] / <loses the value> / xor edx, ecx / mov [rbp], edx

    No proof failed here for a reason the rows hide: the row that lost
    the value is a row an analyst reads. The note exists for declines
    that are invisible, so survival is relaxed only AFTER the first
    transform -- relaxing it before would let a value the rows show being
    discarded arrive at one, and put a note on a window holding
    nothing."""
    code = _conditional_loop(LOAD_EDX_RBP + lost + b"\x31\xca"
                             + STORE_RBP_EDX)
    instructions, result = _decode(code)
    assert find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture="x64") is None, description
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture="x64") is None, description


@_needs_capstone
def test_a_value_lost_after_the_transform_is_still_reported_as_withheld():
    """The other side of that boundary, so the rule above is not read as
    dropping the survival relaxation altogether. Here the transform
    happened TO the loaded value and its result was replaced afterwards
    -- the half the proof declines on, and the half the rows do not
    settle -- so the decline is still said out loud.

        mov edx, [rbp] / xor edx, eax / mov edx, ecx / mov [rbp], edx
    """
    code = _conditional_loop(LOAD_EDX_RBP + XOR_EDX_EAX + b"\x89\xca"
                             + STORE_RBP_EDX)
    instructions, result = _decode(code)
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture="x64") == WITHHELD_UNPROVEN


@_needs_capstone
@pytest.mark.parametrize("destroys, description", [
    (bytes.fromhex("89da"), "mov edx, ebx replaces the untransformed copy"),
    (bytes.fromhex("31d2"), "xor edx, edx zeroes it"),
    (bytes.fromhex("29d2"), "sub edx, edx zeroes it"),
    (bytes.fromhex("19d2"), "sbb edx, edx leaves the carry flag alone"),
    (bytes.fromhex("83e200"), "and edx, 0 writes a constant"),
    (bytes.fromhex("83caff"), "or edx, -1 writes a constant"),
    (bytes.fromhex("88c2"), "mov dl, al writes part of it"),
    (bytes.fromhex("6689c2"), "mov dx, ax writes part of it"),
])
def test_a_transformed_copy_does_not_shelter_an_untransformed_sibling(
        destroys, description):
    """One loaded value can sit in several registers at once, and what
    happened to one copy says nothing about another.

        mov edx, [rbp] / mov ecx, edx   -- two registers, one value
        xor ecx, eax                    -- the COPY is transformed
        <destroys edx>                  -- the original is not
        xor edx, esi                    -- transforms what replaced it
        mov [rbp], edx

    The transformed copy never reaches memory and the register that does
    holds something the rows show arriving from elsewhere. Nothing was
    withheld: no proof came close enough to decline. The survival
    relaxation the note rests on is therefore decided per tracked value,
    because a walk-wide flag would let `ecx` shelter `edx` here."""
    code = _conditional_loop(LOAD_EDX_RBP + bytes.fromhex("89d1" "31c1")
                             + destroys + bytes.fromhex("31f2")
                             + STORE_RBP_EDX)
    instructions, result = _decode(code)
    assert find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture="x64") is None, description
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture="x64") is None, description


@_needs_capstone
def test_a_transformed_copy_that_does_reach_the_store_is_still_withheld():
    """The other side of that boundary. The same two copies, and this
    time the transformed one is what the store reads -- so the decline is
    about whether it survived, which the rows do not settle, and the note
    stands.

        mov edx, [rbp] / mov ecx, edx / xor ecx, eax
        / mov ecx, ebx / mov [rbp], ecx
    """
    code = _conditional_loop(LOAD_EDX_RBP + bytes.fromhex("89d1" "31c1" "89d9")
                             + bytes.fromhex("894d00"))
    instructions, result = _decode(code)
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture="x64") == WITHHELD_UNPROVEN


@_needs_capstone
@pytest.mark.parametrize("code, arch, description", [
    # mov edx, [rax + rcx*4] / xor edx, eax / inc rcx / mov [rax + rcx*4], edx
    (bytes.fromhex("8b1488" "31c2" "48ffc1" "891488"), "x64",
     "a write to the index register"),
    # the same with a 32-bit write, which clears the rest of rcx
    (bytes.fromhex("8b1488" "31c2" "ffc1" "891488"), "x64",
     "a narrower write to the same register family"),
    # mov edx, fs:[rbp] / xor edx, eax / mov fs, eax / mov fs:[rbp], edx
    (bytes.fromhex("648b5500" "31c2" "8ee0" "64895500"), "x64",
     "a write to the segment selector the address names"),
    # the same span with wrfsbase, which moves the base and not the selector
    (bytes.fromhex("648b5500" "31c2" "f3480faed0" "64895500"), "x64",
     "wrfsbase, which moves the FS base without touching fs"),
    # mov edx, gs:[rbp] / xor edx, eax / swapgs / mov gs:[rbp], edx
    (bytes.fromhex("658b5500" "31c2" "0f01f8" "65895500"), "x64",
     "swapgs, which moves the GS base a gs: address resolves through"),
    (bytes.fromhex("648b5500" "31c2" "0f30" "64895500"), "x64",
     "wrmsr, whose target MSR is unresolved and may be either base"),
    # mov edx, [ebp] / xor edx, eax / mov ss, eax / mov [ebp], edx
    (bytes.fromhex("8b5500" "31c2" "8ed0" "895500"), "x86",
     "a write to the SS that a 32-bit [ebp] resolves through"),
])
def test_an_address_version_that_changed_is_not_reported_as_withheld(
        code, arch, description):
    """The address half of the withheld query is the proof's own. A base,
    an index, a named segment selector and an implied one are each a way
    for two accesses with identical text to reach different bytes, and a
    segment BASE moves without the selector being written at all. Each of
    those is an instruction an analyst reads in the rows, so the two
    accesses are not a same-address candidate and there is nothing to
    call unproven."""
    instructions, result = _decode(_conditional_loop(code), architecture=arch)
    assert find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture=arch) is None, description
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture=arch) is None, description


@_needs_capstone
@pytest.mark.parametrize("code, description", [
    # mov edx, [rbp] / xor edx, eax / wrfsbase rax / mov [rbp], edx
    (bytes.fromhex("8b5500" "31c2" "f3480faed0" "895500"),
     "wrfsbase beside an address with no segment prefix at all"),
    # mov edx, gs:[rbp] / xor edx, eax / wrfsbase rax / mov gs:[rbp], edx
    (bytes.fromhex("658b5500" "31c2" "f3480faed0" "65895500"),
     "wrfsbase beside a gs: address"),
    # mov edx, fs:[rbp] / xor edx, eax / wrgsbase rax / mov fs:[rbp], edx
    (bytes.fromhex("648b5500" "31c2" "f3480faed8" "64895500"),
     "wrgsbase beside an fs: address"),
])
def test_a_base_write_to_another_segment_leaves_the_address_proven(
        code, description):
    """A segment base write moves ONE region. `wrfsbase` relocates every
    FS-relative address and leaves a `gs:[rbp]` -- and a plain `[rbp]`,
    which in 64-bit code resolves through a base the architecture forces
    to zero -- exactly where they were. Reading any base write as moving
    every address would surrender a proof the rows fully support, and a
    window holding one of these instructions is not rare."""
    instructions, result = _decode(_conditional_loop(code))
    loop = find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture="x64")
    assert loop is not None, description
    assert loop.form == LOAD_TRANSFORM_STORE


@_needs_capstone
def test_a_reachable_loop_is_not_reported_as_withheld():
    """The control: the same loop with an anchor that falls through to
    it. The lead is read, so there is nothing withheld to report."""
    code = NOP1 + _BARE_LOOP
    instructions, result = _decode(code)
    assert find_transform_loop(instructions, base_va=BASE_VA,
                               window_len=result.window_bytes,
                               architecture="x64") is not None
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture="x64") is None


@_needs_capstone
def test_a_window_with_no_shape_at_all_reports_nothing_withheld():
    """A rejection for any other reason is a statement about the
    instructions and needs no note. A window with no transform loop in it
    has nothing withheld, unreachable or otherwise."""
    instructions, result = _decode(b"\x48\x83\xc0\x10" + b"\x48\xff\xc0" + RET)
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture="x64") is None


@_needs_capstone
def test_a_copy_loop_behind_an_unreachable_anchor_is_still_not_a_shape():
    """The gate reports only what the OTHER rules would have proven. A
    copy loop that no rule accepts is not something reachability
    withheld, so an unreachable anchor over one reports nothing."""
    copy = _conditional_loop(LOAD_EDX_RBP + STORE_RBP_EDX)
    instructions, result = _decode(b"\xc3" + copy)
    assert transform_loop_withheld(
        instructions, base_va=BASE_VA, window_len=result.window_bytes,
        architecture="x64") is None


# ── the caps are consulted ─────────────────────────────────────────────

# The transformed value copied into one more register per instruction.
# With the load's own destination that is nine tracked names by the
# eighth copy, one past MAX_TRACKED_VALUES.
_COPIES_OF_EDX = (b"\x89\xd1" + b"\x89\xd3" + b"\x89\xd6" + b"\x89\xd7"
                  + b"\x41\x89\xd0" + b"\x41\x89\xd1" + b"\x41\x89\xd2"
                  + b"\x41\x89\xd3")


@_needs_capstone
def test_a_span_past_the_tracked_value_cap_ends_the_candidate():
    """Eight copies plus the load's own destination is nine values at
    once. A span this module has stopped being able to account for ends
    the candidate rather than carrying an unbounded set."""
    body = LOAD_EDX_RBP + XOR_EDX_EAX + _COPIES_OF_EDX + STORE_RBP_EDX
    assert _proof(_conditional_loop(body)) is None


@_needs_capstone
def test_a_span_within_the_cap_still_proves_itself():
    """The control: the same span one copy shorter is eight values, at
    the cap and not past it."""
    body = (LOAD_EDX_RBP + XOR_EDX_EAX + _COPIES_OF_EDX[:-3] + STORE_RBP_EDX)
    loop = _proof(_conditional_loop(body))
    assert loop is not None
    assert loop.form == LOAD_TRANSFORM_STORE


@_needs_capstone
def test_the_proof_attempt_cap_is_consulted(monkeypatch):
    """A window that would otherwise prove a loop proves nothing once the
    candidate budget is spent, so the cap bounds the search rather than
    documenting a bound the code does not apply."""
    import dumpex.core.insn_flow as flow
    assert _proof(REGISTER_MEDIATED_STUB) is not None
    monkeypatch.setattr(flow, "MAX_PROOF_ATTEMPTS", 0)
    assert _proof(REGISTER_MEDIATED_STUB) is None


# ── the graph itself ───────────────────────────────────────────────────

@_needs_capstone
def test_a_conditional_branch_has_both_of_its_edges():
    #   je +2 / nop / nop / ret
    instructions, _result = _decode(b"\x74\x02" + NOP1 + NOP1 + RET)
    cfg = build_local_cfg(instructions)
    assert set(cfg.successors(BASE_VA)) == {
        (EdgeKind.CONDITIONAL, BASE_VA + 4), (EdgeKind.FALL_THROUGH, BASE_VA + 2)}


@_needs_capstone
def test_an_unconditional_branch_has_only_its_taken_edge():
    #   jmp +2 / nop / nop / ret
    instructions, _result = _decode(b"\xeb\x02" + NOP1 + NOP1 + RET)
    cfg = build_local_cfg(instructions)
    assert cfg.successors(BASE_VA) == ((EdgeKind.UNCONDITIONAL, BASE_VA + 4),)
    # The two NOPs are in the window, decoded, and reachable from
    # nothing -- which is what "bytes after a branch may be data" means
    # in graph terms.
    assert BASE_VA + 2 not in cfg.reachable_from(BASE_VA)
    assert BASE_VA + 3 not in cfg.reachable_from(BASE_VA)


@_needs_capstone
def test_a_call_keeps_its_own_edge_kind_and_still_continues_below():
    #   call +0 / pop rax / ret
    instructions, _result = _decode(b"\xe8\x00\x00\x00\x00" + b"\x58" + RET)
    cfg = build_local_cfg(instructions)
    assert set(cfg.successors(BASE_VA)) == {
        (EdgeKind.CALL, BASE_VA + 5), (EdgeKind.FALL_THROUGH, BASE_VA + 5)}


@_needs_capstone
def test_a_branch_out_of_the_window_contributes_no_edge():
    """A destination this decode did not produce is not a node, so the
    path that leaves is a path the graph does not follow."""
    #   jmp +0x40, well past these bytes
    instructions, _result = _decode(b"\xeb\x40" + RET)
    cfg = build_local_cfg(instructions)
    assert cfg.successors(BASE_VA) == ()


# ── effective-address equivalence on its own ───────────────────────────

def test_an_address_with_an_unresolved_component_agrees_with_nothing():
    """A component the decoder named and could not represent leaves the
    field holding its own default, which reads exactly like a real
    `[base + 0]`. An unknown is never evidence of agreement, so an
    operand carrying the flag matches nothing -- another operand with the
    same text, and its own identical self, included."""
    known = MemoryOperand(base="rbp", width=4, reads=True)
    unknown = MemoryOperand(base="rbp", width=4, reads=True,
                            components_unknown=True)
    assert same_effective_address(known, known)
    assert not same_effective_address(known, unknown)
    assert not same_effective_address(unknown, known)
    assert not same_effective_address(unknown, unknown)


@_needs_capstone
def test_two_spellings_of_one_address_agree_and_a_third_does_not():
    instructions, _result = _decode(
        LOAD_EDX_RBP + STORE_RBP_EDX + b"\x89\x55\x04" + RET)
    load, store, elsewhere = instructions[0], instructions[1], instructions[2]
    assert same_effective_address(load.memory_operands[0], store.memory_operands[0])
    assert not same_effective_address(load.memory_operands[0],
                                      elsewhere.memory_operands[0])
