"""The build's own capability check.

A Python installation can add the instruction decoder with an extra at
any time. A packaged executable cannot: the decoder it was built with is
the decoder its users get, so a build that lost the `capstone` package,
its package data, or its native library ships a headline `--report`
capability that nobody who has the executable can repair.

This module decodes fixed synthetic bytes -- `90 c3`, x86 `nop` followed
by `ret` -- through :func:`dumpex.core.disasm.decode_window`, the same
seam `--report` instruction context decodes through, and reports whether
the build can do what it advertises. It is the production path under
test, not a copy of it: nothing here re-implements decoding, and no
second disassembler is consulted.

The check reads no dump, no case data, and no file at all. Its exit code
is a release gate in its own right -- 0 usable, 1 not -- and is
deliberately separate from the coverage-derived exit codes the analysis
commands return.
"""
import sys
from dataclasses import dataclass

from dumpex.core.disasm import (
    SUPPORTED_ARCHITECTURES, DisasmAvailability, DisasmBackendStatus,
    backend_status, decode_window,
)
from dumpex.core.runtime import is_frozen, runtime_kind

__all__ = [
    "SELF_CHECK_BYTES",
    "SELF_CHECK_EXPECTED_MNEMONICS",
    "SelfCheckResult",
    "run_disasm_self_check",
    "cmd_self_check",
]

#: The synthetic instruction pair every self-check decodes: `nop` then
#: `ret`, one byte each and valid in both 32-bit and 64-bit mode, so one
#: constant exercises every supported architecture.
SELF_CHECK_BYTES = b"\x90\xc3"
SELF_CHECK_EXPECTED_MNEMONICS = ("nop", "ret")

# The base virtual address each architecture decodes at. x86 decodes
# inside the 32-bit address space so the check never depends on how an
# out-of-range base is handled.
_SELF_CHECK_BASE_VA = {"x86": 0x00401000, "x64": 0x140001000}

# The decoded bytes as they are rendered in the report line, so a release
# log says exactly what was asked of the decoder.
_BYTES_LABEL = " ".join(f"{byte:02x}" for byte in SELF_CHECK_BYTES)

_TITLE = "dumpex self-check: instruction decoder"


@dataclass(frozen=True)
class SelfCheckResult:
    """One self-check run: whether every check passed, and the report
    lines in the order they are printed.

    ``lines`` is printable ASCII with no traceback and no filesystem
    path: a backend failure is described by the raising exception's type
    and the bounded sanitized reason the disassembler seam already
    produced.
    """
    ok: bool
    lines: tuple


def run_disasm_self_check() -> SelfCheckResult:
    """Decode :data:`SELF_CHECK_BYTES` for every architecture in
    ``SUPPORTED_ARCHITECTURES`` and report the outcome.

    Passing requires the backend to load, every supported architecture to
    decode, and each decode to yield exactly
    :data:`SELF_CHECK_EXPECTED_MNEMONICS` with every byte accounted for.
    An absent module, a native library that did not load, an architecture
    this build cannot decode, and a decode that produced other
    instructions are each a reason the build cannot do what its Report
    output claims, and each fails.
    """
    backend = backend_status()
    lines = [_TITLE, f"  runtime: {runtime_kind()}"]

    if not backend.available:
        lines.append(f"  backend: {backend.status.value}")
        if backend.exception_type:
            lines.append(f"  raised: {backend.exception_type}")
        if backend.reason:
            lines.append(f"  reason: {backend.reason}")
        lines.append(f"  {_unavailable_guidance(backend)}")
        return SelfCheckResult(ok=False, lines=tuple(lines))

    version = f" (capstone {backend.version})" if backend.version else ""
    lines.append(f"  backend: {backend.status.value}{version}")

    ok = True
    for architecture in SUPPORTED_ARCHITECTURES:
        detail, passed = _check_architecture(architecture)
        ok = ok and passed
        lines.append(f"  {architecture}: {detail}")
    return SelfCheckResult(ok=ok, lines=tuple(lines))


def _check_architecture(architecture: str) -> "tuple[str, bool]":
    """``(detail, passed)`` for one architecture's decode of
    :data:`SELF_CHECK_BYTES`. The detail names what came back, so a
    failing release log says which stage broke without a traceback."""
    result = decode_window(code=SELF_CHECK_BYTES,
                           base_va=_SELF_CHECK_BASE_VA[architecture],
                           architecture=architecture)
    if result.availability is not DisasmAvailability.AVAILABLE:
        return "no decoder answered", False
    if not result.arch_supported:
        return "this build does not decode this architecture", False
    if not result.decoded_ok:
        return f"decoding stopped at {result.stopped_reason}", False
    mnemonics = tuple(insn.mnemonic for insn in result.instructions)
    if mnemonics != SELF_CHECK_EXPECTED_MNEMONICS:
        return (f"{_BYTES_LABEL} decoded to "
                f"{_render(mnemonics) or '(nothing)'}, expected "
                f"{_render(SELF_CHECK_EXPECTED_MNEMONICS)}"), False
    return f"{_BYTES_LABEL} -> {_render(mnemonics)}", True


def _render(mnemonics) -> str:
    return ", ".join(mnemonics)


def _unavailable_guidance(backend) -> str:
    """The one actionable sentence for a backend that did not load,
    chosen by how this process was packaged.

    A packaged executable ships its own decoder, so a backend missing
    there is a defect in that build and `pip` cannot repair it. Only a
    Python installation is told to install the optional extra, and only
    when the dependency is genuinely absent rather than present and
    unloadable."""
    if is_frozen():
        return ("this executable's bundled decoder is missing or unloadable: "
                "the build is incomplete and must not be published")
    if backend.status is DisasmBackendStatus.MODULE_ABSENT:
        return "install the optional decoder with: pip install dumpex[disasm]"
    return ("the installed decoder did not load: reinstall capstone for this "
            "interpreter and platform")


def cmd_self_check(stream=None) -> int:
    """Run the self-check, print its report, and return the process exit
    code: 0 when this build's decoder is usable, 1 when it is not."""
    out = stream if stream is not None else sys.stdout
    result = run_disasm_self_check()
    for line in result.lines:
        print(line, file=out)
    print(f"self-check: {'PASS' if result.ok else 'FAIL'}", file=out)
    return 0 if result.ok else 1
