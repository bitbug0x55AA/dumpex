"""Release gate: a built dumpex executable must decode instructions.

Runs the executable's own `--self-check` in a separate process and
requires it to report a usable instruction decoder. That check decodes
fixed synthetic bytes (`90 c3`, `nop` then `ret`) through
`dumpex.core.disasm.decode_window()` -- the same seam `--report`
instruction context decodes through -- so a build whose Capstone package,
package data, or native `capstone.dll` did not survive packaging fails
here rather than in front of an analyst.

Run it against `dist/dumpex.exe` and again against the copy extracted
from the final versioned ZIP, so staging and archiving cannot drop a
required file unnoticed.

Deliberately NOT a pytest test: it tests a built artifact and must run
with nothing from this repository imported, against an executable that
carries its own interpreter. No dump, no case data, and no second
disassembler are involved.

Usage:
    python frozen_disasm_smoke.py <path-to-dumpex-executable>
"""
import subprocess
import sys

# The self-check report lines this gate requires, verbatim. They are the
# executable's contract with this script; tests/unit/test_selfcheck.py
# pins them against dumpex.core.selfcheck's own output so the two cannot
# drift apart silently.
REQUIRED_LINES = (
    "backend: available",
    "x86: 90 c3 -> nop, ret",
    "x64: 90 c3 -> nop, ret",
    "self-check: PASS",
)

# Generous enough for a cold one-file executable unpacking itself on a
# loaded runner, short enough that a hung build fails rather than stalls.
TIMEOUT_SECONDS = 180


def _fail(message: str) -> None:
    print(f"FAIL: {message}")
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 2:
        _fail("usage: frozen_disasm_smoke.py <path-to-dumpex-executable>")
    executable = sys.argv[1]

    try:
        completed = subprocess.run(
            [executable, "--self-check"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=TIMEOUT_SECONDS)
    except OSError as exc:
        _fail(f"could not run {executable}: {type(exc).__name__}")
    except subprocess.TimeoutExpired:
        _fail(f"{executable} --self-check did not finish within {TIMEOUT_SECONDS}s")

    output = (completed.stdout or "") + (completed.stderr or "")
    print(output.strip())

    if completed.returncode != 0:
        _fail(f"{executable} --self-check exited {completed.returncode}: this build's "
              f"instruction decoder is missing or unloadable")

    missing = [line for line in REQUIRED_LINES if line not in output]
    if missing:
        _fail(f"{executable} --self-check exited 0 without reporting: "
              f"{', '.join(missing)}")

    print(f"OK: {executable} decodes 90 c3 as nop, ret on x86 and x64")


if __name__ == "__main__":
    main()
