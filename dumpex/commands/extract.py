"""--extract and --strings commands."""
import re
import sys
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.core.memory import read_region

def cmd_extract(mf, addr, size, output, auto_size=False):
    auto_note = DIM(" (auto from region)") if auto_size else ""
    print(f"[*] Reading 0x{size:x}{auto_note} bytes from 0x{addr:x} ...")
    try:
        data = read_region(mf, addr, size)
    except Exception as e:
        print(RED(f"[!] Read failed: {e}")); sys.exit(1)

    if data[:2] == b'MZ':
        print(YELLOW("[!] MZ header detected — this looks like an injected PE!"))

    out = output or f"region_0x{addr:x}.bin"
    Path(out).write_bytes(data)
    print(GREEN(f"[+] Saved {len(data)} bytes → {out}"))


def cmd_strings(mf, addr, size, min_len, grep, encoding, auto_size=False):
    auto_note = DIM(" (auto from region)") if auto_size else ""
    print(f"[*] Extracting strings from 0x{addr:x} (size=0x{size:x}{auto_note}, min={min_len}, enc={encoding})")
    try:
        data = read_region(mf, addr, size)
    except Exception as e:
        print(RED(f"[!] Read failed: {e}")); sys.exit(1)

    results = []
    if encoding in ("ascii", "both"):
        pat = rb'[ -~]{' + str(min_len).encode() + rb',}'
        results += [(m.start(), "ASCII", m.group().decode("ascii", errors="replace"))
                    for m in re.finditer(pat, data)]
    if encoding in ("unicode", "both"):
        pat = rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}'
        results += [(m.start(), "UTF16", m.group().decode("utf-16-le", errors="replace"))
                    for m in re.finditer(pat, data)]

    results.sort(key=lambda x: x[0])
    grep_re = re.compile(grep, re.IGNORECASE) if grep else None

    print(f"\n{BOLD('Offset'):<14} {BOLD('Enc'):<7} {BOLD('String')}")
    print("─" * 70)
    shown = 0
    for offset, enc, s in results:
        if grep_re and not grep_re.search(s):
            continue
        line = f"0x{addr + offset:<12x} {enc:<7} {s}"
        print(YELLOW(line) if grep_re else line)
        shown += 1
    print(f"\n{GREEN(f'[+] {shown} string(s) shown.')}")

