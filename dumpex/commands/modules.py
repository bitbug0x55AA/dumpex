"""--modules command."""
import os
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW
from dumpex.core.memory import get_modules
from dumpex.core.pe_utils import _pe_timestamp_to_str, _version_str

def cmd_modules(mf):
    mods = get_modules(mf)
    rows = []

    for m in sorted(mods, key=lambda x: x.baseaddress):
        name     = m.name or "(unnamed)"
        basename = os.path.basename(name)

        ts_raw   = getattr(m, "timestamp", 0) or 0
        ts_str   = _pe_timestamp_to_str(ts_raw)
        ver_str  = _version_str(getattr(m, "versioninfo", None))
        checksum = getattr(m, "checksum", 0) or 0

        plain_flags, colored_flags = [], []
        if not m.name:
            plain_flags.append("NO_NAME");      colored_flags.append(RED("[NO NAME]"))
        if ts_raw and ts_raw < 315532800:
            plain_flags.append("OLD_TIMESTAMP"); colored_flags.append(YELLOW("[OLD TIMESTAMP]"))
        flag_str = "  " + " ".join(colored_flags) if colored_flags else ""

        print(f"\n  {BOLD(basename)}{flag_str}")
        print(f"  {'Full path':<18} {DIM(name)}")
        print(f"  {'Base → End':<18} 0x{m.baseaddress:016x} → 0x{m.endaddress:016x}  (size 0x{m.size:x})")
        print(f"  {'Compiled (UTC)':<18} {ts_str}")
        if ver_str:
            print(f"  {'File version':<18} {ver_str}")
        if checksum:
            print(f"  {'Checksum':<18} 0x{checksum:08x}")

        rows.append({
            "name":          basename,
            "full_path":     m.name or "",
            "base_address":  f"0x{m.baseaddress:016x}",
            "end_address":   f"0x{m.endaddress:016x}",
            "size":          m.size,
            "size_hex":      f"0x{m.size:x}",
            "compiled_utc":  ts_str,
            "file_version":  ver_str or "",
            "checksum":      f"0x{checksum:08x}" if checksum else "",
            "anomaly_flags": "|".join(plain_flags),
        })

    print(f"\n{GREEN(f'[+] {len(mods)} module(s).')}")
    return rows

