"""PE / FILETIME formatting utilities."""
import datetime
from dumpex.ui.colors import RED, YELLOW, DIM

def _pe_timestamp_to_str(ts: int) -> str:
    """
    Convert a PE TimeDateStamp (Unix epoch, 32-bit) to a UTC string.
    Returns a dimmed note for zero / sentinel values.
    """
    import datetime
    if not ts:
        return DIM("(not set)")
    if ts == 0xFFFFFFFF:
        return DIM("(reproducible build — timestamp suppressed)")
    try:
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        if dt.year < 1980 or dt.year > 2040:
            return f"0x{ts:08x}  {YELLOW('(suspicious value)')}"
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return f"0x{ts:08x}  {YELLOW('(out of range)')}"


def _version_str(vi) -> str:
    """
    Format VS_FIXEDFILEINFO into 'major.minor.patch.build' strings.
    Returns None if the block is absent or entirely zero.
    """
    if vi is None:
        return None
    try:
        fv_ms = vi.dwFileVersionMS
        fv_ls = vi.dwFileVersionLS
        pv_ms = vi.dwProductVersionMS
        pv_ls = vi.dwProductVersionLS
        if fv_ms == 0 and fv_ls == 0 and pv_ms == 0 and pv_ls == 0:
            return None
        file_ver    = f"{fv_ms >> 16}.{fv_ms & 0xFFFF}.{fv_ls >> 16}.{fv_ls & 0xFFFF}"
        product_ver = f"{pv_ms >> 16}.{pv_ms & 0xFFFF}.{pv_ls >> 16}.{pv_ls & 0xFFFF}"
        if file_ver == product_ver:
            return file_ver
        return f"{file_ver}  (product: {product_ver})"
    except Exception:
        return None


def _filetime_to_str(ft: int) -> str:
    """
    Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to a
    human-readable UTC string.  Returns "(none)" for zero / unset values.
    """
    import datetime
    if not ft:
        return "(none)"
    try:
        # FILETIME epoch offset to Unix epoch in microseconds
        EPOCH_DIFF_US = 11644473600 * 1_000_000
        us = ft // 10 - EPOCH_DIFF_US
        dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"0x{ft:x}"


def _dumpflags_str(flags) -> str:
    """Return a compact label for MINIDUMP_THREAD_INFO DumpFlags."""
    if flags is None:
        return ""
    name = flags.name if hasattr(flags, "name") else str(flags)
    # Map verbose enum names to short tags
    TAG = {
        "MINIDUMP_THREAD_INFO_EXITED_THREAD":   "[EXITED]",
        "MINIDUMP_THREAD_INFO_WRITING_THREAD":  "[DUMPER]",
        "MINIDUMP_THREAD_INFO_ERROR_THREAD":    "[ERROR]",
        "MINIDUMP_THREAD_INFO_INVALID_CONTEXT": "[NO_CTX]",
        "MINIDUMP_THREAD_INFO_INVALID_INFO":    "[NO_INFO]",
        "MINIDUMP_THREAD_INFO_INVALID_TEB":     "[NO_TEB]",
    }
    return TAG.get(name, f"[{name}]") if name else ""

