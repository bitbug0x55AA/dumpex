"""Module header parsing, per-section protection deviation checks, and
the unscored IOC-string region scan. Only collects facts — never scores,
never prints.
"""
import ntpath
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import addr_to_module, prot_str, _extract_ioc_strings
from dumpex.core.pe_utils import (parse_pe_header, expected_protection_name,
    section_protection_deviates)
from dumpex.hunt.stomping.models import IocScan

# API-name tokens that ALSO commonly appear in benign/legitimate code paths
# (loader stubs, debuggers, security tooling itself) -- flagged as "weak"
# rather than dropped outright, so an analyst still sees them but doesn't
# have them inflate the apparent strength of an IOC hit.
_WEAK_IOC_TERMS = {"virtualalloc", "writeprocessmemory",
                   "createremotethread", "wsasocket", "base64"}


def _module_basename(module) -> str:
    """
    Module paths recorded in a minidump are from the ORIGINAL Windows
    system (e.g. 'C:\\Windows\\System32\\foo.dll'). os.path.basename only
    splits on '/' when running on a POSIX analysis host, so it returns the
    whole backslash-separated string unchanged there — ntpath.basename
    always applies Windows path rules regardless of the host OS this
    tool itself runs on.
    """
    return ntpath.basename(module.name or "") if module.name else ""


def _regions_covering(start: int, end: int, regions: list) -> list:
    """MemoryInfo regions whose [BaseAddress, BaseAddress+RegionSize) overlaps [start, end)."""
    out = []
    for r in regions:
        rs, re_ = r.BaseAddress, r.BaseAddress + r.RegionSize
        if rs < end and re_ > start:
            out.append(r)
    return out


def read_module_header(mf: MinidumpFile, read_region, module, max_read: int) -> "tuple[dict, bool]":
    """
    Read and parse one module's own PE header out of process memory.
    Returns (pe_dict_or_None, read_failed). `read_region` is threaded
    explicitly (not imported from the facade) so this stays testable and
    monkeypatch-safe -- see dumpex/hunt/_runtime.py.
    """
    try:
        header_bytes = read_region(mf, module.baseaddress, min(max_read, module.size or max_read))
    except Exception:
        return None, True
    return parse_pe_header(header_bytes), False


def section_va_range(module_base: int, section: dict) -> "tuple[int, int]":
    va_start = module_base + section["virtual_address"]
    va_end   = va_start + max(section["virtual_size"], section["size_of_raw_data"], 1)
    return va_start, va_end


def check_section_protection(module, section: dict, va_start: int, va_end: int, regions: list) -> list:
    """
    Protection-deviation LEAD candidates for one eligible (executable,
    non-writable) section — informational, never scored (see
    dumpex/hunt/stomping/__init__.py's module docstring for why WRITECOPY
    is excluded and why deviation alone still isn't proof either way).
    """
    leads = []
    for region in _regions_covering(va_start, va_end, regions):
        if prot_str(region.State) != "MEM_COMMIT":
            continue
        actual = prot_str(region.Protect)
        if section_protection_deviates(actual, section):
            leads.append({
                "module": module, "section": section, "region": region,
                "expected": expected_protection_name(section["is_readable"],
                                                       section["is_writable"], section["is_executable"]),
                "actual": actual,
                "va_start": va_start, "va_end": va_end,
            })
    return leads


def _classify_ioc_hits(strings, patterns) -> list:
    hits = []
    for off, enc, s in strings:
        for pat in patterns:
            for m in pat.finditer(s):
                token = m.group(0)
                hits.append((off + m.start(), enc, token,
                             token.casefold() in _WEAK_IOC_TERMS))
    return hits


def scan_ioc_strings(mf: MinidumpFile, read_region, regions: list, modules: list,
                      whitelist, ioc_patterns, net_ioc_patterns) -> IocScan:
    """
    Scan every executable MEM_IMAGE region for IOC-pattern strings — an
    unscored, low-confidence lead (see dumpex/hunt/_finding.py for why raw
    string matches never drive a verdict on their own in phase two).
    """
    ioc_hits = []
    skipped_wl = []
    weak_only_skipped = []
    ioc_read_failed = 0

    for r in regions:
        mtype = prot_str(r.Type)
        p     = prot_str(r.Protect)
        state = prot_str(r.State)
        if "MEM_IMAGE" not in mtype or state != "MEM_COMMIT":
            continue
        if "EXECUTE" not in p:
            continue
        if r.RegionSize > 0x500000:
            continue

        mod      = addr_to_module(r.BaseAddress, modules)
        mod_name = (_module_basename(mod).lower() if mod else "")
        is_wl    = mod_name in whitelist

        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            ioc_read_failed += 1
            continue

        strings = _extract_ioc_strings(data, r.BaseAddress)
        patterns = ([ioc_patterns] if is_wl else [ioc_patterns, net_ioc_patterns])
        hits = _classify_ioc_hits(strings, patterns)

        if not hits:
            if is_wl:
                skipped_wl.append(mod_name)
            continue
        strong_hits = [h for h in hits if not h[3]]
        if not strong_hits:
            weak_only_skipped.append((r, mod, hits))
            continue
        ioc_hits.append((r, mod, hits, not is_wl))

    return IocScan(ioc_hits=ioc_hits, skipped_wl=skipped_wl,
                    weak_only_skipped=weak_only_skipped, ioc_read_failed=ioc_read_failed)
