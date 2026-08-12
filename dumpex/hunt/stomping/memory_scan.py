"""Module header parsing, per-section protection deviation checks, and
the unscored IOC-string region scan. Only collects facts — never scores,
never prints.

Since the canonical-Report migration this is also one of the two places
(with correlation.py) that a raw minidump `Module`/`MinidumpMemoryInfo`/
`parse_pe_header()` section dict is allowed to be touched at all: every
function here returns the immutable Evidence value objects
dumpex/hunt/stomping/models.py defines, with module basenames and
`prot_str()` protections resolved ONCE, here, so aggregate.py and the
report_* projectors never see a raw object or re-derive a formatted one.
"""
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import (addr_to_module, prot_str, va_to_file_offset,
    _extract_ioc_strings)
from dumpex.core.pe_utils import (parse_pe_header, expected_protection_name,
    section_protection_deviates)
from dumpex.hunt._coverage import CoverageTracker, region_scan_target
from dumpex.hunt.stomping.config import IOC_SCAN_MAX
from dumpex.hunt.stomping.models import (
    IocCoverage, IocHitEvidence, IocScanResult, IocTokenHit, ProtectionLeadEvidence,
    _module_basename, module_ref, region_ref, section_ref,
)

# `_module_basename` is re-exported (imported above from models.py, where
# it now lives alongside `module_ref()` -- resolving a basename IS part of
# building a ModuleRef) so dumpex.hunt.stomping.disk_reference's existing
# `from ...memory_scan import _module_basename` keeps working unchanged.
__all__ = ["_module_basename", "read_module_header", "section_va_range",
            "check_section_protection", "scan_ioc_strings"]

# API-name tokens that ALSO commonly appear in benign/legitimate code paths
# (loader stubs, debuggers, security tooling itself) -- flagged as "weak"
# rather than dropped outright, so an analyst still sees them but doesn't
# have them inflate the apparent strength of an IOC hit.
_WEAK_IOC_TERMS = {"virtualalloc", "writeprocessmemory",
                   "createremotethread", "wsasocket", "base64"}


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


def check_section_protection(mf: MinidumpFile, module, section: dict, va_start: int,
                              va_end: int, regions: list) -> tuple:
    """
    Protection-deviation LEAD candidates for one eligible (executable,
    non-writable) section — informational, never scored (see
    dumpex/hunt/stomping/__init__.py's module docstring for why WRITECOPY
    is excluded and why deviation alone still isn't proof either way).

    Returns a tuple of immutable `ProtectionLeadEvidence`, not the
    pre-migration `{"module": <Module>, "region": <MinidumpMemoryInfo>,
    ...}` dicts: identity/protection strings are snapshotted here, so the
    two live minidump objects those dicts used to carry all the way into
    the JSON projection are unreachable from the Report.

    `module`/`section`/`file_offset` are resolved once for the whole
    section rather than per covering region -- a section can overlap
    several MemoryInfo regions, and rebuilding the same identity per
    region would both repeat a `va_to_file_offset()` lookup and make
    equal-but-distinct copies of a value object the evidence buckets then
    dedup on. All three are resolved LAZILY, only once a region actually
    deviates, so the (rare) skip path costs nothing.
    """
    leads = []
    module_snapshot = None
    section_snapshot = None
    file_offset = None
    for region in _regions_covering(va_start, va_end, regions):
        if prot_str(region.State) != "MEM_COMMIT":
            continue
        actual = prot_str(region.Protect)
        if not section_protection_deviates(actual, section):
            continue
        if module_snapshot is None:
            module_snapshot, section_snapshot = module_ref(module), section_ref(section)
            file_offset = va_to_file_offset(mf, va_start)
        leads.append(ProtectionLeadEvidence(
            module=module_snapshot, section=section_snapshot, region=region_ref(region),
            expected=expected_protection_name(section["is_readable"], section["is_writable"],
                                               section["is_executable"]),
            actual=actual, va_start=va_start, va_end=va_end, file_offset=file_offset))
    return tuple(leads)


def _classify_ioc_hits(strings, patterns, region_base: int) -> tuple:
    """Every IOC-pattern token match across one region's extracted strings,
    as immutable `IocTokenHit`s with their absolute VA already resolved --
    `_extract_ioc_strings` reports region-relative offsets, and resolving
    the VA here (once) is what stops two projectors adding
    `region.base_address + offset` independently."""
    hits = []
    for off, enc, s in strings:
        for pat in patterns:
            for m in pat.finditer(s):
                token = m.group(0)
                offset = off + m.start()
                hits.append(IocTokenHit(offset=offset, va=region_base + offset, encoding=enc,
                                         token=token,
                                         is_weak=token.casefold() in _WEAK_IOC_TERMS))
    return tuple(hits)


def scan_ioc_strings(mf: MinidumpFile, read_region, regions: list, modules: list,
                      whitelist, ioc_patterns, net_ioc_patterns) -> IocScanResult:
    """
    Scan every executable MEM_IMAGE region for IOC-pattern strings — an
    unscored, low-confidence lead (see dumpex/hunt/_finding.py for why raw
    string matches never drive a verdict on their own in phase two).

    Every region that passes the eligibility filters (committed,
    MEM_IMAGE, executable) but is then NOT actually read IN FULL is
    accounted for on the returned IocScanResult.coverage: over IOC_SCAN_MAX
    -> a skipped-oversize ScanTarget carrying that exact region's VA/size/
    file offset/protection and the cap it exceeded; read raised -> a
    read-failure count; fewer bytes came back than RegionSize -> a
    short-read count (the readable prefix is still scanned -- a real hit
    in it is still a real hit -- but this must not be miscounted as a
    complete read of the region: a short read that happens to land on an
    all-zero/patternless prefix is indistinguishable from "nothing here"
    without this flag, and the unread remainder could hide anything).
    None of these three may be dropped silently — a scan that examined
    only part of its own eligible scope must not be renderable as a
    complete, clean IOC result (see report_console.py / this package's
    docstring).

    The live `CoverageTracker` is frozen into an `IocCoverage` before it is
    returned, so nothing downstream can mutate this scan's own result.
    """
    ioc_hits = []
    skipped_wl = []
    weak_only_regions = 0
    coverage = CoverageTracker()

    for r in regions:
        mtype = prot_str(r.Type)
        p     = prot_str(r.Protect)
        state = prot_str(r.State)
        if "MEM_IMAGE" not in mtype or state != "MEM_COMMIT":
            continue
        if "EXECUTE" not in p:
            continue
        # Eligible from here on, so the next two `continue`s are not filter
        # misses but coverage gaps -- a region this scan was supposed to
        # read and didn't. Both are recorded on `coverage`; the `continue`s
        # further down (no hits / weak-only hits) are results from a region
        # that WAS fully read, not gaps.
        if r.RegionSize > IOC_SCAN_MAX:
            coverage.note_skipped_oversize(region_scan_target(mf, r, IOC_SCAN_MAX))
            continue

        mod      = addr_to_module(r.BaseAddress, modules)
        mod_name = (_module_basename(mod).lower() if mod else "")
        is_wl    = mod_name in whitelist

        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            coverage.note_read_failed(region_scan_target(mf, r))
            continue
        if len(data) < r.RegionSize:
            # Fewer bytes came back than the region's own declared size --
            # not the same as "read fine, nothing here" (see
            # dumpex.hunt.pipe.memory_scan.scan_pipe_names for the same
            # distinction). Still scan whatever WAS returned -- a real IOC
            # hit in the readable prefix is still a real hit -- but this
            # region must not silently count toward a "complete" IOC scan.
            coverage.note_short_read(region_scan_target(mf, r))
            if not data:
                continue

        strings = _extract_ioc_strings(data, r.BaseAddress)
        patterns = ([ioc_patterns] if is_wl else [ioc_patterns, net_ioc_patterns])
        hits = _classify_ioc_hits(strings, patterns, r.BaseAddress)

        if not hits:
            if is_wl:
                skipped_wl.append(mod_name)
            continue
        if not any(not h.is_weak for h in hits):
            weak_only_regions += 1
            continue
        ioc_hits.append(IocHitEvidence(region=region_ref(r),
                                        module=module_ref(mod) if mod else None,
                                        tokens=hits, not_whitelisted=not is_wl))

    return IocScanResult(hits=tuple(ioc_hits),
                          coverage=IocCoverage.from_tracker(coverage, skipped_wl),
                          weak_only_regions=weak_only_regions)
