"""RWX region and hidden-PE-header memory scans. Only collects facts —
never scores, never prints.
"""
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import get_modules, get_memory_regions, addr_to_module, prot_str
from dumpex.core.pe_utils import parse_pe_header
from dumpex.hunt.injection.config import PE_VALIDATE_READ_MAX
from dumpex.hunt.injection.models import HiddenPeScan


def _is_suspicious_rwx(protect: str, mtype: str) -> bool:
    """
    PAGE_EXECUTE_READWRITE is always suspicious — no legitimate loader
    grants direct, non-copy-on-write write access to executable memory.

    PAGE_EXECUTE_WRITECOPY is different: on a MEM_IMAGE-backed region it
    is Windows' NORMAL, unmodified-mapping copy-on-write protection for
    executable sections (see core.pe_utils.NORMAL_IMAGE_PROTECTIONS) —
    flagging it there makes every ordinary, untouched DLL "suspicious".
    On anything NOT image-backed (MEM_PRIVATE/MEM_MAPPED), WRITECOPY has
    no such benign explanation and is still worth flagging.
    """
    if protect == "PAGE_EXECUTE_READWRITE":
        return True
    if protect == "PAGE_EXECUTE_WRITECOPY":
        return mtype != "MEM_IMAGE"
    return False


def _hunt_rwx(mf: MinidumpFile) -> list:
    """Return list of RWX regions."""
    regions = get_memory_regions(mf)
    hits = []
    for r in regions:
        if _is_suspicious_rwx(prot_str(r.Protect), prot_str(r.Type)):
            hits.append(r)
    return hits


def _hunt_hidden_pe(mf: MinidumpFile, read_region, module_list_available: bool = True) -> HiddenPeScan:
    """
    Return a HiddenPeScan(hits, read_failed, short_reads).

    If ModuleListStream isn't present, module_list_available is False and
    this returns an empty scan rather than flagging every MZ header as
    "hidden": an empty modules list doesn't mean "nothing here is a known
    module" — it means we have no way to tell. Producing a hit for every
    legitimate loaded PE header would be pure false-positive noise, not a
    finding.

    A region whose header read fails (raises) is not the same as a region
    that was read and doesn't start with 'MZ' — it was never actually
    looked at, so it's tracked separately (read_failed) rather than
    silently dropped. A region whose read SUCCEEDS but returns fewer
    bytes than requested (a short read — e.g. the prefix read comes back
    empty/truncated, or the deep validation read returns only the 2-byte
    prefix instead of up to PE_VALIDATE_READ_MAX bytes) is likewise not
    "read fine, no MZ here" / "read fine, structurally invalid" — the
    unread remainder was never actually examined, so it's tracked
    separately too (short_reads), distinct from an exception.

    `read_region` is threaded explicitly (not imported directly from
    dumpex.core.memory in this module) so a caller/test can substitute a
    fake reader without needing the facade's own `read_region` name to be
    monkeypatched and separately re-imported here — see
    dumpex/hunt/_runtime.py.

    Each hit dict: {"region", "in_module_list", "pe"} where "pe" is the
    full dumpex.core.pe_utils.parse_pe_header() result — callers decide
    what "valid" means for their purposes rather than this function
    silently only returning validated hits.
    """
    if not module_list_available:
        return HiddenPeScan(hits=[], read_failed=0, short_reads=0)
    modules = get_modules(mf)
    hits = []
    read_failed = 0
    short_reads = 0
    for r in get_memory_regions(mf):
        if prot_str(r.State) != "MEM_COMMIT":
            continue
        # Membership is a RANGE check (addr_to_module), not "does this
        # region's BaseAddress exactly equal a module's base" — a prior
        # version used `r.BaseAddress in {m.baseaddress for m in modules}`,
        # which only matches a module's very first page. Any OTHER region
        # belonging to that same module (e.g. a resource section carrying
        # an embedded PE/icon/update payload, or any sub-region a
        # VirtualProtect call split off) has a BaseAddress that is never
        # any module's baseaddress, so it was always misclassified as
        # "unregistered" regardless of being entirely inside a known,
        # legitimately loaded module.
        owner = addr_to_module(r.BaseAddress, modules)
        if prot_str(r.Type) == "MEM_IMAGE" and owner is not None:
            continue   # inside a known module — not a hidden-PE candidate at all
        prefix_want = min(2, r.RegionSize)
        try:
            prefix = read_region(mf, r.BaseAddress, prefix_want)
        except Exception:
            read_failed += 1
            continue
        if len(prefix) < prefix_want:
            # A short prefix read is not the same as "read fine, doesn't
            # start with MZ" — the bytes that would confirm or deny an MZ
            # header were never actually returned.
            short_reads += 1
            continue
        if prefix[:2] != b'MZ':
            continue
        deep_want = min(PE_VALIDATE_READ_MAX, r.RegionSize)
        try:
            deep = read_region(mf, r.BaseAddress, deep_want)
        except Exception:
            # Still report the MZ observation (parse_pe_header will report
            # a truncation reason on just the 2-byte prefix) rather than
            # dropping the hit entirely — but this region could NOT be
            # properly validated, which is a real coverage gap distinct
            # from "read fine, structurally invalid": count it the same as
            # a prefix-read failure so `complete`/pe_read_failed reflects
            # it rather than silently treating this as a completed check.
            read_failed += 1
            deep = prefix
        else:
            if len(deep) < deep_want:
                # Short read, no exception — parse whatever bytes DID come
                # back (parse_pe_header will itself report a truncation
                # reason if that's not enough for a valid header) rather
                # than dropping the hit, but this region was still never
                # fully examined: count it, don't let pe_read_failed==0
                # (and therefore `complete`) silently claim otherwise.
                short_reads += 1
                if not deep:
                    deep = prefix
        pe = parse_pe_header(deep)
        # owner is already known from the range check above for MEM_IMAGE
        # regions; a non-image region can still fall inside a module's
        # declared [baseaddress, endaddress) span in principle, so the
        # same range check is used uniformly rather than re-deriving it.
        hits.append({"region": r, "in_module_list": owner is not None, "pe": pe})
    return HiddenPeScan(hits=hits, read_failed=read_failed, short_reads=short_reads)


def split_hidden_pe_hits(scan: HiddenPeScan) -> "tuple[list, list]":
    """
    Split a HiddenPeScan's hits into (validated, mz_only). Only
    STRUCTURALLY VALID hidden PEs count toward correlation/score; an
    MZ-prefixed region that fails header validation is a much weaker
    observation (could be a decoy, a truncated read, or coincidental
    bytes) — see dumpex/hunt/injection/__init__.py's module docstring.
    Computed once here so correlation.py and aggregate.py agree on the
    same split instead of each re-deriving it.
    """
    validated = [h for h in scan.hits if not h["in_module_list"] and h["pe"]["valid"]]
    mz_only   = [h for h in scan.hits if not h["in_module_list"] and not h["pe"]["valid"]]
    return validated, mz_only
