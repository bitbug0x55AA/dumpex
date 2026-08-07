"""RWX region and hidden-PE-header memory scans. Only collects facts —
never scores, never prints.
"""
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import get_modules, get_memory_regions, addr_to_module, prot_str
from dumpex.core.pe_utils import parse_pe_header
from dumpex.hunt._location import resolve_location
from dumpex.hunt.injection.config import PE_VALIDATE_READ_MAX
from dumpex.hunt.injection.models import (
    HiddenPeScan, RegionRef, PeHeaderInfo, RwxRegionEvidence, HiddenPeEvidence,
)


def region_ref(r) -> RegionRef:
    """Convert a raw minidump Region into an immutable RegionRef -- the
    ONE place this hunter reads a region's raw Type/Protect enum values
    and formats them via prot_str(), so every Evidence type that carries
    "a region" (RWX/hidden-PE/RIP-hit/StartAddress-hit) does so with the
    SAME already-formatted strings, never a second prot_str() call at a
    different layer. Used by this module and by
    dumpex.hunt.injection.correlation (the only other place a raw Region
    is ever converted)."""
    return RegionRef(base_address=r.BaseAddress, allocation_base=r.AllocationBase,
                      size=r.RegionSize, type=prot_str(r.Type), protect=prot_str(r.Protect))


def _pe_header_info(pe: dict) -> PeHeaderInfo:
    """Project dumpex.core.pe_utils.parse_pe_header()'s dict down to the
    lean, immutable PeHeaderInfo this hunter actually consumes -- see that
    type's own docstring for which fields (and why only those)."""
    return PeHeaderInfo(
        valid=pe['valid'], machine_name=pe['machine_name'], is_pe32_plus=pe['is_pe32_plus'],
        number_of_sections=pe['number_of_sections'], address_of_entry_point=pe['address_of_entry_point'],
        image_base=pe['image_base'], reason=pe['reason'])


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


def _hunt_rwx(mf: MinidumpFile) -> tuple:
    """Return tuple of RwxRegionEvidence -- each built here, at the scan
    boundary, WITH its file offset already resolved (see
    dumpex.hunt._location.resolve_location) -- so aggregate.py never
    needs `mf` or a separate region-BaseAddress -> Location lookup table."""
    regions = get_memory_regions(mf)
    hits = []
    for r in regions:
        if _is_suspicious_rwx(prot_str(r.Protect), prot_str(r.Type)):
            hits.append(RwxRegionEvidence(
                region=region_ref(r),
                location=resolve_location(mf, r.BaseAddress, r.BaseAddress, region_size=r.RegionSize)))
    return tuple(hits)


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

    Each hit is a HiddenPeEvidence(region, pe, in_module_list, location) --
    callers decide what "valid" means for their purposes (see
    split_hidden_pe_hits) rather than this function silently only
    returning validated hits. File offset is resolved here too, at scan
    time, same reasoning as `_hunt_rwx`.
    """
    if not module_list_available:
        return HiddenPeScan(hits=(), read_failed=0, short_reads=0)
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
        hits.append(HiddenPeEvidence(
            region=region_ref(r), pe=_pe_header_info(pe), in_module_list=owner is not None,
            location=resolve_location(mf, r.BaseAddress, r.BaseAddress, region_size=r.RegionSize)))
    return HiddenPeScan(hits=tuple(hits), read_failed=read_failed, short_reads=short_reads)


def split_hidden_pe_hits(scan: HiddenPeScan) -> "tuple[tuple, tuple]":
    """
    Split a HiddenPeScan's hits into (validated, mz_only). Only
    STRUCTURALLY VALID hidden PEs count toward correlation/score; an
    MZ-prefixed region that fails header validation is a much weaker
    observation (could be a decoy, a truncated read, or coincidental
    bytes) — see dumpex/hunt/injection/__init__.py's module docstring.
    Computed once here so correlation.py and aggregate.py agree on the
    same split instead of each re-deriving it.
    """
    validated = tuple(h for h in scan.hits if not h.in_module_list and h.pe.valid)
    mz_only   = tuple(h for h in scan.hits if not h.in_module_list and not h.pe.valid)
    return validated, mz_only


def _has_executable_protection(protect: str) -> bool:
    """
    True if `protect` (a prot_str()-rendered Protect name) grants execute
    access. Checked via substring rather than an exact-match set because
    Protect can carry a combined flag name (e.g. "PAGE_EXECUTE_READ|
    PAGE_GUARD") from the underlying enum — every executable PAGE_*
    constant contains "EXECUTE" and no non-executable one does, so this is
    a safe, simpler test than enumerating every combination.
    """
    return "EXECUTE" in protect


def pe_hit_is_context_scoreable(hit) -> bool:
    """
    Classify one validated hidden-PE hit's (a HiddenPeEvidence) OWN memory
    context (before any correlation) as scoreable-by-default or
    context-only/informational. This is a FACT derivation from page type +
    protection — like the rest of this module, it never scores anything
    itself; aggregate.py is still the ONE place score gets computed. A
    context-only classification here can still be PROMOTED to scoreable by
    aggregate.py if correlation.py finds the same AllocationBase carrying
    an RWX region or live thread execution (RIP/EIP or StartAddress) — see
    aggregate.py's `_split_scoreable_pe_hits`.

    Scoreable on its own:
      - MEM_PRIVATE — no legitimate loader maps an unregistered PE image
        into private memory; this needs no further corroboration.
      - non-module-backed (already guaranteed by split_hidden_pe_hits,
        which only keeps hits with in_module_list=False) AND executable
        protection — an executable, unbacked mapping is just as
        suspicious as MEM_PRIVATE regardless of whether the underlying
        page type happens to be MEM_IMAGE or MEM_MAPPED.

    Context-only otherwise: e.g. a read-only/non-executable MEM_MAPPED
    region, or a MEM_IMAGE region absent from the module list but
    carrying no execute permission (a resource-only view, a decoy
    header, ...) — a structurally-valid PE header alone, with no execute
    permission and no correlated RWX/live-execution signal, occurs often
    enough in ordinary file-mapping/DLL-preview scenarios that it must
    not by itself drive a verdict.
    """
    r = hit.region
    if r.type == "MEM_PRIVATE":
        return True
    return _has_executable_protection(r.protect)
