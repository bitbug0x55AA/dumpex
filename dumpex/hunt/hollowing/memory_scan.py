"""Resolve image-base context and collect hollowing signals.

The scan distinguishes an uncaptured image-base region from a failed or short
header read and from a confirmed missing MZ signature. Module-list availability
is recorded independently because it affects only name comparison.
"""
from dumpex.core.memory import addr_to_module, va_to_file_offset

from dumpex.hunt.hollowing.config import MZ_MIN_BYTES, MZ_READ_LEN
from dumpex.hunt.hollowing.models import (
    HeaderRead, ImageBaseContext, MemPrivateEvidence, NameMismatchEvidence,
    OUTCOME_CLEAN, OUTCOME_EXCEPTION, OUTCOME_SHORT_READ, OUTCOME_WIPED_OTHER,
    OUTCOME_WIPED_ZERO, RwxProtectionEvidence, WipedHeaderEvidence,
    basename_lower, module_ref, region_ref,
)


def find_image_base_region(regions, image_base: int):
    """The first MemoryInfo region whose own range contains `image_base`,
    or None when the image base page was not captured in this dump at all.
    Returns the RAW region -- `resolve_image_base_context()` below is what
    snapshots it into a `RegionRef`, so this stays a pure lookup."""
    for region in regions:
        if region.BaseAddress <= image_base < region.BaseAddress + region.RegionSize:
            return region
    return None


def read_image_base_header(mf, read_region, image_base: int) -> HeaderRead:
    """The single MZ/DOS-header read at `image_base`, classified into one
    of `models`' five outcomes.

    The read is deliberately attempted regardless of whether
    `find_image_base_region()` found a region: it targets a fixed window at
    a known address, and a dump can legitimately hold those bytes without a
    MemoryInfo entry describing them (and vice versa). That independence is
    also why its failure is its own coverage flag rather than being folded
    into the region's -- see `domain.CoverageSnapshot`.

    A read that raises is caught here, at the one site that performs it,
    exactly as the pre-migration code did -- an unreadable page is an
    ordinary, expected outcome for a minidump, not an error worth
    abandoning the whole hunter over. `bytes(...)` normalizes whatever the
    resolver returned (a `bytearray`/`memoryview` from some readers) into
    the immutable form the evidence model requires.
    """
    try:
        header = bytes(read_region(mf, image_base, MZ_READ_LEN))
    except Exception as exc:
        return HeaderRead(outcome=OUTCOME_EXCEPTION, error=str(exc))
    if len(header) < MZ_MIN_BYTES:
        # Not enough bytes to confirm OR deny the magic -- a coverage gap,
        # never evidence the header is missing. Combined with MEM_PRIVATE,
        # treating this as "wiped" previously reached a false DETECTED.
        return HeaderRead(outcome=OUTCOME_SHORT_READ, header_bytes=header)
    if header[:2] == b"MZ":
        return HeaderRead(outcome=OUTCOME_CLEAN, header_bytes=header)
    if header == b"\x00" * len(header):
        return HeaderRead(outcome=OUTCOME_WIPED_ZERO, header_bytes=header)
    return HeaderRead(outcome=OUTCOME_WIPED_OTHER, header_bytes=header)


def resolve_image_base_context(mf, read_region, peb, regions, modules) -> ImageBaseContext:
    """Everything about the image base, resolved ONCE -- see this module's
    own docstring. Called only when `mf.peb` is present; a dump without it
    has no image base to resolve at all (see
    `domain.CoverageSnapshot.evaluated`).

    `image_path` keeps the pre-migration "(unknown)" coercion because every
    scoring/fact/console use of it below is unchanged by this migration;
    `peb_image_path` keeps the genuinely-`None`-when-absent raw value for
    `HollowingDetails.peb_image_path`, whose `str | None` contract means
    null, not the display string.
    """
    image_base = peb.image_base_address
    raw_region = find_image_base_region(regions, image_base)
    main_module = addr_to_module(image_base, modules)
    return ImageBaseContext(
        image_base=image_base,
        image_path=peb.image_path or "(unknown)",
        peb_image_path=peb.image_path,
        header=read_image_base_header(mf, read_region, image_base),
        file_offset=va_to_file_offset(mf, image_base),
        region=region_ref(raw_region) if raw_region is not None else None,
        region_file_offset=(va_to_file_offset(mf, raw_region.BaseAddress)
                            if raw_region is not None else None),
        module=module_ref(main_module) if main_module is not None else None,
    )


def collect_signals(context: ImageBaseContext, suspicious_protections,
                     *, modules_available: bool) -> tuple:
    """`(mem_private, wiped_headers, rwx, name_mismatches)` -- the four
    anchor/corroborator buckets, each a 0-or-1-item tuple of typed
    evidence, observed from the already-resolved `context`.

    Reads no dump and decides nothing about the verdict. The four
    conditions are the pre-migration ones, unchanged:

      1. ANCHOR -- the region covering the image base is not MEM_IMAGE.
         Skipped entirely (no evidence, no negative claim) when no region
         was captured: `domain.CoverageSnapshot` records that as a gap
         instead.
      2. ANCHOR -- bytes came back from the header read and are not an MZ
         header. A short/failed read produces NOTHING here (see
         `HeaderRead.read_failed`).
      3. CORROBORATOR -- the region's live protection matches one of
         rules.yaml's `suspicious_protections` entries. Same region gate as
         check 1.
      4. CORROBORATOR -- the PEB's ImagePath basename disagrees with the
         module list's own name for this base, OR the base is in no module
         at all. `modules_available` (ModuleListStream present AND
         non-empty) is what separates the second case from "the check could
         not run": `addr_to_module()` returns None either way, and firing
         this corroborator on a missing stream would report an absent
         module list as a real signal.
    """
    mem_private = ()
    rwx = ()
    if context.region is not None:
        if "MEM_IMAGE" not in context.region.type:
            mem_private = (MemPrivateEvidence(region=context.region),)
        if any(pattern in context.region.protect for pattern in suspicious_protections):
            rwx = (RwxProtectionEvidence(region=context.region),)

    wiped_headers = ()
    if context.header.wiped:
        wiped_headers = (WipedHeaderEvidence(image_base=context.image_base,
                                              header_bytes=context.header.header_bytes),)

    if context.module is not None:
        mismatched = context.module.basename_lower != context.image_name
    else:
        mismatched = modules_available
    name_mismatches = ()
    if mismatched:
        name_mismatches = (NameMismatchEvidence(image_path=context.image_path,
                                                 module=context.module),)

    return mem_private, wiped_headers, rwx, name_mismatches


# Re-exported so `dumpex.hunt.hollowing.memory_scan.basename_lower` reads
# the same name the pre-migration module exposed as `_basename_lower`; the
# canonical home is models.py, where identity resolution lives.
__all__ = ["basename_lower", "collect_signals", "find_image_base_region",
           "read_image_base_header", "resolve_image_base_context"]
