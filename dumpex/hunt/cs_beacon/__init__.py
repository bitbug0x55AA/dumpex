"""Cobalt Strike configuration scanner adapted from Didier Stevens' 1768.py.

A structurally valid TLV configuration with a known BeaconType and plausible
ASN.1 public key is strong payload evidence. Executable-private memory context or
current RIP/EIP in the same allocation raises corroboration; additional copies
alone do not. Static memory cannot establish whether a beacon was active at dump
time, and reported versions are estimates from known field identifiers.

Candidate, byte, time, and retention budgets bound dump-controlled work and feed
coverage when scanning is incomplete.
"""
import time
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import get_memory_regions, get_thread_contexts

from dumpex.hunt.cs_beacon.config import (
    CSBeaconConfig,
    CS_BEACON_SIGNATURE, CS_SIG_XOR69, CS_SIG_XOR2E, CS_MAX_SEG_SCAN,
    CS_CONFIG_DECODE_MAX, CS_MAX_CANDIDATES, CS_MAX_DECODED_BYTES, CS_MAX_HITS,
    CS_SCAN_DEADLINE_SECONDS, CS_MAX_TOTAL_SCANNED_BYTES,
    CS_SUSPICIOUS_PRIVATE_PROTECTIONS,
)
from dumpex.hunt.cs_beacon.schema import (
    CS_FIELD_NAMES, CS_BEACON_TYPES, CS_PROXY_TYPES, CS_INJECT_PERMS,
)
from dumpex.hunt.cs_beacon import scanner
from dumpex.hunt.cs_beacon import context
from dumpex.hunt.cs_beacon import aggregate
from dumpex.hunt.cs_beacon import report_console
from dumpex.hunt.cs_beacon import report_legacy


def _build_cs_beacon_report(mf: MinidumpFile):
    """Run the scan/corroborate/aggregate pipeline and return the
    immutable `domain.CSBeaconReport` -- the ONE place this pipeline is
    assembled, shared by `_hunt_cs_beacon()` (console path, below) and
    `collect_cs_beacon_record()` (dumpex/hunt/cs_beacon/collect.py). Prints
    nothing at all.

    Algorithm (adapted from 1768.py by Didier Stevens, public domain):
      1. Walk every captured memory segment in the minidump.
      2. Search each segment for the XOR-encoded TLV signature with keys
         0x69 (CS3) and 0x2E (CS4).
      3. On a hit: XOR-decode, parse TLV records, run sanity check.
      4. Resolve the enclosing memory region and, once every segment has
         been scanned, each hit's independent memory-context corroboration.
      5. Aggregate into the canonical Report: VA (process address) + file
         offset (.dmp byte position) + enclosing memory region (base/
         size/protection) for each hit, consistent with Dumpex address
         labeling conventions.

    Address note:
      hit VA         = segment.start_virtual_address + offset_within_segment
      hit file offset = segment.start_file_address   + offset_within_segment

      hit VA is a byte-precise address, not a region. Memory64ListStream
      (the segment table this scan walks) and MemoryInfoListStream (the
      VAD-style region table with Protect/State, used by --hunt injection
      for its RWX / hidden-PE region correlation) are independent streams.
      Resolving hit VA -> enclosing region base here is what lets a beacon
      config hit be cross-referenced against injection's region-based
      findings (same region_base means "same memory region").
    """
    segs = scanner.select_segments(mf)
    if not segs:
        return aggregate.build_not_evaluated_report()

    # MemoryInfoListStream is only used for CONTEXT (region base/protect for
    # display, and the score 1 -> 2 corroboration check below) — its
    # absence must not block config DETECTION (a structurally-valid config
    # still scores at least 1), but it does mean the corroboration check
    # could not run to completion, which coverage_status must reflect
    # rather than silently claiming a fully-verified result.
    mem_info_available = bool(mf.memory_info and mf.memory_info.infos)
    regions = get_memory_regions(mf)
    thread_contexts = get_thread_contexts(mf)

    # ThreadList/CONTEXT coverage — the same explicit counts dumpex/hunt/injection/
    # tracks (see its coverage["contexts_missing"]): a bare "did any thread
    # context parse" boolean can't distinguish "every thread's context
    # parsed" from "1 out of 200 did". Unlike dumpex/hunt/injection/, RIP/EIP is NOT
    # the only path to this hunter's top tier (score 2 also comes from
    # executable+private region protection alone — see
    # context._corroborates), so an incomplete thread-context picture only
    # actually matters for a hit that ISN'T already corroborated by region
    # protection (see domain.CoverageSnapshot.thread_context_gap).
    thread_list_stream_available = bool(mf.threads and mf.threads.threads)
    threads_total    = len(mf.threads.threads) if (mf.threads and mf.threads.threads) else 0
    contexts_parsed  = len(thread_contexts)

    # config bundles every cs_beacon.* tunable, read from THIS module's own
    # (re-exported, and therefore still monkeypatchable) globals -- see
    # dumpex/hunt/cs_beacon/config.py for why scanner.py can't just read
    # its own separate copy of these constants directly.
    config = CSBeaconConfig(
        max_seg_scan=CS_MAX_SEG_SCAN, config_decode_max=CS_CONFIG_DECODE_MAX,
        max_candidates=CS_MAX_CANDIDATES, max_decoded_bytes=CS_MAX_DECODED_BYTES,
        max_hits=CS_MAX_HITS, scan_deadline_seconds=CS_SCAN_DEADLINE_SECONDS,
        max_total_scanned_bytes=CS_MAX_TOTAL_SCANNED_BYTES,
    )
    # `time.monotonic` is looked up HERE (not defaulted inside scanner.py's
    # own signature) so a test that monkeypatches this module's `time.
    # monotonic` attribute (a shared stdlib module object -- see
    # dumpex/hunt/_runtime.py) is picked up fresh on every call.
    hits, diagnostics = scanner.scan_segments(mf, segs, config, regions, time.monotonic)

    corroborations = context.corroborate(hits, regions, thread_contexts)

    return aggregate.build_report(
        hits, corroborations, scan=diagnostics, mem_info_available=mem_info_available,
        thread_list_stream_available=thread_list_stream_available,
        threads_total=threads_total, contexts_parsed=contexts_parsed)


def _render_cs_beacon_console(report, verbose: bool = False) -> dict:
    """Render the console report for an ALREADY-BUILT `CSBeaconReport`,
    returning the same v1.1-shaped findings dict `_hunt_cs_beacon()` always
    has -- extracted so `dumpex.hunt.cmd_hunt()`'s console+JSON orchestrator
    can feed ONE built Report to both this and
    `dumpex.hunt.cs_beacon.collect._record_from_cs_beacon_report()` without
    scanning twice.

    No `mf` parameter any more: everything this renders was resolved once,
    at scan time, onto `report.evidence` (see report_console.py's own
    docstring)."""
    report_console.print_console(report, verbose)
    return report_legacy.project_legacy_dict(report)


def _hunt_cs_beacon(mf: MinidumpFile, verbose: bool = False) -> dict:
    """Scan all captured memory segments for Cobalt Strike beacon
    configurations -- see `_build_cs_beacon_report()`'s own docstring for
    the algorithm. Returns dict of findings for use in --hunt all summary.

    Nothing prints before the Report exists (see report_console.py's own
    docstring for why the former "Scanning N segment(s)..."/"Scan
    complete..." progress lines are gone)."""
    report = _build_cs_beacon_report(mf)
    return _render_cs_beacon_console(report, verbose)
