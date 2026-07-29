"""Cobalt Strike beacon config scanner (adapted from 1768.py by Didier Stevens).

Phase-three detection model
────────────────────────────
Brought onto the same evidence semantics as the phase-two hunters
(injection/stomping/pipe/obfuscation): explicit score/max_score/status/
verdict_level/confidence/coverage_status/coverage_reasons/findings,
instead of the config-count-as-score model this hunter used previously.
The `configs` field (per-hit raw data: VA, file offset, region, XOR key,
version estimate, parsed TLV fields) is kept as-is for existing
consumers — everything below is additive.

  score 0 — no structurally-valid (sanity-checked TLV, known BeaconType,
            ASN.1-shaped public key) config found in what was scanned.
  score 1 — at least one structurally-valid config found, with no
            independent memory-context corroboration. Finding MORE
            configs (even at distinct addresses) does NOT raise this —
            config count is a fact reported alongside the finding, not a
            confidence input. A beacon config surviving in memory is
            itself strong, hard-to-fake evidence (the TLV structure,
            field types, and a plausible ASN.1 public key all having to
            line up by chance is vanishingly unlikely) — this is why
            score 1 already maps to "likely", not "possible".
  score 2 — additionally corroborated by memory context independent of
            the config bytes themselves: either the enclosing region is
            executable, private memory (not an inert data-only mapping),
            or a thread's CURRENT RIP/EIP executes somewhere within the
            same allocation as the config hit — i.e. this isn't just an
            orphaned copy sitting in unused/freed memory.

Deliberately NOT reported: a DORMANT/INITIALIZED/LIVE activity label.
A decoded config proves a beacon payload exists (or existed) in this
process's memory — it says nothing about whether it is CURRENTLY
maintaining network callbacks at dump time, and claiming otherwise from
static memory content alone would be exactly the kind of over-attribution
this schema exists to avoid. CS version is an ESTIMATE from the highest
recognized field ID (see parser._cs_guess_version) and is reported as
such, not as a fingerprinted/confirmed build.

This is a package, not a single file: scanner.py only collects facts
(segment/candidate walk, budgets, coverage) and never scores or prints;
context.py establishes memory-context corroboration for each hit;
aggregate.py is the ONE place score/status/coverage_status/verdict_level/
confidence/lead_count/review_priority get computed; presentation.py is
the ONE place anything gets printed to the console. This __init__.py is
the thin entry point: build config, run the scan, corroborate hits,
aggregate, print, return the findings dict.

The stable contract is `_hunt_cs_beacon` itself (imported by
dumpex/hunt/__init__.py): same signature, same fields, same score/status/
coverage/JSON schema as before this package split — this refactor only
changes internal structure. Tunable constants (CS_MAX_SEG_SCAN, CS_MAX_*,
CS_SCAN_DEADLINE_SECONDS, ...) and `get_thread_contexts`/`time` are
re-exported here and remain monkeypatchable (`cs_beacon.CS_MAX_CANDIDATES
= 5` before calling `_hunt_cs_beacon()` still changes its behavior — see
dumpex/hunt/cs_beacon/config.py for why that requires a config object
threaded through scanner.py rather than scanner.py reading its own
separate copy of the same-named constant). Private per-step helper
functions (`_cs_decode_and_parse_tlv`, `_cs_validate_public_key_der`,
`_cs_sanity_check`, etc.) are NOT re-exported here and make no
compatibility promise at all — import them from their actual module
(dumpex.hunt.cs_beacon.parser/.der/...) if you need them directly, as
this package's own tests do.
"""
import time
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import DIM
from dumpex.core.memory import get_memory_regions, get_thread_contexts
from dumpex.hunt._ui import _print_hunt_header
from dumpex.hunt._runtime import HunterRuntime

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
from dumpex.hunt.cs_beacon import presentation


def _hunt_cs_beacon(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Scan all captured memory segments for Cobalt Strike beacon configurations.

    Algorithm (adapted from 1768.py by Didier Stevens, public domain):
      1. Walk every captured memory segment in the minidump.
      2. Search each segment for the XOR-encoded TLV signature with keys
         0x69 (CS3) and 0x2E (CS4).
      3. On a hit: XOR-decode, parse TLV records, run sanity check.
      4. Extract and display: beacon type, C2 server/port/URI, User-Agent,
         pipe name, license ID, sleep/jitter, SpawnTo, Malleable C2 profile
         transforms, process injection settings, SSH/DNS transport fields.
      5. Report VA (process address) + file offset (.dmp byte position) +
         enclosing memory region (base/size/protection) for each hit,
         consistent with Dumpex address labeling conventions.

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
    _print_hunt_header("Cobalt Strike Beacon Config")

    segs = scanner.select_segments(mf)
    if not segs:
        report = aggregate.build_not_evaluated_report()
        presentation.render(report, verbose)
        return report.findings

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
    # context._cs_context_corroborates), so an incomplete thread-context
    # picture only actually matters for a hit that ISN'T already
    # corroborated by region protection (see aggregate.py's
    # top_tier_uncertain check).
    thread_list_stream_available = bool(mf.threads and mf.threads.threads)
    threads_total    = len(mf.threads.threads) if (mf.threads and mf.threads.threads) else 0
    contexts_parsed  = len(thread_contexts)
    contexts_missing = max(0, threads_total - contexts_parsed)

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
    runtime = HunterRuntime(monotonic=time.monotonic)

    print(DIM(f"  [*] Scanning {len(segs)} segment(s) for beacon signature …"))
    outcome = scanner.scan_segments(mf, segs, config, runtime.monotonic)
    print(DIM(f"  [*] Scan complete{scanner.format_scan_note(outcome)}."))

    hit_records = context.corroborate_hits(outcome.hits, regions, thread_contexts)

    report = aggregate.build_report(outcome, hit_records, mem_info_available,
                                     thread_list_stream_available, threads_total,
                                     contexts_parsed, contexts_missing)

    presentation.render(report, verbose)

    return report.findings
