"""The ONE place score/status/coverage_status/verdict_level/confidence/
lead_count/review_priority get computed for the CS beacon hunter, and
where Finding objects and the public `findings` dict are built.

Nothing here prints; nothing here decodes/scans. This module only turns
already-collected facts (a ScanOutcome from scanner.py, corroboration
results from context.py, thread/mem-info coverage counts) into the
hunter's decision fields.
"""
from dataclasses import dataclass, field

from dumpex.core.memory import prot_str
from dumpex.hunt._ui import NOT_EVALUATED, INCONCLUSIVE
from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_DETECTION, overall_confidence, verdict_level,
    lead_count, review_priority)
from dumpex.hunt.cs_beacon.schema import _VERDICT_LEVEL_BY_SCORE
from dumpex.hunt.cs_beacon.parser import _cs_guess_version
from dumpex.hunt.cs_beacon.scanner import format_scan_note


@dataclass
class Report:
    """Bundles the public `findings` dict with everything presentation.py
    needs to render console detail (hit_records, any_corroborated, ...).

    `scan_note` (the "Scan complete<note>." progress-line suffix, only
    computable once a scan has actually run) is stored here so
    `_hunt_cs_beacon()` can print its post-scan progress line from the
    already-built Report instead of re-running the scan just to learn
    it -- see `dumpex/hunt/cs_beacon/__init__.py`'s own docstring for why
    this hunter's progress prints straddle the builder call."""
    findings: dict
    findings_list: list
    hit_records: list = field(default_factory=list)
    score: int = 0
    status: str = NOT_EVALUATED
    any_corroborated: bool = False
    coverage_reasons: list = field(default_factory=list)
    coverage_report: object = None   # dumpex.output.coverage.CoverageReport (v2.4 migration only)
    scan_note: str = ""


def build_not_evaluated_report() -> Report:
    """No memory segments at all in the dump — never a bare CLEAN."""
    findings = {'configs': [], 'score': 0, 'max_score': 2}
    findings['status'] = NOT_EVALUATED
    findings['coverage_status'] = 'not_evaluated'
    findings['coverage_reasons'] = ['Memory64ListStream missing from this dump']
    findings['verdict_level'] = verdict_level(0, _VERDICT_LEVEL_BY_SCORE, status=NOT_EVALUATED)
    findings['confidence'] = overall_confidence([], 0)
    findings['lead_count'] = 0
    findings['review_priority'] = review_priority([], 0, NOT_EVALUATED)
    findings['findings'] = []
    return Report(findings=findings, findings_list=[], status=NOT_EVALUATED,
                  coverage_reasons=findings['coverage_reasons'])


def build_report(scan_outcome, hit_records: list, mem_info_available: bool,
                  thread_list_stream_available: bool, threads_total: int,
                  contexts_parsed: int, contexts_missing: int) -> Report:
    """
    Turn a completed scan (scan_outcome from scanner.py, hit_records from
    context.py) into score/status/coverage/Finding objects. `hit_records`
    is empty when scan_outcome.hits is empty.
    """
    findings = {'configs': [], 'score': 0, 'max_score': 2}
    findings_list = []

    findings['coverage'] = {
        "mem_info_stream":    mem_info_available,
        "thread_list_stream": thread_list_stream_available,
        "threads_total":      threads_total,
        "contexts_parsed":    contexts_parsed,
        "contexts_missing":   contexts_missing,
    }

    # Coverage is uniform across the DETECTED/clean/INCONCLUSIVE outcomes
    # below — the same rule every phase-two hunter uses: MemoryInfoListStream
    # absence always makes coverage partial, since it's the region-context
    # corroboration check's own data source, regardless of whether this
    # scan happens to end up finding a config or not.
    complete = (scan_outcome.coverage.complete and not scan_outcome.budget_exhausted
                and mem_info_available)
    coverage_reasons = scan_outcome.coverage.build_reasons(
        oversize_label="oversized segment(s) skipped",
        read_failed_label="segment(s) failed to read",
        short_read_label="segment(s) returned fewer bytes than declared (short read) — "
                          "not fully scanned",
    )
    if scan_outcome.budget_exhausted:
        coverage_reasons.append(f"scan resource budget exhausted ({scan_outcome.budget_reason}) — "
                                 f"stopped before every segment/candidate was examined")
    if not mem_info_available:
        coverage_reasons.append("MemoryInfoListStream missing from this dump — region/"
                                 "execution-context corroboration for any config hit "
                                 "could not be verified")
    findings['coverage_status']  = derive_coverage_status(True, complete)
    findings['coverage_reasons'] = coverage_reasons
    scan_note = format_scan_note(scan_outcome)

    if not scan_outcome.hits:
        status = derive_status(True, False, complete)
        findings['status'] = status
        findings['verdict_level'] = verdict_level(0, _VERDICT_LEVEL_BY_SCORE, status=status)
        findings_list.append(Finding(
            check="cs_beacon.no_structural_config",
            facts=[f"{scan_outcome.segment_count} memory segment(s) scanned"
                   + (f" ({', '.join(coverage_reasons)})" if coverage_reasons else "")],
            inference="No structurally-valid (sanity-checked TLV, known BeaconType, "
                       "ASN.1-shaped public key) Cobalt Strike beacon configuration found "
                       "in what was scanned.",
            confidence=CONFIDENCE_LOW,
            rationale="Absence of a decodable config is weak evidence of absence — an "
                       "unscanned/skipped/unreadable segment, an unsupported XOR scheme, or "
                       "a config that never touched memory captured in this dump would all "
                       "look identical to this.",
            limitations=(["Coverage was incomplete — see coverage_reasons."] if not complete else []),
            tag=TAG_OBSERVATION,
        ))
        findings['findings']   = [f.to_dict() for f in findings_list]
        findings['confidence'] = overall_confidence(findings_list, 0)
        findings['lead_count'] = lead_count(findings_list)
        findings['review_priority'] = review_priority(findings_list, 0, status)
        return Report(findings=findings, findings_list=findings_list, hit_records=[],
                       score=0, status=status, any_corroborated=False,
                       coverage_reasons=coverage_reasons, scan_note=scan_note)

    # ── Score: structural validity alone is 1 ("likely" — see package ──────
    # docstring for why); independent memory-context corroboration on AT
    # LEAST ONE hit raises it to 2. Deliberately NOT len(hits) — additional
    # (even distinct-address) config copies are a fact reported in
    # config_count, not a confidence multiplier.
    any_corroborated = any(hr.corroborated for hr in hit_records)
    score = 2 if any_corroborated else 1
    findings['score']        = score
    findings['config_count'] = len(scan_outcome.hits)

    # No hit was corroborated by region protection, and thread-context
    # coverage was incomplete (or absent) — RIP/EIP corroboration could
    # not fully run, so a genuine top-tier (score 2) result cannot be
    # ruled out for these hits. This is a real coverage gap, not merely
    # "checked and found nothing", so it downgrades coverage_status the
    # same way a skipped/unreadable segment does.
    thread_context_gap = (not thread_list_stream_available) or contexts_missing > 0
    top_tier_uncertain = not any_corroborated and thread_context_gap
    if top_tier_uncertain:
        complete = False
        if not thread_list_stream_available:
            coverage_reasons.append("ThreadListStream missing from this dump — RIP/EIP-based "
                                     "context corroboration could not run for any uncorroborated hit")
        else:
            coverage_reasons.append(f"{contexts_missing}/{threads_total} thread(s) had no parsed "
                                     f"CONTEXT — RIP/EIP corroboration ran, but not for every "
                                     f"thread, for a hit not otherwise corroborated")
        findings['coverage_status']  = derive_coverage_status(True, complete)
        findings['coverage_reasons'] = coverage_reasons

    status = derive_status(True, True, complete)
    findings['status'] = status

    for hr in hit_records:
        c = hr.candidate
        region = hr.region
        cs_ver = _cs_guess_version(c.fields)
        findings['configs'].append({
            'va': c.hit_va, 'file_offset': c.hit_fo,
            'region_base':    region.BaseAddress if region is not None else None,
            'region_size':    region.RegionSize  if region is not None else None,
            'region_protect': prot_str(region.Protect) if region is not None else None,
            'xor_key': c.xor_key, 'cs_version': cs_ver,
            'cs_version_note': 'estimated from highest recognized field ID — not a '
                                'fingerprinted/confirmed build',
            'context_corroborated': hr.corroborated,
            'fields': c.fields,
        })

        facts = [f"VA=0x{c.hit_va:x} file_offset=0x{c.hit_fo:x} xor_key=0x{c.xor_key:02x} "
                 f"cs_version_estimated={cs_ver} field_count={len(c.fields)}"]
        facts.append(f"region=0x{region.BaseAddress:x} size=0x{region.RegionSize:x} "
                      f"protect={prot_str(region.Protect)}"
                      if region is not None else
                      "enclosing region not covered by MemoryInfoListStream")

        hit_limitations = []
        if not mem_info_available:
            hit_limitations.append("Region/execution-context corroboration could not be "
                                    "verified — MemoryInfoListStream missing from this dump.")
        if not hr.corroborated and thread_context_gap:
            hit_limitations.append(
                "RIP/EIP-based execution corroboration could not fully run — "
                + ("ThreadListStream missing from this dump" if not thread_list_stream_available
                   else f"{contexts_missing}/{threads_total} thread(s) had no parsed CONTEXT")
                + " — a live-execution corroboration for this hit cannot be ruled out.")

        findings_list.append(Finding(
            check="cs_beacon.structural_config",
            facts=facts,
            inference="Structurally-valid Cobalt Strike beacon configuration (TLV wire "
                       "format parsed, known BeaconType, ASN.1-shaped public key) found at "
                       "this address.",
            confidence=CONFIDENCE_HIGH if hr.corroborated else CONFIDENCE_MEDIUM,
            rationale=("Corroborated by independent memory context: " + "; ".join(hr.corrob_reasons)
                       if hr.corroborated else
                       "The config's own structural validity — TLV wire format, known field "
                       "types, a recognized BeaconType, and an ASN.1-shaped public key all "
                       "lining up — is itself hard to produce by chance, but no independent "
                       "memory-context corroboration (executable private region, or a thread "
                       "executing within the same allocation) was found for this hit."),
            limitations=hit_limitations,
            tag=TAG_DETECTION,
        ))

    findings['findings']        = [f.to_dict() for f in findings_list]
    findings['confidence']      = overall_confidence(findings_list, score)
    findings['verdict_level']   = verdict_level(score, _VERDICT_LEVEL_BY_SCORE, status=status)
    findings['lead_count']      = lead_count(findings_list)
    findings['review_priority'] = review_priority(findings_list, score, status)

    return Report(findings=findings, findings_list=findings_list, hit_records=hit_records,
                   score=score, status=status, any_corroborated=any_corroborated,
                   coverage_reasons=coverage_reasons, scan_note=scan_note)
