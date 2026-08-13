"""The ONE place score/status/coverage_status/verdict_level/confidence/
lead_count/review_priority get computed for the CS beacon hunter, and where
`CheckResult`s are built.

Nothing here prints; nothing here decodes/scans/reads memory. This module
turns already-collected TYPED evidence (a tuple of `models.ConfigEvidence`
hits, a tuple of `models.CorroborationEvidence`, a `domain.ScanDiagnostics`)
plus validated scalars into an immutable `domain.CSBeaconReport`. No `mf`,
no `verbose`, no raw region/thread lists, and no live `CoverageTracker`/
`ScanOutcome` -- see dumpex/hunt/cs_beacon/domain.py's own docstring for
what this replaces.

The check ORDER below is part of the frozen output contract: `cs_beacon.
structural_config` appends one `CheckResult` per hit, in the SAME order as
`evidence.hits` -- report_facts.py/report_legacy.py/report_record.py all
zip results against `evidence.hits` positionally.
"""
from dumpex.hunt._domain import CheckResult
from dumpex.hunt._finding import CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH, \
    TAG_OBSERVATION, TAG_DETECTION
from dumpex.hunt.cs_beacon.domain import (
    CoverageSnapshot, CSBeaconEvidence, CSBeaconReport, MAX_SCORE, ScanDiagnostics,
)


def build_not_evaluated_report() -> CSBeaconReport:
    """No memory segments at all in the dump — never a bare CLEAN."""
    return CSBeaconReport(
        score=0, coverage=CoverageSnapshot(scan=ScanDiagnostics(segment_count=0)))


def build_report(hits: tuple = (), corroborations: tuple = (), *,
                  scan: ScanDiagnostics, mem_info_available: bool = False,
                  thread_list_stream_available: bool = False, threads_total: int = 0,
                  contexts_parsed: int = 0) -> CSBeaconReport:
    """
    Turn the scan/corroboration layers' typed evidence into the final
    `CSBeaconReport`. This is the ONE place score/coverage/`CheckResult`s
    are computed for this hunter.

    `hits` is every structurally-valid config scanner.py found, in scan
    order. `corroborations` is one `models.CorroborationEvidence` per
    CORROBORATED hit (never one per hit) -- see context.corroborate().
    """
    coverage = CoverageSnapshot(
        scan=scan, mem_info_available=mem_info_available,
        thread_list_stream_available=thread_list_stream_available,
        threads_total=threads_total, contexts_parsed=contexts_parsed)

    results = []

    if not hits:
        results.append(CheckResult(
            check="cs_beacon.no_structural_config",
            evidence=(),
            inference="No structurally-valid (sanity-checked TLV, known BeaconType, "
                       "ASN.1-shaped public key) Cobalt Strike beacon configuration found "
                       "in what was scanned.",
            confidence=CONFIDENCE_LOW,
            rationale="Absence of a decodable config is weak evidence of absence — an "
                       "unscanned/skipped/unreadable segment, an unsupported XOR scheme, or "
                       "a config that never touched memory captured in this dump would all "
                       "look identical to this.",
            limitations=(("Coverage was incomplete — see coverage_reasons.",)
                         if not coverage.complete(any_corroborated=False) else ()),
            tag=TAG_OBSERVATION,
        ))
        evidence = CSBeaconEvidence()
        return CSBeaconReport(score=0, coverage=coverage, results=tuple(results),
                               evidence=evidence)

    # ── Score: structural validity alone is 1 ("likely" -- see domain.py's ──
    # own VERDICT_LEVEL_BY_SCORE for why); independent memory-context
    # corroboration on AT LEAST ONE hit raises it to 2. Deliberately NOT
    # len(hits) -- additional (even distinct-address) config copies are a
    # fact reported via `config_count`, not a confidence multiplier.
    any_corroborated = bool(corroborations)
    score = MAX_SCORE if any_corroborated else 1
    thread_context_gap = coverage.thread_context_gap

    for hit in hits:
        corroboration = next((c for c in corroborations if c.hit is hit), None)
        corroborated = corroboration is not None

        facts_evidence = (hit,) if corroboration is None else (hit, corroboration)

        limitations = []
        if not mem_info_available:
            limitations.append("Region/execution-context corroboration could not be "
                                "verified — MemoryInfoListStream missing from this dump.")
        if not corroborated and thread_context_gap:
            limitations.append(
                "RIP/EIP-based execution corroboration could not fully run — "
                + ("ThreadListStream missing from this dump" if not thread_list_stream_available
                   else f"{coverage.contexts_missing}/{threads_total} thread(s) had no parsed "
                        f"CONTEXT")
                + " — a live-execution corroboration for this hit cannot be ruled out.")

        results.append(CheckResult(
            check="cs_beacon.structural_config",
            evidence=facts_evidence,
            inference="Structurally-valid Cobalt Strike beacon configuration (TLV wire "
                       "format parsed, known BeaconType, ASN.1-shaped public key) found at "
                       "this address.",
            confidence=CONFIDENCE_HIGH if corroborated else CONFIDENCE_MEDIUM,
            rationale=("Corroborated by independent memory context: " + "; ".join(
                           corroboration.reasons) if corroborated else
                       "The config's own structural validity — TLV wire format, known field "
                       "types, a recognized BeaconType, and an ASN.1-shaped public key all "
                       "lining up — is itself hard to produce by chance, but no independent "
                       "memory-context corroboration (executable private region, or a thread "
                       "executing within the same allocation) was found for this hit."),
            limitations=tuple(limitations),
            tag=TAG_DETECTION,
        ))

    evidence = CSBeaconEvidence(hits=hits, corroborations=corroborations)
    return CSBeaconReport(score=score, coverage=coverage, results=tuple(results), evidence=evidence)
