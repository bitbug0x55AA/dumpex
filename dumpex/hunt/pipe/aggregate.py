"""Aggregate pipe evidence and coverage into one immutable report.

Handle-confirmed pipes drive scoring. String, framework, context, proximity, and
thread observations remain typed leads or corroboration and never become handle
evidence through projection.
"""
from dumpex.hunt._domain import CheckResult
from dumpex.hunt._finding import (
    CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION,
)
from dumpex.hunt.pipe.config import PIPE_CONTEXT_DISTANCE
from dumpex.hunt.pipe.domain import CoverageSnapshot, PipeEvidence, PipeReport
from dumpex.hunt.pipe.patterns import canonical_pipe_name


def build_report(handle_pipes: tuple = (), string_leads: tuple = (),
                  corroborated_handles: tuple = (), start_address_leads: tuple = (),
                  c2_context: tuple = (), framework_string_hits: tuple = (),
                  unbacked_threads: tuple = (), *,
                  memory_info_stream: bool = False, handle_data_stream: bool = False,
                  skipped_oversize: tuple = (), read_failed: int = 0,
                  read_failed_targets: tuple = (), short_reads: int = 0,
                  short_read_targets: tuple = (), unaccounted: int = 0,
                  over_accounted: int = 0, ledger_imbalance: int = 0,
                  c2_budget_exhausted: bool = False, c2_budget_reason: str = "",
                  pipe_name_budget_exhausted: bool = False,
                  pipe_name_budget_reason: str = "",
                  pipe_name_budget_exhausted_targets: tuple = (),
                  c2_budget_exhausted_targets: tuple = (),
                  image_pipe_refs: int = 0, image_pipe_modules: tuple = (),
                  rule_version: "str | None" = None) -> PipeReport:
    """
    Turn the scan/correlation layers' typed evidence into the final
    `PipeReport`. This is the ONLY place score/coverage/the five
    CheckResults are computed for this hunter.

    `rule_version` is the loaded ruleset's own CONTENT hash, attached to
    `pipe.handle_framework_match` alone -- that check's evidence IS a
    `framework_pipes` entry from this exact ruleset. It is threaded in as a
    scalar rather than looked up here: this layer must not reach for
    rules/IO of any kind.
    """
    coverage = CoverageSnapshot(
        memory_info_stream=memory_info_stream, handle_data_stream=handle_data_stream,
        skipped_oversize=skipped_oversize, read_failed=read_failed,
        read_failed_targets=read_failed_targets, short_reads=short_reads,
        short_read_targets=short_read_targets, unaccounted=unaccounted,
        over_accounted=over_accounted, ledger_imbalance=ledger_imbalance,
        c2_budget_exhausted=c2_budget_exhausted, c2_budget_reason=c2_budget_reason,
        pipe_name_budget_exhausted=pipe_name_budget_exhausted,
        pipe_name_budget_reason=pipe_name_budget_reason,
        pipe_name_budget_exhausted_targets=pipe_name_budget_exhausted_targets,
        c2_budget_exhausted_targets=c2_budget_exhausted_targets,
        image_pipe_refs=image_pipe_refs, image_pipe_modules=image_pipe_modules,
    )

    evidence = PipeEvidence(
        handle_pipes=handle_pipes, string_leads=string_leads,
        corroborated_handles=corroborated_handles, start_address_leads=start_address_leads,
        c2_context=c2_context, framework_string_hits=framework_string_hits,
        unbacked_threads=unbacked_threads,
    )
    framework_handles = evidence.framework_handles

    results = []

    # ── Check: open pipe handles (the scored path's raw material) ─────────
    # Gated on the stream, not just on emptiness: `handle_pipes` is empty
    # both when the dump recorded zero pipe handles (a real, checked-and-
    # clean fact) and when HandleDataStream was never captured at all
    # (nothing was checked). Only the first is worth an observation.
    if handle_data_stream and evidence.handle_pipes:
        results.append(CheckResult(
            check="pipe.open_handles",
            evidence=evidence.handle_pipes,
            evidence_limit=20,
            inference=f"Process holds {len(evidence.handle_pipes)} open handle(s) to named "
                       f"pipe object(s), per HandleDataStream.",
            confidence=CONFIDENCE_MEDIUM,
            rationale="HandleDataStream is the OS's own record of what this process "
                       "actually has open — far stronger than a bare string match, but "
                       "having ANY pipe handle open is completely ordinary for most "
                       "Windows processes (IPC, RPC, print spooler, etc.); only a "
                       "handle whose name matches a known C2/lateral-movement framework "
                       "convention, or one corroborated by nearby C2 context / active "
                       "execution, is treated as a detection.",
            limitations=["Presence of a pipe handle is not inherently suspicious."],
            tag=TAG_OBSERVATION,
        ))

    # ── Check: handle name matches a known framework convention ───────────
    if framework_handles:
        mitre_ids = []
        for handle in framework_handles:
            mitre = handle.framework.mitre
            if mitre and mitre not in mitre_ids:
                mitre_ids.append(mitre)
        results.append(CheckResult(
            check="pipe.handle_framework_match",
            evidence=framework_handles,
            # Deliberately uncapped (unlike every other check here): the
            # pre-migration facts list for this one check enumerated every
            # framework-matched handle with no `[:N]` slice, and that array
            # is embedded verbatim in the frozen v1.1 dict/HunterRecord
            # goldens. The natural bound is the framework rule set itself
            # -- a handle only lands here by matching a narrow, specific
            # naming convention.
            evidence_limit=None,
            inference=f"{len(framework_handles)} open pipe handle(s) match a known "
                       f"C2/lateral-movement framework naming convention.",
            confidence=CONFIDENCE_MEDIUM,
            rationale="An OS-confirmed open handle (not just a string sitting in memory) "
                       "whose name matches a specific, narrow framework convention "
                       "(e.g. Cobalt Strike's msagent_/postex_ or PsExec's psexesvc) is "
                       "meaningfully unlikely to be coincidental — raised to HIGH only "
                       "when further corroborated (see pipe.corroboration below).",
            limitations=["Framework pipe-name conventions can be renamed/customized by an "
                         "operator; absence of a match does not mean absence of C2."],
            tag=TAG_DETECTION,
            # Real ATT&CK IDs from rules.yaml's own framework_pipes entries;
            # `rule_version` is the loaded ruleset's own CONTENT hash (not
            # rules.yaml's top-level "version:" FORMAT field -- see
            # dumpex/hunt/pipe/__init__.py's own RULE_VERSION comment for
            # why) -- neither is invented here.
            technique_ids=mitre_ids,
            rule_version=rule_version,
        ))

    # ── Check: string-scan lead (unscored) ────────────────────────────────
    # The core phase-two policy this hunter exists to hold: a bare
    # '\pipe\' byte pattern is a LEAD and never becomes scored handle
    # evidence, no matter what its name matches (see
    # dumpex/hunt/pipe/__init__.py's package docstring).
    if evidence.string_leads:
        # Per-check limitation text, not per-item: `CheckResult.limitations`
        # is one flat list for the whole check, so it must describe the
        # WHOLE `string_leads` bucket accurately rather than assume none of
        # them correlates to a handle -- OR claim an unmatched remainder
        # ("others") that may not exist. A string lead sharing its
        # canonical name with an open handle (surfaced separately above, in
        # pipe.open_handles/pipe.handle_framework_match/pipe.corroboration)
        # is a real, reachable case, and so is EVERY lead correlating (a
        # boolean "any correlated" collapses that into the same "...others
        # have no corresponding open handle" wording as a genuine mixed
        # case, which is false when there is no unmatched remainder at
        # all) -- the real matched COUNT against the total is what this
        # text must track, in three distinct, individually true states.
        handle_names = {h.canonical_name for h in evidence.handle_pipes}
        total = len(evidence.string_leads)
        matched_count = sum(1 for lead in evidence.string_leads
                             if canonical_pipe_name(lead.name) in handle_names)
        if not handle_data_stream:
            limitations = ["Not corroborated by HandleDataStream."]
        elif matched_count == 0:
            limitations = ["No corresponding open handle found for this exact name."]
        elif matched_count == total:
            limitations = [f"Every one of these {total} occurrence(s) shares a canonical name "
                            f"with an open handle reported above (see pipe.open_handles/"
                            f"pipe.handle_framework_match/pipe.corroboration) — the string match "
                            f"itself is still not scored; see those checks for the scored handle "
                            f"evidence."]
        else:
            limitations = [f"{matched_count} of these {total} occurrence(s) share a canonical "
                            f"name with an open handle reported above (see pipe.open_handles/"
                            f"pipe.handle_framework_match/pipe.corroboration) — the remaining "
                            f"{total - matched_count} have no corresponding open handle found "
                            f"for their exact name."]
        results.append(CheckResult(
            check="pipe.string_scan_lead",
            evidence=evidence.string_leads,
            evidence_limit=15,
            inference=f"{len(evidence.string_leads)} occurrence(s) of a '\\pipe\\' name found in "
                       f"non-system-DLL memory via byte-pattern scan.",
            confidence=CONFIDENCE_LOW,
            rationale="A string match proves only that these bytes exist somewhere in "
                       "memory — not that any handle was ever opened by that name, nor "
                       "that the name isn't leftover/freed heap data or an unrelated "
                       "buffer. Reported as a lead for the analyst and to locate regions "
                       "for C2-context/execution correlation; does NOT contribute to the "
                       "pipe score on its own.",
            limitations=limitations,
            tag=TAG_LEAD,
        ))

    # ── Check: handle corroborated by C2 context and/or live execution ────
    if evidence.corroborated_handles:
        # HIGH only when at least one corroborated handle has BOTH nearby
        # C2 context AND a nearby RIP/EIP hit at once (the score=3 case
        # below) — a check's confidence must track what actually justified
        # it, not be uniformly HIGH regardless of whether one or both
        # signals fired.
        full_corroboration = any(e.fully_corroborated for e in evidence.corroborated_handles)
        results.append(CheckResult(
            check="pipe.corroboration",
            evidence=evidence.corroborated_handles,
            evidence_limit=10,
            inference=f"{len(evidence.corroborated_handles)} open pipe handle(s) are corroborated "
                       f"by C2-style context and/or live RIP/EIP execution within "
                       f"±{PIPE_CONTEXT_DISTANCE} bytes of a matching pipe-name string's "
                       f"own address.",
            confidence=CONFIDENCE_HIGH if full_corroboration else CONFIDENCE_MEDIUM,
            rationale=("Combines an OS-confirmed open handle with BOTH independent memory "
                       "signals (C2 artifacts AND live execution), both within "
                       f"{PIPE_CONTEXT_DISTANCE} bytes of that pipe's name string — the "
                       "strongest correlation this hunter can produce." if full_corroboration else
                       "Combines an OS-confirmed open handle with ONE independent memory "
                       "signal (C2 artifacts or live execution, not both) within "
                       f"{PIPE_CONTEXT_DISTANCE} bytes of that pipe's name string."),
            limitations=["Name correlation between a handle's ObjectName and a string scan "
                         "hit uses exact match on the canonicalized pipe name (prefix "
                         "stripped, casefolded) — still not a cryptographic guarantee both "
                         "refer to the identical kernel object if the process has multiple "
                         "same-named pipe instances.",
                         f"Proximity window is ±{PIPE_CONTEXT_DISTANCE} bytes, not a proof of "
                         "logical association — an unrelated string or thread could "
                         "coincidentally fall within that window in a dense region."],
            tag=TAG_DETECTION,
        ))

    # ── Check: StartAddress-only proximity (lead, never scored) ───────────
    if evidence.start_address_leads:
        results.append(CheckResult(
            check="pipe.start_address_proximity_lead",
            evidence=evidence.start_address_leads,
            evidence_limit=15,
            inference=f"{len(evidence.start_address_leads)} handle-confirmed pipe(s) have an "
                       f"unbacked thread whose StartAddress (not current RIP/EIP) falls within "
                       f"±{PIPE_CONTEXT_DISTANCE} bytes of the pipe name string.",
            confidence=CONFIDENCE_LOW,
            rationale="StartAddress records where a thread BEGAN, not where it is executing "
                       "now — unlike a live RIP/EIP hit, this is not evidence the thread is "
                       "currently doing anything related to the pipe. Reported as a lead "
                       "only and does NOT contribute to the pipe score.",
            limitations=["Superseded by pipe.corroboration whenever a live RIP/EIP hit is "
                         "also present for the same handle — this only appears when no RIP "
                         "hit was found."],
            tag=TAG_LEAD,
        ))

    # ── Score ─────────────────────────────────────────────────────────────
    # 0 — string leads / a generic open handle only.
    # 1 — a handle-confirmed pipe matches a known C2/lateral-movement
    #     framework naming convention (OS-confirmed usage + specific name),
    #     even with no further corroboration.
    # 2 — ANY handle-confirmed pipe (framework-matched or not) is
    #     corroborated by C2-style context OR live RIP/EIP execution
    #     within PIPE_CONTEXT_DISTANCE of the same-named string occurrence.
    # 3 — corroborated by BOTH at once, within that same distance window.
    #
    # Deliberately NOT gated on a framework match for tiers 2-3: a
    # same-named handle actively corroborated by nearby C2 context or live
    # execution is strong evidence on its own (an OS-confirmed handle PLUS
    # independent, PROXIMATE memory evidence), and requiring a
    # framework-name match on top of that would silently downgrade a
    # genuinely corroborated custom/non-framework pipe to a finding the
    # score doesn't reflect — exactly the finding/verdict mismatch this
    # scoring model exists to avoid. StartAddress proximity never
    # contributes here — see pipe.start_address_proximity_lead. Nor does
    # any string-only evidence: `string_leads`/`framework_string_hits`/
    # `c2_context`/`unbacked_threads` are absent from this computation on
    # purpose.
    score = 0
    if framework_handles:
        score = 1
    for entry in evidence.corroborated_handles:
        if entry.fully_corroborated:
            score = max(score, 3)
        else:
            score = max(score, 2)

    return PipeReport(score=score, coverage=coverage, results=tuple(results),
                       evidence=evidence)
