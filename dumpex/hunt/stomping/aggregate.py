"""
Aggregation layer for dumpex.hunt.stomping: the ONLY place score,
coverage, and the six `CheckResult`s (protection_deviation_lead /
rip_in_anomalous_section_lead / verified_content_change /
reference_identity_mismatch / module_header_invalid / ioc_string_lead) are
computed for this hunter. Takes the typed evidence the scan/correlation
layers (memory_scan, disk_reference, correlation) produced -- with module/
section/region identity and RIP correlation already resolved once, at scan
time -- and turns it into an immutable `StompingReport`
(dumpex.hunt.stomping.domain).

Nothing here prints, nothing here scans/diffs, and nothing here builds
rendered `facts`/`verbose_facts` text: `CheckResult.evidence` carries the
typed value objects; report_facts.py/report_legacy.py/report_record.py/
report_console.py are the pure projections that render them (see
domain.py's own docstring for why this split removes the parallel-
representation drift the pre-migration `Report` had).

Takes ONLY typed evidence tuples plus int/bool scalars -- no `mf`, no
`verbose`, no raw `modules`/`regions`/`thread_contexts` lists, and no
`ref_dir` PATH (only `ref_dir_supplied`, a bool: whether a reference
directory was given is a coverage fact the verdict depends on; the path
itself is a live filesystem handle this layer must never see).
`dumpex/hunt/stomping/__init__.py` is where those raw inputs still live; it
converts them into the typed evidence and scalars this module consumes.
"""
from dumpex.hunt._domain import CheckResult
from dumpex.hunt._finding import (
    CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION,
)
from dumpex.hunt.stomping.domain import (
    CoverageSnapshot, StompingEvidence, StompingReport,
)


def build_report(protection_leads: tuple = (), rip_correlated_leads: tuple = (),
                  verified_changes: tuple = (), identity_mismatches: tuple = (),
                  parse_failures: tuple = (), ioc_hits: tuple = (), *,
                  memory_info_stream: bool = False, module_list_stream: bool = False,
                  ref_dir_supplied: bool = False,
                  modules_total: int = 0, headers_parsed: int = 0,
                  sections_total: int = 0, sections_compared: int = 0,
                  reference_missing: int = 0, reference_mismatch: int = 0,
                  reference_read_failed: int = 0, memory_read_failed: int = 0,
                  short_reads: int = 0, relocation_failed: int = 0,
                  header_read_failed: int = 0, header_parse_failed: int = 0,
                  ioc_oversized: tuple = (), ioc_read_failed: int = 0,
                  ioc_short_reads: int = 0,
                  ioc_whitelisted_modules: tuple = ()) -> StompingReport:
    """
    Turn the scan/correlation layers' typed evidence into the final
    `StompingReport`. This is the ONLY place score/coverage/the six
    CheckResults are computed for this hunter.

    `rip_correlated_leads` is computed unconditionally by correlation.py
    (a pure pairing of protection leads with executing threads); the
    DECISION about whether that pairing is worth reporting as its own
    check is made here -- see the `stomping.rip_in_anomalous_section_lead`
    block below for the "only when the scored path couldn't already settle
    it" gate that decision preserves.
    """
    coverage = CoverageSnapshot(
        memory_info_stream=memory_info_stream, module_list_stream=module_list_stream,
        ref_dir_supplied=ref_dir_supplied,
        modules_total=modules_total, headers_parsed=headers_parsed,
        sections_total=sections_total, sections_compared=sections_compared,
        reference_missing=reference_missing, reference_mismatch=reference_mismatch,
        reference_read_failed=reference_read_failed, memory_read_failed=memory_read_failed,
        short_reads=short_reads, relocation_failed=relocation_failed,
        header_read_failed=header_read_failed, header_parse_failed=header_parse_failed,
        ioc_oversized=ioc_oversized, ioc_read_failed=ioc_read_failed,
        ioc_short_reads=ioc_short_reads, ioc_whitelisted_modules=ioc_whitelisted_modules,
    )

    results = []

    # ── Check: protection-deviation lead (never scored) ───────────────────
    if protection_leads:
        results.append(CheckResult(
            check="stomping.protection_deviation_lead",
            evidence=protection_leads,
            evidence_limit=20,
            inference=f"{len(protection_leads)} module section(s) declared executable-but-"
                       f"not-writable show LIVE protection other than the normal, "
                       f"unmodified-mapping set (PAGE_EXECUTE_WRITECOPY excluded — that is "
                       f"routine loader behavior).",
            confidence=CONFIDENCE_MEDIUM,
            rationale="An unusual protection state is a structural fact, but proves nothing "
                       "about content by itself: an attacker can VirtualProtect a section "
                       "back to RX after stomping it and before a dump is captured, and a "
                       "debugger/EDR hook can transiently reprotect memory for entirely "
                       "benign reasons. This is reported as a LEAD and does NOT contribute "
                       "to the stomping score — only a verified content diff "
                       "(stomping.verified_content_change, requires --ref-dir) does.",
            limitations=["Protection state alone cannot confirm or rule out that section "
                         "content actually changed."],
            tag=TAG_LEAD,
        ))
    elif coverage.evaluated:
        # Legitimately evidence-free: the claim is about the ABSENCE of an
        # anomaly across everything that was checked, so its single fact is
        # rendered from the Report's own coverage snapshot
        # (`headers_parsed`) rather than from an evidence item -- the same
        # shape dumpex.hunt.injection's `rip_correlation_unavailable` uses.
        #
        # Gated on `coverage.evaluated`: this is an "absence of anomaly"
        # claim, true only if the module/section walk actually ran over
        # everything. When it never ran at all (e.g. ModuleListStream
        # missing -- the IOC sub-scan can still fire independently, see
        # domain.CoverageSnapshot.evaluated), `protection_leads` is empty
        # not because nothing was found but because nothing was checked;
        # emitting "No module section ... shows anomaly" in that case would
        # misreport an unevaluated scope as a clean one.
        results.append(CheckResult(
            check="stomping.protection_deviation_lead",
            inference="No module section declared executable-but-not-writable shows a "
                       "live protection state outside the normal set.",
            confidence=CONFIDENCE_LOW,
            rationale="Absence of a protection anomaly is weak evidence of absence — "
                       "stomping via careful VirtualProtect bookkeeping (reprotect to RX "
                       "before the dump) would not show up here at all.",
            limitations=[],
            tag=TAG_OBSERVATION,
        ))

    # ── Check: protection anomaly + a thread's LIVE RIP/EIP inside that ───
    # same section — a stronger, more specific signal than the bare
    # protection-deviation lead above, but still not the verified,
    # relocation-normalized byte diff that alone earns "confirmed
    # stomping" (stomping.verified_content_change below). Only reported
    # when the scored path couldn't already settle it (no --ref-dir, or
    # --ref-dir supplied but no verified diff came out of it) — once a
    # verified diff exists, its OWN rip_in_changed_range already covers
    # this correlation with actual evidence behind it, not just a
    # protection-state guess.
    if (protection_leads and (not ref_dir_supplied or not verified_changes)
            and rip_correlated_leads):
        results.append(CheckResult(
            check="stomping.rip_in_anomalous_section_lead",
            evidence=rip_correlated_leads,
            evidence_limit=20,
            inference=f"{len(rip_correlated_leads)} module section(s) with anomalous live "
                       f"protection ALSO have a thread's current RIP/EIP executing "
                       f"inside that exact section.",
            confidence=CONFIDENCE_MEDIUM,
            rationale="A protection deviation alone proves nothing about content "
                       "(see stomping.protection_deviation_lead), but a thread "
                       "actively executing inside the SAME anomalously-protected "
                       "range is a materially stronger, more specific correlation "
                       "worth a closer manual look — without --ref-dir there is no "
                       "verified byte-level diff behind it, so this stays a lead, "
                       "not a confirmed stomping detection.",
            limitations=["Protection state + live RIP still cannot rule out a "
                         "debugger/EDR hook or other benign reprotect-then-execute "
                         "sequence — only a verified content diff "
                         "(stomping.verified_content_change, requires --ref-dir) can."],
            tag=TAG_LEAD,
        ))

    # ── Check: verified content change (the only scored signal) ───────────
    if verified_changes:
        any_rip = any(vc.rip_in_changed_range for vc in verified_changes)
        results.append(CheckResult(
            check="stomping.verified_content_change",
            evidence=verified_changes,
            evidence_limit=15,
            inference=f"{len(verified_changes)} module section(s) have relocation-normalized, "
                       f"byte-level content differences from an identity-matched "
                       f"(Machine/SizeOfImage/TimeDateStamp) reference file supplied via "
                       f"--ref-dir.",
            confidence=CONFIDENCE_HIGH if any_rip else CONFIDENCE_MEDIUM,
            rationale=("A thread's current RIP/EIP executes inside one of the actually-"
                       "changed byte ranges — the strongest evidence this hunter can "
                       "produce." if any_rip else
                       "Verified byte-level difference against an identity-matched, "
                       "relocation-normalized reference, but no observed thread is currently "
                       "executing inside the changed range(s)."),
            limitations=["IAT/delay-import ranges and hotpatch trampolines are NOT "
                         "specifically excluded before diffing — restricting the diff to "
                         "executable, non-writable sections already excludes the import "
                         "tables themselves for typical PE layouts, but a legitimate hotpatch "
                         "NOP-padding/trampoline at a function prologue can still produce a "
                         "genuine, non-malicious difference inside .text.",
                         "PDB GUID/Age (CodeView debug directory) is not checked as part of "
                         "reference-identity matching — Machine/SizeOfImage/TimeDateStamp "
                         "matching all three is a strong but not perfect guarantee the "
                         "reference is the exact same build.",
                         "Relocation normalization applies IMAGE_REL_BASED_HIGHLOW/DIR64 "
                         "fixups only — the types real x86/x64 linkers emit; an exotic or "
                         "corrupt relocation table would leave some fixups un-normalized."],
            tag=TAG_DETECTION,
        ))

    # ── Check: reference build-identity mismatch (a coverage gap) ─────────
    if identity_mismatches:
        results.append(CheckResult(
            check="stomping.reference_identity_mismatch",
            evidence=identity_mismatches,
            evidence_limit=15,
            inference=f"{len(identity_mismatches)} section(s) had a matching-basename reference "
                       f"file under --ref-dir, but its own header identity did not match the "
                       f"in-memory module — comparison was skipped rather than risk a false "
                       f"positive from diffing against a different build.",
            confidence=CONFIDENCE_LOW,
            rationale="A same-named file that is actually a different build/version/patch "
                       "level would show ordinary compiler-output differences that are not "
                       "stomping — skipping is the safe choice, but it also means this "
                       "section could not be verified at all.",
            limitations=["Coverage gap: supply a reference file matching the exact build "
                         "(Machine/SizeOfImage/TimeDateStamp) to verify these sections."],
            tag=TAG_OBSERVATION,
        ))

    # ── Check: module header failed structural validation (coverage gap) ──
    if parse_failures:
        results.append(CheckResult(
            check="stomping.module_header_invalid",
            evidence=parse_failures,
            evidence_limit=15,
            inference=f"{len(parse_failures)} known module(s) failed PE header structural "
                       f"validation at their own recorded base address.",
            confidence=CONFIDENCE_LOW,
            rationale="A loaded module's own header failing to parse is itself unusual "
                       "(the loader required a valid header to map it) — could be a "
                       "partially-paged-out header at dump time, or could itself be "
                       "evidence of tampering. Either way, these modules could NOT be "
                       "checked for stomping at all — this is a coverage gap, not a "
                       "negative result.",
            limitations=["These modules are excluded from both the protection-deviation "
                         "lead and the verified-content-change check."],
            tag=TAG_OBSERVATION,
        ))

    # ── Score ─────────────────────────────────────────────────────────────
    # The verified, relocation-normalized content diff is the ONLY path to
    # a nonzero score; a thread's live RIP/EIP inside one of the actually-
    # changed byte ranges is what takes it from 1 to 2.
    score = 0
    if verified_changes:
        score = 2 if any(vc.rip_in_changed_range for vc in verified_changes) else 1

    # ── Check: IOC string lead (unscored) ─────────────────────────────────
    if ioc_hits:
        n_strong = sum(sum(1 for t in hit.tokens if not t.is_weak) for hit in ioc_hits)
        n_weak   = sum(sum(1 for t in hit.tokens if t.is_weak) for hit in ioc_hits)
        results.append(CheckResult(
            check="stomping.ioc_string_lead",
            evidence=ioc_hits,
            evidence_limit=15,
            inference=f"{n_strong} strong + {n_weak} weak IOC-keyword token(s) found across "
                       f"{len(ioc_hits)} executable module region(s).",
            confidence=CONFIDENCE_LOW,
            rationale="A string match proves only that the bytes exist somewhere in the "
                       "region — it is trivial to plant, coincidentally match tool/API "
                       "names, or survive from unrelated benign code. This is reported as "
                       "an investigative lead only and does NOT contribute to the stomping "
                       "score; see stomping.verified_content_change for the only signal "
                       "that scores.",
            # An IOC lead found in PART of the eligible scope must carry the
            # unexamined remainder with it: "N regions had IOC strings" is
            # a floor, not a total, whenever an eligible region was never
            # read (oversized) or could not be read at all. The reason text
            # comes from CoverageSnapshot.ioc_gap_reasons() -- the ONE
            # canonical wording, shared with coverage_reasons and the
            # console's COVERAGE section (see domain.py's IOC_*_LABEL).
            limitations=["Not corroborated by any structural (section/protection) evidence "
                         "on its own."]
                        + [f"Coverage gap — {reason}." for reason in coverage.ioc_gap_reasons()],
            tag=TAG_LEAD,
        ))

    evidence = StompingEvidence(
        protection_leads=protection_leads, rip_correlated_leads=rip_correlated_leads,
        verified_changes=verified_changes, identity_mismatches=identity_mismatches,
        parse_failures=parse_failures, ioc_hits=ioc_hits,
    )
    return StompingReport(score=score, coverage=coverage, results=tuple(results),
                           evidence=evidence)
