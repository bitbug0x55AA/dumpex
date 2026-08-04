"""Process hollowing / image-base mismatch hunter."""
import ntpath
from dataclasses import dataclass, field
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (get_modules, get_memory_regions,
    addr_to_module, va_to_file_offset, prot_str, read_region)
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_LEAD, TAG_DETECTION, overall_confidence, verdict_level,
    lead_count, review_priority, leads_suffix)
from dumpex.output.coverage import (
    build_coverage_report, observe_source, SourceObservation, SourceState,
    SourceRequirement, EvaluationRequirement, LimitationCode,
)
from dumpex.output.records import HunterRecord, HollowingDetails, hex_address

# score -> verdict_level, owned by this hunter (see _finding.verdict_level).
_VERDICT_LEVEL_BY_SCORE = {1: "likely", 2: "high"}


@dataclass
class Report:
    """Everything `_hunt_hollowing()` (console) and
    `dumpex.hunt.hollowing.collect.collect_hollowing_record()` (the v2.4
    HunterRecord path) both need -- the ONE place this hunter's checks
    run, extracted from what used to be a single monolithic
    `_hunt_hollowing()` (see PR2b of the `--hunt` v2.4 migration). Both
    consuming the exact same Report is what guarantees they can never
    compute a different score/status/coverage for the same input.

    Raw objects (`base_region`, `main_mod`) are kept here ONLY for
    `_hunt_hollowing()`'s own console formatting (VA/protection/file-
    offset text) -- `collect_hollowing_record()` never reads them
    directly, only the already-sanitized boolean/hex fields below (see
    that module's own docstring)."""
    peb_present:            bool
    image_base:             "int | None"   # raw VA, None if peb missing
    image_path:             "str | None"   # "(unknown)"-coerced, same as pre-split behavior
    peb_image_path_raw:     "str | None"   # genuinely None when PEB carries no path -- see HollowingDetails
    fo_base:                "int | None"   # byte offset in .dmp, None if not captured
    base_region:            object          # raw MinidumpMemoryInfo, or None if not found
    mem_private:            bool
    mz_read_failed:         bool
    mz_outcome:             "str | None"   # "short_read"/"exception"/"clean"/"wiped_zero"/"wiped_other"
    mz_header_bytes:        "bytes | None"
    mz_exception_text:      "str | None"
    mz_wiped:               bool
    is_rwx:                 bool
    main_mod:                object          # raw module, or None if not found
    module_list_unavailable: bool
    name_mismatch:           bool
    findings_list:           list = field(default_factory=list)   # list[Finding]
    score:                   int = 0
    max_score:               int = 2
    status:                  "str | None" = None
    coverage_status:         "str | None" = None   # v1.1 free-text status
    coverage_reasons:        list = field(default_factory=list)   # v1.1 free-text reasons
    coverage_report:         object = None          # dumpex.output.coverage.CoverageReport
    confidence:              "str | None" = None
    verdict_level:           "str | None" = None
    findings:                list = field(default_factory=list)   # list[dict], Finding.to_dict()
    lead_count:              int = 0
    review_priority:         "str | None" = None


def _build_hollowing_report(mf: MinidumpFile) -> Report:
    """Run every hollowing check and return the Report -- no printing.
    Behavior (score/status/coverage_status/coverage_reasons/findings)
    unchanged from before this split; `coverage_report` is new (v2.4
    migration only, see dumpex.output.coverage). `get_modules`/
    `get_memory_regions`/`get_rules(announce=False)` run unconditionally
    here, BEFORE the `peb` check below, matching the pre-split function's
    own exact order -- moving them behind the early-return would skip
    that call entirely for a PEB-missing dump, a real behavior change
    caught by tests/integration/test_hunt_cli_compat_freeze.py's frozen
    console fixtures. `announce=False`: this function must stay silent
    (see dumpex.hunt.collect_hunt()'s own docstring on why) -- the
    console entry point's own bare `get_rules()` call is what prints
    "Rules loaded from ..." the first time it's ever called in a
    process, not this one."""
    modules = get_modules(mf)
    # get_modules() returns [] both when ModuleList is entirely missing/empty
    # AND when it's present but genuinely has no entry for this address —
    # those are different coverage situations for check 4 below (the first
    # means the check never actually ran; the second is a real signal).
    modules_available = bool(mf.modules and mf.modules.modules)
    regions = get_memory_regions(mf)
    SUSPICIOUS_PROTS = get_rules(announce=False)["suspicious_protections"]

    peb = mf.peb
    if not peb:
        return Report(
            peb_present=False, image_base=None, image_path=None, peb_image_path_raw=None,
            fo_base=None,
            base_region=None, mem_private=False, mz_read_failed=False, mz_outcome=None,
            mz_header_bytes=None, mz_exception_text=None, mz_wiped=False, is_rwx=False,
            main_mod=None, module_list_unavailable=True, name_mismatch=False,
            score=0, max_score=2, status=NOT_EVALUATED, coverage_status="not_evaluated",
            coverage_reasons=["PEB stream missing from this dump"],
            coverage_report=_hollowing_not_evaluated_coverage_report(),
            confidence=overall_confidence([], 0),
            verdict_level=verdict_level(0, _VERDICT_LEVEL_BY_SCORE, status=NOT_EVALUATED),
            findings=[], lead_count=0, review_priority=review_priority([], 0, NOT_EVALUATED),
        )

    findings_list = []

    image_base = peb.image_base_address
    # `image_path` is coerced to "(unknown)" exactly as before this split --
    # every existing scoring/Finding-text/print use of it below is
    # unchanged. `peb_image_path_raw` (genuinely None when PEB carries no
    # path) is tracked separately purely for HollowingDetails.peb_image_path,
    # whose "str | None" contract means null, not the display string "(unknown)".
    image_path = peb.image_path or "(unknown)"
    peb_image_path_raw = peb.image_path
    fo_base = va_to_file_offset(mf, image_base)

    base_region = None
    for r in regions:
        if r.BaseAddress <= image_base < r.BaseAddress + r.RegionSize:
            base_region = r
            break

    # ── Check 1 (anchor): memory type at image base ────────────────────
    mem_private = False
    if base_region:
        mtype = prot_str(base_region.Type)
        if "MEM_IMAGE" not in mtype:
            mem_private = True
            p = prot_str(base_region.Protect)
            findings_list.append(Finding(
                check="hollowing.mem_private_at_image_base",
                facts=[f"VA=0x{base_region.BaseAddress:x} type={mtype} protect={p}"],
                inference="The main module's image base is backed by MEM_PRIVATE memory, "
                           "not a file-mapped MEM_IMAGE region.",
                confidence=CONFIDENCE_MEDIUM,
                rationale="A genuine PE image loaded normally is always MEM_IMAGE at its "
                           "base — MEM_PRIVATE there means nothing was actually mapped from "
                           "the executable file this process is supposed to be running. "
                           "Structural on its own, but a manually-mapped, otherwise benign "
                           "loader (some DRM/anti-cheat/packer stubs) can also produce this "
                           "without hollowing — correlated with a second anomaly below before "
                           "it counts toward the score.",
                limitations=["A manual-mapping loader that isn't hollowing can also produce "
                             "this signal alone."],
                tag=TAG_LEAD,
            ))

    # ── Check 2 (anchor): MZ header at image base ───────────────────────
    mz_wiped = False
    mz_read_failed = False
    mz_outcome = None
    mz_header_bytes = None
    mz_exception_text = None
    try:
        header = read_region(mf, image_base, min(64, 0x1000))
        mz_header_bytes = header
        if len(header) < 2:
            mz_read_failed = True
            mz_outcome = "short_read"
        elif header[:2] == b'MZ':
            mz_outcome = "clean"
        elif header == b'\x00' * len(header):
            mz_wiped = True
            mz_outcome = "wiped_zero"
        else:
            mz_wiped = True
            mz_outcome = "wiped_other"
        if mz_wiped:
            findings_list.append(Finding(
                check="hollowing.mz_header_missing",
                facts=[f"VA=0x{image_base:x} header_bytes={header[:8].hex()}"],
                inference="No valid MZ/DOS header is present where the PEB's own image base "
                           "says the main module should start.",
                confidence=CONFIDENCE_MEDIUM,
                rationale="A loaded PE image always has an MZ header at its base — its "
                           "absence (zeroed or overwritten) is a structural fact, but reads "
                           "that raced a legitimate unmap/remap, or a short/partial capture "
                           "of that exact page, can also produce this without hollowing — "
                           "correlated with a second anomaly below before it counts toward "
                           "the score.",
                limitations=["Cannot distinguish deliberate header wiping from a capture-time "
                             "race or partial read of this specific page."],
                tag=TAG_LEAD,
            ))
    except Exception as e:
        mz_read_failed = True
        mz_outcome = "exception"
        mz_exception_text = str(e)

    # ── Check 3 (corroborator): RWX at image base ───────────────────────
    is_rwx = False
    if base_region:
        p = prot_str(base_region.Protect)
        if any(s in p for s in SUSPICIOUS_PROTS):
            is_rwx = True
            findings_list.append(Finding(
                check="hollowing.rwx_at_image_base",
                facts=[f"VA=0x{base_region.BaseAddress:x} protect={p}"],
                inference="The main module's image base carries RWX-family protection.",
                confidence=CONFIDENCE_LOW,
                rationale="RWX at the image base is needed to write replacement code during "
                           "hollowing, but RWX alone is routinely used by JITs, debuggers, "
                           "and some legitimate packers — a lead, not proof, on its own.",
                limitations=["Does not by itself distinguish hollowing from JIT/legitimate "
                             "self-modifying-code use cases at this address."],
                tag=TAG_LEAD,
            ))

    # ── Check 4 (corroborator): module list sanity ──────────────────────
    name_mismatch = False
    module_list_unavailable = not modules_available
    main_mod = addr_to_module(image_base, modules)
    if main_mod:
        mod_name = _basename_lower(main_mod.name)
        peb_name = _basename_lower(image_path)
        if mod_name != peb_name:
            name_mismatch = True
    elif not module_list_unavailable:
        name_mismatch = True
    if name_mismatch:
        findings_list.append(Finding(
            check="hollowing.peb_module_name_mismatch",
            facts=[f"PEB_image_path={image_path!r} module_list_match={bool(main_mod)}"],
            inference="The PEB's own ImagePath name doesn't match the module list's name "
                       "for this base address, or the base isn't in the module list at all.",
            confidence=CONFIDENCE_LOW,
            rationale="A name mismatch or missing module-list entry can also come from "
                       "DLL redirection, WoW64 path differences, or a capture-time race — "
                       "a lead, not proof, on its own.",
            limitations=["Does not by itself distinguish hollowing from benign path/"
                         "redirection differences."],
            tag=TAG_LEAD,
        ))

    # ── Correlation: DETECTED requires anchor 1 (MEM_PRIVATE) together ──
    # with at least one of anchor 2 (MZ wiped) or corroborator 3 (RWX) —
    # a single anomaly, including either anchor alone, stays lead-only.
    score = 0
    if mem_private and (mz_wiped or is_rwx):
        both_anchors_and_rwx = mz_wiped and is_rwx
        score = 2 if both_anchors_and_rwx else 1
        corroborators = ["MEM_PRIVATE at image base"]
        if mz_wiped:
            corroborators.append("MZ header missing/wiped")
        if is_rwx:
            corroborators.append("RWX protection")
        findings_list.append(Finding(
            check="hollowing.structural_correlation",
            facts=[f"VA=0x{image_base:x} " + " + ".join(corroborators)],
            inference=f"{len(corroborators)} independent structural signal(s) correlate at "
                       f"the same image base: {', '.join(corroborators)}.",
            confidence=CONFIDENCE_HIGH if both_anchors_and_rwx else CONFIDENCE_MEDIUM,
            rationale="Any one of these signals alone has a plausible benign explanation "
                       "(manual mapping, a capture-time read race, a JIT/packer using RWX). "
                       "MEM_PRIVATE at the image base correlated with a missing/wiped MZ "
                       "header AND/OR RWX protection at that same address is materially "
                       "harder to explain away — the combination the module's own checks "
                       "were designed to catch.",
            limitations=["Structural correlation is strong evidence but not a substitute "
                         "for live-execution corroboration (no thread-context signal is "
                         "available for this hunter)."],
            tag=TAG_DETECTION,
        ))

    evaluated = True   # PEB was present — the check actually ran
    # `complete` must reflect every check that failed to actually run, not
    # just a missing region: the MZ-header anchor reads a fixed 64-byte
    # window at image_base independently of base_region, and an OSError/
    # short-read failure there was previously only printed, never folded
    # into coverage -- as long as base_region existed, the result claimed
    # coverage_status: complete even though anchor 2 never actually ran.
    complete = base_region is not None and not mz_read_failed and not module_list_unavailable
    coverage_reasons = []
    if base_region is None:
        coverage_reasons.append("Image base page not captured in this dump — memory-type and "
                                 "RWX checks could not run")
    if mz_read_failed:
        coverage_reasons.append("Image base MZ header could not be read — MZ-header check "
                                 "could not run")
    if module_list_unavailable:
        coverage_reasons.append("ModuleListStream missing/empty from this dump — module-list "
                                 "sanity check could not run")
    coverage_status = derive_coverage_status(evaluated, complete)
    status = derive_status(evaluated, score > 0, complete)

    coverage_report = _hollowing_evaluated_coverage_report(
        base_region_found=base_region is not None, mz_read_failed=mz_read_failed,
        modules_available=modules_available)

    return Report(
        peb_present=True, image_base=image_base, image_path=image_path,
        peb_image_path_raw=peb_image_path_raw, fo_base=fo_base,
        base_region=base_region, mem_private=mem_private, mz_read_failed=mz_read_failed,
        mz_outcome=mz_outcome, mz_header_bytes=mz_header_bytes,
        mz_exception_text=mz_exception_text, mz_wiped=mz_wiped, is_rwx=is_rwx,
        main_mod=main_mod, module_list_unavailable=module_list_unavailable,
        name_mismatch=name_mismatch, findings_list=findings_list, score=score, max_score=2,
        status=status, coverage_status=coverage_status, coverage_reasons=coverage_reasons,
        coverage_report=coverage_report,
        confidence=overall_confidence(findings_list, score),
        verdict_level=verdict_level(score, _VERDICT_LEVEL_BY_SCORE, status=status),
        findings=[f.to_dict() for f in findings_list], lead_count=lead_count(findings_list),
        review_priority=review_priority(findings_list, score, status),
    )


def _hollowing_not_evaluated_coverage_report():
    """Matches dumpex.commands.peb.collect_peb()'s own PEB_UNAVAILABLE
    precedent exactly -- --peb's own docstring explains why this needs a
    dedicated code rather than the automatic single-source SOURCE_ABSENT
    default: 'PEB could not be parsed (missing sysinfo or thread list in
    dump)' doesn't fit the generic 'X not present in this dump'
    template."""
    sources = {"peb": observe_source("peb", present=False)}
    return build_coverage_report(
        sources,
        evaluation_sources=EvaluationRequirement(
            sources=("peb",), all_absent_code=LimitationCode.PEB_UNAVAILABLE),
    )


def _hollowing_evaluated_coverage_report(*, base_region_found: bool, mz_read_failed: bool,
                                          modules_available: bool):
    """Real dumpex.output.coverage.CoverageReport for a hollowing run that
    actually evaluated (PEB present) -- built from the exact same three
    gap facts `complete`/`coverage_reasons` above derive from, at the
    site each gap is discovered (never parsed back out of free text; see
    docs/hunt_migration_field_matrix.md's own migration rule). `peb`
    itself isn't repeated here as a completeness_check: it's already the
    sole `evaluation_sources` gate below, and per
    build_coverage_report()'s own docstring that group short-circuits to
    NOT_EVALUATED before completeness_checks are ever consulted, so
    listing it again here would only ever matter for a state this
    function is never called in. `image_base_region`/`mz_header_read`
    are synthetic sources (not real minidump streams) purely so PE-style
    per-check gaps have a source key to attach a limitation to — the
    same pattern injection's own `hidden_pe_scan` source uses (see
    dumpex.hunt.injection.aggregate.build_report)."""
    sources = {
        "peb":                observe_source("peb", present=True, items=["present"]),
        "image_base_region":  observe_source("image_base_region", present=base_region_found,
                                              items=["found"] if base_region_found else []),
        "mz_header_read":     (SourceObservation(name="mz_header_read", state=SourceState.FAILED)
                                if mz_read_failed else
                                observe_source("mz_header_read", present=True, items=["read"])),
        "modules":            observe_source("modules", present=modules_available,
                                              items=["present"] if modules_available else []),
    }
    completeness_checks = [
        "image_base_region",
        "mz_header_read",
        SourceRequirement(source="modules",
                          absent_code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE),
    ]
    return build_coverage_report(
        sources, evaluation_sources=("peb",), completeness_checks=completeness_checks)


def _hunt_hollowing(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect Process Hollowing by comparing PEB image path against the
    actual memory backing of the main module base address.

    Two STRUCTURAL ANCHORS, each meaningful alone but each with a
    plausible benign explanation in isolation:
      1. Main module memory type is MEM_PRIVATE instead of MEM_IMAGE —
         not mapped from a file backing at all.
      2. MZ header at image base is missing or zeroed — no valid PE
         header where one is expected.
    Two CORROBORATORS — weak on their own (RWX/JIT-style memory and
    name/case/redirection comparisons are routinely benign):
      3. Image base memory is RWX (needed to write replacement code).
      4. PEB ImagePath's name doesn't match the module list's own name
         for this base address (or the base isn't in the module list at
         all).

    DETECTED requires correlation, not a single flag: anchor 1
    (MEM_PRIVATE) firing together with EITHER anchor 2 (MZ wiped) or
    corroborator 3 (RWX) — mirrors dumpex/hunt/injection/'s own RWX+hidden-PE
    same-allocation correlation requirement. A single signal alone
    (including anchor 2 by itself, or either corroborator alone) is
    reported as a lead, not a detection — see
    dumpex.hunt._finding.review_priority for how it still surfaces for
    an analyst even at score==0.
    """
    _print_hollowing_pre_build_console()
    report = _build_hollowing_report(mf)
    return _render_hollowing_console(mf, report, verbose)


def _print_hollowing_pre_build_console() -> None:
    """The announcing `get_rules()` call, extracted so both
    `_hunt_hollowing()` (above) and `dumpex.hunt.cmd_hunt()`'s own inline
    hollowing block (see that function's own docstring) can trigger the
    one-time "Rules loaded from ..." print at the right point -- BEFORE
    `_build_hollowing_report()` runs its own now-silent
    `get_rules(announce=False)` call -- without duplicating this line as
    a bare copy in each caller. Unlike stomping/pipe/cs-beacon/
    obfuscation, hollowing's own header print happens AFTER the builder
    call (see `_render_hollowing_console()`'s own docstring for why), so
    this is deliberately its own separate function rather than folded
    into a single "header + rules" pre-build helper."""
    get_rules()


def _render_hollowing_console(mf: MinidumpFile, report: Report, verbose: bool = False) -> dict:
    """Print the console report for an ALREADY-BUILT hollowing `Report`
    and return the same v1.1-shaped findings dict `_hunt_hollowing()`
    always has -- extracted so `dumpex.hunt.collect_hunt()`'s console+
    JSON orchestrator (see that function's own docstring) can call
    `_build_hollowing_report()` once and feed the SAME Report to this
    function AND `_record_from_hollowing_report()`, instead of calling
    `_hunt_hollowing()` (which would build its own second Report and
    scan again). Does NOT call `get_rules()` itself -- the caller (either
    `_hunt_hollowing()` or `dumpex.hunt.cmd_hunt()`'s own inline hollowing
    block) must call `_print_hollowing_pre_build_console()` BEFORE
    `_build_hollowing_report()`, so the announcing call happens before
    the builder's own now-silent one (see that function's own
    docstring)."""
    _print_hunt_header("Process Hollowing")

    if not report.peb_present:
        print(RED("  [!] PEB not available — cannot run hollowing check.\n"))
        print(f"  {BOLD('[ VERDICT ]')}  {_status_text(NOT_EVALUATED, 'PEB stream missing from this dump')}\n")
        return {
            "score": 0, "max_score": 2, "status": NOT_EVALUATED,
            "coverage_status": "not_evaluated",
            "coverage_reasons": ["PEB stream missing from this dump"],
            "confidence": report.confidence, "verdict_level": report.verdict_level,
            "lead_count": 0, "review_priority": report.review_priority, "findings": [],
        }

    image_base = report.image_base
    image_path = report.image_path
    fo_base_str = f"0x{report.fo_base:x}" if report.fo_base is not None else "(not captured)"
    print(f"  {DIM('PEB ImagePath     :')} {image_path}")
    print(f"  {DIM('ImageBase VA      :')} 0x{image_base:016x}  {DIM('(process virtual address)')}")
    print(f"  {DIM('ImageBase offset  :')} {fo_base_str}          {DIM('(byte offset in .dmp file)')}")
    print()

    base_region = report.base_region

    # ── Check 1 (anchor): memory type at image base ────────────────────
    if not base_region:
        _print_check("Memory type at image base",
                     YELLOW("NOTABLE — region not found in dump"),
                     "Image base page may not have been captured")
    else:
        mtype = prot_str(base_region.Type)
        p     = prot_str(base_region.Protect)
        fo_reg = va_to_file_offset(mf, base_region.BaseAddress)
        fo_reg_str = f"0x{fo_reg:x}" if fo_reg is not None else "(not captured)"
        if not report.mem_private:
            _print_check("Memory type at image base",
                         GREEN("CLEAN — MEM_IMAGE (mapped from disk)"),
                         f"VA (process) 0x{base_region.BaseAddress:016x}  File offset {fo_reg_str}  {mtype}  {p}")
        else:
            _print_check("Memory type at image base",
                         RED("SUSPICIOUS — MEM_PRIVATE (not mapped from disk)"),
                         f"VA (process) 0x{base_region.BaseAddress:016x}  File offset {fo_reg_str}  {mtype}  {p}")

    # ── Check 2 (anchor): MZ header at image base ───────────────────────
    header = report.mz_header_bytes
    if report.mz_outcome == "short_read":
        _print_check("MZ header at image base",
                     YELLOW("NOTABLE — short read, could not check"),
                     f"Only {len(header)} byte(s) returned")
    elif report.mz_outcome == "exception":
        _print_check("MZ header at image base",
                     YELLOW("NOTABLE — could not read"),
                     report.mz_exception_text)
    elif report.mz_outcome == "clean":
        _print_check("MZ header at image base",
                     GREEN("CLEAN — MZ present"),
                     f"Header bytes: {header[:8].hex()}")
    elif report.mz_outcome == "wiped_zero":
        _print_check("MZ header at image base",
                     RED("SUSPICIOUS — MZ zeroed out (header wiping)"),
                     f"First bytes: {header[:8].hex()}")
    elif report.mz_outcome == "wiped_other":
        _print_check("MZ header at image base",
                     YELLOW("NOTABLE — unexpected bytes where MZ should be"),
                     f"First bytes: {header[:8].hex()}")

    # ── Check 3 (corroborator): RWX at image base ───────────────────────
    if base_region:
        p = prot_str(base_region.Protect)
        if report.is_rwx:
            _print_check("Protection at image base",
                         RED("SUSPICIOUS — RWX (write needed to hollow)"),
                         f"{p}")
        else:
            _print_check("Protection at image base",
                         GREEN(f"CLEAN — {p}"))

    # ── Check 4 (corroborator): module list sanity ──────────────────────
    main_mod = report.main_mod
    if main_mod:
        mod_name = _basename_lower(main_mod.name)
        peb_name = _basename_lower(image_path)
        if mod_name == peb_name:
            _print_check("PEB image name vs module list",
                         GREEN(f"CLEAN — both report '{mod_name}'"))
        else:
            _print_check("PEB image name vs module list",
                         RED("SUSPICIOUS — name mismatch"),
                         f"PEB says '{peb_name}', module list says '{mod_name}'")
    elif report.module_list_unavailable:
        _print_check("PEB image name vs module list",
                     YELLOW("NOTABLE — ModuleList unavailable, cannot verify"),
                     "ModuleListStream missing/empty from this dump")
    else:
        _print_check("PEB image name vs module list",
                     YELLOW("NOTABLE — image base not in any module"),
                     "Main executable may have been unmapped")

    score = report.score
    status = report.status
    coverage_reasons = report.coverage_reasons
    complete = not coverage_reasons

    if not complete:
        print(YELLOW(f"  [~] {'; '.join(coverage_reasons)}.\n"))

    if status == INCONCLUSIVE:
        verdict = _status_text(INCONCLUSIVE,
                                ("; ".join(coverage_reasons) or "partial coverage")
                                + leads_suffix(report.findings_list))
    elif status == NOT_DETECTED_IN_SCANNED_SCOPE:
        verdict = GREEN("CLEAN — no correlated hollowing indicators" + leads_suffix(report.findings_list))
    else:
        verdict = (RED("HIGH CONFIDENCE HOLLOWING — MEM_PRIVATE, MZ wiped, AND RWX all correlate")
                   if score >= 2 else
                   YELLOW("LIKELY HOLLOWING — MEM_PRIVATE at image base correlated with "
                          + ("MZ header wiped" if report.mz_wiped else "RWX protection")))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/2 — requires MEM_PRIVATE at image "
          f"base correlated with a second structural anomaly; single signals above are "
          f"leads only)\n")

    return {
        "score": score, "max_score": report.max_score, "status": status,
        "coverage_status": report.coverage_status, "coverage_reasons": coverage_reasons,
        "confidence": report.confidence, "verdict_level": report.verdict_level,
        "findings": report.findings, "lead_count": report.lead_count,
        "review_priority": report.review_priority,
    }


def _basename_lower(path: str) -> str:
    # Paths embedded in a minidump use Windows separators regardless of
    # the host running dumpex.  ntpath keeps the comparison portable.
    return ntpath.basename(path or "").lower()


def _record_from_hollowing_report(report: Report) -> HunterRecord:
    """Pure `Report` -> `HunterRecord` conversion -- no scanning, no
    printing. The ONE place both `collect_hollowing_record()` (below)
    and `collect_hunt()` (dumpex/hunt/__init__.py's v2.4 orchestrator,
    PR4) build the typed record from an ALREADY-BUILT Report, so a
    single `_build_hollowing_report()` call can feed both the console
    renderer and this conversion without scanning twice. Each of
    `HollowingDetails`' four boolean/module facts is `None` exactly when
    the corresponding check never actually ran (the region wasn't found,
    the MZ read failed, or the module list was unavailable) rather than
    a default `False` -- see that dataclass's own field comments in
    dumpex/output/records.py."""
    if report.base_region is not None:
        mem_private_at_base = report.mem_private
        is_rwx_at_base = report.is_rwx
    else:
        mem_private_at_base = None
        is_rwx_at_base = None

    # mz_outcome is None only in the peb-missing (NOT_EVALUATED) case, where
    # the MZ check never ran at all -- distinct from mz_read_failed, which
    # means it ran but the read itself failed. Both collapse to null here.
    mz_header_present = (None if report.mz_outcome is None or report.mz_read_failed
                          else not report.mz_wiped)

    module_name = report.main_mod.name if report.main_mod else None
    name_mismatch = None if report.module_list_unavailable else report.name_mismatch

    details = HollowingDetails(
        image_base=hex_address(report.image_base),
        mem_private_at_base=mem_private_at_base,
        mz_header_present=mz_header_present,
        is_rwx_at_base=is_rwx_at_base,
        peb_image_path=report.peb_image_path_raw,
        module_name=module_name,
        name_mismatch=name_mismatch,
    )

    return HunterRecord(
        hunter="hollowing", status=report.status, score=report.score,
        max_score=report.max_score, verdict_level=report.verdict_level,
        confidence=report.confidence, lead_count=report.lead_count,
        review_priority=report.review_priority, coverage=report.coverage_report,
        findings=report.findings, details=details,
    )


def collect_hollowing_record(mf: MinidumpFile) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="hollowing"`) for `mf` -- the
    v2.4 equivalent of `_hunt_hollowing()`'s v1.1 dict, sharing the exact
    same underlying `Report`. Thin compat wrapper: builds a fresh Report
    and converts it -- `collect_hunt()` calls `_build_hollowing_report()`
    and `_record_from_hollowing_report()` directly instead, so it never
    scans twice just to also get console output from the same run."""
    return _record_from_hollowing_report(_build_hollowing_report(mf))
