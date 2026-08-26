"""Aggregate hollowing evidence into one immutable report.

Scoring requires the defined structural correlation, while isolated signals and
name mismatch remain leads. Coverage and findings are derived from typed
evidence without reading memory or rendering output.
"""
from dumpex.hunt._domain import CheckResult
from dumpex.hunt._finding import (
    CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH, TAG_LEAD, TAG_DETECTION,
)
from dumpex.hunt.hollowing.domain import (
    CoverageSnapshot, HollowingEvidence, HollowingReport,
)


def build_report(mem_private: tuple = (), wiped_headers: tuple = (), rwx: tuple = (),
                  name_mismatches: tuple = (), correlations: tuple = (), *,
                  context=None, peb_present: bool = False,
                  image_base_region_found: bool = False, mz_read_failed: bool = False,
                  modules_available: bool = False) -> HollowingReport:
    """
    Turn the scan/correlation layers' typed evidence into the final
    `HollowingReport`. This is the ONLY place score/coverage/the five
    CheckResults are computed for this hunter.

    Every argument defaults to its "nothing was observed" value, so the
    PEB-missing early path is a bare `build_report()` call -- the same
    NOT_EVALUATED result the pre-migration builder hand-assembled as a
    fully-populated `Report(...)` literal with twenty explicit `False`/
    `None`/`0` arguments.
    """
    coverage = CoverageSnapshot(
        peb_present=peb_present, image_base_region_found=image_base_region_found,
        mz_read_failed=mz_read_failed, modules_available=modules_available)

    results = []

    # ── Check 1 (anchor): memory type at the image base ───────────────────
    if mem_private:
        results.append(CheckResult(
            check="hollowing.mem_private_at_image_base",
            evidence=mem_private,
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

    # ── Check 2 (anchor): MZ header at the image base ─────────────────────
    if wiped_headers:
        results.append(CheckResult(
            check="hollowing.mz_header_missing",
            evidence=wiped_headers,
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

    # ── Check 3 (corroborator): RWX at the image base ─────────────────────
    if rwx:
        results.append(CheckResult(
            check="hollowing.rwx_at_image_base",
            evidence=rwx,
            inference="The main module's image base carries RWX-family protection.",
            confidence=CONFIDENCE_LOW,
            rationale="RWX at the image base is needed to write replacement code during "
                       "hollowing, but RWX alone is routinely used by JITs, debuggers, "
                       "and some legitimate packers — a lead, not proof, on its own.",
            limitations=["Does not by itself distinguish hollowing from JIT/legitimate "
                         "self-modifying-code use cases at this address."],
            tag=TAG_LEAD,
        ))

    # ── Check 4 (corroborator): module list sanity ────────────────────────
    if name_mismatches:
        results.append(CheckResult(
            check="hollowing.peb_module_name_mismatch",
            evidence=name_mismatches,
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

    # ── Correlation: the ONE scored signal ────────────────────────────────
    # DETECTED requires anchor 1 (MEM_PRIVATE) together with at least one of
    # anchor 2 (MZ wiped) or corroborator 3 (RWX) -- a single anomaly,
    # including either anchor alone, stays lead-only. correlation.py is what
    # decides whether that relationship holds; this block only turns the
    # resulting evidence into a score and a check.
    score = 0
    if correlations:
        correlation = correlations[0]
        score = 2 if correlation.full_correlation else 1
        corroborators = correlation.corroborators
        results.append(CheckResult(
            check="hollowing.structural_correlation",
            evidence=correlations,
            inference=f"{len(corroborators)} independent structural signal(s) correlate at "
                       f"the same image base: {', '.join(corroborators)}.",
            confidence=CONFIDENCE_HIGH if correlation.full_correlation else CONFIDENCE_MEDIUM,
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

    evidence = HollowingEvidence(
        mem_private=mem_private, wiped_headers=wiped_headers, rwx=rwx,
        name_mismatches=name_mismatches, correlations=correlations,
    )
    return HollowingReport(score=score, coverage=coverage, context=context,
                            results=tuple(results), evidence=evidence)
