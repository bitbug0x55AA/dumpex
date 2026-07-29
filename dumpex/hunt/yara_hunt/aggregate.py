"""The ONE place score/status/coverage_status/verdict_level get computed
for the YARA hunter, and where the public `findings` dict is built.

Nothing here prints; nothing here scans. This module only turns an
already-collected ScanOutcome into the hunter's decision fields.
yara_hunt deliberately does NOT use the Finding model (see package
docstring) — it keeps its own "matches"/"rules_hit" shape, predating
the phase-two Finding-model hunters, and this split does not change
that; only structure moved, not the output contract.
"""
from dataclasses import dataclass, field

from dumpex.hunt._ui import DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE


@dataclass
class Report:
    """Bundles the public `findings` dict with everything presentation.py
    needs to render console detail."""
    findings: dict
    outcome: object = None
    compile_failed: int = 0
    rule_groups: list = field(default_factory=list)   # list[RuleGroup], sorted by rule_name
    any_gap: bool = False
    verdict_reason: str = ""
    has_hits: bool = False


def build_not_evaluated_report(reason: str) -> Report:
    """
    The ONE place the four "prerequisite missing" early returns (no
    yara-python, no rules directory, no usable rule files, no memory
    segments) build their findings dict and status/coverage_status/
    verdict_level fields — presentation.py only prints the bespoke
    diagnostic lines for each case and this report's `verdict_reason`, it
    never constructs or mutates verdict fields itself.
    """
    findings = {"matches": [], "score": 0, "status": NOT_EVALUATED,
                "coverage_status": "not_evaluated", "verdict_level": "not_evaluated"}
    return Report(findings=findings, outcome=None, compile_failed=0,
                  rule_groups=[], any_gap=False, verdict_reason=reason, has_hits=False)


def build_coverage(outcome, compile_failed: int) -> dict:
    return {
        "rule_files_compiled": compile_failed == 0,
        "segments_read":       outcome.read_failed == 0,
        "segments_short_read": outcome.short_reads == 0,
        "segments_size_ok":    outcome.skipped == 0,
        "matches_completed":   outcome.match_failed == 0 and outcome.timed_out == 0,
        "hit_cap_not_reached": not outcome.truncated,
        "scan_budget_ok":      not outcome.budget_exhausted,
    }


def build_report(outcome, compile_failed: int) -> Report:
    """
    Turn a completed scan (outcome from scanner.py) into score/status/
    coverage/the public findings dict. Handles both the "nothing found"
    and "grouped hits" cases — mirroring the single-file hunter's own
    `if not all_hits:` branch.
    """
    findings = {"matches": [], "score": 0, "status": NOT_EVALUATED}
    coverage = build_coverage(outcome, compile_failed)
    findings["coverage"] = coverage
    any_gap = not all(coverage.values())

    if not outcome.all_hits:
        if any_gap:
            reason = ", ".join(filter(None, [
                f"{compile_failed} rule file(s) failed to compile" if compile_failed else "",
                f"{outcome.skipped} oversized segment(s) skipped" if outcome.skipped else "",
                f"{outcome.read_failed} segment(s) failed to read" if outcome.read_failed else "",
                f"{outcome.short_reads} segment(s) short-read" if outcome.short_reads else "",
                f"{outcome.timed_out} match() call(s) timed out" if outcome.timed_out else "",
                f"{outcome.match_failed} match() call(s) failed" if outcome.match_failed else "",
                f"hit cap reached" if outcome.truncated else "",
                f"scan budget exhausted" if outcome.budget_exhausted else "",
            ]))
            findings["status"] = INCONCLUSIVE
            findings["scan_complete"] = False
            findings["coverage_status"] = "partial"
            findings["verdict_level"]   = "inconclusive"
        else:
            reason = ""
            findings["status"] = NOT_DETECTED_IN_SCANNED_SCOPE
            findings["scan_complete"] = True
            findings["coverage_status"] = "complete"
            findings["verdict_level"]   = "clean"
        return Report(findings=findings, outcome=outcome, compile_failed=compile_failed,
                      rule_groups=[], any_gap=any_gap, verdict_reason=reason, has_hits=False)

    # ── Group hits by rule, deduplicated by segment base VA ──────────────
    from collections import defaultdict
    from dumpex.hunt.yara_hunt.models import RuleGroup
    by_rule = defaultdict(list)
    for hit in outcome.all_hits:
        by_rule[hit["rule"]].append(hit)

    rule_groups = []
    for rule_name, hits in sorted(by_rule.items()):
        seen_vas = {}
        for hit in hits:
            if hit["seg_va"] not in seen_vas:
                seen_vas[hit["seg_va"]] = hit

        # A rule whose EVERY hit is context_unverified (PE_In_Private_Memory,
        # or any dumpex_scope="private_or_unbacked" rule — see
        # dumpex/hunt/yara_hunt/context.py and config.py — matched in a
        # MemoryContext.OTHER or MemoryContext.UNKNOWN region) cannot be
        # reported as a confirmed detection — it's shown for visibility but
        # with a distinct, non-alarming status. This is already rule-name-
        # agnostic: it reads the per-hit context_unverified flag scanner.py
        # set, not the rule's identity.
        rule_is_unverified = all(h.get("context_unverified") for h in hits)
        unverified_contexts = ({h.get("memory_context") for h in hits}
                                if rule_is_unverified else set())

        rule_groups.append(RuleGroup(
            rule_name=rule_name, file=hits[0]["file"], tags=hits[0]["tags"],
            meta=hits[0]["meta"], seen_vas=seen_vas,
            rule_is_unverified=rule_is_unverified, unverified_contexts=unverified_contexts,
        ))

    # ── Verdict ───────────────────────────────────────────────────────
    # score/DETECTED are driven only by confidently classified hits
    # (triggered_rules); rules whose only evidence is context_unverified
    # don't get to unilaterally declare DETECTED — see INCONCLUSIVE branch.
    score = len(outcome.triggered_rules)
    findings["matches"]   = outcome.all_hits
    findings["score"]     = score
    findings["rules_hit"] = sorted(outcome.triggered_rules)

    if outcome.triggered_rules:
        findings["status"]        = DETECTED
        findings["scan_complete"] = not any_gap   # keep DETECTED even with
                                                   # partial coverage, but say so
        # coverage_status/verdict_level mirror scan_complete/score here so
        # this hunter's JSON output satisfies the same cross-hunter
        # invariants the Finding-model hunters already do (see
        # dumpex/schemas/dumpex-output-v1.1.schema.json) even though
        # yara_hunt is still on its own "matches" list, not tag=observation/
        # lead/detection Finding objects.
        findings["coverage_status"] = "complete" if not any_gap else "partial"
        findings["verdict_level"]   = "high" if score >= 3 else "likely"
        reason = ""
    else:
        # Only unverified hits (and/or coverage gaps) — a negative can't be
        # trusted and a positive can't be confirmed either.
        findings["status"]        = INCONCLUSIVE
        findings["scan_complete"] = False
        findings["coverage_status"] = "partial"
        findings["verdict_level"]   = "inconclusive"
        reason = (f"{len(outcome.unverified_rules)} rule(s) matched but could not be classified "
                  f"(context_unverified)" if outcome.unverified_rules else
                  "coverage incomplete, see above")

    return Report(findings=findings, outcome=outcome, compile_failed=compile_failed,
                   rule_groups=rule_groups, any_gap=any_gap, verdict_reason=reason, has_hits=True)
