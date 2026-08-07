"""Legacy v1.1 findings-dict projector for the injection hunter --
converts the frozen Evidence dataclasses (dumpex/hunt/injection/models.py)
Report.findings holds back into plain, JSON-safe dicts before
presentation.render() hands `_hunt_injection()`'s/`cmd_hunt()`'s bare
`results["injection"]` dict back to a caller. This is the ONE place that
boundary is crossed -- presentation.render() itself stays a pure
"print, then hand back what the caller gets" function, never deciding
what the legacy dict shape is.

This is NOT a resurrection of the pre-Evidence-migration raw-Region/dict
shape (that raw-object leak into dumpex.ui.structured._json_safe()'s
str(obj) fallback was itself already a known, accepted defect -- see
tests/integration/test_hunt_compat_freeze.py's own module docstring, and
is unreachable from the real --hunt CLI path either way -- cli.py has
exclusively used dumpex.hunt.injection.collect's v2.6 adapter since PR4).
It is a NEW, well-defined, plain-dict projection of the SAME Evidence
content: a caller reading `results["injection"]["rwx"]` always gets a
JSON-safe dict (never an internal Evidence dataclass or its repr), with
stable, documented keys -- even though those keys are the Evidence's own
field names (base_address/allocation_base/...), not the raw minidump
attribute names (BaseAddress/AllocationBase/...) a pre-migration caller
would have used.
"""


def _region_dict(r) -> dict:
    """`r` is a dumpex.hunt.injection.models.RegionRef."""
    return {"base_address": r.base_address, "allocation_base": r.allocation_base,
            "size": r.size, "type": r.type, "protect": r.protect}


def _pe_dict(pe) -> dict:
    """`pe` is a dumpex.hunt.injection.models.PeHeaderInfo -- see that
    type's own docstring for why it carries fewer fields than
    dumpex.core.pe_utils.parse_pe_header()'s raw dict."""
    return {"valid": pe.valid, "machine_name": pe.machine_name, "is_pe32_plus": pe.is_pe32_plus,
            "number_of_sections": pe.number_of_sections,
            "address_of_entry_point": pe.address_of_entry_point, "image_base": pe.image_base,
            "reason": pe.reason}


def _pe_hit_dict(hit) -> dict:
    """`hit` is a dumpex.hunt.injection.models.HiddenPeEvidence."""
    return {"region": _region_dict(hit.region), "in_module_list": hit.in_module_list,
            "pe": _pe_dict(hit.pe)}


def _thread_dict(ev) -> dict:
    """`ev` is a dumpex.hunt.injection.models.UnbackedThreadEvidence."""
    return {"thread_id": ev.thread_id, "start_address": ev.start_address}


def _rip_hit_dict(hit) -> dict:
    """`hit` is a dumpex.hunt.injection.models.RipHitEvidence."""
    return {"thread_id": hit.thread_id, "ip": hit.ip, "ip_reg": hit.ip_reg,
            "region": _region_dict(hit.region)}


def _start_hit_dict(hit) -> dict:
    """`hit` is a dumpex.hunt.injection.models.StartHitEvidence."""
    return {"thread_id": hit.thread_id, "start_address": hit.start_address,
            "region": _region_dict(hit.region)}


def legacy_findings_dict(findings: dict) -> dict:
    """Return a NEW dict -- shallow-copies every key from `findings`
    unchanged EXCEPT the Evidence-holding ones (see this module's own
    docstring), which get projected into plain dicts. Never mutates
    `findings` itself: `Report.findings` (what aggregate.py built, and
    what dumpex.hunt.injection.collect's v2.6 adapter separately projects
    from `report.rwx`/`report.validated_pe_hits`/etc, not from this dict)
    stays exactly as constructed."""
    out = dict(findings)
    out["rwx"] = [_region_dict(ev.region) for ev in findings["rwx"]]
    out["hidden_pe_validated"] = [_pe_hit_dict(h) for h in findings["hidden_pe_validated"]]
    out["hidden_pe_unvalidated"] = [_pe_hit_dict(h) for h in findings["hidden_pe_unvalidated"]]
    out["suspicious_validated_pe_hits"] = [
        _pe_hit_dict(h) for h in findings["suspicious_validated_pe_hits"]]
    out["informational_validated_pe_hits"] = [
        _pe_hit_dict(h) for h in findings["informational_validated_pe_hits"]]
    out["threads"] = [_thread_dict(ev) for ev in findings["threads"]]
    out["rip_hits"] = [_rip_hit_dict(hit) for hit in findings["rip_hits"]]
    out["rip_full_correlation"] = [_rip_hit_dict(hit) for hit in findings["rip_full_correlation"]]
    out["start_hits"] = [_start_hit_dict(hit) for hit in findings["start_hits"]]
    return out
