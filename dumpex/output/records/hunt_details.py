"""The hunter-specific `details` record of each of the seven hunters."""
from dataclasses import dataclass

from dumpex.output.records.common import (
    _require_bool,
    _require_hex_address,
    _require_nonneg_int,
    _require_optional_diff_str,
    _require_optional_hex_address,
)
from dumpex.output.records.hunt_scope import (
    HuntPeHeaderHit,
    HuntRegionRef,
    HuntThreadRef,
    HuntThreadRegionHit,
    _require_list_of,
    _require_optional_targeted_scope,
    _targeted_scope_dict,
)


@dataclass
class InjectionDetails:
    """`--hunt injection`'s hunter-specific evidence. `pe_read_failed`/
    `pe_short_reads` deliberately do NOT appear here -- per the field
    matrix, those are coverage counts, not evidence, and instead inform
    this hunter's own CoverageReport limitations (PE_HEADER_READ_FAILED/
    PE_HEADER_SHORT_READ, see dumpex.output.coverage)."""
    rwx:                              list   # list[HuntRegionRef]
    hidden_pe_validated:              list   # list[HuntPeHeaderHit], valid=True
    hidden_pe_unvalidated:            list   # list[HuntPeHeaderHit], valid=False (MZ-prefix only)
    suspicious_validated_pe_hits:     list   # subset of hidden_pe_validated that's scoreable
    informational_validated_pe_hits: list   # the other (context-only) subset
    threads:                          list   # list[HuntThreadRef] -- unbacked StartAddress threads
    thread_contexts:                  list   # list[HuntThreadRef] -- every parsed thread context
    rwx_and_pe_alloc_bases:           list   # list[str] -- hex allocation bases
    rip_hits:                         list   # list[HuntThreadRegionHit] -- RIP inside a flagged region
    rip_full_correlation:             list   # subset of rip_hits with full (RWX+PE) correlation
    start_hits:                       list   # list[HuntThreadRegionHit] -- StartAddress-correlated

    def __post_init__(self):
        _require_list_of(self.rwx, HuntRegionRef, "InjectionDetails.rwx")
        _require_list_of(self.hidden_pe_validated, HuntPeHeaderHit,
                          "InjectionDetails.hidden_pe_validated")
        _require_list_of(self.hidden_pe_unvalidated, HuntPeHeaderHit,
                          "InjectionDetails.hidden_pe_unvalidated")
        _require_list_of(self.suspicious_validated_pe_hits, HuntPeHeaderHit,
                          "InjectionDetails.suspicious_validated_pe_hits")
        _require_list_of(self.informational_validated_pe_hits, HuntPeHeaderHit,
                          "InjectionDetails.informational_validated_pe_hits")
        _require_list_of(self.threads, HuntThreadRef, "InjectionDetails.threads")
        _require_list_of(self.thread_contexts, HuntThreadRef, "InjectionDetails.thread_contexts")
        if not isinstance(self.rwx_and_pe_alloc_bases, list) or any(
                not isinstance(a, str) for a in self.rwx_and_pe_alloc_bases):
            raise TypeError("InjectionDetails.rwx_and_pe_alloc_bases must be a list of str")
        for a in self.rwx_and_pe_alloc_bases:
            _require_hex_address(a, "InjectionDetails.rwx_and_pe_alloc_bases[]")
        _require_list_of(self.rip_hits, HuntThreadRegionHit, "InjectionDetails.rip_hits")
        _require_list_of(self.rip_full_correlation, HuntThreadRegionHit,
                          "InjectionDetails.rip_full_correlation")
        _require_list_of(self.start_hits, HuntThreadRegionHit, "InjectionDetails.start_hits")

    def to_dict(self) -> dict:
        return {
            "rwx":                              [r.to_dict() for r in self.rwx],
            "hidden_pe_validated":               [h.to_dict() for h in self.hidden_pe_validated],
            "hidden_pe_unvalidated":             [h.to_dict() for h in self.hidden_pe_unvalidated],
            "suspicious_validated_pe_hits":       [h.to_dict() for h in self.suspicious_validated_pe_hits],
            "informational_validated_pe_hits":    [h.to_dict() for h in self.informational_validated_pe_hits],
            "threads":                            [t.to_dict() for t in self.threads],
            "thread_contexts":                    [t.to_dict() for t in self.thread_contexts],
            "rwx_and_pe_alloc_bases":             list(self.rwx_and_pe_alloc_bases),
            "rip_hits":                            [t.to_dict() for t in self.rip_hits],
            "rip_full_correlation":                [t.to_dict() for t in self.rip_full_correlation],
            "start_hits":                          [t.to_dict() for t in self.start_hits],
        }


@dataclass
class HollowingDetails:
    """Image-base evidence for ``--hunt hollowing``.

    ``image_base`` is ``None`` when the PEB is unavailable. Each tri-state
    check is ``None`` when it could not run, not a clean ``False`` result.

    ``mem_private_at_base`` is true for ANY non-MEM_IMAGE type at the image
    base, not just MEM_PRIVATE specifically (frozen wire name kept for
    compatibility -- see docs/user/OUTPUT_MIGRATION.md's v2.20 entry):
    ``region_type`` (added in v2.20) is where a consumer reads WHICH type it
    actually was (``MEM_PRIVATE``, ``MEM_MAPPED``, ...), so a JSON reader is
    never left inferring "private" from this boolean alone.
    """
    image_base:           "str | None"
    mem_private_at_base:  "bool | None"   # None if the image-base region wasn't found at all
    mz_header_present:    "bool | None"   # None if the header read itself failed
    is_rwx_at_base:       "bool | None"   # None if the image-base region wasn't found at all
    peb_image_path:       "str | None"
    module_name:          "str | None"    # None if no module was found at image_base
    name_mismatch:        "bool | None"   # None if module list itself was unavailable
    region_type:          "str | None" = None   # the image-base region's own observed
                                                 # MemoryInfo Type; None iff mem_private_at_base
                                                 # is None (the region wasn't found at all)

    def __post_init__(self):
        _require_optional_hex_address(self.image_base, "HollowingDetails.image_base")
        for f_name in ("mem_private_at_base", "mz_header_present", "is_rwx_at_base", "name_mismatch"):
            v = getattr(self, f_name)
            if v is not None:
                _require_bool(v, f"HollowingDetails.{f_name}")
        _require_optional_diff_str(self.peb_image_path, "HollowingDetails.peb_image_path")
        _require_optional_diff_str(self.module_name, "HollowingDetails.module_name")
        _require_optional_diff_str(self.region_type, "HollowingDetails.region_type")
        if (self.region_type is None) != (self.mem_private_at_base is None):
            raise ValueError(
                "HollowingDetails.region_type must be set exactly when mem_private_at_base "
                "is -- both describe the same image-base region, found or not")

    def to_dict(self) -> dict:
        return {
            "image_base":          self.image_base,
            "mem_private_at_base": self.mem_private_at_base,
            "mz_header_present":   self.mz_header_present,
            "is_rwx_at_base":      self.is_rwx_at_base,
            "peb_image_path":      self.peb_image_path,
            "module_name":         self.module_name,
            "name_mismatch":       self.name_mismatch,
            "region_type":         self.region_type,
        }


@dataclass
class StompingDetails:
    """Protection leads and verified changes for ``--hunt stomping``.

    ``targeted_scope`` is present only for a targeted (``--hunt-addr``)
    rescan; see :func:`_targeted_scope_dict`.
    """
    protection_leads: list   # list[dict]
    verified_changes: list   # list[dict]
    targeted_scope:   "list | None" = None   # list[TargetedScopeRecord], targeted only

    def __post_init__(self):
        for name in ("protection_leads", "verified_changes"):
            value = getattr(self, name)
            if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
                raise TypeError(f"StompingDetails.{name} must be a list of dict")
        _require_optional_targeted_scope(self.targeted_scope, "StompingDetails.targeted_scope")

    def to_dict(self) -> dict:
        return {
            "protection_leads": [dict(x) for x in self.protection_leads],
            "verified_changes": [dict(x) for x in self.verified_changes],
            **_targeted_scope_dict(self),
        }


@dataclass
class PipeDetails:
    """`--hunt pipe`'s hunter-specific evidence.

    ``targeted_scope`` is present only for a targeted (``--hunt-addr``)
    rescan; see :func:`_targeted_scope_dict`.
    """
    handle_pipes:    list   # list[dict]
    private_pipes:   list   # list[dict]
    c2_context:      list   # list[dict]
    framework_pipes: list   # list[dict]
    unbacked_in_rgn: list   # list[dict]
    targeted_scope:  "list | None" = None   # list[TargetedScopeRecord], targeted only

    def __post_init__(self):
        for name in ("handle_pipes", "private_pipes", "c2_context", "framework_pipes",
                      "unbacked_in_rgn"):
            value = getattr(self, name)
            if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
                raise TypeError(f"PipeDetails.{name} must be a list of dict")
        _require_optional_targeted_scope(self.targeted_scope, "PipeDetails.targeted_scope")

    def to_dict(self) -> dict:
        return {
            "handle_pipes":    [dict(x) for x in self.handle_pipes],
            "private_pipes":   [dict(x) for x in self.private_pipes],
            "c2_context":      [dict(x) for x in self.c2_context],
            "framework_pipes": [dict(x) for x in self.framework_pipes],
            "unbacked_in_rgn": [dict(x) for x in self.unbacked_in_rgn],
            **_targeted_scope_dict(self),
        }


@dataclass
class CsBeaconDetails:
    """Decoded configuration evidence for ``--hunt cs-beacon``.

    Process addresses use normalized hex strings in this typed shape;
    dump-file offsets remain integers. ``targeted_scope`` is present only for
    a targeted (``--hunt-addr``) rescan; see :func:`_targeted_scope_dict`.
    """
    configs:        list   # list[dict]
    config_count:   int
    targeted_scope: "list | None" = None   # list[TargetedScopeRecord], targeted only

    def __post_init__(self):
        if not isinstance(self.configs, list) or any(not isinstance(x, dict) for x in self.configs):
            raise TypeError("CsBeaconDetails.configs must be a list of dict")
        _require_nonneg_int(self.config_count, "CsBeaconDetails.config_count")
        if self.config_count != len(self.configs):
            raise ValueError(
                f"CsBeaconDetails.config_count ({self.config_count}) must equal "
                f"len(configs) ({len(self.configs)})")
        _require_optional_targeted_scope(self.targeted_scope, "CsBeaconDetails.targeted_scope")

    def to_dict(self) -> dict:
        return {"configs": [dict(x) for x in self.configs], "config_count": self.config_count,
                **_targeted_scope_dict(self)}


@dataclass
class YaraDetails:
    """`--hunt yara`'s hunter-specific evidence. YARA deliberately stays
    off the shared Finding model -- see docs/developer/hunt_architecture.md
    for why `matches` must not be reclassified as `finding`."""
    matches:        list   # list[dict]
    rules_hit:      list   # list[str]
    targeted_scope: "list | None" = None   # list[TargetedScopeRecord], targeted only

    def __post_init__(self):
        if not isinstance(self.matches, list) or any(not isinstance(x, dict) for x in self.matches):
            raise TypeError("YaraDetails.matches must be a list of dict")
        if not isinstance(self.rules_hit, list) or any(not isinstance(x, str) for x in self.rules_hit):
            raise TypeError("YaraDetails.rules_hit must be a list of str")
        _require_optional_targeted_scope(self.targeted_scope, "YaraDetails.targeted_scope")

    def to_dict(self) -> dict:
        return {"matches": [dict(x) for x in self.matches], "rules_hit": list(self.rules_hit),
                **_targeted_scope_dict(self)}


@dataclass
class ObfuscationDetails:
    """`--hunt obfuscation`'s hunter-specific evidence -- the seven decode
    layers' own hit lists."""
    sleep_mask:        list   # list[dict]
    entropy:           list   # list[dict]
    base64:            list   # list[dict]
    xor:               list   # list[dict]
    compressed:        list   # list[dict]
    hidden_pe:         list   # list[dict]
    hidden_shellcode:  list   # list[dict]
    targeted_scope:    "list | None" = None   # list[TargetedScopeRecord], targeted only

    def __post_init__(self):
        for name in ("sleep_mask", "entropy", "base64", "xor", "compressed", "hidden_pe",
                      "hidden_shellcode"):
            value = getattr(self, name)
            if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
                raise TypeError(f"ObfuscationDetails.{name} must be a list of dict")
        _require_optional_targeted_scope(self.targeted_scope, "ObfuscationDetails.targeted_scope")

    def to_dict(self) -> dict:
        return {
            "sleep_mask":       [dict(x) for x in self.sleep_mask],
            "entropy":          [dict(x) for x in self.entropy],
            "base64":           [dict(x) for x in self.base64],
            "xor":              [dict(x) for x in self.xor],
            "compressed":       [dict(x) for x in self.compressed],
            "hidden_pe":        [dict(x) for x in self.hidden_pe],
            "hidden_shellcode": [dict(x) for x in self.hidden_shellcode],
            **_targeted_scope_dict(self),
        }
