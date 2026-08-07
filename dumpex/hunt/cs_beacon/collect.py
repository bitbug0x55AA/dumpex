"""
`collect_cs_beacon_record()` -- the v2.4 migration's (PR2b) `HunterRecord`-
producing entry point for the cs-beacon hunter, alongside the console-
oriented `_hunt_cs_beacon()` in `dumpex/hunt/cs_beacon/__init__.py`. Both
call the exact same `_build_cs_beacon_report()` pipeline, so this module
only RESHAPES the resulting `aggregate.Report` into a `HunterRecord` --
it never recomputes score, status, verdict, or coverage itself.

`configs[*]["fields"]` is int-keyed (by TLV field ID) and its `value`
entries can be raw `bytes` -- this is ALSO sanitized at the CLI
dispatcher layer (`dumpex/hunt/__init__.py`'s `_json_safe_cs_configs`-
equivalent block), which was not deleted; it still runs, unchanged, for
`cmd_hunt()`'s console-rendering `results` dict and any other non-v2
caller. This module's own, independent conversion is what feeds
`--hunt`'s v2 `--json`/`--csv` output specifically (see
docs/hunt_migration_field_matrix.md's cs-beacon section and its own
cross-cutting finding #2 update). `va`/`region_base` (real process
addresses) become hex strings; `file_offset` (a .dmp BYTE OFFSET, not a
memory address) and `xor_key` (a one-byte XOR key value, not an
address/pointer/handle) stay plain JSON integers, per this project's own
address-vs-offset type rule.

As of schema_version 2.6, `_field_dict()` deliberately drops the parser's
own `rec["raw"]` bytes from the public dict it returns -- PublicKey,
Malleable C2, and inject-transform fields could carry very long raw hex
strings there, degrading JSON/CSV/tool display for no benefit once
`value` already carries the field's decoded/hex-rendered content. The
parser (`dumpex/hunt/cs_beacon/parser.py`) still returns `raw` on its own
internal field dicts -- DER public-key validation
(`fields[0x0007]["raw"]`) and Malleable C2 instruction decoding both
still need it -- this function just never copies it into the shape that
reaches `CsBeaconDetails`/`--json`/`--csv`.

As of schema_version 2.7, `_config_dict()` additionally keys the public
`fields` dict by field NAME (e.g. `"BeaconType"`) instead of the raw TLV
field ID (`"1"`) -- a consumer no longer needs to already know that field
ID 1 means BeaconType before it can look anything up
(`fields["BeaconType"]["value"]` instead of `fields["1"]["value"]`), and
`_field_dict()` correspondingly drops the now-redundant `name` property
(the key IS the name). The parser's own internal field dict
(`fields[0x0007]["raw"]`, keyed by integer field ID) is completely
unaffected -- this reshaping happens ONLY here, at the v2 public-output
boundary, the same layering `_field_dict()`'s own `raw`-drop already
established for 2.6. Unknown field IDs still render as `field_0xNNNN`
(`dumpex/hunt/cs_beacon/parser.py`'s own `CS_FIELD_NAMES.get(fid,
f'field_0x{fid:04x}')` fallback, unchanged) -- `_config_dict()` just uses
whatever name the parser already resolved, never re-deriving it.
`CS_FIELD_NAMES` (`dumpex/hunt/cs_beacon/schema.py`) has no duplicate
values today, but `_config_dict()` does not trust that silently: a name
collision (two different field IDs resolving to the same name) raises
`ValueError` at collect time rather than letting the second field
silently overwrite the first in the output dict.
"""
from dumpex.hunt.cs_beacon import _build_cs_beacon_report
from dumpex.output.records import HunterRecord, CsBeaconDetails, hex_address


def _field_dict(rec: dict) -> dict:
    value = rec.get("value")
    return {
        "type": rec.get("type", ""),
        "value": value.hex() if isinstance(value, bytes) else value,
    }


def _config_dict(cfg: dict) -> dict:
    fields = {}
    for fid, rec in cfg["fields"].items():
        name = rec.get("name", f"field_0x{fid:04x}")
        if name in fields:
            raise ValueError(
                f"cs-beacon field name collision: field ID 0x{fid:04x} resolves to "
                f"{name!r}, which another field ID in this same config already used -- "
                f"CS_FIELD_NAMES must not map two different field IDs to the same name")
        fields[name] = _field_dict(rec)
    return {
        "va": hex_address(cfg["va"]),
        "file_offset": cfg["file_offset"],
        "region_base": hex_address(cfg["region_base"]),
        "region_size": cfg["region_size"],
        "region_protect": cfg["region_protect"],
        "xor_key": cfg["xor_key"],
        "cs_version": cfg["cs_version"],
        "cs_version_note": cfg["cs_version_note"],
        "context_corroborated": cfg["context_corroborated"],
        "fields": fields,
    }


def _record_from_cs_beacon_report(report) -> HunterRecord:
    """Pure `aggregate.Report` -> `HunterRecord` conversion -- no
    scanning, no printing. The ONE place both `collect_cs_beacon_record()`
    (below) and `collect_hunt()` (dumpex/hunt/__init__.py's v2.4
    orchestrator, PR4) build the typed record from an ALREADY-BUILT
    Report, so a single `_build_cs_beacon_report()` call can feed both
    the console renderer and this conversion without scanning twice."""
    f = report.findings

    configs = [_config_dict(cfg) for cfg in f["configs"]]
    details = CsBeaconDetails(configs=configs, config_count=len(configs))

    return HunterRecord(
        hunter="cs-beacon", status=f["status"], score=f["score"], max_score=f["max_score"],
        verdict_level=f["verdict_level"], confidence=f["confidence"],
        lead_count=f["lead_count"], review_priority=f["review_priority"],
        coverage=report.coverage_report, findings=f["findings"], details=details,
    )


def collect_cs_beacon_record(mf) -> HunterRecord:
    """Build one `HunterRecord` (`hunter="cs-beacon"`) for `mf` -- the
    v2.4 equivalent of `_hunt_cs_beacon()`'s v1.1 dict, sharing the exact
    same underlying `Report`. Thin compat wrapper: builds a fresh Report
    and converts it -- `collect_hunt()` calls `_build_cs_beacon_report()`
    and `_record_from_cs_beacon_report()` directly instead, so it never
    scans twice just to also get console output from the same run."""
    return _record_from_cs_beacon_report(_build_cs_beacon_report(mf))
