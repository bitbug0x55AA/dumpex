"""v2 CSV export.

Every v2 record is already a flat dict via its own to_dict() by the time
it reaches a dumpex.output.envelope.Result, so unlike
dumpex/ui/structured.py's `_section_to_tables` -- which special-cases
"modules"/"threads"/"sysinfo"/"pid"/"hunt" by string key and reshapes
sysinfo/pid's single dict into {field, value} rows -- most of the work
here is uniform across kinds. A few things still need real handling,
though, because `csv.DictWriter` has no concept of a nested value or a
heterogeneous row shape:

- list/dict-typed fields (ThreadRecord.flags, ModuleRecord.anomaly_flags,
  PebRecord.environment_variables) are JSON-encoded into the cell rather
  than left to csv.DictWriter's default str() behavior, which produces a
  Python repr() (`"['EXITED']"`) -- not valid JSON, not a stable format
  any other language's CSV/JSON tooling can parse back reliably.
- PEB's environment_variables is additionally broken out into its own
  "environment_variables" table (one row per variable) rather than only
  living as a JSON-encoded cell in the main "records" table -- kept
  narrow (a single field of a single kind) rather than the old
  per-section special-casing this design otherwise avoids.
- A "comparison" result's `records` array is a tagged union
  (ModuleDiffRecord/ThreadDiffRecord/MemoryDiffRecord, discriminated by
  `entity_type`) -- entries don't share one fieldname set, so a single
  csv.DictWriter can't write them as one table the way every other kind's
  homogeneous `records` array can. The generic "records" table is skipped
  entirely for this kind; result.records is split by `entity_type` into
  up to three homogeneous tables instead (module_diffs/thread_diffs/
  memory_diffs), each written the same way every other table is.
- A "hunt" result has the SAME problem one level deeper: `records` is
  homogeneous at the top (every entry is a hunterRecord), but each
  record's OWN `details` is itself a hunter-specific tagged shape (see
  dumpex.output.records' 7 *Details dataclasses) with no shared fieldname
  set across hunters, and several of THOSE fields are themselves lists of
  differently-shaped evidence. The generic "records" table is skipped
  for this kind too; see the "hunt" section below for the full table
  breakdown (hunters/findings/injection_evidence/stomping_changes/
  pipe_evidence/beacon_configs/yara_matches/obfuscation_hits).

A "summary" table (kind/execution_status/coverage/count) is always
produced, even when `records` is empty, so a directory-mode CSV export
never silently writes zero files just because a stream came back empty.
"""
import json


def _flatten_value(value):
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return value


def _flatten_row(record: dict) -> dict:
    return {k: _flatten_value(v) for k, v in record.items()}


def records_to_rows(result) -> list:
    """Flatten result.records into CSV-ready rows: every list/dict-typed
    field becomes a JSON-encoded string cell, never a Python repr()."""
    rows = []
    for record in result.records:
        row = _flatten_row(record)
        if result.kind == "peb":
            # Broken out into its own table below instead -- see module
            # docstring.
            row.pop("environment_variables", None)
        rows.append(row)
    return rows


# ── hunt (result.kind == "hunt") ────────────────────────────────────────────
#
# Like "comparison", a "hunt" result's `records` array doesn't share one
# fieldname set across entries -- but the split here isn't by a top-level
# discriminator alone (entity_type there vs hunter here): each hunterRecord's
# OWN `details` dict is itself a second, hunter-specific tagged shape (see
# dumpex.output.records' 7 *Details dataclasses). Cramming a whole `details`
# blob into one CSV cell as JSON would defeat the point of a "flat table"
# export, so each hunter's list-shaped evidence fields get their own table
# (injection_evidence/stomping_changes/pipe_evidence/beacon_configs/
# yara_matches/obfuscation_hits) -- EXCEPT hollowing, whose `details` is
# entirely scalar (no list-shaped evidence at all) and so is flattened
# straight into the "hunters" table's own row instead of a table with
# nothing but scalars duplicating what "hunters" already has.
_HUNT_DETAIL_FIELDS = {
    "injection": frozenset({
        "rwx", "hidden_pe_validated", "hidden_pe_unvalidated", "suspicious_validated_pe_hits",
        "informational_validated_pe_hits", "threads", "thread_contexts",
        "rwx_and_pe_alloc_bases", "rip_hits", "rip_full_correlation", "start_hits"}),
    "hollowing": frozenset({
        "image_base", "mem_private_at_base", "mz_header_present", "is_rwx_at_base",
        "peb_image_path", "module_name", "name_mismatch"}),
    "stomping": frozenset({"protection_leads", "verified_changes"}),
    "pipe": frozenset({
        "handle_pipes", "private_pipes", "c2_context", "framework_pipes", "unbacked_in_rgn"}),
    "cs-beacon": frozenset({"configs", "config_count"}),
    "yara": frozenset({"matches", "rules_hit"}),
    "obfuscation": frozenset({
        "sleep_mask", "entropy", "base64", "xor", "compressed", "hidden_pe", "hidden_shellcode"}),
}

_HOLLOWING_DETAIL_FIELDS = (
    "image_base", "mem_private_at_base", "mz_header_present", "is_rwx_at_base",
    "peb_image_path", "module_name", "name_mismatch")

_INJECTION_EVIDENCE_FIELDS = (
    "rwx", "hidden_pe_validated", "hidden_pe_unvalidated", "suspicious_validated_pe_hits",
    "informational_validated_pe_hits", "threads", "thread_contexts", "rwx_and_pe_alloc_bases",
    "rip_hits", "rip_full_correlation", "start_hits")

_STOMPING_EVIDENCE_FIELDS = ("protection_leads", "verified_changes")

_PIPE_EVIDENCE_FIELDS = (
    "handle_pipes", "private_pipes", "c2_context", "framework_pipes", "unbacked_in_rgn")

_OBFUSCATION_EVIDENCE_FIELDS = (
    "sleep_mask", "entropy", "base64", "xor", "compressed", "hidden_pe", "hidden_shellcode")


def _check_hunt_partition_completeness(result) -> None:
    """Mirrors build_tables' kind == "comparison" unrecognized-entity_type
    check: a future 8th hunter, or a *Details dataclass that gains/drops a
    field without this module's own field lists being updated to match,
    must fail loudly here rather than silently dropping rows from every
    per-hunter table while summary.hunter_count still reports the true
    total."""
    for record in result.records:
        hunter = record.get("hunter")
        if hunter not in _HUNT_DETAIL_FIELDS:
            raise ValueError(
                f"build_tables(kind='hunt') encountered unrecognized hunter {hunter!r} -- "
                f"csv_export.py's hunt tables must be updated in lockstep with "
                f"dumpex.output.records.HUNTERS")
        expected = _HUNT_DETAIL_FIELDS[hunter]
        actual = set(record.get("details") or {})
        if actual != expected:
            raise ValueError(
                f"build_tables(kind='hunt') found a details shape mismatch for hunter "
                f"{hunter!r}: unexpected keys {sorted(actual - expected)!r}, missing keys "
                f"{sorted(expected - actual)!r} -- csv_export.py's hunt detail tables must be "
                f"updated in lockstep with dumpex.output.records' *Details dataclasses")


def hunt_hunters_rows(result) -> list:
    """One row per hunterRecord -- the common judgment fields every hunter
    carries (null for confidence/max_score/lead_count/review_priority only
    for hunter == 'yara', see HunterRecord's own docstring), plus a few
    small per-hunter extras that don't warrant a whole extra table:
    hollowing's entirely-scalar `details` (flattened straight in, see this
    section's own module comment above), yara's `rules_hit` (a short list
    of rule names, JSON-encoded same as any other list-typed cell), and
    cs-beacon's `config_count` (already redundant with beacon_configs'
    own row count, kept here too for a summary-at-a-glance)."""
    rows = []
    for record in result.records:
        coverage = record.get("coverage") or {}
        row = {
            "hunter":           record.get("hunter"),
            "status":           record.get("status"),
            "score":            record.get("score"),
            "max_score":        record.get("max_score"),
            "verdict_level":    record.get("verdict_level"),
            "confidence":       record.get("confidence"),
            "lead_count":       record.get("lead_count"),
            "review_priority":  record.get("review_priority"),
            "coverage_status":  coverage.get("status"),
            "coverage_reasons": "; ".join(coverage.get("reasons") or []),
            "finding_count":    len(record.get("findings") or []),
        }
        details = record.get("details") or {}
        hunter = record.get("hunter")
        if hunter == "hollowing":
            for field in _HOLLOWING_DETAIL_FIELDS:
                row[field] = details.get(field)
        elif hunter == "yara":
            row["rules_hit"] = _flatten_value(list(details.get("rules_hit") or []))
        elif hunter == "cs-beacon":
            row["config_count"] = details.get("config_count")
        rows.append(row)
    return rows


def hunt_findings_rows(result) -> list:
    """One row per Finding (check/tag/confidence/facts/inference/rationale/
    limitations), across every hunter's `findings` array -- always empty
    for hunter == 'yara' (see YaraDetails' own docstring for why its
    matches/rules_hit never become Finding entries)."""
    rows = []
    for record in result.records:
        hunter = record.get("hunter")
        for finding in record.get("findings") or []:
            rows.append({"hunter": hunter, **_flatten_row(finding)})
    return rows


def _hunt_evidence_rows(result, hunter: str, field_names: tuple) -> list:
    """One row per list entry across `field_names` of ONE hunter's
    `details` -- tagged with which field it came from, since a hunter's
    own evidence lists don't share one shape (e.g. injection's `rwx` is a
    list of region refs, `rip_hits` a list of thread+region pairs).
    Dict-shaped entries are flattened in place; a bare scalar entry (e.g.
    injection's `rwx_and_pe_alloc_bases`, a list of hex-string addresses)
    gets a single `value` column instead."""
    rows = []
    for record in result.records:
        if record.get("hunter") != hunter:
            continue
        details = record.get("details") or {}
        for field in field_names:
            for item in details.get(field) or []:
                if isinstance(item, dict):
                    rows.append({"hunter": hunter, "field": field, **_flatten_row(item)})
                else:
                    rows.append({"hunter": hunter, "field": field, "value": _flatten_value(item)})
    return rows


def beacon_configs_rows(result) -> list:
    """One row per extracted CS Beacon config -- CsBeaconDetails.configs is
    already a single homogeneous list (unlike injection/stomping/pipe/
    obfuscation's multiple differently-shaped lists), so no `field` tag is
    needed."""
    rows = []
    for record in result.records:
        if record.get("hunter") != "cs-beacon":
            continue
        for config in (record.get("details") or {}).get("configs") or []:
            rows.append({"hunter": "cs-beacon", **_flatten_row(config)})
    return rows


def yara_matches_rows(result) -> list:
    """One row per YARA rule match -- YaraDetails.matches, same
    single-homogeneous-list rationale as beacon_configs_rows above."""
    rows = []
    for record in result.records:
        if record.get("hunter") != "yara":
            continue
        for match in (record.get("details") or {}).get("matches") or []:
            rows.append({"hunter": "yara", **_flatten_row(match)})
    return rows


def diff_rows_for_entity(result, entity_type: str) -> list:
    """One homogeneous table's worth of rows out of a "comparison"
    result's tagged-union `records` array -- every entry whose
    `entity_type` matches, in original order. See build_tables' kind ==
    "comparison" branch."""
    return [_flatten_row(record) for record in result.records
            if record.get("entity_type") == entity_type]


def environment_variables_rows(result) -> list:
    """One row per {"name", "value"} entry, across every peb record that
    has any -- in practice exactly one record, since peb is a
    single-element-array kind, but this doesn't assume that."""
    rows = []
    for record in result.records:
        env_vars = record.get("environment_variables")
        if env_vars:
            rows.extend(env_vars)
    return rows


def artifacts_rows(artifacts) -> list:
    """One row per already-dict-ified Artifact (see
    dumpex.output.records.Artifact.to_dict()) -- id/kind/path/size_bytes/
    sha256/description are all flat scalars already, so _flatten_row is
    only for uniformity with every other table, not because any of these
    fields is ever list/dict-typed."""
    return [_flatten_row(a) for a in artifacts]


def diagnostics_rows(diagnostics) -> list:
    """One row per already-dict-ified Diagnostic (severity/message/code)
    -- shared by both the 'diagnostic_warnings' and 'diagnostic_errors'
    tables, which differ only in which list the caller passes."""
    return [_flatten_row(d) for d in diagnostics]


def summary_rows(result) -> list:
    """One row summarizing the whole result. Always exactly one row,
    even when `records` is empty, so this table's file always gets
    written in directory mode.

    Any command-specific field in result.summary (e.g. --strings' shown/
    requested_size/bytes_read/auto_sized/requested_address) is merged in
    alongside the five fixed fields below -- CSV's own summary table
    would otherwise silently drop
    everything result.summary carries beyond the generic count, unlike
    JSON's result.summary, which serializes it verbatim. A fixed field
    name always wins over a same-named result.summary entry (there is
    none today, but a future command's summary dict must never be able to
    shadow kind/execution_status/coverage_status/coverage_reasons/count
    by accident)."""
    row = {
        "kind":              result.kind,
        "execution_status":  result.execution_status,
        "coverage_status":   result.coverage_status,
        "coverage_reasons":  "; ".join(result.coverage_reasons),
        "count":             len(result.records),
    }
    fixed_fields = set(row)
    for key, value in (result.summary or {}).items():
        if key in fixed_fields:
            continue
        row[key] = _flatten_value(value)
    return [row]


def build_tables(result, artifacts=(), diagnostic_warnings=(), diagnostic_errors=()) -> dict:
    """{table_name: [row, ...]}. 'summary' is always present. For every
    kind except "comparison": 'records' is always present too;
    'environment_variables' is added only for a peb result that actually
    has at least one variable to report. For "comparison": 'records' is
    never present (see module docstring) -- 'module_diffs'/'thread_diffs'/
    'memory_diffs' take its place, always present (empty tables are
    simply never written -- see collector.py's write_csv, which already
    skips any table with zero rows in both single-file and directory
    mode), exactly mirroring how 'records' itself is always present but
    silently unwritten when empty for the other six kinds.

    'artifacts'/'diagnostic_warnings'/'diagnostic_errors' are independent
    of `kind` -- any command can populate them (see CommandResult) -- so
    they're added the same way regardless of which branch above ran, and
    only when the caller actually passed any (mirroring
    'environment_variables'' own conditional-presence precedent, so a
    kind that has never populated them doesn't grow new always-empty
    tables no test or consumer expects)."""
    if result.kind == "comparison":
        module_diffs = diff_rows_for_entity(result, "module")
        thread_diffs = diff_rows_for_entity(result, "thread")
        memory_diffs = diff_rows_for_entity(result, "memory_region")
        partitioned = len(module_diffs) + len(thread_diffs) + len(memory_diffs)
        if partitioned != len(result.records):
            # A record whose entity_type isn't one of the three known
            # values (a future entity type added to the tagged union
            # without updating this function) would otherwise vanish from
            # every table with no error at all -- summary's own `count`
            # would still show the true total, silently contradicting the
            # (empty) per-entity tables underneath it. Failing loudly here
            # is what forces this function to be updated the day a fourth
            # entity type is ever added, instead of quietly losing rows.
            unknown = {r.get("entity_type") for r in result.records} - {
                "module", "thread", "memory_region"}
            raise ValueError(
                f"build_tables(kind='comparison') partitioned {partitioned} of "
                f"{len(result.records)} records by entity_type -- unrecognized "
                f"entity_type value(s): {sorted(unknown)!r}")
        tables = {
            "summary":      summary_rows(result),
            "module_diffs": module_diffs,
            "thread_diffs": thread_diffs,
            "memory_diffs": memory_diffs,
        }
    elif result.kind == "hunt":
        _check_hunt_partition_completeness(result)
        tables = {
            "summary":            summary_rows(result),
            "hunters":            hunt_hunters_rows(result),
            "findings":           hunt_findings_rows(result),
            "injection_evidence": _hunt_evidence_rows(result, "injection", _INJECTION_EVIDENCE_FIELDS),
            "stomping_changes":   _hunt_evidence_rows(result, "stomping", _STOMPING_EVIDENCE_FIELDS),
            "pipe_evidence":      _hunt_evidence_rows(result, "pipe", _PIPE_EVIDENCE_FIELDS),
            "beacon_configs":     beacon_configs_rows(result),
            "yara_matches":       yara_matches_rows(result),
            "obfuscation_hits":   _hunt_evidence_rows(result, "obfuscation", _OBFUSCATION_EVIDENCE_FIELDS),
        }
    else:
        tables = {
            "summary": summary_rows(result),
            "records": records_to_rows(result),
        }
        if result.kind == "peb":
            env_rows = environment_variables_rows(result)
            if env_rows:
                tables["environment_variables"] = env_rows

    if artifacts:
        tables["artifacts"] = artifacts_rows(artifacts)
    if diagnostic_warnings:
        tables["diagnostic_warnings"] = diagnostics_rows(diagnostic_warnings)
    if diagnostic_errors:
        tables["diagnostic_errors"] = diagnostics_rows(diagnostic_errors)
    return tables
