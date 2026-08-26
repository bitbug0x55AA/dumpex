"""Verify that dump-derived text cannot control terminal rendering.

Cases keep raw evidence in records/JSON, drive real console renderers, and
require every declared hostile field to reach stdout before escape checks pass.
"""
import ast
import contextlib
import dataclasses
import io
import warnings
from pathlib import Path

import pytest

from minidump.constants import MINIDUMP_STREAM_TYPE

import dumpex.ui.colors as colors
from dumpex.ui.colors import console_safe, _CONSOLE_ESCAPES

from dumpex.output import records as records_module
from dumpex.output.coverage import (
    build_coverage_report, SourceObservation, SourceState,
)
from dumpex.core.memory import ParsedHandleDataStream, ParsedHandleDescriptor
from tests.fixtures.fakes import FakeMF

from dumpex.commands.diff import render_diff_console
from dumpex.commands.extract import render_strings_console
from dumpex.commands.handles import collect_handles, render_handles_console
from dumpex.commands.list_cmd import render_regions_console
from dumpex.commands.modules import render_modules_console
from dumpex.commands.process import render_process_console
from dumpex.commands.profile import collect_profile, render_profile_console
from dumpex.commands.report import render_report_console
from dumpex.commands.sysinfo import render_sysinfo_console
from dumpex.commands.threads import render_threads_console


REPO_ROOT = Path(__file__).resolve().parents[2]


# ── The payload ─────────────────────────────────────────────────────────
# Built FROM the real escape table, so a codepoint added to console_safe()
# is exercised here automatically and one removed from it fails this
# module instead of silently widening the hole.
HOSTILE_CODEPOINTS = tuple(sorted(_CONSOLE_ESCAPES))

# A per-field marker that survives escaping unchanged. Its presence in
# the rendered output proves that field's text actually REACHED the
# console: a renderer that never prints the field would otherwise look
# "clean" for the one reason that must never count as a pass. Per FIELD
# rather than per case, so "the renderer prints two of the four fields I
# declared" is visible instead of averaging out to a pass.
TAINT_MARKER = "DUMPEXTAINT"

FORGED_REASON = "  [~] HandleDataStream fully parsed, 0 limitations"


def hostile_text_for(field_name: str) -> str:
    return (
        f"{TAINT_MARKER}{field_name.upper().replace('_', '')}"
        + "".join(chr(c) for c in HOSTILE_CODEPOINTS)   # every char it claims to handle
        + "\n" + FORGED_REASON                            # a forged coverage line
        + "\x1b[2J\x1b[H"                                  # clear screen + home
        + "user\u202egnp.exe"                            # Trojan Source reordering
    )


HOSTILE_TEXT = hostile_text_for("probe")

# `\n` is the only entry in the table dumpex itself legitimately emits (it
# separates its own lines). Every other one reaching stdout is a leak.
FORBIDDEN_IN_OUTPUT = frozenset(HOSTILE_CODEPOINTS) - {0x0A}


@pytest.fixture(autouse=True)
def _no_ansi_colour(monkeypatch):
    """`_c()` reads USE_COLOR at call time; pin it off so dumpex's OWN
    escape codes can never be mistaken for leaked ones (and so this suite
    stays valid if it is ever run attached to a real tty)."""
    monkeypatch.setattr(colors, "USE_COLOR", False)


def leaked_codepoints(text: str) -> list:
    return sorted({ord(ch) for ch in text} & FORBIDDEN_IN_OUTPUT)


def forged_lines(text: str) -> list:
    return [line for line in text.splitlines() if line.rstrip() == FORGED_REASON.rstrip()]


# ── Generic hostile records ─────────────────────────────────────────────

def hostile_record(record_cls, baseline: dict, dump_derived_fields):
    """Build a record with distinct hostile values in declared dump-derived fields.

    Fields are explicit because provenance cannot be inferred from Python types.
    """
    for name in dump_derived_fields:
        try:
            record_cls(**{**baseline, name: hostile_text_for(name)})
        except Exception as exc:
            raise AssertionError(
                f"{record_cls.__name__}.{name} was declared dump-derived but rejects free "
                f"text ({type(exc).__name__}: {exc}) -- either the field is validated and "
                f"cannot carry dump text, or the baseline is wrong") from None
    return record_cls(**{**baseline,
                         **{name: hostile_text_for(name) for name in dump_derived_fields}})


def _coverage(*source_names):
    return build_coverage_report({
        name: SourceObservation(name=name, state=SourceState.PRESENT, record_count=1)
        for name in source_names})


def _rendered(render, *args) -> str:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        render(*args)
    return buffer.getvalue()


# ── Per-renderer cases ──────────────────────────────────────────────────

class _Header:
    def __init__(self, number_of_descriptors):
        self.NumberOfDescriptors = number_of_descriptors


# `HandleDataStream` TypeName/ObjectName: bounded reads of dump bytes.
_HANDLES_FIELDS = ("type_name", "object_name")


def _case_handles():
    descriptor = ParsedHandleDescriptor(
        handle=0x10, type_name=hostile_text_for("type_name"),
        object_name=hostile_text_for("object_name"),
        attributes=0, granted_access=1, handle_count=1, pointer_count=1,
        type_name_rva=8, object_name_rva=16)
    mf = FakeMF()
    mf.handles = ParsedHandleDataStream(header=_Header(1), handles=[descriptor])
    mf._dumpex_stream_failures = {}
    mf.directories = []
    result = collect_handles(mf)
    # The record layer must NOT be sanitized: --json carries evidence, not
    # a display projection. Asserted inside the case so the two halves of
    # the contract cannot drift apart.
    assert result.records[0].type_name == hostile_text_for("type_name")
    assert result.records[0].object_name == hostile_text_for("object_name")
    return _rendered(render_handles_console, result.records, result.coverage)


# ModuleListStream's own name/path strings.
_MODULES_FIELDS = ("name", "full_path", "file_version")


def _case_modules():
    record = hostile_record(records_module.ModuleRecord, dict(
        name="ntdll.dll", full_path="C:\\Windows\\System32\\ntdll.dll",
        base_address="0x0000000000001000", end_address="0x0000000000002000",
        size=4096, compiled_utc="2024-01-01T00:00:00Z", file_version=None,
        checksum=None, anomaly_flags=[]), _MODULES_FIELDS)
    return _rendered(render_modules_console, [record], _coverage("modules"))


# `backing_module` is ntpath.basename(module.name) -- a ModuleListStream
# string. `module_context` beside it is dumpex's own vocabulary and is
# deliberately NOT listed.
_THREADS_FIELDS = ("backing_module",)


def _case_threads():
    record = hostile_record(records_module.ThreadRecord, dict(
        tid=1, start_address="0x0000000000001000", backing_module="ntdll.dll",
        # `backing_module` is printed ONLY on the resolved branch -- the
        # per-field reachability check below is what caught this fixture
        # silently exercising the "not in any module" branch instead.
        module_context=records_module.MODULE_CONTEXT_RESOLVED,
        create_time="2024-01-01T00:00:00Z", exit_time=None,
        exit_status=None, kernel_time_100ns=0, user_time_100ns=0, suspend_count=0,
        priority=0, teb="0x0000000000003000", flags=[]), _THREADS_FIELDS)
    return _rendered(render_threads_console, [record],
                     _coverage("threads", "thread_info", "modules"))


# hostname/username come from the captured environment block; cpu_vendor
# is decoded from SystemInfoStream's CPU-information bytes. `os`/
# `architecture`/`product_type` are dumpex's own display names for
# integer enums and are deliberately NOT listed.
_SYSINFO_FIELDS = ("hostname", "username", "cpu_vendor", "current_directory")


def _case_sysinfo():
    # `os` must be set: the whole CPU block (and with it cpu_vendor) is
    # gated on it. Another fixture gap the per-field reachability check
    # caught rather than passing over.
    #
    # Rendered with verbose=True, and with hostile environment entries in
    # the baseline, so the --verbose listing -- the single most
    # attacker-controlled surface in this command, and the one that now
    # pads, wraps and colours its text (§4.6.1) -- is inside the
    # leaked_codepoints()/forged_lines() sweep below, which reads the
    # WHOLE output rather than only the declared fields.
    #
    # environment_variables is deliberately NOT in _SYSINFO_FIELDS:
    # hostile_record() sets a declared field to a plain string, and this
    # one holds a tuple of {name, value} dicts, so declaring it would
    # replace the tuple with a string the renderer then iterates
    # character-by-character. Its own reachability and escaping are
    # asserted directly in test_sysinfo_cmd.py, where the fixture can be
    # the right shape.
    record = hostile_record(
        records_module.SysInfoRecord,
        dict(os="Windows 10", processors=8,
             environment_variables=({"name": hostile_text_for("env_name"),
                                      "value": hostile_text_for("env_value")},)),
        _SYSINFO_FIELDS)
    return _rendered(lambda rec, cov: render_sysinfo_console(rec, cov, verbose=True),
                     record,
                     _coverage("sysinfo", "misc_info", "threads", "modules", "peb",
                                "environment_block"))


# renderer -> (case callable, the dump-derived fields it was given)
# process_name/process_path/command_line come from the PEB (or, for the
# name, the basename of a ModuleListStream path) -- §3.3's precedence
# table. process_start_utc/image_base_address are dumpex-formatted.
# The three top-level ProcessRecord strings hostile_record() can plant
# directly. The verbose block's own dump-derived strings live inside
# `iat`/`identity_evidence`/`peb_extended` (a tuple and two dicts, which
# hostile_record() cannot fill field-by-field), so they are planted by
# the builders below and checked by the whole-output sweep -- their
# per-field reachability is asserted in tests/unit/test_process_cmd.py,
# where the fixture can be the right shape.
_PROCESS_FIELDS = ("process_name", "process_path", "command_line")


def _hostile_iat() -> records_module.IatRecord:
    """One import whose DLL and API names are dump strings (read out of
    the image's import directory, #98's verbose table prints both)."""
    entry = records_module.ImportEntryRecord(
        dll=hostile_text_for("dll"), import_by="name", symbol=hostile_text_for("symbol"),
        ordinal=None, iat_slot_va="0x0000000000401000",
        resolved_target_va="0x00007ffb00001000", slot_in_bounds=False)
    return records_module.IatRecord(
        table_present=True, table_va="0x0000000000401000", table_size=8,
        import_directory_present=True, import_directory_va="0x0000000000402000",
        import_directory_size=40, has_entries=True, dll_count=1, entry_count=1,
        entries=(entry,), diagnostics=())


def _hostile_identity_evidence() -> dict:
    """§3.4's claim block. Every string below is a PEB or
    ModuleListStream value, and #98's `Identity Verification` block
    prints all of them."""
    return {
        "misc_info_claim": {"pid": 1234, "process_create_time_utc": None,
                            "raw_pid": 1234, "raw_process_create_time": None},
        "peb_claim": {"image_base_address": "0x0000000000400000",
                      "image_path": hostile_text_for("peb_image_path"),
                      "name": hostile_text_for("peb_name"),
                      "raw_image_base_address": None, "raw_image_path": None,
                      "raw_command_line": None},
        "module_claim": {"match_state": "unregistered", "base_address": None,
                         "name": None, "path": None,
                         "name_matched_candidate": {
                             "base_address": "0x0000000000500000",
                             "name": hostile_text_for("candidate_name"),
                             "path": hostile_text_for("candidate_path")},
                         "name_matched_candidate_ambiguous": False},
        "main_image_pe": {"checked": True, "valid": False,
                          "reason": hostile_text_for("pe_reason")},
        "selected_path_source": "peb",
        "diagnostics": [],
    }


def _hostile_peb_extended() -> dict:
    """§3.6's verbose-only block: WindowTitle and DllPath are PEB
    strings."""
    return {"peb_address": "0x0000000000001000", "being_debugged": False,
            "window_title": hostile_text_for("window_title"),
            "dll_path": hostile_text_for("dll_path"),
            "standard_input": None, "standard_output": None, "standard_error": None}


def _case_process():
    """Rendered TWICE -- the default projection and `--verbose` -- and the
    two outputs are swept together. The verbose block is the larger
    surface by far (#98: the import table's DLL/API names, the identity
    block's paths/names and PE rejection reason, and the Extended PEB's
    window title and DLL path are all dump strings), and rendering only
    the default view would leave every one of them unchecked."""
    record = hostile_record(records_module.ProcessRecord, dict(
        process_name="svchost.exe", pid=1234,
        process_path="C:\\Windows\\System32\\svchost.exe",
        command_line="svchost.exe -k netsvcs", process_start_utc="2024-01-01T00:00:00Z",
        image_base_address="0x0000000000400000", iat=_hostile_iat(),
        identity_evidence=_hostile_identity_evidence(),
        peb_extended=_hostile_peb_extended()), _PROCESS_FIELDS)
    coverage = _coverage("process_identity")
    return (_rendered(render_process_console, record, coverage)
            + _rendered(lambda rec, cov: render_process_console(rec, cov, verbose=True),
                        record, coverage))


# ModuleDiffRecord's name/full_path_* are ModuleListStream strings from
# whichever of the two dumps the module appeared in.
_DIFF_FIELDS = ("name", "full_path_before", "full_path_after")


def _case_diff():
    # One record per change_type: added and removed each print only their
    # own side's full_path, and rebased is the only branch that prints
    # `name` -- so all three are needed for the per-field reachability
    # check below to be satisfiable at all.
    rebased = hostile_record(records_module.ModuleDiffRecord, dict(
        change_type=records_module.MODULE_DIFF_REBASED, name="ntdll.dll",
        full_path_before="C:\\Windows\\ntdll.dll", full_path_after="C:\\Windows\\ntdll.dll",
        base_address_before="0x0000000000001000", base_address_after="0x0000000000002000"), ("name",))
    added = hostile_record(records_module.ModuleDiffRecord, dict(
        change_type=records_module.MODULE_DIFF_ADDED, name="evil.dll",
        full_path_before=None, full_path_after="C:\\evil.dll", base_address_before=None,
        base_address_after="0x0000000000003000"),
        ("full_path_after",))
    removed = hostile_record(records_module.ModuleDiffRecord, dict(
        change_type=records_module.MODULE_DIFF_REMOVED, name="gone.dll",
        full_path_before="C:\\gone.dll", full_path_after=None,
        base_address_before="0x0000000000004000", base_address_after=None), ("full_path_before",))
    coverage = _coverage("baseline.modules", "target.modules",
                          "baseline.thread_info", "target.thread_info",
                          "baseline.memory_info", "target.memory_info")
    return _rendered(render_diff_console, [rebased, added, removed], coverage,
                     "baseline.dmp", "target.dmp")


# StringRecord.text is bytes lifted straight out of process memory. The
# extractor's own `[ -~]{n,}` pattern happens to admit printable ASCII
# only, so nothing hostile reaches the renderer through the real pipeline
# today -- but that is an invariant of dumpex.core.memory, not of this
# renderer, and the record type accepts any string. The case builds the
# record directly so the renderer's safety does not rest on an upstream
# filter that a future extractor change could relax.
_STRINGS_FIELDS = ("text",)


def _case_strings():
    record = hostile_record(records_module.StringRecord, dict(
        offset=0, address="0x0000000000001000", encoding="ASCII",
        text="hello", matched_grep=None), _STRINGS_FIELDS)
    return _rendered(render_strings_console, [record], _coverage("memory_segments"))


# ProfileStreamEntry.detail: a parser exception's own text ("ExcType:
# message", dumpex.core.memory.open_dump's stream isolation) can embed
# bytes read from the dump (a struct.error interpolating a malformed
# length, a decoded fragment) -- see dumpex.commands.profile.
# render_profile_console's own docstring. Every other field --profile
# prints (architecture, stream_type_name, capability labels/codes) is a
# dumpex-owned display name for a closed-vocabulary integer enum/registry
# id, never dump text, so `detail` is the one field declared here.
_PROFILE_FIELDS = ("detail",)


class _ProfileLocation:
    def __init__(self, rva=0, data_size=0):
        self.Rva = rva
        self.DataSize = data_size


class _ProfileDirectory:
    def __init__(self, stream_type):
        self.StreamType = stream_type
        self.Location = _ProfileLocation()


class _ProfileHeader:
    Flags = 0


def _case_profile():
    mf = FakeMF()
    mf.header = _ProfileHeader()
    mf.directories = [_ProfileDirectory(MINIDUMP_STREAM_TYPE.ModuleListStream)]
    mf._dumpex_stream_failures = {MINIDUMP_STREAM_TYPE.ModuleListStream: hostile_text_for("detail")}
    result = collect_profile(mf)
    assert result.records[0].streams[0].detail == hostile_text_for("detail")
    return _rendered(render_profile_console, result.records, result.coverage)


_REPORT_FIELDS = ("thread_backing_module", "ioc_text", "image_hit_module")


def _case_report():
    thread = records_module.ReportThreadInfo(
        tid=1,
        start_address="0x0000000000001000",
        backing_module=hostile_text_for("thread_backing_module"),
        module_context=records_module.MODULE_CONTEXT_RESOLVED,
        kernel_time_100ns=0,
        user_time_100ns=0,
        backing_module_base="0x0000000000001000",
        backing_module_end="0x0000000000002000",
    )
    region = records_module.ReportRegionInfo(
        base_address="0x0000000000001000",
        size=4096,
        protect="PAGE_READWRITE",
        type="MEM_PRIVATE",
        module_owner=None,
        file_offset=0,
        is_rwx_private=False,
        module_context=records_module.MODULE_CONTEXT_UNREGISTERED,
        mz_header_detected=False,
        has_injected_pe=False,
        protection_suspicious=False,
    )
    ioc = records_module.ReportIocString(
        offset=0,
        address="0x0000000000001000",
        encoding="ASCII",
        text=hostile_text_for("ioc_text"),
        is_network_pattern=False,
    )
    card = records_module.TriageCardRecord(
        anchor_tid=1,
        anchor_address="0x0000000000001000",
        anchor_source=records_module.TRIAGE_ANCHOR_STRING_HIT,
        thread=thread,
        region=region,
        string_hit={"offset": 0, "address": "0x0000000000001000", "encoding": "ASCII"},
        other_threads_in_region=[],
        notable_strings=[],
        ioc_strings=[ioc],
        string_scan={
            "requested_bytes": 4096,
            "bytes_read": 4096,
            "clamped": False,
            "truncated": False,
            "total": 1,
            "ascii_count": 1,
            "utf16_count": 0,
        },
        string_scan_error=None,
        thread_region_correlation_excluded=False,
        findings=[],
        finding_details={},
        verdict="CLEAN",
        artifact_id=None,
        extract_read_clamped=None,
        extract_read_truncated=None,
    )
    summary = {
        "mode": "string",
        "card_count": 1,
        "query_string": "needle",
        "query_tid": None,
        "query_addr": None,
        "total_hits": 2,
        "hits_private": 1,
        "hits_image": 1,
        "image_hit_modules": [hostile_text_for("image_hit_module")],
        "skipped_unreadable_regions": 0,
        "truncated_regions": 0,
        "clamped_regions": 0,
    }
    return _rendered(
        render_report_console,
        [card],
        _coverage("memory_segments"),
        [],
        [],
        summary,
        FakeMF(),
        6,
    )


RENDER_CASES = {
    "dumpex.commands.handles.render_handles_console": (_case_handles, _HANDLES_FIELDS),
    "dumpex.commands.profile.render_profile_console": (_case_profile, _PROFILE_FIELDS),
    "dumpex.commands.process.render_process_console": (_case_process, _PROCESS_FIELDS),
    "dumpex.commands.report.render_report_console":   (_case_report, _REPORT_FIELDS),
    "dumpex.commands.diff.render_diff_console":        (_case_diff, _DIFF_FIELDS),
    "dumpex.commands.extract.render_strings_console": (_case_strings, _STRINGS_FIELDS),
    "dumpex.commands.modules.render_modules_console": (_case_modules, _MODULES_FIELDS),
    "dumpex.commands.threads.render_threads_console": (_case_threads, _THREADS_FIELDS),
    "dumpex.commands.sysinfo.render_sysinfo_console": (_case_sysinfo, _SYSINFO_FIELDS),
}

# Every field these renderers print is dumpex's own text, so there is
# nothing for a dump to inject. Listed explicitly rather than left out:
# an unexplained absence is indistinguishable from an oversight, and this
# is the one claim here that rests on reading the collector rather than on
# an assertion -- provenance is not inferable from a type.
NO_UNTRUSTED_INPUT = {
    # MemoryRegionRecord's state/protect/type are prot_str(<int>) -- a
    # dumpex lookup table, never dump text; base_address is hex.
    "dumpex.commands.list_cmd.render_regions_console":
        "MemoryInfoStream supplies integers only; every string is a dumpex lookup",
    # Prints coverage reasons, Diagnostic.message, and the written
    # Artifact's own path/size/sha256 -- all dumpex-produced. The bytes it
    # extracted go to a file, never to the terminal.
    "dumpex.commands.extract.render_extract_console":
        "prints only dumpex-produced text and the artifact it just wrote",
}

# Renderers that print untrusted dump text unescaped TODAY -- measured by
# running them, not assumed. Delete an entry when you fix the renderer; a
# stale entry fails test_no_stale_entries_in_the_leak_list below.
#
# EMPTY, and it should stay that way. It exists because this harness was
# added while modules/threads/peb/sysinfo still leaked, and it is the
# mechanism that lets known leaks remain explicit. A renderer added here
# is a decision to ship known
# terminal-injection exposure -- write down why, next to the entry.
LEAKS_UNTRUSTED_TEXT = set()


# ── The gate ────────────────────────────────────────────────────────────

def _marker_for(field_name: str) -> str:
    return f"{TAINT_MARKER}{field_name.upper().replace('_', '')}"


@pytest.mark.parametrize("renderer", sorted(RENDER_CASES))
def test_renderer_does_not_let_untrusted_text_drive_the_terminal(renderer):
    case, declared_fields = RENDER_CASES[renderer]
    output = case()

    # A field whose text never reached stdout proves nothing about that
    # field. Fail loudly rather than record a pass -- "the renderer does
    # not print it" is a fixture bug (or a field that moved), not a safety
    # property, and it is exactly how a suite drifts into testing nothing.
    unreached = [name for name in declared_fields if _marker_for(name) not in output]
    assert not unreached, (
        f"{renderer}: {len(unreached)} declared dump-derived field(s) never reached the "
        f"console ({', '.join(unreached)}), so this case tests less than it claims -- "
        f"point the fixture at fields the renderer actually prints, or drop them from "
        f"the declaration with a reason")

    leaked = leaked_codepoints(output)
    forged = forged_lines(output)

    if renderer in LEAKS_UNTRUSTED_TEXT:
        assert leaked or forged, (
            f"{renderer} no longer leaks untrusted text -- remove it from "
            f"LEAKS_UNTRUSTED_TEXT so the list keeps meaning something")
        warnings.warn(
            f"{renderer} prints dump-derived text unescaped: "
            + (f"{len(leaked)} raw control codepoint(s) "
                f"({', '.join(f'U+{c:04X}' for c in leaked)})" if leaked else "")
            + (" and a forged coverage-reason line" if forged else "")
            + " -- wrap the value in dumpex.ui.colors.console_safe() at the print site "
              "(before any colour helper) and keep the record/--json value raw",
            UserWarning, stacklevel=2)
        return

    assert not leaked, (
        f"{renderer}: {len(leaked)} raw terminal-control codepoint(s) reached stdout "
        f"({', '.join(f'U+{c:04X}' for c in leaked)}). Everything read out of a dump is "
        f"attacker-controlled -- route it through dumpex.ui.colors.console_safe() at the "
        f"print site, BEFORE any colour helper, and keep the record/--json value raw.")
    assert not forged, (
        f"{renderer}: a dump-supplied string forged a coverage-reason line verbatim "
        f"({forged[0]!r}) -- a newline in an untrusted value must never produce a line an "
        f"analyst reads as dumpex's own output")


def test_no_stale_entries_in_the_leak_list():
    """The ratchet's teeth, stated separately so a fixed renderer produces
    one obvious failure naming the line to delete, rather than only the
    per-renderer assertion above."""
    still_leaking = set()
    for renderer in LEAKS_UNTRUSTED_TEXT & set(RENDER_CASES):
        output = RENDER_CASES[renderer][0]()
        if leaked_codepoints(output) or forged_lines(output):
            still_leaking.add(renderer)
    fixed = sorted(LEAKS_UNTRUSTED_TEXT - still_leaking)
    assert not fixed, (
        f"LEAKS_UNTRUSTED_TEXT lists {len(fixed)} renderer(s) that no longer leak -- "
        f"delete them: {fixed}")
    unknown = sorted(LEAKS_UNTRUSTED_TEXT - set(RENDER_CASES))
    assert not unknown, (
        f"LEAKS_UNTRUSTED_TEXT names renderer(s) with no case in RENDER_CASES: {unknown}")


def test_payload_exercises_the_whole_escape_table():
    """Guards the guard: if HOSTILE_TEXT stopped containing a character
    console_safe() handles, every test above would pass while testing
    less."""
    assert set(HOSTILE_CODEPOINTS) <= {ord(ch) for ch in HOSTILE_TEXT}
    assert not leaked_codepoints(console_safe(HOSTILE_TEXT))
    # Escaping must not cost readability on the names an analyst reads all
    # day -- a projection that mangles ordinary evidence gets turned off.
    assert console_safe("\\Device\\NamedPipe\\mypipe") == "\\Device\\NamedPipe\\mypipe"
    assert console_safe("WaitCompletionPacket") == "WaitCompletionPacket"
    assert console_safe("C:\\Windows\\System32\\ntdll.dll") == "C:\\Windows\\System32\\ntdll.dll"


def test_every_console_renderer_has_a_case_or_is_reported():
    """Coverage of the harness itself. This one IS a naming heuristic --
    it finds `render_*` functions in dumpex/commands -- which is exactly
    why it only WARNS: a renderer it fails to discover must not be able to
    make the suite red, and a renderer it does discover is not evidence of
    anything until someone writes it a case. The gate is the behavioural
    test above; this is the to-do list."""
    discovered = set()
    for py in sorted((REPO_ROOT / "dumpex" / "commands").glob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("render_"):
                discovered.add(f"dumpex.commands.{py.stem}.{node.name}")

    accounted = set(RENDER_CASES) | set(NO_UNTRUSTED_INPUT)
    missing = sorted(discovered - accounted)
    if missing:
        warnings.warn(
            f"{len(missing)} console renderer(s) have no untrusted-text case -- their "
            f"behaviour with attacker-controlled dump strings is unverified:\n  "
            + "\n  ".join(missing), UserWarning, stacklevel=2)

    stale = sorted(accounted - discovered)
    assert not stale, f"this file names renderer(s) that no longer exist: {stale}"
    overlap = sorted(set(RENDER_CASES) & set(NO_UNTRUSTED_INPUT))
    assert not overlap, (
        f"renderer(s) are both exercised and declared input-free -- pick one: {overlap}")
