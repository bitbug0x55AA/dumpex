"""`--process`'s `pe_image` record and its console block.

Every case here is one rule of
`docs/developer/recon_process_sysinfo_handles_contract.md` §3.10 evaluated
against `dumpex.commands.process` over synthetic images: what the record
carries, what an absent profile may and may not do to the rest of the
command, and what the two console projections show.

The images come from `tests.unit.test_pe_profile.build_image`, the same
builder the canonical collector's own suite uses, so a case that makes one
field hostile is making exactly that field hostile in an otherwise whole
image.
"""
import contextlib
import dataclasses
import io

import pytest

from dumpex.commands.process import (
    _PE_ACTIONABLE_UNAVAILABLE_REASONS, _PE_DEFAULT_OBSERVATION_ROWS,
    _PE_MODULE_MATCH_TEXT, _PE_OBSERVATION_SUBJECT, _PE_REASON_TEXT, _PE_SOURCE_TEXT,
    _PE_STRUCTURAL_STATE_TEXT, _PE_TABLE_NAME, _PE_TABLE_STATE_TEXT,
    _PE_UNCOLLECTED_TEXT, _pe_captured_text, collect_process, render_process_console,
)
from dumpex.core.pe_correlation import OBSERVATION_NAMES, _REASONS
from dumpex.core.pe_profile import DIRECTORY_NAMES, MAX_E_LFANEW, MAX_STRING_BYTES
from dumpex.commands import process as process_module
from dumpex.output import records as records_module
from dumpex.output.coverage import CoverageStatus, exit_code_for
from tests.fixtures.fakes import MiscInfo, Module, Peb, Region, FakeStream
from tests.unit.test_pe_profile import TEXT, build_image
from tests.unit.test_process_cmd import IMAGE_BASE, _mf


DATA = {"name": b".data", "vaddr": 0x3000, "vsize": 0x1000, "rawptr": 0x2400,
        "rawsize": 0x1000, "chars": 0xC0000040}

PREFERRED_BASE = 0x140000000


def _image(**kwargs) -> bytes:
    """One whole PE32+ image, loaded away from its preferred base unless a
    case says otherwise."""
    kwargs.setdefault("image_base", PREFERRED_BASE)
    kwargs.setdefault("size_of_image", 0x5000)
    kwargs.setdefault("directories", [(0, 0), (0x2000, 40)])
    return build_image(**kwargs)


def _dump(*, image=None, base=IMAGE_BASE, image_path=r"C:\Samples\malware.exe",
          modules=None, regions=None, memory=None):
    memory = dict(memory or {})
    if image is not None:
        memory[base] = image
    mf = _mf(misc_info=MiscInfo(process_id=4242),
             peb=Peb(base, image_path) if base is not None else None,
             modules=modules, memory=memory)
    if regions is not None:
        mf.memory_info = FakeStream(regions, "infos")
    return mf


def _pe(mf, *, verbose=False):
    return collect_process(mf, verbose=verbose).records[0].pe_image


def _console(mf, *, verbose=False):
    result = collect_process(mf, verbose=verbose)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        render_process_console(result.records[0], result.coverage, verbose=verbose)
    return buffer.getvalue()


def _observation(pe_record, name, **operands):
    """The first observation called `name` whose operands match, or None."""
    for observation in pe_record.observations:
        if observation.name != name:
            continue
        if all(observation.operands.get(key) == value for key, value in operands.items()):
            return observation
    return None


# ── What a collected profile carries ────────────────────────────────────


def test_a_collected_profile_reports_the_headers_own_facts():
    pe_record = _pe(_dump(image=_image()))

    assert pe_record.collected is True
    assert pe_record.unavailable_reason is None
    assert pe_record.source_kind == "peb_image_base"
    assert (pe_record.machine, pe_record.machine_name) == (0x8664, "AMD64")
    assert pe_record.format == "PE32+"
    assert pe_record.size_of_image == 0x5000
    assert pe_record.size_of_headers == 0x400
    assert (pe_record.section_alignment, pe_record.file_alignment) == (0x1000, 0x200)
    assert pe_record.time_date_stamp == 0x12345678
    assert pe_record.subsystem == 2
    assert pe_record.structural_state == "complete"


def test_the_actual_base_is_where_the_header_was_read_not_what_it_declares():
    """The two bases are different facts. Reading a relocated image's RVAs
    against its preferred base would resolve every one of them at the
    wrong address."""
    pe_record = _pe(_dump(image=_image()))

    assert pe_record.actual_base == "0x00007ff600010000"
    assert pe_record.preferred_image_base == "0x0000000140000000"
    assert pe_record.relocation["delta"] == IMAGE_BASE - PREFERRED_BASE


def test_an_image_below_its_preferred_base_reports_a_negative_delta():
    """The delta is signed: clamping it at zero would report an image that
    moved down as one that did not move."""
    pe_record = _pe(_dump(image=_image(image_base=IMAGE_BASE + 0x10000)))

    assert pe_record.relocation["delta"] == -0x10000


def test_an_image_at_its_preferred_base_has_a_zero_delta_not_a_null_one():
    pe_record = _pe(_dump(image=_image(image_base=IMAGE_BASE)))

    assert pe_record.relocation["delta"] == 0
    assert _observation(pe_record, "relocation_expected").reason == "zero_delta"


def test_every_decoded_section_is_projected_in_table_order():
    pe_record = _pe(_dump(image=_image(sections=(TEXT, DATA))))

    assert [s.name for s in pe_record.sections] == [".text", ".data"]
    assert [s.section_index for s in pe_record.sections] == [0, 1]
    text = pe_record.sections[0]
    assert (text.virtual_address, text.virtual_size) == (0x1000, 0x2000)
    assert (text.declared_readable, text.declared_writable, text.declared_executable) \
        == (True, False, True)
    assert text.mapped_base_address == "0x00007ff600011000"
    assert text.mapped_size == 0x2000


def test_the_declared_and_decoded_section_counts_are_separate_facts():
    """A header claiming more sections than its table yields must not read
    as a table that yielded them."""
    whole = _pe(_dump(image=_image(sections=(TEXT, DATA))))
    assert (whole.declared_section_count, whole.decoded_section_count) == (2, 2)

    overclaimed = _pe(_dump(image=_image(sections=(TEXT,), number_of_sections=4)))
    assert overclaimed.declared_section_count == 4
    assert overclaimed.decoded_section_count == len(overclaimed.sections)


def test_all_sixteen_descriptors_are_present_including_the_absent_ones():
    """An omitted descriptor would make "not captured" indistinguishable
    from "not declared"."""
    pe_record = _pe(_dump(image=_image()))

    assert [d.index for d in pe_record.directories] == list(range(16))
    assert [d.name for d in pe_record.directories] == list(DIRECTORY_NAMES)
    assert pe_record.directories[0].present is False
    assert pe_record.directories[1].present is True
    assert pe_record.directories[1].value == 0x2000
    assert pe_record.directories[1].size == 40


def test_the_security_directory_is_addressed_by_file_offset():
    """Index 4 is a file offset, not an image RVA, so it is not part of the
    mapping and carries no capture claim."""
    pe_record = _pe(_dump(image=_image()))
    security = pe_record.directories[4]

    assert security.value_kind == "file_offset"
    assert security.containing_section_index is None
    assert security.capture_state is None
    assert _observation(pe_record, "directory_image_bound", index=4).reason \
        == "file_offset_semantics"


def test_the_entry_point_is_resolved_against_the_actual_base():
    pe_record = _pe(_dump(image=_image()))

    assert pe_record.entry_point.rva == 0x1000
    assert pe_record.entry_point.va == "0x00007ff600011000"
    assert pe_record.entry_point.va_overflow is False
    assert pe_record.entry_point.section_index == 0
    assert pe_record.entry_point.section_name == ".text"


def test_a_zero_entry_point_is_no_entry_point_not_the_header_page():
    """Resolving `actual_base + 0` would present the header page as where
    execution begins."""
    pe_record = _pe(_dump(image=_image(entry_point=0)))

    assert pe_record.entry_point.rva == 0
    assert pe_record.entry_point.va is None
    assert pe_record.entry_point.section_index is None
    assert _observation(pe_record, "entry_point_in_section").reason == "zero_entry_point"


def test_the_acquisition_keeps_the_three_byte_facts_apart():
    pe_record = _pe(_dump(image=_image()))
    acquisition = pe_record.acquisition

    assert acquisition.requested_stage == "sections"
    assert acquisition.highest_completed_stage == "sections"
    assert acquisition.requested_bytes > acquisition.read_bytes
    # A staged acquisition stops when its ladder is satisfied, so reading
    # less than was captured is the healthy outcome -- and is not an I/O
    # shortfall.
    assert acquisition.read_bytes == acquisition.read_target_bytes
    assert acquisition.target_io_short is False
    assert tuple(acquisition.components) == (
        "dos_header", "coff_header", "optional_header", "directory_array",
        "directory_descriptors", "section_table")
    assert set(acquisition.components.values()) == {"complete"}


def test_an_over_budget_e_lfanew_is_an_attributed_stop_not_a_defect():
    """A budget dumpex chose is never reported as damage to the image."""
    pe_record = _pe(_dump(image=_image(e_lfanew=0x40000)))

    assert pe_record.acquisition.bounded_stop["scope"] == "e_lfanew"
    assert pe_record.acquisition.bounded_stop["budget_consumed"] == 0x40000
    assert pe_record.structural_state == "unavailable"


# ── An absent profile takes nothing else with it ────────────────────────


def test_no_image_base_leaves_the_profile_uncollected_with_its_own_reason():
    pe_record = _pe(_dump(base=None))

    assert pe_record.collected is False
    assert pe_record.unavailable_reason == "no_image_base"
    assert pe_record.sections == () and pe_record.directories == ()
    assert pe_record.observations == ()
    assert pe_record.acquisition is None
    assert pe_record.observation_coverage == {
        "total": 0, "consistent": 0, "conflict": 0, "unavailable": 0, "not_applicable": 0}


def test_an_image_base_with_nothing_captured_at_it_is_header_unreadable():
    pe_record = _pe(_dump(image=None))

    assert pe_record.collected is False
    assert pe_record.unavailable_reason == "header_unreadable"


def test_collected_tracks_the_legacy_checked_flag_for_a_normalized_base():
    """§3.10.3's mapping: the one relationship between the new record and
    the v2.13 triple a consumer may rely on."""
    record = collect_process(_dump(image=None)).records[0]

    assert record.identity_evidence["main_image_pe"]["checked"] is False
    assert record.pe_image.collected is False
    assert record.pe_image.unavailable_reason == "header_unreadable"


def test_two_captured_bytes_are_a_profile_that_stops_early_not_an_absent_one():
    """`checked` and `collected` both turn on bytes being there at all, so
    a capture too short to hold a header still yields a profile -- one that
    says how far it got."""
    record = collect_process(_dump(image=b"MZ")).records[0]

    assert record.identity_evidence["main_image_pe"]["checked"] is True
    assert record.pe_image.collected is True
    assert record.pe_image.structural_state in ("partial", "unavailable", "malformed")
    assert record.pe_image.acquisition.read_bytes <= 2
    assert record.pe_image.sections == ()


def test_a_whole_image_makes_both_the_legacy_triple_and_the_profile_positive():
    record = collect_process(_dump(image=_image())).records[0]

    assert record.identity_evidence["main_image_pe"] == {
        "checked": True, "valid": True, "reason": None}
    assert record.pe_image.collected is True
    assert record.pe_image.unavailable_reason is None


def test_absent_pe_evidence_cannot_downgrade_the_identity_fields():
    """Optional evidence stays optional: an image nothing could be read at
    leaves every other process fact, the coverage status, and the exit
    code exactly as the other four sources established them."""
    modules = [Module(IMAGE_BASE, 0x5000, r"C:\Samples\malware.exe")]
    with_image = collect_process(_dump(image=_image(), modules=modules))
    without = collect_process(_dump(image=None, modules=modules))

    assert without.records[0].pe_image.collected is False
    for field in ("process_name", "pid", "process_path", "command_line", "image_base_address"):
        assert getattr(with_image.records[0], field) == getattr(without.records[0], field)
    assert without.records[0].identity_evidence["module_claim"]["match_state"] == "resolved"
    assert without.coverage.status is not CoverageStatus.NOT_EVALUATED


def test_a_pe_conflict_is_not_a_limitation_and_moves_no_exit_code():
    """A section reaching past the declared image size is a disagreement
    between two captured facts -- an observation, never coverage."""
    escaping = {"name": b".evil", "vaddr": 0x4000, "vsize": 0x8000, "rawptr": 0x400,
                "rawsize": 0x200, "chars": 0xE0000020}
    result = collect_process(_dump(image=_image(sections=(TEXT, escaping))))
    pe_record = result.records[0].pe_image

    conflicts = [o.name for o in pe_record.observations if o.state == "conflict"]
    assert "section_image_bound" in conflicts
    assert not any(lim.code.value.startswith("PROCESS_MAIN_IMAGE") for lim in
                    result.coverage.limitations)
    assert exit_code_for(result.coverage.status) == exit_code_for(
        collect_process(_dump(image=_image())).coverage.status)


# ── Collection is one pass over one read ────────────────────────────────


def test_the_profile_adds_no_read_of_its_own_at_the_image_base():
    """The snapshot's own main-image read is the only read of these bytes:
    the canonical profile decodes that run rather than issuing a second
    one."""
    mf = _dump(image=_image())
    reads = []
    inner = mf.get_reader()._buffered

    class _CountingBufferedReader:
        @property
        def current_segment(self):
            return inner.current_segment

        @property
        def current_position(self):
            return inner.current_position

        def move(self, address):
            return inner.move(address)

        def read(self, size):
            reads.append((inner.current_position, size))
            return inner.read(size)

    class _Reader:
        def get_buffered_reader(self):
            return _CountingBufferedReader()

    mf.get_reader = lambda: _Reader()
    collect_process(mf)

    assert len([r for r in reads if r[0] == IMAGE_BASE]) == 1


def test_the_profile_requests_exactly_the_span_the_snapshot_read():
    """Asking for a longer span than the retained run covers would make
    that run read as a short read of a longer request -- a read failure
    this command never had."""
    from dumpex.core.process_info import MAIN_IMAGE_PE_READ_MAX

    acquisition = _pe(_dump(image=_image())).acquisition

    assert acquisition.requested_bytes == MAIN_IMAGE_PE_READ_MAX
    assert acquisition.target_io_short is False


def test_a_capture_shorter_than_the_budget_is_a_gap_not_a_read_failure():
    """`captured < requested` is a collection gap; `read < captured` over
    bytes the stages asked for is the read failure. A staged acquisition
    that stopped satisfied is neither."""
    image = _image()
    pe_record = _pe(_dump(image=image[:0x300]))
    acquisition = pe_record.acquisition

    assert acquisition.captured_bytes == 0x300
    assert acquisition.requested_bytes > acquisition.captured_bytes
    assert acquisition.target_io_short is False


def test_two_runs_over_one_dump_produce_the_same_record():
    image = _image(sections=(TEXT, DATA))
    first = _pe(_dump(image=image)).to_dict()
    second = _pe(_dump(image=image)).to_dict()

    assert first == second


def test_verbosity_changes_no_collected_fact():
    """The structured record carries everything either way; `--verbose`
    selects what the console prints."""
    image = _image(sections=(TEXT, DATA))
    assert _pe(_dump(image=image), verbose=False).to_dict() \
        == _pe(_dump(image=image), verbose=True).to_dict()


# ── The record layer enforces the same state machine as the schema ──────
# A JSON Schema catches a malformed document; this catches a producer
# building one. Both are needed: nothing guarantees a consumer validates,
# and nothing guarantees a record is serialized before it is trusted.


@pytest.mark.parametrize("field,value", [
    ("source_kind", "peb_image_base"),
    ("actual_base", "0x0000000000400000"),
    ("preferred_image_base", "0x0000000000400000"),
    ("format", "PE32+"),
    ("machine", 0x8664),
    ("machine_name", "AMD64"),
    ("size_of_image", 0x5000),
    ("declared_section_count", 1),
    ("decoded_section_count", 1),
    ("structural_state", "complete"),
    ("module_match", "resolved"),
])
def test_an_uncollected_record_refuses_a_pe_fact(field, value):
    uncollected = records_module.ProcessPeRecord.uncollected("no_image_base")

    with pytest.raises(ValueError):
        dataclasses.replace(uncollected, **{field: value})


@pytest.mark.parametrize("owner,key,value", [
    ("module_identity", "value", r"C:\a.exe"),
    ("relocation", "delta", 0),
    ("relocation", "basereloc_descriptor_state", "complete"),
    ("directory_summary", "declared_count", 16),
    ("observation_coverage", "consistent", 1),
])
def test_an_uncollected_records_nested_objects_refuse_a_fact(owner, key, value):
    uncollected = records_module.ProcessPeRecord.uncollected("no_image_base")
    replacement = dict(getattr(uncollected, owner))
    replacement[key] = value

    with pytest.raises(ValueError):
        dataclasses.replace(uncollected, **{owner: replacement})


def test_an_uncollected_record_refuses_an_established_entry_point():
    uncollected = records_module.ProcessPeRecord.uncollected("header_unreadable")
    entry_point = dataclasses.replace(uncollected.entry_point, rva=0x1000)

    with pytest.raises(ValueError):
        dataclasses.replace(uncollected, entry_point=entry_point)


@pytest.mark.parametrize("state", ["absent", "failed", "lossy", "unreadable"])
def test_a_record_refuses_a_capture_no_table_could_have_resolved(state):
    """A byte count under a segment table that established nothing claims
    a slice resolved against evidence dumpex does not have. The record
    layer refuses it, so a producer cannot build the contradiction the
    schema would reject."""
    acquisition = _pe(_dump(image=_image())).acquisition
    assert acquisition.captured_bytes is not None

    with pytest.raises(ValueError, match="captured_bytes"):
        dataclasses.replace(acquisition, segment_table=state)
    # With the byte provenance withdrawn, the same state is legitimate.
    withdrawn = dataclasses.replace(
        acquisition, segment_table=state, captured_bytes=None, capture_overlapping=None)
    assert withdrawn.captured_bytes is None


def test_the_region_tables_state_does_not_bound_the_header_read():
    """The region table describes the process's mapping, not the dump's
    bytes: it can be in any state without touching the byte provenance."""
    acquisition = _pe(_dump(image=_image())).acquisition

    for state in ("absent", "failed", "lossy", "unreadable"):
        assert dataclasses.replace(
            acquisition, region_table=state).captured_bytes == acquisition.captured_bytes


def test_an_enumerated_table_may_still_leave_the_capture_unresolved():
    """`_capture_for` also refuses a slice accounting for fewer bytes than
    the read returned, so the implication runs one way only."""
    acquisition = _pe(_dump(image=_image())).acquisition

    unresolved = dataclasses.replace(
        acquisition, captured_bytes=None, capture_overlapping=None)
    assert unresolved.segment_table == "enumerated"


@pytest.mark.parametrize("field", [
    "source_kind", "actual_base", "structural_state", "acquisition", "module_match",
])
def test_a_collected_record_refuses_to_omit_what_produced_it(field):
    collected = _pe(_dump(image=_image()))

    with pytest.raises(ValueError):
        dataclasses.replace(collected, **{field: None})


def test_a_collected_record_refuses_a_short_descriptor_array():
    collected = _pe(_dump(image=_image()))

    with pytest.raises(ValueError):
        dataclasses.replace(collected, directories=collected.directories[:8])


# ── Observations ────────────────────────────────────────────────────────


def test_every_observation_is_carried_in_every_state_and_the_tally_sums():
    pe_record = _pe(_dump(image=_image(sections=(TEXT, DATA))))
    tally = pe_record.observation_coverage

    assert len(pe_record.observations) == tally["total"]
    assert sum(tally[state] for state in
               ("consistent", "conflict", "unavailable", "not_applicable")) == tally["total"]
    assert {o.state for o in pe_record.observations} >= {
        "consistent", "unavailable", "not_applicable"}
    # The frozen checks, the identity triple, three per section and one per
    # descriptor -- the whole set, not a filtered one.
    assert {o.name for o in pe_record.observations} >= {
        "base_vs_preferred", "relocation_expected", "machine_vs_format",
        "entry_point_in_section", "size_vs_image_extent", "size_vs_modulelist",
        "size_vs_section_extent", "section_image_bound", "directory_image_bound"}


def test_a_per_section_observation_names_the_section_it_is_about():
    pe_record = _pe(_dump(image=_image(sections=(TEXT, DATA))))

    for index in (0, 1):
        assert _observation(pe_record, "section_image_bound", section_index=index) is not None


def test_a_section_observation_is_not_also_nested_in_the_section_record():
    """One observation, one home: a second copy inside the section could
    drift from the array a consumer reads."""
    pe_record = _pe(_dump(image=_image()))
    section = pe_record.sections[0].to_dict()

    assert "image_bound" not in section
    assert not any(key.endswith("observations") for key in section)


def test_an_image_the_loader_records_a_different_size_for_is_a_conflict():
    modules = [Module(IMAGE_BASE, 0x9000, r"C:\Samples\malware.exe")]
    pe_record = _pe(_dump(image=_image(), modules=modules))

    size_check = _observation(pe_record, "size_vs_modulelist")
    assert size_check.state == "conflict"
    assert size_check.reason == "size_contradicts_modulelist"
    assert pe_record.module_match == "resolved"


def test_no_module_at_the_base_leaves_the_size_check_unavailable():
    """An absent second source is a gap, never a PE defect -- whether the
    module list confirms nothing is registered here or could not be read
    at all."""
    for modules in ([], None):
        pe_record = _pe(_dump(image=_image(), modules=modules))
        assert _observation(pe_record, "size_vs_modulelist").state == "unavailable"


# ── `module_match` is the identity boundary's own answer ────────────────
# "Is a module registered at this image base" is one question. Deriving it
# a second time from whether the module list happens to be non-empty would
# report a stream that parsed and legitimately holds zero modules -- a
# confirmed "nothing is registered here" -- as evidence that was not
# available, and contradict `identity_evidence` inside one record.


def test_a_present_but_empty_module_stream_confirms_nothing_is_registered():
    record = collect_process(_dump(image=_image(), modules=[])).records[0]

    assert record.identity_evidence["module_claim"]["match_state"] == "unregistered"
    assert record.pe_image.module_match == "unregistered"


def test_a_module_stream_with_no_matching_base_is_unregistered():
    elsewhere = [Module(IMAGE_BASE + 0x100000, 0x5000, r"C:\Windows\other.dll")]
    record = collect_process(_dump(image=_image(), modules=elsewhere)).records[0]

    assert record.identity_evidence["module_claim"]["match_state"] == "unregistered"
    assert record.pe_image.module_match == "unregistered"


def test_an_exact_base_match_is_resolved():
    modules = [Module(IMAGE_BASE, 0x5000, r"C:\Samples\malware.exe")]
    record = collect_process(_dump(image=_image(), modules=modules)).records[0]

    assert record.identity_evidence["module_claim"]["match_state"] == "resolved"
    assert record.pe_image.module_match == "resolved"


def test_an_absent_module_stream_is_unavailable():
    record = collect_process(_dump(image=_image(), modules=None)).records[0]

    assert record.identity_evidence["module_claim"]["match_state"] == "unavailable"
    assert record.pe_image.module_match == "unavailable"


def test_a_failed_module_stream_is_unavailable():
    from minidump.constants import MINIDUMP_STREAM_TYPE

    mf = _dump(image=_image(), modules=None)
    mf._dumpex_stream_failures = {
        MINIDUMP_STREAM_TYPE.ModuleListStream: "ValueError: corrupt module list"}
    record = collect_process(mf).records[0]

    assert record.identity_evidence["module_claim"]["match_state"] == "unavailable"
    assert record.pe_image.module_match == "unavailable"


# ── Hostile input ───────────────────────────────────────────────────────


def test_a_module_identity_longer_than_the_bound_is_kept_short_and_flagged():
    """A shortened string is never presented as a whole one, and the flag
    is what says so."""
    long_path = "C:\\" + "a" * (MAX_STRING_BYTES * 2) + ".exe"
    pe_record = _pe(_dump(image=_image(), image_path=long_path))

    assert pe_record.module_identity["truncated"] is True
    assert len(pe_record.module_identity["value"]) <= MAX_STRING_BYTES
    assert pe_record.module_identity["form"] == "path"


def test_a_hostile_section_count_cannot_make_the_record_unbounded():
    """_MAX_SECTIONS is a structural constraint, so a count no image can
    declare is malformed rather than 65535 projected rows."""
    pe_record = _pe(_dump(image=_image(number_of_sections=0xFFFF)))

    assert pe_record.decoded_section_count == len(pe_record.sections)
    assert len(pe_record.sections) <= 96
    assert pe_record.structural_state == "malformed"


def test_an_overlapping_section_table_reports_the_overlap_once_per_section():
    overlapping = {"name": b".over", "vaddr": 0x1800, "vsize": 0x1000, "rawptr": 0x400,
                   "rawsize": 0x1000, "chars": 0x40000040}
    pe_record = _pe(_dump(image=_image(sections=(TEXT, overlapping))))

    overlaps = [o for o in pe_record.observations
                if o.name == "section_overlap" and o.state == "conflict"]
    assert len(overlaps) == 2
    assert {o.operands["section_index"] for o in overlaps} == {0, 1}


# ── Console ─────────────────────────────────────────────────────────────


def test_the_default_console_states_the_image_in_one_block():
    output = _console(_dump(image=_image()))

    assert "Main Image PE" in output
    assert "AMD64 / PE32+" in output
    assert "RVA 0x1000 -> 0x00007ff600011000" in output
    assert "use --verbose" in output


def test_the_default_console_hides_the_tables_without_claiming_they_are_empty():
    output = _console(_dump(image=_image()))

    assert "Sections" not in output
    assert "Data Directories" not in output
    assert "(none decoded)" not in output


def test_an_uncollected_profile_says_which_of_the_two_reasons_applied():
    assert "no image base" in _console(_dump(base=None))
    assert "could not be read" in _console(_dump(image=None))


def test_the_verbose_console_adds_the_five_bounded_blocks():
    output = _console(_dump(image=_image(sections=(TEXT, DATA))), verbose=True)

    for heading in ("Sections", "Data Directories", "Relocation Evidence",
                     "Consistency Checks", "Header Acquisition"):
        assert heading in output
    assert ".text" in output and ".data" in output
    assert "R-X" in output
    # Every descriptor, including the absent ones.
    for name in DIRECTORY_NAMES:
        assert name in output


_INTERNAL_TOKENS = (
    "profile.optional_header", "profile.source:peb_image_base",
    "section_within_image_bound", "machine_no_independent_source",
    "declared_absent", "dos_header=", "directory_descriptors=",
    "requested sections", "file_offset", "not_applicable",
    "pe_header_bytes", "pe_header_read_operations", "e_lfanew",
)


def test_the_console_never_prints_an_internal_token():
    """A reason token and an evidence token are `--json` vocabulary. The
    console renders the sentence an analyst reads instead."""
    output = _console(_dump(image=_image(sections=(TEXT, DATA))), verbose=True)

    for token in _INTERNAL_TOKENS:
        assert token not in output


def _pe_block(output: str) -> str:
    """The `Main Image PE` block alone -- the region §3.10.10's vocabulary
    rule governs."""
    return output.split("Main Image PE", 1)[1].split("Import Address Table", 1)[0]


@pytest.mark.parametrize("image", [
    pytest.param(lambda: _max_section_image(), id="byte_budget"),
    pytest.param(lambda: _image(e_lfanew=MAX_E_LFANEW * 2), id="offset_budget"),
])
def test_a_bounded_stop_names_its_budget_without_naming_its_scope(image):
    """A budget scope is dumpex's own identifier for its own limit -- the
    most clearly internal string the provenance block has left."""
    mf = _dump(image=image())
    assert _pe(mf).acquisition.bounded_stop is not None

    block = _pe_block(_console(mf, verbose=True))
    stop = next(l for l in block.splitlines() if "Bounded stop" in l)
    assert "dumpex's own" in stop or "past dumpex's own budget" in stop
    for token in _INTERNAL_TOKENS:
        assert token not in block


def test_the_default_console_bounds_its_conflict_rows_and_counts_the_rest():
    """A hostile image can carry a conflict per section; the default block
    is a summary, and what it leaves out it counts."""
    sections = tuple(
        {"name": b".s%d" % i, "vaddr": 0x9000 + i * 0x1000, "vsize": 0x1000,
         "rawptr": 0x400, "rawsize": 0x1000, "chars": 0x40000040}
        for i in range(_PE_DEFAULT_OBSERVATION_ROWS + 3))
    output = _console(_dump(image=_image(sections=sections, size_of_image=0x2000)))

    conflict_rows = [line for line in output.splitlines() if line.strip().startswith("[!!]")]
    assert len(conflict_rows) == _PE_DEFAULT_OBSERVATION_ROWS
    assert "further conflicting or unanswered check(s) -- see --verbose" in output


def test_a_shortened_identity_marks_itself_outside_the_value():
    """A marker inside the value is forgeable: an image whose own name ends
    in one must not read as a name dumpex cut short."""
    long_path = "C:\\" + "b" * (MAX_STRING_BYTES * 2) + ".exe"
    output = _console(_dump(image=_image(), image_path=long_path), verbose=True)

    line = next(l for l in output.splitlines() if "Named as" in l)
    assert line.rstrip().endswith("[shortened] (path from the PEB-reported image base)")


def test_the_live_region_protection_reaches_the_section_table():
    regions = [Region(IMAGE_BASE, IMAGE_BASE, 0x5000, "MEM_COMMIT", "PAGE_EXECUTE_READ",
                       "MEM_IMAGE")]
    pe_record = _pe(_dump(image=_image(), regions=regions))

    assert pe_record.sections[0].live_protections == ("PAGE_EXECUTE_READ",)
    assert "PAGE_EXECUTE_READ" in _console(_dump(image=_image(), regions=regions), verbose=True)



# ── A table dumpex cannot walk in full bounds nothing ───────────────────
# The header run the snapshot read is, by construction, captured and read.
# A capture slice resolved from a table that dropped a descriptor accounts
# for fewer bytes than that run, and the collector treats a slice as a hard
# ceiling -- so handing it one would clamp the acquisition to less than the
# bytes already parsed, contradict `identity_evidence.main_image_pe` about
# the same run, and report the shortfall as a defect in the image.


class _SegmentEntry:
    """One Memory64List entry. A negative `start_file_address` is a value
    the capture model refuses, which is what makes the table lossy."""

    def __init__(self, base, file_offset, size):
        self.start_virtual_address = base
        self.start_file_address = file_offset
        self.size = size
        self.end_virtual_address = base + size


class _UnwalkableEntry:
    """A descriptor carrying neither a size nor an end address: genuine
    parser-shape drift, which the value model deliberately raises on."""

    def __init__(self, base):
        self.start_virtual_address = base
        self.start_file_address = 0x1000


class _UnrepresentableRegion:
    """A region descriptor whose values the capture model refuses -- a
    zero-length span. The walk survives and counts it as skipped, which is
    what makes the table lossy rather than unreadable."""

    BaseAddress = 0x1000
    AllocationBase = 0x1000
    RegionSize = 0
    State = None
    Type = None
    Protect = None


class _NoFileOffsetEntry:
    """A segment descriptor whose virtual extent is there but whose file
    offset is not. The address walk `dumpex.core.memory` performs never
    reads that field and succeeds; the capture model needs it and raises,
    which is what makes the segment table unreadable for this record while
    the header behind it still reads."""

    def __init__(self, base, size):
        self.start_virtual_address = base
        self.size = size
        self.end_virtual_address = base + size


def _split_segment_dump(*, lossy):
    """One whole image behind two contiguous segment entries, the second
    of which the capture model refuses when `lossy`."""
    image = _image(sections=(TEXT, DATA))
    mf = _dump(image=image, modules=[])
    mf.memory_segments_64 = FakeStream(
        [_SegmentEntry(IMAGE_BASE, 0x1000, 0x100),
         _SegmentEntry(IMAGE_BASE + 0x100, -1 if lossy else 0x1100, len(image) - 0x100)],
        "memory_segments")
    return mf


def test_a_lossy_segment_table_does_not_clamp_what_was_already_read():
    whole = collect_process(_split_segment_dump(lossy=False)).records[0]
    lossy = collect_process(_split_segment_dump(lossy=True)).records[0]

    # The snapshot read and parsed the same bytes either way.
    assert whole.identity_evidence["main_image_pe"] \
        == lossy.identity_evidence["main_image_pe"]
    # ... so the profile decodes the same header either way.
    assert lossy.pe_image.structural_state == whole.pe_image.structural_state == "complete"
    assert [s.name for s in lossy.pe_image.sections] == [".text", ".data"]
    assert lossy.pe_image.acquisition.components == whole.pe_image.acquisition.components
    assert len(lossy.pe_image.directories) == 16


def test_a_lossy_segment_table_does_not_downgrade_a_real_conflict():
    lossy = _pe(_split_segment_dump(lossy=True))
    whole = _pe(_split_segment_dump(lossy=False))

    assert _observation(lossy, "relocation_expected").state == "conflict"
    assert {(o.name, o.state) for o in lossy.observations} \
        == {(o.name, o.state) for o in whole.observations}


def test_a_lossy_segment_table_names_itself_as_the_cause():
    """The gap belongs to the dump's own table, and the record says so
    rather than leaving it to read as a property of the image."""
    pe_record = _pe(_split_segment_dump(lossy=True))

    assert pe_record.acquisition.segment_table == "lossy"
    # No table in hand can bound the run, so the byte provenance is not
    # established -- which is a different claim from "nothing was captured".
    assert pe_record.acquisition.captured_bytes is None
    assert pe_record.acquisition.capture_overlapping is None
    assert pe_record.acquisition.target_io_short is False


def test_a_whole_segment_table_still_establishes_the_byte_provenance():
    pe_record = _pe(_split_segment_dump(lossy=False))

    assert pe_record.acquisition.segment_table == "enumerated"
    assert pe_record.acquisition.captured_bytes >= pe_record.acquisition.read_bytes
    assert pe_record.acquisition.capture_overlapping is False


def test_the_console_attributes_a_lossy_table_to_the_dump():
    """The default block names the table and what happened to it; what is
    withheld because of it is stated once, under `--verbose`."""
    default = _console(_split_segment_dump(lossy=True))
    assert "memory segment table dropped a descriptor" in default

    verbose = _console(_split_segment_dump(lossy=True), verbose=True)
    assert "withheld, not decided" in verbose


def test_a_table_that_cannot_be_walked_is_not_reported_as_an_absent_one():
    """Library-shape drift is not evidence about the dump's contents. The
    record says the table could not be walked rather than claiming it was
    not there."""
    mf = _dump(image=_image(), modules=[])
    mf.memory_info = FakeStream([_UnwalkableEntry(IMAGE_BASE)], "infos")
    pe_record = _pe(mf)

    assert pe_record.acquisition.region_table == "unreadable"
    assert pe_record.collected is True
    output = _console(mf, verbose=True)
    assert "memory region table could not be walked" in output
    assert "memory region table is absent" not in output


# ── A correlation that did not run is never a clean image ───────────────


def test_a_failed_correlation_is_published_as_one_that_did_not_run(monkeypatch):
    """Both collectors document that they never raise over established
    facts, so this can only fire on a dumpex defect -- and a defect must
    not be published as a zero tally an analyst reads as "nothing to
    flag"."""
    import dumpex.commands.process as process_module

    def _boom(*args, **kwargs):
        raise RuntimeError("internal defect")

    monkeypatch.setattr(process_module, "correlate_main_image", _boom)
    record = collect_process(_dump(image=_image())).records[0]

    assert record.pe_image.collected is True
    assert record.pe_image.correlated is False
    assert record.pe_image.observations == ()
    assert record.pe_image.observation_coverage["total"] == 0
    # The profile's own decoded facts survive; only what the correlation
    # resolves is withheld.
    assert record.pe_image.machine_name == "AMD64"
    assert record.pe_image.entry_point.rva == 0x1000
    assert record.pe_image.entry_point.va is None
    assert record.pe_image.sections[0].mapped_base_address is None


def test_a_failed_correlation_says_so_on_the_console(monkeypatch):
    import dumpex.commands.process as process_module

    monkeypatch.setattr(process_module, "correlate_main_image",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("defect")))
    output = _console(_dump(image=_image()))

    assert "not produced" in output
    assert "0 consistent, 0 conflicting, 0 not evaluated" not in output


def test_a_failed_collection_is_not_reported_as_an_unreadable_header(monkeypatch):
    """The bytes were there: naming a dumpex defect as a fact about the
    image would send an analyst to re-collect a dump that is fine."""
    import dumpex.commands.process as process_module

    monkeypatch.setattr(process_module, "collect_pe_image_profile",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("defect")))
    record = collect_process(_dump(image=_image())).records[0]

    assert record.identity_evidence["main_image_pe"]["checked"] is True
    assert record.pe_image.collected is False
    assert record.pe_image.unavailable_reason == "collection_failed"
    assert "dumpex defect" in _console(_dump(image=_image()))


# ── One canonical profile, two surfaces ─────────────────────────────────


def test_the_two_surfaces_read_the_same_budget():
    """`--process` decodes the profile from the run the identity snapshot
    read, so the two budgets are not two constants that happen to agree."""
    from dumpex.core.pe_profile import PE_HEADER_READ_MAX
    from dumpex.core.process_info import MAIN_IMAGE_PE_READ_MAX

    assert MAIN_IMAGE_PE_READ_MAX is PE_HEADER_READ_MAX


def test_process_and_report_describe_the_same_image():
    """The published claim that the two commands cannot disagree about one
    dump, evaluated rather than asserted: same dump, both surfaces, every
    fact they both carry."""
    from dumpex.commands.report_enrichment import PeProfileCache, collect_pe_context

    modules = [Module(IMAGE_BASE, 0x5000, r"C:\Samples\malware.exe")]
    regions = [Region(IMAGE_BASE, IMAGE_BASE, 0x5000, "MEM_COMMIT", "PAGE_EXECUTE_READ",
                       "MEM_IMAGE")]
    mf = _dump(image=_image(sections=(TEXT, DATA)), modules=modules, regions=regions)

    pe_image = collect_process(mf).records[0].pe_image
    pe_context = collect_pe_context(PeProfileCache(mf, main_base=IMAGE_BASE))

    assert pe_context.image_base == pe_image.actual_base
    assert pe_context.preferred_image_base == pe_image.preferred_image_base
    assert pe_context.machine == pe_image.machine
    assert pe_context.machine_name == pe_image.machine_name
    assert pe_context.time_date_stamp == pe_image.time_date_stamp
    assert pe_context.size_of_image == pe_image.size_of_image
    assert pe_context.entry_point_rva == pe_image.entry_point.rva
    assert pe_context.entry_point_va == pe_image.entry_point.va
    assert pe_context.section_count == pe_image.declared_section_count
    assert pe_context.pe32_plus is (pe_image.format == "PE32+")
    assert pe_context.module_match == pe_image.module_match
    tally = pe_image.observation_coverage
    assert (pe_context.consistent_count, pe_context.conflict_count,
            pe_context.unavailable_count) == (
        tally["consistent"], tally["conflict"], tally["unavailable"])


def test_the_two_surfaces_report_the_same_conflicts():
    from dumpex.commands.report_enrichment import PeProfileCache, collect_pe_context

    modules = [Module(IMAGE_BASE, 0x9000, r"C:\Samples\malware.exe")]
    mf = _dump(image=_image(), modules=modules)

    pe_image = collect_process(mf).records[0].pe_image
    pe_context = collect_pe_context(PeProfileCache(mf, main_base=IMAGE_BASE))

    process_conflicts = [(o.name, o.reason) for o in pe_image.observations
                         if o.state == "conflict"]
    report_conflicts = [(o.name, o.reason) for o in pe_context.observations]
    assert process_conflicts == report_conflicts
    assert process_conflicts


# ── The loader-record distinction the reasons cannot make ───────────────


def test_a_confirmed_and_an_uncomparable_module_list_are_told_apart():
    """`no_modulelist_entry` fires for both, so the sentence states the
    comparison and `module_match` carries the distinction -- the two cases
    must not read identically on the record."""
    confirmed = _pe(_dump(image=_image(), modules=[]))
    uncomparable = _pe(_dump(image=_image(), modules=None))

    assert confirmed.module_match == "unregistered"
    assert uncomparable.module_match == "unavailable"
    assert (_observation(confirmed, "size_vs_modulelist").reason
            == _observation(uncomparable, "size_vs_modulelist").reason
            == "no_modulelist_entry")


def test_the_console_states_the_loader_record_for_each_case():
    assert "no module is registered at this image base" in _console(
        _dump(image=_image(), modules=[]))
    assert "could not be compared" in _console(_dump(image=_image(), modules=None))


def test_no_reason_sentence_claims_an_absence_the_dump_did_not_establish():
    """A table or record that could not be compared is not a table or
    record the dump confirms is not there."""
    for reason in ("no_modulelist_entry", "no_second_source", "regions_unavailable",
                    "segments_unavailable"):
        assert "is absent" not in _PE_REASON_TEXT[reason]
        assert "is registered" not in _PE_REASON_TEXT[reason]


# ── The provenance line names its own cause ─────────────────────────────
# `captured_bytes` is null for four different reasons. A line that names
# one of them unconditionally is the same class of false statement as a
# reason sentence claiming a table is absent -- it just moved.


def test_the_captured_line_names_a_lossy_table_as_the_cause():
    output = _console(_split_segment_dump(lossy=True), verbose=True)
    captured = next(l for l in output.splitlines() if "Captured in that window" in l)

    assert "segment table dropped a descriptor" in captured
    assert "no segment table" not in captured


def test_the_captured_line_names_an_unwalkable_table_as_the_cause():
    mf = _dump(image=_image(), modules=[])
    mf.memory_segments_64 = FakeStream(
        [_NoFileOffsetEntry(IMAGE_BASE, 0x1000)], "memory_segments")
    pe_record = _pe(mf)
    assert pe_record.acquisition.segment_table == "unreadable"
    assert pe_record.collected is True

    output = _console(mf, verbose=True)
    captured = next(l for l in output.splitlines() if "Captured in that window" in l)
    assert "could not be walked" in captured
    assert "no segment table" not in captured


def test_the_captured_line_reports_a_byte_count_when_one_was_resolved():
    output = _console(_split_segment_dump(lossy=False), verbose=True)
    captured = next(l for l in output.splitlines() if "Captured in that window" in l)

    assert "bytes" in captured and "not resolved" not in captured


def test_a_table_loss_is_stated_once_per_render():
    """The default block and the provenance block each have a reason to
    mention it; saying the whole sentence twice in one render is noise,
    and saying it in neither would leave the conflicts with no cause."""
    verbose_output = _console(_split_segment_dump(lossy=True), verbose=True)
    full = [l for l in verbose_output.splitlines()
            if "memory segment table" in l and "withheld, not decided" in l]
    assert len(full) == 1, verbose_output
    assert "see Header Acquisition below" in verbose_output

    # Without the verbose block there is nowhere else to say it, and the
    # default block still names the table and its state.
    default = _console(_split_segment_dump(lossy=True))
    named = [l for l in default.splitlines() if "memory segment table" in l]
    assert len(named) == 1, default


# ── The one input the two surfaces deliberately differ on ───────────────


def test_library_shape_drift_degrades_process_and_fails_report():
    """The value model raises on parser-shape drift rather than papering
    over it. `--process` records which table could not be walked and
    keeps the four other identity sources; a `--report` run over the same
    dump fails loudly. That difference is deliberate and documented
    (contract §3.10.5), and it is pinned here so it stays a decision
    rather than becoming an accident."""
    from dumpex.commands.report_enrichment import PeProfileCache

    mf = _dump(image=_image(), modules=[])
    mf.memory_info = FakeStream([_UnwalkableEntry(IMAGE_BASE)], "infos")

    record = collect_process(mf).records[0]
    assert record.pe_image.collected is True
    assert record.pe_image.acquisition.region_table == "unreadable"
    assert record.process_name == "malware.exe"

    with pytest.raises((AttributeError, TypeError)):
        PeProfileCache(mf, main_base=IMAGE_BASE)


# ── The default block says what could not be checked, and why ───────────
# "18 not evaluated" on its own tells an analyst nothing about what to go
# and collect. The reasons that change what they do next are shown; the
# routine ones are counted and left to `--verbose`.


def test_the_default_block_names_the_evidence_a_check_was_missing():
    """A dump with no region table cannot support the mapped-extent
    check, and the default console says so rather than only counting it."""
    output = _console(_dump(image=_image(), modules=[]))

    assert "image size vs. mapped memory" in output
    assert "no usable memory region table" in output


def test_the_default_block_names_a_truncated_structure():
    """A section table that was cut short leaves a real question about
    the entry point unanswered, which is actionable in a way a declared
    absence is not."""
    image = _image(sections=(TEXT, DATA))
    truncated = image[:len(image) - 0x200 - 40]   # the second section header is gone
    output = _console(_dump(image=truncated, modules=[]))

    assert "entry point placement" in output or "image size vs. section table" in output
    assert "incomplete" in output


def test_routine_unavailable_checks_stay_out_of_the_default_block():
    """Fifteen `directory_declared_absent` rows would bury the one line
    that matters, and an image declaring no TLS directory is not a
    finding."""
    output = _console(_dump(image=_image(), modules=[Module(
        IMAGE_BASE, 0x5000, r"C:\Samples\malware.exe")]))

    assert "declares this directory absent" not in output
    assert "no second source for this image's architecture" not in output
    assert "the header carries no checksum" not in output


def test_the_row_budget_is_shared_and_conflicts_are_never_displaced():
    """An unevaluated check is the weaker result: it may fill the rows a
    conflict left, never take one."""
    sections = tuple(
        {"name": b".s%d" % i, "vaddr": 0x9000 + i * 0x1000, "vsize": 0x1000,
         "rawptr": 0x400, "rawsize": 0x1000, "chars": 0x40000040}
        for i in range(_PE_DEFAULT_OBSERVATION_ROWS + 3))
    output = _console(_dump(image=_image(sections=sections, size_of_image=0x2000)))

    rows = [l for l in output.splitlines()
            if l.strip().startswith("[!!]") or l.strip().startswith("[--]")]
    conflicts = [l for l in rows if l.strip().startswith("[!!]")]
    assert len(conflicts) == _PE_DEFAULT_OBSERVATION_ROWS
    assert "further conflicting or unanswered check(s)" in output


def test_the_omitted_count_is_stable_across_runs():
    mf_a = _dump(image=_image(sections=(TEXT, DATA)), modules=[])
    mf_b = _dump(image=_image(sections=(TEXT, DATA)), modules=[])

    assert _console(mf_a) == _console(mf_b)


def test_every_actionable_reason_is_one_the_correlation_can_emit():
    """An allowlist entry for a token nothing emits is dead weight that
    hides the real gap, exactly as a missing rendering would."""
    assert _PE_ACTIONABLE_UNAVAILABLE_REASONS <= set(_REASONS)


def test_the_allowlist_excludes_the_reasons_that_would_bury_it():
    """Membership is "would an analyst act on this?", so the routine
    structural absences are named here as excluded rather than left to an
    implicit filter."""
    for reason in ("directory_declared_absent", "file_offset_semantics",
                    "machine_no_independent_source", "header_checksum_absent",
                    "size_of_image_null", "machine_null", "entry_point_null",
                    "no_decoded_sections", "operand_null"):
        assert reason not in _PE_ACTIONABLE_UNAVAILABLE_REASONS


def test_every_console_lookup_table_is_closed_over_its_own_vocabulary():
    """Each of these is indexed, not `.get()`-ed, so a value added to the
    record vocabulary without a sentence here is a `KeyError` that takes
    `--process` down -- not a missing line. Pinned as equalities for the
    same reason the reason and evidence tables are."""
    from dumpex.output.records import (
        PROCESS_PE_COMPONENT_STATES, PROCESS_PE_TABLE_STATES,
        PROCESS_PE_UNAVAILABLE_REASONS, _MODULE_CONTEXTS,
    )

    assert set(_PE_UNCOLLECTED_TEXT) == set(PROCESS_PE_UNAVAILABLE_REASONS)
    assert set(_PE_MODULE_MATCH_TEXT) == set(_MODULE_CONTEXTS) | {None}
    assert set(_PE_STRUCTURAL_STATE_TEXT) == set(PROCESS_PE_COMPONENT_STATES)
    # `enumerated` is the one state with nothing to say, so the loss table
    # covers the other four exactly.
    assert set(_PE_TABLE_STATE_TEXT) == set(PROCESS_PE_TABLE_STATES) - {"enumerated"}


def test_the_table_name_and_consequence_tables_cover_both_tables():
    from dumpex.commands.process import _PE_TABLE_CONSEQUENCE

    assert set(_PE_TABLE_NAME) == set(_PE_TABLE_CONSEQUENCE) == {
        "segment_table", "region_table"}


def test_the_captured_line_names_a_slice_that_could_not_account_for_the_read():
    """`_capture_for`'s last guard -- an `enumerated` table whose slice
    accounts for fewer bytes than the read returned -- is the one path to
    a null `captured_bytes` with no table state to blame. It is the guard
    that keeps the profile from being clamped below what
    `identity_evidence.main_image_pe` already parsed, so the line it
    produces is pinned even though a healthy dump cannot reach it."""
    acquisition = records_module.ProcessPeAcquisitionRecord(
        requested_stage="sections", highest_completed_stage="sections",
        requested_bytes=0x1000, captured_bytes=None, read_bytes=0x400,
        read_target_bytes=0x400, target_io_short=False, bounded_stop=None,
        components={name: "complete" for name in records_module.PROCESS_PE_COMPONENTS},
        segment_table="enumerated", region_table="enumerated", capture_overlapping=None,
        unexamined=())

    text = _pe_captured_text(acquisition)
    assert text == "(not resolved -- the segment table accounts for fewer bytes than were read)"
    assert "not in this dump" not in text


@pytest.mark.parametrize("state,expected", [
    ("absent", "is not in this dump"),
    ("failed", "yielded nothing usable"),
    ("lossy", "dropped a descriptor"),
    ("unreadable", "could not be walked"),
])
def test_the_captured_line_names_every_unusable_table_state(state, expected):
    acquisition = records_module.ProcessPeAcquisitionRecord(
        requested_stage="sections", highest_completed_stage="sections",
        requested_bytes=0x1000, captured_bytes=None, read_bytes=0x400,
        read_target_bytes=0x400, target_io_short=False, bounded_stop=None,
        components={name: "complete" for name in records_module.PROCESS_PE_COMPONENTS},
        segment_table=state, region_table="enumerated", capture_overlapping=None,
        unexamined=())

    assert expected in _pe_captured_text(acquisition)


@pytest.mark.parametrize("field,value", [
    ("va", "0x0000000000401000"),
    ("section_index", 0),
    ("section_name", ".text"),
    ("capture_state", "complete"),
    ("region_state", "MEM_COMMIT"),
    ("region_type", "MEM_IMAGE"),
    ("region_protection", "PAGE_EXECUTE_READ"),
    ("va_overflow", True),
])
def test_a_record_refuses_a_zero_entry_point_that_resolved_something(field, value):
    """The producer already builds it this way; the record refuses the
    contradiction so it cannot be built at all, and a consumer can read
    `rva: 0` as "no entry point" without checking seven other fields."""
    zero = records_module.ProcessPeEntryPointRecord(
        rva=0, va=None, va_overflow=False, section_index=None, section_name=None,
        capture_state=None, region_state=None, region_type=None, region_protection=None)

    with pytest.raises(ValueError):
        dataclasses.replace(zero, **{field: value})


def test_a_record_refuses_a_section_count_its_table_does_not_match():
    """One of the three relationships JSON Schema cannot express, so the
    record layer is the only thing standing behind it."""
    collected = _pe(_dump(image=_image()))

    with pytest.raises(ValueError, match="decoded_section_count"):
        dataclasses.replace(collected, sections=())


def test_a_record_refuses_an_observation_tally_its_array_does_not_match():
    collected = _pe(_dump(image=_image()))
    tally = dict(collected.observation_coverage)
    tally["total"] += 1
    tally["unavailable"] += 1

    with pytest.raises(ValueError, match="observation_coverage"):
        dataclasses.replace(collected, observation_coverage=tally)


def test_a_record_refuses_a_tally_whose_states_do_not_sum():
    collected = _pe(_dump(image=_image()))
    tally = dict(collected.observation_coverage)
    tally["consistent"] += 1

    with pytest.raises(ValueError, match="sum"):
        dataclasses.replace(collected, observation_coverage=tally)


def test_a_record_refuses_a_descriptor_out_of_index_order():
    collected = _pe(_dump(image=_image()))
    shuffled = (collected.directories[1], collected.directories[0]) + collected.directories[2:]

    with pytest.raises(ValueError, match="index order"):
        dataclasses.replace(collected, directories=shuffled)


def test_a_lossy_enumeration_still_reaches_the_correlation_for_attribution():
    """`absent`, `failed` and `unreadable` hand the correlation nothing;
    `lossy` hands it the enumeration so the observation can say the table
    dropped a descriptor rather than that there was no table. Its
    surviving views are still withheld from every judgement."""
    lossy = _pe(_split_segment_dump(lossy=True))
    extent = _observation(lossy, "size_vs_image_extent")

    assert lossy.acquisition.segment_table == "lossy"
    # The region table is absent in this fixture, so the extent check
    # stops there first -- what matters is that the segment enumeration
    # was passed at all, which the byte provenance and the reason token
    # below both rest on.
    assert lossy.acquisition.captured_bytes is None
    assert extent.state == "unavailable"


def test_an_absent_table_and_a_lossy_one_do_not_share_a_reason():
    """The whole point of handing a lossy enumeration over: an analyst
    reads which of the two happened."""
    regions = [Region(IMAGE_BASE, IMAGE_BASE, 0x5000, "MEM_COMMIT", "PAGE_EXECUTE_READ",
                       "MEM_IMAGE")]
    absent = _pe(_dump(image=_image(), modules=[]))

    mf = _dump(image=_image(), modules=[], regions=regions)
    mf.memory_info = FakeStream(regions + [_UnrepresentableRegion()], "infos")
    lossy = _pe(mf)

    assert lossy.acquisition.region_table == "lossy"
    assert absent.acquisition.region_table == "absent"
    assert _observation(absent, "size_vs_image_extent").reason == "regions_unavailable"
    assert _observation(lossy, "size_vs_image_extent").reason == "regions_lossy"


# ── The rendering vocabulary is closed on both sides ────────────────────


def test_every_correlation_reason_has_an_analyst_facing_sentence():
    """The correlation layer's reason set is closed, so a token with no
    rendering here is a missing sentence rather than a new vocabulary --
    and would otherwise reach the console verbatim."""
    assert set(_PE_REASON_TEXT) == set(_REASONS)


def test_every_observation_name_is_named_on_the_console():
    """The per-section and per-descriptor families name themselves from
    their own operands; every other observation needs a subject."""
    from_operands = {"section_range_overflow", "section_image_bound", "section_overlap",
                      "directory_image_bound"}
    assert set(_PE_OBSERVATION_SUBJECT) | from_operands == set(OBSERVATION_NAMES)


def test_the_evidence_token_table_is_closed_over_what_can_be_named():
    """Pinned as an equality, like the reason table: an unmapped token
    falls through to the console verbatim, and a table entry for a token
    nothing can emit is dead weight that hides the real gap."""
    from dumpex.core.pe_profile import MEMORY_SOURCE_KINDS
    from dumpex.output.records import PROCESS_PE_COMPONENTS

    emittable = (
        {f"profile.{component}" for component in PROCESS_PE_COMPONENTS}
        | {f"profile.source:{kind.value}" for kind in MEMORY_SOURCE_KINDS}
        | {"module_list", "memory_info", "memory_segments"}
    )
    assert set(_PE_SOURCE_TEXT) == emittable


def test_every_evidence_token_a_real_run_names_has_a_display_name():
    pe_record = _pe(_dump(image=_image(sections=(TEXT, DATA))))
    named = {source for observation in pe_record.observations
             for source in observation.sources}

    assert named
    assert named <= set(_PE_SOURCE_TEXT)


# ── The two withheld answers are counted and rendered apart ─────────────
# An `unavailable` check is evidence this dump does not carry; a
# `not_applicable` one is a comparison the image's own declarations leave
# no subject for. A console that reports both as unevaluated tells an
# analyst that an ordinary PE layout is an incomplete analysis.


def test_the_default_summary_counts_the_two_withheld_answers_apart():
    output = _console(_dump(image=_image()))
    line = next(l for l in output.splitlines() if "Consistency" in l)

    assert "unavailable" in line and "not applicable" in line
    assert "not evaluated" not in output


def test_the_summary_counts_are_the_records_own_tally():
    mf = _dump(image=_image())
    tally = _pe(mf).observation_coverage
    line = next(l for l in _console(mf).splitlines() if "Consistency" in l)

    assert line.split("Consistency")[1].strip() == (
        f"{tally['consistent']} consistent, {tally['conflict']} conflicting, "
        f"{tally['unavailable']} unavailable, {tally['not_applicable']} not applicable")


def test_a_withheld_check_says_which_of_the_two_it_is():
    output = _console(_dump(image=_image()), verbose=True)

    absent = next(l for l in output.splitlines() if "directory 0 (EXPORT)" in l)
    assert absent.strip().startswith("[--]")
    assert "not applicable -- the image declares this directory absent" in absent

    security = next(l for l in output.splitlines() if "directory 4 (SECURITY)" in l)
    assert security.strip().startswith("[--]")
    assert "not applicable -- this directory is addressed by file offset" in security

    architecture = next(l for l in output.splitlines()
                        if "architecture vs. a second source" in l)
    assert architecture.strip().startswith("[??]")
    assert "unavailable -- the dump carries no second source" in architecture


def test_a_routine_declaration_is_not_counted_as_an_evidence_gap():
    """A whole image declaring most of its directories absent must leave
    the gap count at the checks the dump really could not answer."""
    pe_record = _pe(_dump(image=_image()))
    tally = pe_record.observation_coverage

    absent = [o for o in pe_record.observations
              if o.reason in ("directory_declared_absent", "file_offset_semantics")]
    assert absent
    assert all(o.state == "not_applicable" for o in absent)
    assert tally["unavailable"] < len(absent)


# ── A heading is never printed over nothing ─────────────────────────────


def test_no_identity_heading_is_printed_over_nothing():
    """The identity checks are `--verbose` and carry their own heading, so
    a default render with no identity diagnostic has nothing to put under
    this one -- and an empty heading reads as output that was cut off."""
    for verbose in (False, True):
        output = _console(_dump(image=_image()), verbose=verbose)
        assert "\n  Identity\n" not in output


def test_an_identity_diagnostic_brings_its_heading_with_it():
    modules = [Module(IMAGE_BASE, 0x5000, r"C:\Samples\other.exe")]
    output = _console(_dump(image=_image(), modules=modules))

    assert "\n  Identity\n" in output
    assert "PROCESS_MODULE_IDENTITY_MISMATCH" in output or "disagrees with" in output


# ── What the block is, and is not, evidence of ──────────────────────────


def test_every_render_states_what_the_checks_do_not_establish():
    """Agreeing structural checks read as a clean process to anyone who
    does not already know the checks only covered this one image."""
    for verbose in (False, True):
        output = _console(_dump(image=_image()), verbose=verbose)
        assert "structural main-image checks only" in output
        assert "does not establish" in output and "is benign" in output


def test_the_scope_note_survives_a_correlation_that_did_not_run(monkeypatch):
    monkeypatch.setattr("dumpex.commands.process.correlate_main_image",
                        _raise_correlation)
    output = _console(_dump(image=_image()))

    assert "not produced" in output
    assert "structural main-image checks only" in output


def _raise_correlation(*args, **kwargs):
    raise ValueError("synthetic correlation failure")


# ── The two bases, and the relocation answer drawn from them ────────────


def test_the_two_bases_and_the_relocation_answer_are_separate_lines():
    output = _console(_dump(image=_image()))

    actual = next(l for l in output.splitlines() if "Actual Base" in l)
    preferred = next(l for l in output.splitlines() if "Preferred Base" in l)
    relocation = next(l for l in output.splitlines() if l.strip().startswith("Relocation"))
    assert actual.split()[-1] == "0x00007ff600010000"
    assert preferred.split()[-1] == "0x0000000140000000"
    assert relocation.strip().startswith("Relocation       required --")


def test_an_image_at_its_preferred_base_needed_no_relocation():
    output = _console(_dump(image=_image(image_base=IMAGE_BASE)))

    actual = next(l for l in output.splitlines() if "Actual Base" in l)
    preferred = next(l for l in output.splitlines() if "Preferred Base" in l)
    relocation = next(l for l in output.splitlines() if l.strip().startswith("Relocation"))
    assert actual.split()[-1] == preferred.split()[-1] == "0x00007ff600010000"
    assert "not required -- loaded at the preferred base" in relocation


def test_a_relocated_image_declaring_a_relocation_directory_is_consistent():
    """The relocated path with the declarations that allow it: the answer
    is `required`, and the check that weighs it agrees rather than
    conflicting."""
    image = _image(directories=[(0, 0)] * 5 + [(0x2000, 0x40)])
    mf = _dump(image=image)
    pe_record = _pe(mf)
    output = _console(mf, verbose=True)

    assert pe_record.relocation["basereloc_present"] is True
    assert _observation(pe_record, "relocation_expected").state == "consistent"
    assert "required -- loaded 0x7ff4c0010000 above the preferred base" in output
    evidence = next(l for l in output.splitlines() if "Directory " in l and "declares" in l)
    assert "the image declares a base-relocation directory" in evidence


def test_a_relocated_image_with_no_relocation_directory_conflicts():
    mf = _dump(image=_image())
    pe_record = _pe(mf)

    assert pe_record.relocation["basereloc_present"] is False
    assert _observation(pe_record, "relocation_expected").state == "conflict"
    assert "relocation evidence" in _console(mf)


def test_relocation_evidence_the_dump_does_not_carry_withholds_the_answer():
    """The bases are decoded and the relocation evidence is not, so the
    image is reported as relocated while the check that would judge it
    stays a gap -- never a conflict, and never a clean result."""
    mf = _dump(image=_image()[:0xD8])
    pe_record = _pe(mf)
    output = _console(mf, verbose=True)

    assert pe_record.relocation["basereloc_present"] is None
    observation = _observation(pe_record, "relocation_expected")
    assert observation.state == "unavailable"
    assert observation.reason == "relocation_undetermined"
    assert "required -- loaded 0x7ff4c0010000 above the preferred base" in output
    directory = next(l for l in output.splitlines()
                     if l.strip().startswith("Directory ") and "not established" in l)
    assert "(not established)" in directory


def test_an_undecoded_preferred_base_leaves_the_relocation_answer_open():
    output = _console(_dump(image=b"MZ"), verbose=True)

    preferred = next(l for l in output.splitlines() if "Preferred Base" in l)
    relocation = next(l for l in output.splitlines() if l.strip().startswith("Relocation"))
    assert "(not decoded)" in preferred
    assert "undetermined -- the preferred base was not decoded" in relocation


def test_the_relocation_block_makes_no_capture_claim_about_an_absent_directory():
    output = _console(_dump(image=_image()), verbose=True)
    block = output.split("Relocation Evidence")[1].split("Consistency Checks")[0]

    assert "the image declares no base-relocation directory" in block
    assert "Directory bytes" not in block


# ── The relocation check speaks for the declarations, not the bytes ─────
# `relocation_expected` weighs the two bases against `relocs_stripped`
# and `basereloc_present` -- declarations, all four of them. How much of
# the directory the dump actually holds is the Relocation Evidence
# block's `Directory bytes` line, and a consistency row that spoke for
# both would contradict that line on the same screen.

_BASERELOC_RVA = 0x2000
_BASERELOC_SIZE = 0x40
_DECLARES_BASERELOC = [(0, 0)] * 5 + [(_BASERELOC_RVA, _BASERELOC_SIZE)]


def _basereloc_dump(captured_bytes: int):
    """A relocated image declaring a base-relocation directory, with
    `captured_bytes` of that directory's own content in the dump."""
    memory = ({IMAGE_BASE + _BASERELOC_RVA: b"\x00" * captured_bytes}
              if captured_bytes else None)
    return _dump(image=_image(directories=_DECLARES_BASERELOC), memory=memory)


@pytest.mark.parametrize("captured, capture_state, held", [
    pytest.param(_BASERELOC_SIZE, "complete", "every byte", id="complete"),
    pytest.param(_BASERELOC_SIZE // 2, "partial", "only part", id="partial"),
    pytest.param(0, "none", "none", id="uncaptured"),
])
def test_the_relocation_row_claims_no_more_than_the_header_declares(
        captured, capture_state, held):
    """A declared directory is a declaration. Reading it as captured
    relocation data would tell an analyst the relocation evidence was
    verified in a dump that holds none of it."""
    mf = _basereloc_dump(captured)
    pe_record = _pe(mf)
    descriptor = pe_record.directories[process_module._PE_BASERELOC_INDEX]
    assert descriptor.capture_state == capture_state

    observation = _observation(pe_record, "relocation_expected")
    assert observation.state == "consistent"
    assert set(observation.operands) == {
        "relocation_delta", "relocs_stripped", "basereloc_present"}

    output = _console(mf, verbose=True)
    row = next(l for l in output.splitlines() if "relocation evidence:" in l)
    assert "the header's own declarations allow that" in row
    # The one line that speaks for the bytes says something else
    # entirely, and it is the only line that may.
    assert "the dump holds" not in row
    assert f"the dump holds {held}" in next(
        l for l in output.splitlines() if "Directory bytes" in l)


def test_the_relocation_row_reads_the_same_whatever_the_dump_holds():
    """The check is capture-independent by construction, so its row is
    one sentence across all three capture states while the block that
    does speak for the bytes says three different things."""
    rows, held = set(), set()
    for captured in (_BASERELOC_SIZE, _BASERELOC_SIZE // 2, 0):
        lines = _console(_basereloc_dump(captured), verbose=True).splitlines()
        rows.add(next(l for l in lines if "relocation evidence:" in l))
        held.add(next(l for l in lines if "Directory bytes" in l))

    assert len(rows) == 1
    assert len(held) == 3


# ── The header read is measured against what parsing needed ─────────────
# A staged acquisition asks for a fraction of the window it requested, so
# comparing the requested window with the bytes read would report every
# healthy image as a partial read.


def test_a_whole_header_read_is_not_reported_as_a_partial_one():
    mf = _dump(image=_image())
    acquisition = _pe(mf).acquisition
    output = _console(mf, verbose=True)

    assert acquisition.read_bytes >= acquisition.read_target_bytes
    assert acquisition.requested_bytes > acquisition.read_target_bytes
    lines = output.splitlines()
    assert f"0x{acquisition.requested_bytes:x} bytes at the image base" in \
        next(l for l in lines if "Requested window" in l)
    assert f"0x{acquisition.read_target_bytes:x} bytes" in \
        next(l for l in lines if "Required for parsing" in l)
    assert next(l for l in lines if "Required bytes present" in l).split()[-1] == "yes"
    assert "complete -- every header structure was read in full" in output


def test_a_capture_short_of_what_parsing_needs_says_so():
    """The partial fixture reads visibly differently, and agrees with the
    structural state beside it."""
    mf = _dump(image=_image()[:0xD8])
    acquisition = _pe(mf).acquisition
    output = _console(mf, verbose=True)

    assert acquisition.read_bytes < acquisition.read_target_bytes
    present = next(l for l in output.splitlines() if "Required bytes present" in l)
    assert present.strip().endswith(
        f"no -- 0x{acquisition.read_bytes:x} of 0x{acquisition.read_target_bytes:x} "
        f"bytes were read")
    assert "the dump holds no more than was read" in output
    assert "unavailable -- a header structure could not be read at all" in output


@pytest.mark.parametrize("short, cause", [
    (True, "the dump holds bytes this read did not return"),
    (False, "the dump holds no more than was read"),
    (None, "no segment table says which of the two applies"),
])
def test_a_shortfall_names_which_of_the_two_causes_applies(short, cause):
    """Bytes the dump never held and bytes it holds that the read did not
    return have different remedies, so the line names which one it is."""
    acquisition = dataclasses.replace(
        _pe(_dump(image=_image())).acquisition,
        read_bytes=0x10, read_target_bytes=0x1b0, target_io_short=short)

    lines = process_module._pe_required_bytes_lines(acquisition)
    assert lines[0] == "no -- 0x10 of 0x1b0 bytes were read"
    assert lines[1] == cause


# ── Investigator-facing vocabulary in the verbose blocks ────────────────


def test_the_verbose_blocks_state_the_parse_and_the_components_in_words():
    output = _console(_dump(image=_image()), verbose=True)

    assert "completed through the section table, as requested" in output
    assert ("read in full: DOS header, COFF header, optional header, directory array, "
            "directory descriptors, section table") in output


def test_a_stage_short_of_the_one_requested_names_both():
    output = _console(_dump(image=_image()[:0xD8]), verbose=True)

    assert "completed through the COFF header; the read asked for the section table" in output
    assert "could not be read: directory array, directory descriptors, section table" in output


def test_the_descriptor_table_states_its_columns_in_words():
    output = _console(_dump(image=_image()), verbose=True)
    row = next(l for l in output.splitlines() if "SECURITY" in l)

    assert "file offset" in row
    assert "declared absent" in row


def test_every_console_vocabulary_table_is_closed_over_its_own_records():
    """A state with no display entry would reach the console as its own
    token, which is exactly what these tables exist to prevent."""
    assert set(process_module._PE_TABLE_WALK_TEXT) == set(records_module.PROCESS_PE_TABLE_STATES)
    assert set(process_module._PE_STAGE_TEXT) == set(records_module.PROCESS_PE_STAGES)
    assert set(process_module._PE_COMPONENT_NAME) == set(records_module.PROCESS_PE_COMPONENTS)
    assert set(process_module._PE_COMPONENT_STATE_TEXT) == \
        set(records_module.PROCESS_PE_COMPONENT_STATES) | {None}
    assert set(process_module._PE_DESCRIPTOR_STATE_TEXT) == \
        set(records_module.PROCESS_PE_COMPONENT_STATES)
    assert set(process_module._PE_RELOCATION_CAPTURE_TEXT) == \
        set(records_module.PROCESS_PE_CAPTURE_STATES) | {None}
    assert set(process_module._PE_OBSERVATION_MARKER) == set(records_module.PE_OBSERVATION_STATES)


# ── A budget of dumpex's own is never reported as a truncated dump ─────
# The requested window IS the byte budget, so a stopped read has always
# captured every byte it asked for and `target_io_short` is false. Read
# as an answer about the dump, that says the dump holds no more -- which
# inverts the analyst's remedy: re-read the header, not re-collect.


def _max_section_image() -> bytes:
    """A whole image whose header structures end past the read budget:
    96 sections at 40 bytes each puts the section table's last entry
    beyond `PE_HEADER_READ_MAX`."""
    sections = tuple(
        {"name": b".s%03d" % index, "vaddr": 0x1000 + index * 0x1000, "vsize": 0x1000,
         "rawptr": 0x400, "rawsize": 0x1000, "chars": 0x60000020}
        for index in range(96))
    return _image(sections=sections, size_of_image=0x62000)


def test_a_budget_stop_does_not_blame_the_dump_for_the_shortfall():
    mf = _dump(image=_max_section_image())
    acquisition = _pe(mf).acquisition

    # The preconditions that make the misreading possible: the whole
    # window was captured, nothing failed to come back, and parsing
    # still needed more than the budget allowed.
    assert acquisition.bounded_stop["scope"] == "pe_header_bytes"
    assert acquisition.read_bytes == acquisition.captured_bytes
    assert acquisition.target_io_short is False
    assert acquisition.read_bytes < acquisition.read_target_bytes

    output = _console(mf, verbose=True)
    present = next(l for l in output.splitlines() if "Required bytes present" in l)
    assert present.strip().endswith(
        f"no -- 0x{acquisition.read_bytes:x} of 0x{acquisition.read_target_bytes:x} "
        f"bytes were read")
    assert "dumpex's own byte budget stopped the read, not the dump" in output
    assert "the dump holds no more than was read" not in output


def _stopped_acquisition(scope: str, consumed: int = 4096):
    return dataclasses.replace(
        _pe(_dump(image=_image())).acquisition,
        read_bytes=0x10, read_target_bytes=0x1b0, target_io_short=False,
        bounded_stop={"scope": scope, "budget_limit": 4096, "budget_consumed": consumed})


def test_the_budget_cause_wins_over_the_dump_causes():
    """`target_io_short` answers a question about the dump, and a bounded
    stop makes it `false` by construction -- so the budget is consulted
    first rather than the two dump causes being reached at all."""
    lines = process_module._pe_required_bytes_lines(
        _stopped_acquisition("pe_header_bytes"))

    assert lines[1] == "dumpex's own byte budget stopped the read, not the dump"
    assert lines[1] not in process_module._PE_SHORTFALL_CAUSE.values()


def test_only_the_byte_budget_denies_the_dump_a_part_in_the_shortfall():
    """The byte budget is the one that settles it: the window it asked
    for arrived whole. A read-count budget does not -- a header spread
    across enough captured segments costs one read per segment, so this
    dump's own layout can reach that limit -- and an `e_lfanew` stop is a
    fact about what the image declared."""
    byte_cause, = process_module._pe_required_bytes_lines(
        _stopped_acquisition("pe_header_bytes"))[1:]
    assert "not the dump" in byte_cause

    for scope, consumed in (("pe_header_read_operations", 4096), ("e_lfanew", 8192)):
        cause, = process_module._pe_required_bytes_lines(
            _stopped_acquisition(scope, consumed))[1:]
        assert "not the dump" not in cause, scope
        assert scope not in cause, scope


def test_the_budget_cause_table_is_closed_over_the_budgets_it_explains():
    from dumpex.core.pe_profile import _BOUNDED_STOP_RELATIONS

    assert set(process_module._PE_BUDGET_SHORTFALL_CAUSE) == set(_BOUNDED_STOP_RELATIONS)


def test_an_unnamed_budget_scope_claims_nothing_about_the_dump():
    cause, = process_module._pe_required_bytes_lines(
        _stopped_acquisition("some_future_budget"))[1:]

    assert cause == "one of dumpex's own budgets stopped the read"
    assert "some_future_budget" not in cause


def test_a_genuinely_short_capture_still_names_the_dump():
    """The budget check must not swallow the case it was added beside."""
    mf = _dump(image=_image()[:0xD8])
    assert _pe(mf).acquisition.bounded_stop is None

    assert "the dump holds no more than was read" in _console(mf, verbose=True)


def test_the_capture_line_is_scoped_to_the_window_it_measures():
    """`captured_bytes` cannot exceed the requested window, so the line
    must not read as a statement about how much of the image is in the
    dump -- the one block an analyst consults to decide whether
    re-collecting would help."""
    mf = _dump(image=_max_section_image())
    acquisition = _pe(mf).acquisition
    assert acquisition.captured_bytes == acquisition.requested_bytes

    output = _console(mf, verbose=True)
    assert f"{'Captured in that window':<24} 0x{acquisition.captured_bytes:x} bytes" in output
    assert "Available in dump" not in output


def test_the_bounded_stop_scope_table_is_closed_over_the_budgets_it_renders():
    """A scope the profile layer validates and this console cannot name
    would reach a reader as its own token."""
    from dumpex.core.pe_profile import _BOUNDED_STOP_RELATIONS

    assert set(process_module._PE_BOUNDED_SCOPE_TEXT) == set(_BOUNDED_STOP_RELATIONS)


def test_an_unnamed_budget_scope_still_names_no_token():
    """The set of budgets is deliberately not frozen by the profile
    contract, so the fallback has to be safe rather than absent."""
    lines = process_module._pe_bounded_stop_lines(
        {"scope": "some_future_budget", "budget_limit": 8, "budget_consumed": 8})

    assert "some_future_budget" not in lines[0]
    assert lines[0] == "one of dumpex's own budgets stopped the read"
    assert lines[1] == "limit 8, consumed 8"


# ── The record is total where the console reads it ─────────────────────


def test_a_collected_profile_must_state_its_relocation_descriptor_state():
    """Every one of the sixteen descriptors has a state, including one
    nothing was read of, so a collected profile that leaves this null
    describes a descriptor that does not exist."""
    pe_record = _pe(_dump(image=_image()))
    assert pe_record.relocation["basereloc_descriptor_state"] is not None

    with pytest.raises(ValueError, match="basereloc_descriptor_state"):
        dataclasses.replace(
            pe_record,
            relocation=dict(pe_record.relocation, basereloc_descriptor_state=None))


def test_the_addressing_mode_vocabulary_is_the_records_own():
    assert set(process_module._PE_VALUE_KIND_TEXT) == \
        set(records_module.PROCESS_PE_VALUE_KINDS)
