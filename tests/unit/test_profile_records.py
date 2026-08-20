"""
Construction-time validation tests for dumpex.output.records' --profile
record family (issue #95): ProfileStreamEntry, ProfileMemoryCapture,
CapabilityLimitation, ProfileCapabilityEntry, and ProfileRecord.

tests/unit/test_profile_cmd.py exercises these types the way the real
collector builds them -- from a FakeMF, through collect_profile(). This
module drives the OTHER half of the same contract: every rule each
__post_init__ enforces on a record handed to it directly. That split
matters because the whole point of validating in __post_init__ (rather
than in dumpex.commands.profile) is that NO caller -- collector, future
hunter, or test -- can construct a record that contradicts
docs/recon_profile_contract.md. A rule only the collector happens to
respect is caller discipline, not enforcement, and the difference stays
invisible until something else builds one of these records.
"""
import pytest

from dumpex.output import records as records_module
from dumpex.output.records import (
    CAPABILITY_REGISTRY, CAPABILITY_IDS,
    CapabilityLimitation, CapabilityLimitationCode, CapabilityStatus,
    ProfileCapabilityEntry, ProfileMemoryCapture, ProfileRecord, ProfileStreamEntry,
    StreamParserState,
)


# ── fixtures: the minimal VALID record of each type ─────────────────────
# Every test below starts from one of these and breaks exactly one rule,
# so a failure names the rule that broke rather than an unrelated field
# that happened to be wrong in the same literal.

def _stream(**overrides) -> ProfileStreamEntry:
    kwargs = dict(directory_index=0, stream_type_id=3, stream_type_name="ThreadListStream",
                   parser_state=StreamParserState.PARSED.value, record_count=2, detail=None)
    kwargs.update(overrides)
    return ProfileStreamEntry(**kwargs)


def _memory_capture(**overrides) -> ProfileMemoryCapture:
    kwargs = dict(full_memory_flag_set=True, memory64_list_present=True,
                   memory_list_present=False, captured_segment_count=2,
                   captured_bytes_total=0x3000)
    kwargs.update(overrides)
    return ProfileMemoryCapture(**kwargs)


def _capability(capability_id="memory_region_analysis", **overrides) -> ProfileCapabilityEntry:
    definition = next(d for d in CAPABILITY_REGISTRY if d.capability_id == capability_id)
    kwargs = dict(capability_id=capability_id, status=CapabilityStatus.AVAILABLE.value,
                   required_source_groups=definition.required_source_groups,
                   required_sources=definition.required_sources,
                   optional_sources=definition.optional_sources, limitations=())
    kwargs.update(overrides)
    return ProfileCapabilityEntry(**kwargs)


def _every_capability() -> tuple:
    return tuple(_capability(d.capability_id) for d in CAPABILITY_REGISTRY)


def _profile(**overrides) -> ProfileRecord:
    kwargs = dict(architecture="AMD64", raw_flags=0, recognized_flags=(),
                   unrecognized_flag_bits=0, memory_capture=_memory_capture(),
                   streams=(_stream(),), capabilities=_every_capability())
    kwargs.update(overrides)
    return ProfileRecord(**kwargs)


def test_the_baseline_fixtures_are_themselves_valid():
    # Guards every negative test below: if a fixture silently stopped
    # being constructible, each `pytest.raises` could pass for the wrong
    # reason (the fixture's own defect, not the rule under test).
    assert _profile().to_dict()["capabilities"][0]["status"] == "available"


# ── ProfileStreamEntry ──────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["", 3, b"ThreadListStream"])
def test_stream_entry_rejects_an_unusable_stream_type_name(name):
    # None (an unrecognized numeric type) is the ONLY non-string this
    # field accepts -- "" would print as a nameless row indistinguishable
    # from a type this build has never heard of, which §2.4 keeps apart.
    with pytest.raises(ValueError, match="stream_type_name"):
        _stream(stream_type_name=name)


def test_stream_entry_rejects_a_parser_state_outside_the_vocabulary():
    with pytest.raises(ValueError, match="parser_state must be one of"):
        _stream(parser_state="probably_fine")


def test_stream_entry_rejects_a_non_string_detail():
    with pytest.raises(ValueError, match="detail must be None or a string"):
        _stream(detail=123)


def test_present_empty_must_carry_an_explicit_zero_count():
    # "dumpex parsed it and verified zero items" is a positive claim; a
    # null count would say "no count was taken", a different fact.
    with pytest.raises(ValueError, match="record_count must be exactly 0"):
        _stream(parser_state=StreamParserState.PRESENT_EMPTY.value, record_count=3)
    with pytest.raises(ValueError, match="record_count must be exactly 0"):
        _stream(parser_state=StreamParserState.PRESENT_EMPTY.value, record_count=None)


@pytest.mark.parametrize("state,detail", [
    (StreamParserState.UNPARSED.value, None),
    (StreamParserState.FAILED.value, "boom"),
    (StreamParserState.INDETERMINATE.value, "duplicate of directory index 2"),
])
def test_states_that_counted_nothing_may_not_carry_a_count(state, detail):
    with pytest.raises(ValueError, match="record_count must be None"):
        _stream(parser_state=state, record_count=1, detail=detail)


def test_failed_requires_the_parser_error_text():
    with pytest.raises(ValueError, match="detail is required when parser_state is failed"):
        _stream(parser_state=StreamParserState.FAILED.value, record_count=None, detail=None)


def test_indeterminate_requires_its_explanation():
    with pytest.raises(ValueError, match="detail is required when parser_state is indeterminate"):
        _stream(parser_state=StreamParserState.INDETERMINATE.value, record_count=None, detail=None)


@pytest.mark.parametrize("state,count", [
    (StreamParserState.PRESENT_EMPTY.value, 0),
    (StreamParserState.UNPARSED.value, None),
])
def test_states_with_nothing_to_explain_may_not_carry_a_detail(state, count):
    # PARSED is the one state allowed an optional note (a stream that
    # declares more items than dumpex actually read); these two have no
    # outcome a detail could describe, so a detail here is invented text.
    with pytest.raises(ValueError, match="detail must be None"):
        _stream(parser_state=state, record_count=count, detail="unexpected note")


def test_parsed_may_carry_a_shortfall_note_and_a_singular_stream_has_no_count():
    assert _stream(detail="declares 9 descriptors, read 4").detail
    assert _stream(record_count=None).to_dict()["record_count"] is None


# ── ProfileMemoryCapture ────────────────────────────────────────────────

@pytest.mark.parametrize("value", ["true", 1, "MiniDumpWithFullMemory"])
def test_memory_capture_rejects_a_non_bool_full_memory_flag(value):
    # §5.3.2: this field is read from the header's own MINIDUMP_TYPE bit
    # and nothing else -- a truthy stand-in would quietly become a claim
    # about a flag that was never read.
    with pytest.raises(ValueError, match="full_memory_flag_set"):
        _memory_capture(full_memory_flag_set=value)


@pytest.mark.parametrize("count,total", [(2, None), (None, 0x3000)])
def test_captured_segment_count_and_bytes_total_travel_together(count, total):
    # Either neither stream parsed (both None) or a real segment table
    # was measured (both set) -- one without the other would report a
    # captured range that was never actually summed.
    with pytest.raises(ValueError, match="both be None or both set together"):
        _memory_capture(captured_segment_count=count, captured_bytes_total=total)


# ── CapabilityLimitation ────────────────────────────────────────────────

def test_limitation_rejects_a_code_outside_the_closed_vocabulary():
    with pytest.raises(ValueError, match="code must be one of"):
        CapabilityLimitation(code="SOURCE_LOOKED_WRONG", source="handles")


@pytest.mark.parametrize("source", ["", None, 7])
def test_limitation_requires_a_named_source(source):
    # `detail` is derived from (code, source); an unnamed source would
    # render a sentence naming nothing at all.
    with pytest.raises(ValueError, match="source must be a non-empty string"):
        CapabilityLimitation(code=CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value,
                              source=source)


# ── ProfileCapabilityEntry: shape rules ─────────────────────────────────

def test_capability_entry_rejects_an_id_outside_the_frozen_registry():
    with pytest.raises(ValueError, match="capability_id must be one of"):
        ProfileCapabilityEntry(
            capability_id="freeform_analysis", status=CapabilityStatus.AVAILABLE.value,
            required_source_groups=(("memory_info",),), required_sources=("memory_info",),
            optional_sources=(), limitations=())


def test_capability_entry_rejects_a_status_outside_the_vocabulary():
    with pytest.raises(ValueError, match="status must be one of"):
        _capability(status="probably_available")


@pytest.mark.parametrize("groups", [(), [("memory_info",)]])
def test_capability_entry_requires_at_least_one_required_group(groups):
    with pytest.raises(ValueError, match="required_source_groups must be a non-empty tuple"):
        _capability(required_source_groups=groups)


@pytest.mark.parametrize("groups", [
    ("memory_info",),           # a bare string where a group tuple belongs
    ((),),                       # an empty group requires nothing at all
    ((None,),),                  # a non-string member
    (("",),),                    # an unnamed member
])
def test_every_required_group_must_be_a_non_empty_tuple_of_names(groups):
    with pytest.raises(ValueError, match="must each be a non-empty tuple of non-empty strings"):
        _capability(required_source_groups=groups)


def test_a_required_group_may_not_repeat_a_member():
    with pytest.raises(ValueError, match="duplicate members"):
        _capability(required_source_groups=(("memory_info", "memory_info"),))


def test_a_source_may_not_appear_in_two_required_groups():
    # An OR-group's members are alternatives; the same source standing in
    # two groups would make one group's satisfaction silently satisfy the
    # other, which §4.3's per-group rule does not mean.
    with pytest.raises(ValueError, match="must not repeat across groups"):
        _capability(required_source_groups=(("memory_info",), ("memory_info",)))


@pytest.mark.parametrize("optional", [["modules"], ("",), (None,)])
def test_optional_sources_must_be_a_tuple_of_names(optional):
    with pytest.raises(ValueError, match="optional_sources must be a tuple of non-empty"):
        _capability("thread_analysis", optional_sources=optional)


def test_required_and_optional_sources_may_not_overlap():
    with pytest.raises(ValueError, match="must not overlap"):
        _capability(optional_sources=("memory_info",))


@pytest.mark.parametrize("flattened", [(), ("modules",), ("memory_info", "modules")])
def test_required_sources_must_equal_the_flattened_groups(flattened):
    # The two are kept side by side for a consumer that only wants "which
    # sources matter at all" -- validated here so they can never drift.
    with pytest.raises(ValueError, match="required_sources must equal the flattened"):
        _capability(required_sources=flattened)


@pytest.mark.parametrize("limitations", [
    [CapabilityLimitation(code=CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value,
                           source="modules")],
    ("modules absent",),
])
def test_limitations_must_be_a_tuple_of_limitation_records(limitations):
    with pytest.raises(TypeError, match="limitations must be a tuple of CapabilityLimitation"):
        _capability("thread_analysis", status=CapabilityStatus.LIMITED.value,
                     limitations=limitations)


def test_a_required_limitation_must_name_a_required_group_member():
    # REQUIRED_SOURCE_* is a claim about this capability's own required
    # evidence; naming a source the capability never required would
    # publish a gap that does not exist for it.
    with pytest.raises(ValueError, match="must be a member of one of this capability's own"):
        _capability(status=CapabilityStatus.UNAVAILABLE.value,
                     limitations=(CapabilityLimitation(
                         code=CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value,
                         source="modules"),))


def test_a_limitation_code_in_no_family_is_rejected_rather_than_silently_ignored(monkeypatch):
    # Every code in the enum belongs to exactly one family tuple today,
    # so this state is only reachable by drift -- a future code added to
    # CapabilityLimitationCode but not to any of the four family tuples.
    # Simulating that drift is the only way to prove the guard is a real
    # check rather than dead code: without it, such a code would slip
    # past every family-specific rule below (source membership, status
    # cross-checks) and land in the record unexamined.
    monkeypatch.setattr(
        records_module, "_OPTIONAL_LIMITATION_CODES",
        tuple(c for c in records_module._OPTIONAL_LIMITATION_CODES
              if c != CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value))
    with pytest.raises(ValueError, match="outside the closed"):
        _capability("thread_analysis", status=CapabilityStatus.LIMITED.value,
                     limitations=(CapabilityLimitation(
                         code=CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value,
                         source="modules"),))


# ── ProfileCapabilityEntry: status <-> limitations cross-checks ─────────

def test_unavailable_requires_a_required_source_limitation():
    with pytest.raises(ValueError, match="carries no REQUIRED_SOURCE_"):
        _capability("thread_analysis", status=CapabilityStatus.UNAVAILABLE.value,
                     limitations=(CapabilityLimitation(
                         code=CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value,
                         source="modules"),))


def test_limited_may_not_carry_a_required_source_limitation():
    # §4.3: missing REQUIRED evidence is 'unavailable'. Publishing it as
    # 'limited' would advertise an analysis that cannot run at all.
    with pytest.raises(ValueError, match="never 'limited'"):
        _capability("handle_analysis", status=CapabilityStatus.LIMITED.value,
                     limitations=(CapabilityLimitation(
                         code=CapabilityLimitationCode.REQUIRED_SOURCE_ABSENT.value,
                         source="handles"),))


def test_limited_must_say_what_limits_it():
    with pytest.raises(ValueError, match="carries no REQUIRED_GROUP_MEMBER_"):
        _capability(status=CapabilityStatus.LIMITED.value, limitations=())


def test_available_may_not_carry_any_limitation():
    with pytest.raises(ValueError, match="'available' but carries limitations"):
        _capability("thread_analysis", status=CapabilityStatus.AVAILABLE.value,
                     limitations=(CapabilityLimitation(
                         code=CapabilityLimitationCode.OPTIONAL_SOURCE_ABSENT.value,
                         source="modules"),))


# ── ProfileRecord ───────────────────────────────────────────────────────

@pytest.mark.parametrize("architecture", ["", 9])
def test_profile_record_rejects_an_unusable_architecture(architecture):
    # None (SystemInfoStream absent) is the only "no architecture" value;
    # "" would render as a blank field that looks like a read one.
    with pytest.raises(ValueError, match="architecture must be None or a non-empty string"):
        _profile(architecture=architecture)


@pytest.mark.parametrize("raw_flags,unrecognized", [(None, 0), (0, None)])
def test_raw_flags_and_unrecognized_flag_bits_travel_together(raw_flags, unrecognized):
    # unrecognized_flag_bits is derived from raw_flags: one without the
    # other is either a count of unknown bits in a value that was never
    # read, or a read value whose unknown bits were silently dropped.
    with pytest.raises(ValueError, match="both be None or both set together"):
        _profile(raw_flags=raw_flags, unrecognized_flag_bits=unrecognized)


@pytest.mark.parametrize("flags", [["MiniDumpNormal"], ("",), (7,)])
def test_recognized_flags_must_be_a_tuple_of_names(flags):
    with pytest.raises(ValueError, match="recognized_flags must be a tuple of non-empty strings"):
        _profile(recognized_flags=flags)


def test_recognized_flags_must_be_empty_when_the_flags_were_never_read():
    with pytest.raises(ValueError, match="must be empty when raw_flags is None"):
        _profile(raw_flags=None, unrecognized_flag_bits=None,
                  recognized_flags=("MiniDumpWithFullMemory",))


@pytest.mark.parametrize("memory_capture", [None, {"memory64_list_present": True}])
def test_profile_record_requires_a_real_memory_capture(memory_capture):
    with pytest.raises(TypeError, match="memory_capture must be a ProfileMemoryCapture"):
        _profile(memory_capture=memory_capture)


@pytest.mark.parametrize("streams", [[_stream()], (_memory_capture(),)])
def test_streams_must_be_a_tuple_of_stream_entries(streams):
    with pytest.raises(TypeError, match="streams must be a tuple of ProfileStreamEntry"):
        _profile(streams=streams)


def test_streams_must_be_in_directory_order():
    # §2.4: the inventory IS the dump's own directory table, in the order
    # open_dump() read it -- a row whose directory_index disagrees with
    # its position means the table was reordered or a row was dropped.
    with pytest.raises(ValueError, match="must be in directory order"):
        _profile(streams=(_stream(directory_index=1),))
    with pytest.raises(ValueError, match="must be in directory order"):
        _profile(streams=(_stream(directory_index=0), _stream(directory_index=2)))


@pytest.mark.parametrize("capabilities", [list(_every_capability()), (_stream(),)])
def test_capabilities_must_be_a_tuple_of_capability_entries(capabilities):
    with pytest.raises(TypeError, match="capabilities must be a tuple of ProfileCapabilityEntry"):
        _profile(capabilities=capabilities)


@pytest.mark.parametrize("mutate", [
    lambda entries: entries[:-1],                        # a missing capability
    lambda entries: entries[::-1],                        # the registry's order, reversed
    lambda entries: entries + (entries[0],),               # a repeated id
])
def test_capabilities_must_be_exactly_the_frozen_registry_in_order(mutate):
    # The matrix is closed: every dump reports every capability, so a
    # consumer never has to distinguish "not applicable to this dump"
    # from "this build forgot to compute it".
    with pytest.raises(ValueError, match="exactly the frozen registry ids"):
        _profile(capabilities=mutate(_every_capability()))


def test_a_valid_profile_record_round_trips_every_capability_id():
    assert tuple(c["capability_id"] for c in _profile().to_dict()["capabilities"]) == CAPABILITY_IDS
