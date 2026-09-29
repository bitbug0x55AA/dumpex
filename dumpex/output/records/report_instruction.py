"""`--report` instruction context: the decoded window at a card's anchor,
its branch targets, and the static-analysis leads read from it. Part of
report enrichment Phase 2 (see dumpex.output.records.report_pe).
"""
from dataclasses import dataclass

from dumpex.output.records.common import (
    ENRICHMENT_TEXT_CAP,
    _require_bool,
    _require_bounded_text,
    _require_hex_address,
    _require_nonneg_int,
    _require_optional_diff_str,
    _require_optional_hex_address,
)
from dumpex.output.records.report_common import (
    ENRICHMENT_SCOPE_CARD,
    EnrichmentSection,
    _require_enrichment_section,
    _require_optional_bounded_text,
)
from dumpex.output.records.report_pe import ANCHOR_PE_REGISTRATIONS


INSTRUCTION_ANCHOR_SOURCES = (
    "exception_rip",         # a faulting instruction pointer from the ExceptionStream
    "thread_rip",            # the anchor thread's live RIP/EIP from its CONTEXT
    "thread_start_address",  # the anchor thread's StartAddress
    "card_anchor",           # the card's own resolved anchor address
)

INSTRUCTION_DECODER_STATES = (
    "decoded",              # the window decoded to its end or a cap
    "not_run",              # no bytes were captured at the anchor, so no decode was attempted
    "unavailable",          # no decoder backend answered: absent, or installed
                            # and unloadable -- the section limitation says which
    "unsupported_arch",     # a determined machine the decoder does not handle (e.g. ARM64)
    "arch_undetermined",    # no signal fixed the instruction-set architecture
    "decode_error",         # the decoder stopped at an invalid opcode mid-stream
    "undecoded_tail",       # a short trailing run did not decode: an invalid opcode or an
                            # instruction the capture cut short, indistinguishable here
)

INSTRUCTION_BRANCH_KINDS = ("direct", "indirect_slot", "indirect_register", "none")

# One instruction shape a decoded window mechanically contains, weakest
# first. A lead is evidence to look at, never a claim that the shape ran:
# a linear decode shows byte order, and only a debugger or a trace shows
# a path.
#
# The two names are a deliberate ladder. `memory_transform_loop` is what
# an in-place write inside a loop supports on its own, and an ordinary
# buffer transform is exactly that shape -- the name says no more.
# `self_decoding_stub` additionally requires the address written to be
# derived from the code's own address, so the write lands in the code
# region rather than in some buffer; only that one is described as
# position-independent, and only one of the two is ever emitted.
INSTRUCTION_LEAD_NAMES = (
    "memory_transform_loop",
    "self_decoding_stub",
)

# The supporting shapes a lead names. Each is a mechanically determinable
# property of the decoded window, so a reader can re-check every one of
# them against the instruction rows the same record carries.
INSTRUCTION_LEAD_SIGNALS = (
    "memory_write_back",            # an arithmetic/logic instruction both reads and writes one
                                    # explicit memory operand, leaving a non-identity result
    "register_mediated_write_back",  # a load, a non-identity transform of the loaded value in
                                    # a register, and a store of that surviving value back to
                                    # the same proven effective address
    "backward_branch_loop",         # a direct branch whose target is at or before its own
                                    # address, with the transform inside the span it closes
    "get_pc_register_flows_to_write",  # the register a call/pop pair left the code's own
                                    # address in reaches the transformed address's base
                                    # register
    "linear_fall_through_from_get_pc",  # no return and no unconditional branch separates
                                    # that pop from the loop, so one linear path covers both
    "register_transfer_after_loop",  # a call/jmp through a register is reachable over the
                                    # decoded graph from the edge that leaves the loop. That
                                    # edge always belongs to a CONDITIONAL branch -- the
                                    # closing branch's own fall-through, or a conditional
                                    # branch before it; an unconditional backward jmp has no
                                    # fall-through, so nothing is "after" one. The transfer's
                                    # destination is run-time state and is never reported
)

# Instruction addresses one lead carries as evidence.
MAX_INSTRUCTION_LEAD_EVIDENCE = 8

# Sentences one window carries about what its lead analysis could not
# establish. There is one such reason today; the cap bounds the field
# rather than the reason.
MAX_INSTRUCTION_LEAD_LIMITATIONS = 4

BRANCH_TARGET_KINDS = (
    "direct",             # a direct call/jump to a fixed address
    "iat_slot",           # an indirect call/jump through a slot the module's IAT names
    "indirect_memory",    # an indirect call/jump through a fixed memory slot not identified
                          # as an IAT slot -- confirmed outside the IAT only when the
                          # section's limitations do not say the IAT bounds were unreadable
    "indirect_register",  # an indirect call/jump through a register -- target is run-time state
)


@dataclass(frozen=True)
class ReportInstructionLead:
    """One qualified static-analysis lead read from a card's decoded
    instruction window.

    ``name`` is one of :data:`INSTRUCTION_LEAD_NAMES` and ``signals``
    every supporting shape from :data:`INSTRUCTION_LEAD_SIGNALS` the
    window carries, each anchored by an address in
    ``evidence_addresses`` so an analyst re-reads the same rows rather
    than taking the name on trust.

    ``evidence_addresses`` is capped at
    :data:`MAX_INSTRUCTION_LEAD_EVIDENCE`, and a proof can rest on more
    instructions than that -- the copies that carried a value, the
    address arithmetic between a `pop` and the access, the control-flow
    path to a transfer. ``evidence_truncated`` says the list is a cut of
    what the proof named, so a reader never takes a bounded list for a
    complete one.

    A lead is console and text-report presentation only. It is NOT part
    of the JSON contract: no ``to_dict`` of any record carries it, so a
    consumer pinned to the published schema sees exactly what it saw
    before. It also never enters ``findings``, ``finding_details``,
    ``verdict``, the indicator count, ``coverage.status``, or the exit
    code, and it asserts nothing about execution."""
    name:               str
    signals:            tuple = ()
    evidence_addresses: tuple = ()
    detail:             "str | None" = None
    evidence_truncated: bool = False

    def __post_init__(self):
        if self.name not in INSTRUCTION_LEAD_NAMES:
            raise ValueError(
                f"ReportInstructionLead.name must be one of {INSTRUCTION_LEAD_NAMES}, "
                f"got {self.name!r}")
        object.__setattr__(self, "signals", tuple(self.signals))
        object.__setattr__(self, "evidence_addresses", tuple(self.evidence_addresses))
        for signal in self.signals:
            if signal not in INSTRUCTION_LEAD_SIGNALS:
                raise ValueError(
                    f"ReportInstructionLead.signals must name only "
                    f"{INSTRUCTION_LEAD_SIGNALS}, got {signal!r}")
        if len(set(self.signals)) != len(self.signals):
            raise ValueError("ReportInstructionLead.signals must not repeat a signal")
        if not self.signals:
            raise ValueError(
                "ReportInstructionLead.signals must name the shapes the lead was read "
                "from: a lead with no supporting signal is an unsupported claim")
        for address in self.evidence_addresses:
            _require_hex_address(address, "ReportInstructionLead.evidence_addresses")
        if len(self.evidence_addresses) > MAX_INSTRUCTION_LEAD_EVIDENCE:
            raise ValueError(
                f"ReportInstructionLead.evidence_addresses must hold at most "
                f"{MAX_INSTRUCTION_LEAD_EVIDENCE} addresses")
        if not self.evidence_addresses:
            raise ValueError(
                "ReportInstructionLead.evidence_addresses must name at least one "
                "instruction the lead was read from")
        _require_bool(self.evidence_truncated,
                      "ReportInstructionLead.evidence_truncated")
        _require_optional_bounded_text(self.detail, "ReportInstructionLead.detail")


@dataclass(frozen=True)
class ReportDecodedInstruction:
    """One decoded instruction of this card's bounded window."""
    address:        str
    size:           int
    text:           str
    text_truncated: bool
    is_call:        bool
    is_jump:        bool
    is_return:      bool
    is_anchor:      bool
    branch_kind:    str

    def __post_init__(self):
        _require_hex_address(self.address, "ReportDecodedInstruction.address")
        _require_nonneg_int(self.size, "ReportDecodedInstruction.size")
        _require_bounded_text(self.text, "ReportDecodedInstruction.text", ENRICHMENT_TEXT_CAP)
        for field_name in ("text_truncated", "is_call", "is_jump", "is_return", "is_anchor"):
            _require_bool(getattr(self, field_name),
                          f"ReportDecodedInstruction.{field_name}")
        if self.branch_kind not in INSTRUCTION_BRANCH_KINDS:
            raise ValueError(
                f"ReportDecodedInstruction.branch_kind must be one of "
                f"{INSTRUCTION_BRANCH_KINDS}, got {self.branch_kind!r}")

    def to_dict(self) -> dict:
        return {
            "address":        self.address,
            "size":           self.size,
            "text":           self.text,
            "text_truncated": self.text_truncated,
            "is_call":        self.is_call,
            "is_jump":        self.is_jump,
            "is_return":      self.is_return,
            "is_anchor":      self.is_anchor,
            "branch_kind":    self.branch_kind,
        }


@dataclass(frozen=True)
class ReportBranchTarget:
    """One resolved branch target from this card's instruction window.

    ``target_address`` is the direct destination for a ``direct`` target
    and the IAT slot address for an ``iat_slot`` target;
    ``resolved_target_address`` is the pointer read from that slot. The
    module / section / region fields describe wherever the destination
    lands. An ``indirect_register`` target carries only its instruction
    address -- the destination is run-time state and is not reported.

    ``iat_classification_uncertain`` is set only on an ``indirect_memory``
    target the run could not confirm is outside the IAT (the owning
    module's IAT directory bounds were unreadable and no import table
    parsed); the same fact is in the section's limitations."""
    instruction_address:     str
    kind:                    str
    target_address:          "str | None" = None
    resolved_target_address: "str | None" = None
    module_owner:            "str | None" = None
    module_owner_truncated:  bool = False
    section_name:            "str | None" = None
    section_name_truncated:  bool = False
    region_type:             "str | None" = None
    registration:            "str | None" = None
    iat_symbol:              "str | None" = None
    iat_symbol_truncated:    bool = False
    iat_classification_uncertain: bool = False

    def __post_init__(self):
        _require_hex_address(self.instruction_address,
                             "ReportBranchTarget.instruction_address")
        if self.kind not in BRANCH_TARGET_KINDS:
            raise ValueError(
                f"ReportBranchTarget.kind must be one of {BRANCH_TARGET_KINDS}, "
                f"got {self.kind!r}")
        _require_optional_hex_address(self.target_address, "ReportBranchTarget.target_address")
        _require_optional_hex_address(self.resolved_target_address,
                                     "ReportBranchTarget.resolved_target_address")
        for name in ("module_owner", "section_name", "iat_symbol"):
            _require_optional_diff_str(getattr(self, name), f"ReportBranchTarget.{name}")
            _require_optional_bounded_text(getattr(self, name), f"ReportBranchTarget.{name}")
        for value_field, flag_field in (("module_owner", "module_owner_truncated"),
                                        ("section_name", "section_name_truncated"),
                                        ("iat_symbol", "iat_symbol_truncated")):
            _require_bool(getattr(self, flag_field), f"ReportBranchTarget.{flag_field}")
            if getattr(self, flag_field) and getattr(self, value_field) is None:
                raise ValueError(
                    f"ReportBranchTarget.{flag_field} requires a {value_field}")
        _require_optional_diff_str(self.region_type, "ReportBranchTarget.region_type")
        if self.registration is not None and self.registration not in ANCHOR_PE_REGISTRATIONS:
            raise ValueError(
                f"ReportBranchTarget.registration must be None or one of "
                f"{ANCHOR_PE_REGISTRATIONS}, got {self.registration!r}")
        if self.kind == "indirect_register" and (self.target_address is not None
                                                 or self.resolved_target_address is not None):
            raise ValueError(
                "ReportBranchTarget(kind='indirect_register') resolves no address -- the "
                "target is run-time state")
        if self.resolved_target_address is not None and self.kind == "direct":
            raise ValueError(
                "ReportBranchTarget.resolved_target_address is a memory-slot dereference, "
                "which a direct branch does not have")
        if self.iat_symbol is not None and self.kind != "iat_slot":
            raise ValueError("ReportBranchTarget.iat_symbol is an IAT-slot cross-link")
        _require_bool(self.iat_classification_uncertain,
                      "ReportBranchTarget.iat_classification_uncertain")
        if self.iat_classification_uncertain and self.kind != "indirect_memory":
            raise ValueError(
                "ReportBranchTarget.iat_classification_uncertain applies only to an "
                "'indirect_memory' target")

    def to_dict(self) -> dict:
        return {
            "instruction_address":     self.instruction_address,
            "kind":                    self.kind,
            "target_address":          self.target_address,
            "resolved_target_address": self.resolved_target_address,
            "module_owner":            self.module_owner,
            "module_owner_truncated":  self.module_owner_truncated,
            "section_name":            self.section_name,
            "section_name_truncated":  self.section_name_truncated,
            "region_type":             self.region_type,
            "registration":            self.registration,
            "iat_symbol":              self.iat_symbol,
            "iat_symbol_truncated":    self.iat_symbol_truncated,
            "iat_classification_uncertain": self.iat_classification_uncertain,
        }


@dataclass(frozen=True)
class ReportInstructionContext:
    """This card's bounded instruction window and its resolved branch
    targets.

    ``anchor_source`` names which approved anchor the window was read at
    -- an exception RIP, a live thread RIP, a thread StartAddress, or the
    card's own anchor -- in that priority. ``decoder_state`` is one of
    :data:`INSTRUCTION_DECODER_STATES`; every value but ``decoded`` makes
    the section `partial`, never a claim about the code. Nothing here
    names a function, an argument, or a call stack.

    ``bytes_decoded``, ``decode_stop_address``, ``leads`` and
    ``lead_limitations`` are presentation state for the console and text
    report and are NOT part of the JSON contract: ``to_dict`` below omits
    all four, so the published schema and every consumer pinned to it are
    untouched by them. ``lead_limitations`` is deliberately NOT folded
    into ``section.limitations``: that tuple IS published, and a sentence
    about what the lead analysis could not establish is lead analysis --
    it belongs with ``leads``, on the same side of the contract.

    ``bytes_read`` is the window this decode was offered and
    ``bytes_decoded`` how far into it linear decoding reached;
    ``decode_stop_address`` is the virtual address it stopped at, present
    whenever a decode actually ran. Together they locate where decoding
    ended; WHY it ended there is the section's own limitation sentences,
    which distinguish an undecodable byte mid-window, an incomplete
    instruction at the end of the capture, and the byte cap. The location
    alone asserts none of the three.

    ``leads`` carries the qualified static-analysis leads
    (:class:`ReportInstructionLead`) this window's own instruction shapes
    support. Like every other enrichment fact they reach no finding,
    verdict, indicator count, or exit code.

    ``lead_limitations`` carries what that analysis could not establish
    for a reason an analyst cannot read off the instruction rows -- a
    shape withheld because no decoded branch reaches it from this anchor.
    Each is one bounded sentence naming no address: a withheld proof is
    not a lead, and pointing at the bytes that nearly carried one would
    assert what the analysis declined to assert."""
    section:                   EnrichmentSection
    anchor_source:             "str | None"
    anchor_address:            "str | None"
    architecture:              "str | None"
    decoder_state:             str
    window_base:               "str | None"
    bytes_read:                int
    bytes_decoded:             int = 0
    decode_stop_address:       "str | None" = None
    branch_targets_total:      int = 0
    branch_targets_truncated:  bool = False
    instructions:              tuple = ()
    branch_targets:            tuple = ()
    leads:                     tuple = ()
    lead_limitations:          tuple = ()

    def __post_init__(self):
        _require_enrichment_section(self.section, "ReportInstructionContext.section",
                                    scope=ENRICHMENT_SCOPE_CARD, name="instruction_context")
        if self.anchor_source is not None and self.anchor_source not in INSTRUCTION_ANCHOR_SOURCES:
            raise ValueError(
                f"ReportInstructionContext.anchor_source must be None or one of "
                f"{INSTRUCTION_ANCHOR_SOURCES}, got {self.anchor_source!r}")
        _require_optional_hex_address(self.anchor_address,
                                     "ReportInstructionContext.anchor_address")
        if self.architecture is not None and self.architecture not in ("x86", "x64"):
            raise ValueError(
                "ReportInstructionContext.architecture must be None, 'x86', or 'x64', "
                f"got {self.architecture!r}")
        if self.decoder_state not in INSTRUCTION_DECODER_STATES:
            raise ValueError(
                f"ReportInstructionContext.decoder_state must be one of "
                f"{INSTRUCTION_DECODER_STATES}, got {self.decoder_state!r}")
        _require_optional_hex_address(self.window_base,
                                     "ReportInstructionContext.window_base")
        _require_nonneg_int(self.bytes_read, "ReportInstructionContext.bytes_read")
        _require_nonneg_int(self.bytes_decoded, "ReportInstructionContext.bytes_decoded")
        if self.bytes_decoded > self.bytes_read:
            raise ValueError(
                "ReportInstructionContext.bytes_decoded cannot exceed the window that "
                "was read")
        _require_optional_hex_address(self.decode_stop_address,
                                      "ReportInstructionContext.decode_stop_address")
        if self.decode_stop_address is not None:
            if self.window_base is None:
                raise ValueError(
                    "ReportInstructionContext.decode_stop_address is an offset into the "
                    "window, so the window base must be known")
            if int(self.decode_stop_address, 16) != int(self.window_base, 16) + self.bytes_decoded:
                raise ValueError(
                    "ReportInstructionContext.decode_stop_address must be window_base + "
                    "bytes_decoded")
        _require_nonneg_int(self.branch_targets_total,
                            "ReportInstructionContext.branch_targets_total")
        _require_bool(self.branch_targets_truncated,
                      "ReportInstructionContext.branch_targets_truncated")
        object.__setattr__(self, "instructions", tuple(self.instructions))
        object.__setattr__(self, "branch_targets", tuple(self.branch_targets))
        object.__setattr__(self, "leads", tuple(self.leads))
        if any(not isinstance(lead, ReportInstructionLead) for lead in self.leads):
            raise TypeError(
                "ReportInstructionContext.leads must be ReportInstructionLead instances")
        if len({lead.name for lead in self.leads}) != len(self.leads):
            raise ValueError("ReportInstructionContext.leads must not repeat a lead name")
        if any(not isinstance(i, ReportDecodedInstruction) for i in self.instructions):
            raise TypeError(
                "ReportInstructionContext.instructions must be ReportDecodedInstruction instances")
        if any(not isinstance(t, ReportBranchTarget) for t in self.branch_targets):
            raise TypeError(
                "ReportInstructionContext.branch_targets must be ReportBranchTarget instances")
        if len(self.instructions) != self.section.included:
            raise ValueError(
                "ReportInstructionContext.instructions length must equal section.included")
        if len(self.branch_targets) > self.branch_targets_total:
            raise ValueError(
                "ReportInstructionContext.branch_targets_total must count every eligible "
                "target, including those the cap dropped")
        if self.branch_targets_truncated != (len(self.branch_targets) < self.branch_targets_total):
            raise ValueError(
                "ReportInstructionContext.branch_targets_truncated must equal "
                "included < total for the branch-target sub-collection")
        instruction_addresses = {i.address for i in self.instructions}
        for target in self.branch_targets:
            if self.instructions and target.instruction_address not in instruction_addresses:
                raise ValueError(
                    "ReportInstructionContext.branch_targets must reference a decoded "
                    "instruction in this window")
        for lead in self.leads:
            for address in lead.evidence_addresses:
                if address not in instruction_addresses:
                    raise ValueError(
                        "ReportInstructionLead.evidence_addresses must name decoded "
                        "instructions of this window")
        object.__setattr__(self, "lead_limitations", tuple(self.lead_limitations))
        for note in self.lead_limitations:
            _require_bounded_text(note, "ReportInstructionContext.lead_limitations",
                                  ENRICHMENT_TEXT_CAP)
        if len(self.lead_limitations) > MAX_INSTRUCTION_LEAD_LIMITATIONS:
            raise ValueError(
                f"ReportInstructionContext.lead_limitations must hold at most "
                f"{MAX_INSTRUCTION_LEAD_LIMITATIONS} notes")

    def to_dict(self) -> dict:
        """The published projection. `bytes_decoded`, `decode_stop_address`,
        `leads` and `lead_limitations` are console presentation state and
        are deliberately absent: the JSON contract is closed, and a field
        added here would be rejected by every consumer validating against
        it. `lead_limitations` is a separate tuple rather than an entry in
        `section.limitations` for exactly that reason -- the section's own
        limitations ARE published, and lead analysis is not."""
        return {
            "section":                  self.section.to_dict(),
            "anchor_source":            self.anchor_source,
            "anchor_address":           self.anchor_address,
            "architecture":             self.architecture,
            "decoder_state":            self.decoder_state,
            "window_base":              self.window_base,
            "bytes_read":               self.bytes_read,
            "branch_targets_total":     self.branch_targets_total,
            "branch_targets_truncated": self.branch_targets_truncated,
            "instructions":             [i.to_dict() for i in self.instructions],
            "branch_targets":           [t.to_dict() for t in self.branch_targets],
        }
