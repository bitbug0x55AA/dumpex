"""Canonical v2 record types and their explicit wire projections.

Every record, vocabulary and validator is defined once, in the module that
owns its evidence domain. This package re-exports, by explicit name, every
name the ``dumpex.output.records`` path has supported, so an import through
the package and an import through the owning module return the very same
object. It defines nothing of its own: new record code belongs in its owner
module.

The wire type rule every record follows is stated once, in
:mod:`dumpex.output.records.common`.

Owner modules import only the lower-level owners they need, never this
package; docs/developer/records_layout.md lists what each one owns and the
dependency rules between them.
"""
from dumpex.output.records.common import (  # noqa: F401
    hex_address,
    ENRICHMENT_TEXT_CAP,
    _require_nonneg_int,
    _require_hex_address,
)
from dumpex.output.records.diagnostics import (  # noqa: F401
    SEVERITY_WARNING,
    SEVERITY_ERROR,
    Diagnostic,
    Artifact,
)
from dumpex.output.records.base import (  # noqa: F401
    MemoryRegionRecord,
    ModuleRecord,
    MODULE_CONTEXT_RESOLVED,
    MODULE_CONTEXT_UNREGISTERED,
    MODULE_CONTEXT_UNAVAILABLE,
    START_ADDRESS_RECORDED,
    START_ADDRESS_INVALID,
    START_ADDRESS_UNVERIFIED,
    START_ADDRESS_ABSENT,
    DUMP_FLAGS_RESOLVED,
    DUMP_FLAGS_UNRESOLVED,
    DUMP_FLAGS_ABSENT,
    ThreadRecord,
    SysInfoRecord,
    _MODULE_CONTEXTS,
)
from dumpex.output.records.extraction import (  # noqa: F401
    ExtractRecord,
    StringRecord,
)
from dumpex.output.records.comparison import (  # noqa: F401
    MODULE_DIFF_ADDED,
    MODULE_DIFF_REMOVED,
    MODULE_DIFF_REBASED,
    ModuleDiffRecord,
    THREAD_DIFF_ADDED,
    THREAD_DIFF_REMOVED,
    ThreadDiffRecord,
    MEMORY_DIFF_ADDED,
    MEMORY_DIFF_REMOVED,
    MEMORY_DIFF_PROTECTION_CHANGED,
    MemoryDiffRecord,
    COMPARISON_SCOPE_INVENTORY,
    COMPARISON_FACTS,
    COMPARISON_FACT_STATES,
    FACT_STATE_RECORDED,
    FACT_STATE_ABSENT,
    FACT_STATE_FAILED,
    FACT_STATE_UNSET,
    FACT_STATE_UNRECONSTRUCTED,
    FACT_STATE_BASE_UNKNOWN,
    FACT_STATE_UNMATCHED,
    FACT_STATE_UNCAPTURED,
    FACT_STATE_TRUNCATED,
    FACT_STATE_INVALID,
    COMPARISON_SIDE_BASELINE,
    COMPARISON_SIDE_TARGET,
    FACT_RELATION_SAME,
    FACT_RELATION_DIFFERENT,
    FACT_RELATION_UNKNOWN,
    PROCESS_INSTANCE_SAME,
    PROCESS_INSTANCE_DIFFERENT,
    PROCESS_INSTANCE_UNKNOWN,
    CAPTURE_ORDER_BASELINE_FIRST,
    CAPTURE_ORDER_TARGET_FIRST,
    CAPTURE_ORDER_SAME_SECOND,
    CAPTURE_ORDER_UNKNOWN,
    ComparisonFactRecord,
    ComparisonCaptureDiagnostic,
    ComparisonPremiseRecord,
)
from dumpex.output.records.handles import (  # noqa: F401
    HANDLE_NAME_STATUSES,
    HANDLE_NAME_STATUS_LABELS,
    HANDLE_RESERVED_NAME_LABELS,
    HANDLE_CAPTURED_NAME_SUFFIX,
    handle_name_display,
    HandleRecord,
)
from dumpex.output.records.report_common import (  # noqa: F401
    ENRICHMENT_MISSING,
    ENRICHMENT_PARTIAL,
    ENRICHMENT_COMPLETE,
    ENRICHMENT_SCOPE_PROCESS,
    ENRICHMENT_SCOPE_CARD,
    EnrichmentSection,
)
from dumpex.output.records.report_thread import (  # noqa: F401
    REGION_MEMBERSHIP_START,
    REGION_MEMBERSHIP_CURRENT,
    REGION_MEMBERSHIP_START_AND_CURRENT,
    ReportThreadInfo,
    ReportRegionInfo,
    ReportIocString,
)
from dumpex.output.records.report_process import (  # noqa: F401
    ReportEnvironmentValue,
    ReportEnvironmentSummary,
    ReportHandleTypeCount,
    ReportHandleSummary,
    TOKEN_CAPABILITY_STATUSES,
    ReportTokenCapability,
    IDENTITY_CONFLICT_SEVERITIES,
    ReportIdentityConflict,
    ReportProcessEnrichment,
)
from dumpex.output.records.report_context import (  # noqa: F401
    ACCESS_VIOLATION_TYPES,
    ReportAddressContext,
    EXCEPTION_SELECTION_REASONS,
    ReportExceptionEntry,
    ReportExceptionContext,
    NEIGHBOR_RELATIONS,
    ReportNeighborRegion,
    ReportAllocationNeighborhood,
    HANDLE_SELECTION_REASONS,
    ReportCorrelatedHandle,
    ReportHandleCorrelation,
    STRING_CONTEXT_SELECTION_REASONS,
    ReportStringContextEntry,
    ReportStringContext,
)
from dumpex.output.records.pe_observation import (  # noqa: F401
    PE_OBSERVATION_STATES,
    PeObservationRecord,
)
from dumpex.output.records.report_pe import (  # noqa: F401
    PE_MODULE_MATCH_STATES,
    ReportPeContext,
    ANCHOR_PE_CLASSIFICATIONS,
    ANCHOR_PE_REGISTRATIONS,
    ReportAnchorPeContext,
)
from dumpex.output.records.report_instruction import (  # noqa: F401
    INSTRUCTION_ANCHOR_SOURCES,
    INSTRUCTION_DECODER_STATES,
    INSTRUCTION_BRANCH_KINDS,
    INSTRUCTION_LEAD_NAMES,
    INSTRUCTION_LEAD_SIGNALS,
    MAX_INSTRUCTION_LEAD_EVIDENCE,
    MAX_INSTRUCTION_LEAD_LIMITATIONS,
    BRANCH_TARGET_KINDS,
    ReportInstructionLead,
    ReportDecodedInstruction,
    ReportBranchTarget,
    ReportInstructionContext,
)
from dumpex.output.records.report_iat import (  # noqa: F401
    IAT_IMPORT_BY,
    IAT_ENTRY_SELECTION_REASONS,
    ReportIatCorrelatedEntry,
    ReportIatCorrelation,
)
from dumpex.output.records.report_card import (  # noqa: F401
    TRIAGE_ANCHOR_TID,
    TRIAGE_ANCHOR_ADDRESS,
    TRIAGE_ANCHOR_STRING_HIT,
    TRIAGE_ANCHOR_TID_CURRENT_IP,
    TriageCardRecord,
    _TRIAGE_VERDICTS,
    _TRIAGE_FINDING_KEYS,
)
from dumpex.output.records.hunt_identity import (  # noqa: F401
    HUNTERS,
    _HUNT_CONFIDENCES,
    _HUNT_REVIEW_PRIORITIES,
)
from dumpex.output.records.hunt_scope import (  # noqa: F401
    TargetedMeasurement,
    TargetedScopeRecord,
    HuntRegionRef,
    HuntThreadRef,
    HuntThreadRegionHit,
    HuntPeHeaderHit,
)
from dumpex.output.records.hunt_details import (  # noqa: F401
    InjectionDetails,
    HollowingDetails,
    StompingDetails,
    PipeDetails,
    CsBeaconDetails,
    YaraDetails,
    ObfuscationDetails,
)
from dumpex.output.records.hunt_result import (  # noqa: F401
    HunterRecord,
)
from dumpex.output.records.process_pe import (  # noqa: F401
    PROCESS_PE_COMPONENT_STATES,
    PROCESS_PE_COMPONENTS,
    PROCESS_PE_STAGES,
    PROCESS_PE_SOURCE_KINDS,
    PROCESS_PE_FORMATS,
    PROCESS_PE_CAPTURE_STATES,
    PROCESS_PE_UNAVAILABLE_REASONS,
    PROCESS_PE_TABLE_STATES,
    PROCESS_PE_UNUSABLE_TABLE_STATES,
    PROCESS_PE_VALUE_KINDS,
    PROCESS_PE_IDENTITY_FORMS,
    ProcessPeSectionRecord,
    ProcessPeDirectoryRecord,
    ProcessPeEntryPointRecord,
    ProcessPeAcquisitionRecord,
    ProcessPeRecord,
)
from dumpex.output.records.process import (  # noqa: F401
    ImportEntryRecord,
    ProcessDiagnosticRecord,
    IatRecord,
    ProcessRecord,
    _PROCESS_DIAGNOSTIC_DETAILS_SCHEMA,
)
from dumpex.output.records.capabilities import (  # noqa: F401
    CapabilityStatus,
    CapabilityDefinition,
    CAPABILITY_REGISTRY,
    CAPABILITY_IDS,
    CAPABILITY_BY_ID,
    CapabilityLimitationCode,
    CAPABILITY_SOURCE_DISPLAY_NAMES,
    render_capability_limitation,
    CapabilityLimitation,
    ProfileCapabilityEntry,
    _OPTIONAL_LIMITATION_CODES,
)
from dumpex.output.records.stream_state import (  # noqa: F401
    StreamParserState,
)
from dumpex.output.records.profile import (  # noqa: F401
    ProfileStreamEntry,
    ProfileMemoryCapture,
    ProfileRecord,
)
