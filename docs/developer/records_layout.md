# Records package layout

Status: **implemented**. `dumpex.output.records` is a package: a
compatibility facade over one owner module per evidence domain. This
document states where a record belongs and how the modules may depend on
one another. Field-level wire contracts stay in the command contracts and
[Output and Evidence Schema](../user/OUTPUT_SCHEMA.md).

## Owners

Every record, vocabulary and validator has exactly one definition, in the
module that owns its domain. A validator one domain applies lives with that
domain's records; only validation more than one domain applies belongs in
`common`.

| Module | Owns |
|---|---|
| `common` | `hex_address()`, the shared field validators, the retained-text cap (`ENRICHMENT_TEXT_CAP`) and its validator, and the one statement of the wire type rule |
| `diagnostics` | `Diagnostic`, `Artifact` |
| `base` | Memory region, module, thread and system records; module-context, start-address and DumpFlags vocabularies |
| `extraction` | `--extract` and `--strings` records (`StringRecord` is also a `--report` card's notable-string record) |
| `stream_state` | `StreamParserState`, the parser state of one minidump stream |
| `comparison` | `--diff` module, thread and memory records |
| `handles` | `--handles` records and handle-name display |
| `report_common` | `EnrichmentSection`, enrichment states and scopes, the optional bounded-text rule |
| `report_thread` | `--report` thread, region and IOC-string records |
| `report_process` | `--report` environment, handle, token and identity enrichment |
| `report_context` | `--report` address, exception, allocation, handle and string context |
| `pe_observation` | `PeObservationRecord`, shared by `--report` and `--process` |
| `report_pe` | `--report` main-image and anchor PE context |
| `report_instruction` | `--report` instruction window, branch targets and leads |
| `report_iat` | `--report` IAT correlation |
| `report_card` | `TriageCardRecord` and its anchor, verdict and finding vocabularies |
| `hunt_identity` | `HUNTERS` and the hunt judgment vocabularies |
| `hunt_scope` | Targeted scope, measurements, and region/thread/PE-header references |
| `hunt_details` | The seven `*Details` records |
| `hunt_result` | `HunterRecord` |
| `process_pe` | `--process` main-image PE profile, acquisition, section, directory and entry-point records |
| `process` | `--process` IAT, diagnostic and process records |
| `capabilities` | `--profile` capability registry, limitation codes and text, `ProfileCapabilityEntry` |
| `profile` | `--profile` stream inventory, memory capture and `ProfileRecord` |

The symbol-by-symbol map from the pre-package `records.py` to these owners
is the `owners` table of
`tests/fixtures/decomposition_baseline/golden/surface_structure.json`; the
[decomposition baseline](decomposition_baseline.md) keeps it complete.

## Dependency rules

- An owner module imports the lower-level owners it needs directly, by
  their module path. It never imports the `dumpex.output.records` facade.
- Each top-level name is defined in exactly one owner; an owner that
  needs another owner's constant, budget or validator imports it, never
  restates it as a local literal.
- The import graph between owners is acyclic, and each owner imports
  correctly on its own, loading only the owners it declares.
- `common`, `diagnostics`, `base`, `extraction`, `pe_observation` and
  `stream_state` are the shared layer: the records of more than one
  command build on them, and they import only one another. Every other
  owner belongs to one command domain -- `report_*`, `hunt_*`, `process`
  and `process_pe`, `profile` and `capabilities`, `comparison`, `handles`
  -- and imports only the shared layer and owners of its own domain. A
  vocabulary or validator a second domain needs moves down into the shared
  layer; it is not imported across domains.
- No owner's import chain loads `dumpex.hunt.*` or `dumpex.commands.*`,
  directly or through another module. Outside the package an owner may
  import only `dumpex.core.pe_utils` and `dumpex.output.coverage`.
- Hunt wire identity (`HUNTERS`) stays in `hunt_identity`, in the neutral
  record layer; hunter implementations validate against it.

## The facade

`dumpex/output/records/__init__.py` defines nothing. It re-exports, by
explicit name and without star imports, every name the
`dumpex.output.records` path has supported -- including the private names
shipped code or tests use -- so an import through the facade and through
the owner return the same object. It also imports every owner module, so a
build that follows imports statically (the PyInstaller executable) carries
the whole package.

A private name no shipped file or test used through that path -- a
vocabulary such as `_STREAM_PARSER_STATES`, a domain-only validator -- is
not re-exported; code that needs one imports it from its owner.

The facade only binds names; no record code reads its globals. A test
that replaces a vocabulary, cap or validator does so on the owner module
the reading code resolves it in -- rebinding the facade's attribute reaches
nothing, and the decomposition baseline reports it. Patching an object
reached through the facade (a record class's method, say) is unaffected.

New record code goes in its owner module. A new name joins the facade only
when it is part of the supported `dumpex.output.records` surface; code
inside the package imports it from its owner.

Importing the facade or any owner reads no file. The facade loads every
owner and no hunter or command module.

## Where changes go

The package is not an append location. A record states what one command
established, so a change lands with the owner of that command's domain, in
its own reviewed change, with any affected baseline expectation updated
there; a relocation never changes a contract golden.

| Change | Owner |
|---|---|
| A field, default, validator or vocabulary of one command's records | That command's owner module; the shared layer only when a second domain needs it |
| Requested, read and missing extents of a captured-range read that `--extract` or `--strings` reports | The read itself in `dumpex.core.dumpfile.reads` (see [the memory module layout](memory_layout.md)); its records in `extraction`, together with the schema and migration decision the new shape needs |
| Which `--report-string` hits are kept, including registered-image matches | `dumpex.commands.report`; `report_context` and `report_card` only when a card's record shape changes |
| Console wording and layout of any record | The renderer that consumes the record. Records hold values, not presentation; `handle_name_display()` and its status labels in `handles` are the display rule the `--handles` console and the record share, and a renderer that takes them over keeps the facade names as compatibility imports |
| Capture-bound evidence objects and shared address resolution | An internal core module beside `dumpex.core.dumpfile` and `dumpex.core.dumpquery`, not this package. Records change only when public output does, in its own change with a schema decision |

A build that follows imports statically carries every owner because the
facade imports them all; the release gate `scripts/frozen_layout_smoke.py`
reads the built executable's archive and fails when any `dumpex` module is
missing from it.

`tests/unit/test_records_layout.py` enforces these rules.
