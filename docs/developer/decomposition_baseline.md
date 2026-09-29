# Records and memory decomposition baseline

Status: **implemented**. This baseline captures the observable behaviour of
`dumpex.output.records`, `dumpex.core.memory` and `dumpex.output.coverage`
so that splitting those modules into owner modules can be shown to change
structure only. It proves relocation equivalence at a declared commit. It
does not certify that the captured behaviour is correct.

## Comparison commit

The committed goldens describe **v3.9.1**,
`601dfdebcd0eae21c819ac95206f6ffa8a4c3e9e` (also recorded as
`BASELINE_COMMIT` in `tests/fixtures/decomposition_baseline/__init__.py`).
Symbol and consumer inventories are derived from the source at that commit,
not from historical counts; the goldens are the inventory.

## What is captured

| Golden (`tests/fixtures/decomposition_baseline/golden/`) | Kind | Content |
|---|---|---|
| `surface_contract.json` | Contract | Per module: the export list (every public name, plus every private name another file imports, reads or patches), and for each export its kind, signature, dataclass fields in order with types, defaults and flags, enum members in order, class members, constant value, and which exports are the very same object where identity is observable (mutable values, classes, functions, enum members). Also the value of every other module-level value binding -- private and unused constants, vocabularies and tables included |
| `surface_structure.json` | Structural | Every baseline definition's current owner module, the legacy module's own import provenance and definitions, for every function and method the module it resolves globals in and the globals it loads, and how the decomposed modules import one another (`family_consumers`) |
| `consumers.json` | Contract for shipped code | Every name of the three modules imported (`from`), read module-qualified (`attr`), or replaced (`patch`, `assign`) by production and script files |
| `seams.json` | Inventory | Names tests replace on the legacy paths, and attributes of other `dumpex` modules that hold one of these modules' objects by name and that tests replace there, with whether each is the canonical object |
| `coverage_corpus.json` | Contract | `_CODE_SPECS` order and every non-callable spec field, the ordered derived collections, construction cases for every limitation code (rendered text, card summary, `to_dict()`, missed-bytes projection, or exact rejection) including one case per member of every renderer and validator vocabulary and per oversized-skip source contract, capability limitation text, coverage-report assembly and combination over source states, requirements and prebuilt limitations (status, exit code, reasons, sources, limitations, missed bytes, or exact rejection), and the shared formatting helpers |
| `record_corpus.json` | Contract | For one sample of every record dataclass: its `to_dict()` projection; every constructor field probed with `None` and with an unacceptable value; and cross-field probes -- each vocabulary-valued field set to every other member of its vocabulary, each boolean flipped. For one variant per other value of each state-like field (an uncollected profile, an unavailable capability, a failed decode, ...): a projection digest, the cross-field probes, and fill probes that set each field the variant leaves empty to the populated sample's value. Every probe records the exact rejection or the acceptance |
| `cli/<scenario>.json` | Contract | For each command scenario: exit code, stdout and stderr line by line, the full `--json` document, the `--txt` transcript, and the size and SHA-256 of an `--output` artifact |

The loader and reader characterization is not a golden file: it lives as
literal expectations in `tests/unit/test_memory_baseline_characterization.py`,
driven through real synthetic dump bytes written by
`tests/fixtures/minidump_bytes.py`. It covers the header union and flag
width, the file-size-bounded directory walk, unrecognized stream ids,
per-stream parse isolation and recorded failure text, observed stream states,
handle stream states, thread start/current-IP/conflict joins, partial,
truncated and entry-capped thread-info records, WOW64 contexts, exact and
adjacent segment boundaries, holes, short-backed segments, zero-length
reads, reads that reach or wrap past the top of the address space,
overlapping and unsorted segments, Memory64List-over-MemoryList precedence,
segment-index caching, reader construction and reuse, size resolution,
string search telemetry, IOC string extraction in every encoding, verdict
tiers, hexdump presentation, address labels, and file-cursor restoration.
Segment contents are position-dependent and every successful read is
compared byte for byte.

The CLI scenarios run the real `dumpex.cli.main()` on byte-level dumps (no
`open_dump` stand-in) covering `--list`, `--modules`, `--threads`,
`--extract`, `--strings`, `--process`, `--handles`, `--profile`,
`--sysinfo`, `--diff`, `--report` (TID, address and string anchors, and a
self-decoding stub whose static-analysis lead cites more evidence than a
lead keeps, in console and `--txt`), `--hunt injection` and `--hunt all`,
console, `--verbose`, `--json`, `--txt`, `--output` and `--redact-paths`
modes, and argument, input and output-file errors. Static-analysis leads
appear in console and TXT output only. No current command writes CSV, so
there is no CSV surface.

### Normalization

Only values that vary between runs or machines are replaced: scratch and
repository paths become `<TMP>` and `<REPO>` with `/` separators, the wall
clock is frozen, installed version strings become `<VERSION>`, the
parenthesized size/digest after "JSON written" or "TXT written" becomes
`<WRITTEN>` in console and TXT output (the file embeds a scratch path), and
argparse's usage block becomes `usage: <argparse usage>` because its
wrapping belongs to the interpreter. Everything else, including every
rendered sentence, is compared exactly. A serialization value that could
vary by Python version (an annotation spelling, a set's iteration order, an
object address) is projected to a stable form, so the same goldens hold on
every supported interpreter.

## Contract versus structure

The export list, the private value list and the baseline definition list of
each module are **sticky**: the generator unites the committed lists with
what the current source derives, and a name leaves a list only through an
explicit `--drop <module>:<name>`. Comparisons capture exactly the committed
names. Each entry is read from the runtime object -- on the legacy module,
or, for a private value the legacy module does not expose, on the owner module that
defines it now -- and a dumpex class's members come from its owning module's
source; a third-party class or callable is recorded by name only. The same
object defined in place or re-exported from a new owner therefore has the
identical contract, and regenerating after a pure relocation reproduces
`surface_contract.json` byte for byte. A process-lifetime cache is recorded
only as runtime state; its source initializer is structural.

A name the legacy module does not expose is found where it is defined
now (`surface.Locator`): the search follows `from X import name` provenance
from the legacy module, from the owner modules of its exported classes and
functions and, once it is a package, from its submodules, to the module
whose own source defines the name. A private vocabulary or helper can
therefore move to a module that owns no export -- a constants or internals
module -- without being re-exported from the facade. The record and
coverage corpora, the seam leak guard and the vocabulary guard resolve
every private name the same way.

A pure relocation regenerates `structure` -- the reviewed old-to-new
ownership map, which follows every baseline definition to its new owner,
records the module each function now resolves globals in, and records how
the decomposed modules import one another. Every other golden stays
byte-identical.

The object reachable through the legacy path must stay the one canonical
definition: a class or function is the object its owning module defines
under that name, and a non-scalar export or private value is never bound to
a copy in the facade or a second owner
(`test_every_exported_definition_has_one_canonical_owner`,
`test_no_baseline_value_has_a_second_definition`). Identity cannot tell an
equal scalar copied into a second owner from an import -- a budget literal
may even be the same interned object -- so every baseline name is also
defined in the source of one family module only
(`test_no_baseline_name_is_defined_in_two_family_modules`).

Test files never feed a contract: the consumer inventory and the export
derivation read shipped files only, so a change that only adds a test leaves
`--check` clean.

## Patch seams and test isolation

Many tests replace a reader, cap or cache by assigning to a module
attribute. Two different seams exist:

* **Legacy module seams.** A function in `dumpex.core.memory` that reads
  another module global resolves it in `dumpex.core.memory` at call time.
  Moving the function elsewhere makes a patch to the legacy name stop
  reaching it unless the move delegates explicitly. The `check_*` functions
  in `tests/fixtures/decomposition_baseline/seams.py` patch each legacy name
  tests rely on and assert its consumer observes it;
  `surface_structure.json`'s `global_resolution` lists every such
  dependency. These seams are part of `dumpex.core.memory`'s
  compatibility contract: splitting it keeps explicit compatibility
  exports or small delegating wrappers at `dumpex.core.memory`, so a patch
  applied to a legacy reader or context entry point still affects the
  executions that use it. The owner modules in `dumpex.core.dumpfile` and
  the entry points that delegate to them are listed in
  [the memory module layout](memory_layout.md); the consumer scan counts
  `dumpex/core/dumpfile/` as part of the family.
  `dumpex.output.records` has no such seams and does not delegate: its
  owner modules resolve their globals in their own namespaces, so a test
  replaces a records name on the owner module, never on the facade.
  `test_no_test_rebinds_a_legacy_name_that_is_read_from_its_owner` fails
  when a test rebinds a legacy attribute that a relocated function reads
  from another module -- a records owner, or a `memory` owner a split
  failed to delegate for (patching an object reached through the legacy
  path, such as `setattr(records.ThreadRecord, ...)`, is unaffected).
* **Consumer seams.** Hunters and commands hold readers by name
  (`dumpex.hunt.injection.read_region`, `dumpex.hunt.stomping.
  enriched_thread_contexts`, ...). The scanner finds them whether a test
  replaces one by plain assignment, by `setattr` on the module, or by a
  dotted-string patch. `tests/conftest.py` restores every such seam before
  and after each test; `test_conftest_resets_every_consumer_reader_seam`
  checks the live scan of the test files against that table, and no test
  may replace a target module attribute by plain assignment.

A module imported for the first time while a legacy name is patched binds
the patched object permanently. Tests that perturb these modules import all
of `dumpex` first.

## Current behaviour this baseline freezes

These outcomes are captured as they are, including ones that are weak
evidence handling. A deliberate fix updates the affected expectation in its
own reviewed change; a relocation never does.

* A region that spans two adjacent captured segments is skipped by the
  `--report-string` search, because its single read cannot cross a segment
  boundary; a needle inside it is not found.
* `va_range_captured_bytes()` counts a segment's declared size even when the
  file ends before the segment's data does; the read of that range is short.
* A thread whose context location is empty gets a context parsed from file
  offset 0.
* `read_region()` raises for a zero-length request; the clamped and spanning
  readers return `b""`.
* The directory walk reads bytes after the real directory table as further
  entries when the header declares more streams than it holds, bounded only
  by the file size.
* Building a reader requires both SystemInfoStream and ModuleListStream;
  without either, `read_region()` raises and the clamped and spanning
  readers return `b""`.
* `open_dump()` reports a missing or unparseable file on stdout.
* `hex_address()` formats a negative integer with the sign inside the digits.
* The UTF-16 IOC string pattern starts on the last ASCII character before a
  wide string when that character's zero terminator reads as a high byte.

## Updating the baseline

```bash
python scripts/update_decomposition_baseline.py --check
python scripts/update_decomposition_baseline.py
```

`--check` compares without writing. It exits 1 when a contract, structure
or consumer golden would change, when a committed seam entry does not
resolve, and when a scenario could not run here (`hunt_all` needs
yara-python) unless `--allow-skip` is given. New entries in the `seams.json`
inventory are reported without failing: recording additions is a routine
update. Without `--check` the script rewrites the goldens. Sections can be
named (`contract`, `structure`, `consumers`, `seams`, `coverage`, `records`,
`cli`). Tests never write a golden.

`--drop <module>:<name>` removes a name from the sticky lists and always
regenerates contract and structure together; `--drop-seam <module>:<name>`
removes a seam entry whose consumer was renamed or removed. Either is
refused when the committed baseline does not hold what it names.

An approved behaviour change (a correctness fix, an accepted console
change) regenerates only the affected goldens, in its own commit, with the
rationale in the commit message; the diff is reviewed like code. A
relocation commit that changes any contract golden is not a relocation.

## Mutation controls

`tests/integration/test_decomposition_baseline_mutations.py` applies one
representative perturbation per failure class and asserts the baseline
reports it: a lost public or private export, a dropped validator, a
reworded validation message, a disabled state-dependent record check (the
uncollected-profile check of `ProcessPeRecord`), a changed field default, a
reordered
vocabulary and code registry, a reworded reason in a private renderer
vocabulary, a removed oversized-skip source contract, a cross-source or
report-input validator replaced by a no-op carrying its own name, changed
limitation, console and JSON text, a relocated function that does not see a
legacy patch, a value copied into a facade, a hole reported as captured, a
hole zero-filled by a read, a spanning read whose middle bytes are zeroed,
and adjacent segments joined at the wrong offset.

The same module runs the opposite controls, which must produce no
difference: every export re-exported through a facade module; every
definition re-executed in a different owner module (new `__module__`, class
members from the new owner's source) behind a facade; a split across three
modules -- exported classes, exported functions and values, and every
private value, vocabulary and helper in a module that owns no export --
behind a facade exposing only the committed exports
(`tests/fixtures/decomposition_baseline/relocation.py`), under which the
contract and both corpora are byte-identical, every baseline definition has
an owner, the leak guard holds, and a copy or an unregistered vocabulary in
the split modules is still reported; and the generator run over the
relocated layouts, which must reproduce the committed contract byte for
byte and place every moved definition in its new owner. The simulated
relocations re-execute a target's single source file, so they run against
the targets whose baseline definitions all still live in that one module;
a target already decomposed -- into a package (`dumpex.output.records`,
see [the records package layout](records_layout.md)) or behind a legacy
module over owner modules (`dumpex.core.memory`, see
[the memory module layout](memory_layout.md)) -- is its own positive
control, and a copy bound in its facade is still reported. The seam
controls still split `dumpex.core.memory`'s own source, whose entry points
must keep delegating.
