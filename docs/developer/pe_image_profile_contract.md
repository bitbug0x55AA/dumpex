# Canonical PE image profile and coverage contract

Status: **frozen contract; partially implemented**. The internal
memory-sourced collector implements the raw-profile and staged-acquisition
subset of this contract, but is not connected to any shipped production
path. Cache reuse (§7), consistency observations (§8), projections (§9),
disk-reference collection (§5.1.1), and consumer migrations remain future
work. Shipped behavior is unchanged.

It is the normative definition that the report PE projection, the
candidate-image resolver, and a later `--process` PE projection implement
against, so that no consumer invents its own PE semantics.

Today, PE facts are produced by `dumpex.core.pe_utils.parse_pe_header()`
and consumed independently by `dumpex.core.process_info`'s
`MainImagePeClaim`, `dumpex.core.pe_utils.parse_iat()`,
`dumpex.hunt.injection`'s hidden-PE evidence, and `dumpex.hunt.stomping`'s
section and disk-reference analysis. Each consumer projects the same
parser dict into its own type. This contract freezes the meanings those
projections share — image identity, actual versus preferred base, memory
versus file addressing, component coverage, and projection ownership — so
a shared profile can be introduced without a report-only parser,
incompatible record shapes, duplicate reads, or Recon and Hunt
contradicting each other.

Read alongside:

- [Recon `--process`/`--sysinfo`/`--handles` contract](recon_process_sysinfo_handles_contract.md)
  — §3.4.4 `main_image_pe`, §3.5 `iat`, §6 code registry.
- [Report enrichment contract](report_enrichment_contract.md) —
  invocation-scoped collection and evidence states.
- `dumpex.core.va_range` — the single virtual-range and capture model.
  This contract adds no second one.

---

## Table of contents

- §0 Scope and non-goals
- §1 Vocabulary, ownership tiers, and ordering
- §2 Image identity and addressing
- §3 The P0 field matrix
- §4 Data directories
- §5 Coverage, provenance, and component state
- §6 Staged acquisition and bounded stops
- §7 Cache identity and reuse
- §8 Derived main-image consistency observations
- §9 Projection rules
- §10 Resource and safety constraints
- §11 What exists today and what is new work
- §12 Compatibility

---

## §0 Scope and non-goals

### 0.1 What this contract covers

1. An immutable `PeImageProfile`: source identity, actual base, raw header
   facts, section table, all sixteen directory descriptors, and
   per-component coverage (§2, §3, §4, §5).
2. The address arithmetic every consumer shares, including PE32/PE32+
   pointer width and the Security Directory exception (§2).
3. Byte provenance — requested, captured, read — and the exact unexamined
   ranges a partial profile leaves behind (§5).
4. Staged header acquisition and the bounded-stop rules that end a stage
   without turning a budget stop into a structural claim (§6).
5. Cache identity, so a targeted or short profile is never reused where
   full-scope evidence is required (§7).
6. Ownership: what belongs in the raw profile, what belongs in a derived
   Recon consistency observation, and what belongs in a Hunt finding
   (§1.1, §8).
7. Default, verbose, and structured projection rules (§9).

### 0.2 Non-goals

- No production code, CLI, console, JSON, CSV, coverage-vocabulary, or
  exit-code change. This document ships alone.
- No schema version selection and no edit to a frozen schema file. It may
  name fields a future schema would carry; it does not add them.
- No complete directory-content parsers. Export, Resource, Exception,
  Debug, TLS, Load Config, and CLR contents stay unparsed: this contract
  freezes their **descriptors**, not their bodies.
- No disassembler, no raw-file reconstruction, no Authenticode or
  certificate-chain verification.
- No scoring, confidence, verdict, or ATT&CK mapping.
- No change to injection, hollowing, stomping, or IAT findings and
  diagnostics. Their existing projections keep their current shapes.
- No second virtual-range or capture model. `dumpex.core.va_range` is the
  only one.

---

## §1 Vocabulary, ownership tiers, and ordering

### 1.1 Three tiers, never merged

| Tier | Owner | May contain | May never contain |
|---|---|---|---|
| **Raw profile** | `PeImageProfile` | Bytes actually read, decoded fields, per-component state, exact unexamined ranges | Any comparison, any interpretation, any severity |
| **Derived observation** | Recon | `consistent` / `conflict` / `unavailable` over established facts (§8.3) | `trusted`, `malicious`, `DETECTED`, a score, a confidence |
| **Finding** | Hunt | A detection claim with its own evidence and coverage | A raw profile field re-read from memory a second time |

A derived observation uses **only established facts**. When those facts
determine its predicate it is `consistent` or `conflict`; when they do
not, it is `unavailable`. §8.3's three-valued rule is that evaluation,
and it governs every observation in §8.3 without exception — including
the cases where one established fact settles a predicate on its own
(§8.3.1).

An uncaptured fact is therefore never on its own a `conflict`, and never
on its own an `unavailable` either: what decides is whether the facts in
hand determine the answer.

### 1.2 Component states

A **component** is one independently acquirable part of the image. The
names are frozen, and every table in this contract uses them:

| Component | Covers |
|---|---|
| `dos_header` | §3.1 |
| `coff_header` | §3.2 |
| `optional_header` | §3.3's fixed fields |
| `directory_array` | `NumberOfRvaAndSizes` and the array as a whole (§4.4) |
| `directory_descriptors` | The sixteen descriptors (§4.1), each its own component |
| `section_table` | §3.4 |

A component holds bytes. §3.5's relocation context does not: it is
derived facts, it carries no state, and it is not in this set (§3.5.2).
Every byte those facts decode from belongs to a component listed above,
and that component's state is what explains them.

Every component carries exactly one state:

| State | Meaning |
|---|---|
| `complete` | Every byte this component needs was captured, read, and decoded. |
| `partial` | Some of the component was decoded and a stated, byte-precise remainder was not. The remainder is named in `unexamined` (§5.2). |
| `unavailable` | Nothing was decoded, because the bytes were not captured or the read did not return them. Not a claim about the component's contents. |
| `malformed` | Every byte **the defect rests on** was read, and what they decode to is structurally impossible. A deterministic rejection reached from bytes that were all there. Other bytes of the component may be missing (§5.3.1). |
| `declared_absent` | An owning field or descriptor **was** captured and positively says this component does not exist. |

Three rules bind this vocabulary, and no consumer may relax them:

1. **Uncaptured bytes never support a `malformed`, and never a
   `declared_absent`.** A component known only through missing bytes is
   `unavailable` or `partial`. What a missing byte cannot do is *soften*
   a defect that was already determined from bytes that were all read:
   §5.3.1 registers those, and §5.3's step 3 decides them ahead of the
   gap. A wrong `MZ` is a wrong `MZ` however little followed it.
2. **`declared_absent` requires a captured owner.** A directory index is
   `declared_absent` only when `NumberOfRvaAndSizes` itself was captured
   and excludes the index, or the index's own eight descriptor bytes were
   captured and hold a zero first value. An index past what was read is
   `unavailable`.
3. **`malformed` requires the contradiction itself to be fully read.**
   Every `malformed` state rests on specific bytes, and all of those
   bytes must have been read. Unread bytes *elsewhere* in the component
   neither create a defect nor soften one that was fully read — §5.3.1
   registers the determined defects this contract decides that way,
   and §5.3's step 3 is where they are decided. What the rule forbids is
   the common case: a component whose structurally required bytes ran
   past the read is `partial` or `unavailable`, however wrong the bytes
   that are present look.

This is close to the distinction `parse_pe_header()`'s shipped
`insufficient_data` flag already draws: a rejection with
`insufficient_data` true is a capture-length gap, one with it false is a
deterministic rejection. Not every such rejection is a structural defect
under this vocabulary — §11.6 and §11.7 name the two places the shipped
parser rejects on a limit of its own — so a consumer maps the flag
through §11.6 rather than reading it as a component state directly.
Consumers read that flag; they never pattern-match the free-text `reason`,
which is not a closed vocabulary.

### 1.3 `null` versus empty versus zero

`null` means the fact could not be established. An empty tuple or `0` means
it was established and the answer is none or zero. The two are never
conflated. `declared_directory_count` is `null` when the
`NumberOfRvaAndSizes` field's own four bytes were not captured, and `0`
only when they were captured and say zero.

### 1.4 Ordering

Every collection is in **structural order** — never sorted, never
insertion-order-of-a-dict:

- sections in section-table order, `section_index` equal to position;
- directories in index order `0..15`;
- unexamined ranges by ascending `base_address`;
- observations in the frozen declaration order of their codes (§8.3).

A profile built twice from the same dump is identical field for field.

### 1.5 Frozen constants

| Constant | Value | Governs |
|---|---|---|
| `MAIN_IMAGE_PE_READ_MAX` | `4096` | bytes requested at an image base for header acquisition |
| `PE_VALIDATE_READ_MAX` | `4096` | the same budget as applied by the injection and stomping scans |
| `_MAX_SECTIONS` | `96` | section-table entries accepted before the table is structurally rejected |
| `MAX_IAT_DLLS` | `256` | import descriptors walked |
| `MAX_IAT_ENTRIES_PER_DLL` | `4096` | thunks per descriptor |
| `MAX_IAT_TOTAL_ENTRIES` | `65536` | thunks overall |
| `MAX_IAT_NAME_LENGTH` | `512` | bytes read for one DLL or symbol name |
| `MAX_IAT_BYTES_READ` | `16777216` | cumulative bytes across a directory walk |
| `MAX_IAT_READ_OPERATIONS` | `8192` | individual bounded reads across a directory walk |
| `MAX_E_LFANEW` | `4096` | how far past the image start header acquisition will follow `e_lfanew` |
| `MAX_DIRECTORY_COUNT` | `16` | descriptors this contract assigns meanings to |

Neither is a format maximum, and §2.6 keeps them on the right side of
that line. The PE format fixes neither: a DOS stub may be arbitrarily
long, and the format explicitly declines to fix the directory count,
requiring a reader to consult `NumberOfRvaAndSizes` instead. Reaching
either is never evidence about the image.

These constants are **four different kinds** of limit, and they produce
four different outcomes. Nothing in this contract may treat one as
another:

| Kind | Constants | Reaching it produces |
|---|---|---|
| **Acquisition budget** — work dumpex declined to do | `MAIN_IMAGE_PE_READ_MAX`, `PE_VALIDATE_READ_MAX`, `MAX_E_LFANEW`, every `MAX_IAT_*` | A bounded stop (§6.2): an attributed record, and a component that is `partial` or `unavailable` by bytes. Never `malformed`. |
| **Projection scope** — meaning this contract does not define | `MAX_DIRECTORY_COUNT` | `unprojected_directory_count` (§4.5). Not a bounded stop; nothing was declined. |
| **Structural constraint** — a value the format does not permit | `_MAX_SECTIONS` | `malformed` (§2.6). A fact about the image, not about dumpex. |
| **Retention bound** — how much of one value the profile keeps | `MAX_STRING_BYTES` | A `truncated` flag on that field (§10.3.1). Nothing else. |

`_MAX_SECTIONS` belongs in the third row, not the first. The PE format
caps an image at 96 sections, so `NumberOfSections = 200` is not a table
dumpex stopped walking — it is a count no loadable image can declare, and
the shipped parser already rejects it deterministically rather than as a
capture gap.

`MAX_STRING_BYTES` needs the fourth row rather than the first, because a
bounded stop is a specific thing and a truncated string is none of it. A
retention bound:

- does **not** end acquisition — the next component is read normally;
- produces **no** unexamined range, because no PE structure went
  unexamined;
- changes **no** component state — the field is `complete`, holding a
  value the profile shortened;
- carries **no** consumed/limit record; its whole attribution is the
  per-field `truncated` flag;
- never affects coverage.

It bounds what the profile keeps of one already-established value. What
the source read to establish it is that source's own concern.

A budget stop leaves a question unanswered. Running out of scope means
the question was never this contract's to ask. Violating a structural
constraint is the image answering, wrongly. Reaching a retention bound
means the answer was longer than the profile carries — and the
`truncated` flag is what says so.

The two cumulative directory-walk budgets — bytes and read operations —
stay independent. A byte budget alone does not catch thousands of one-byte
reads, which stay far under the byte ceiling while still hanging a walk.

---

## §2 Image identity and addressing

### 2.1 Source identity

A profile is identified by **where it came from**, not by what it turned
out to contain:

| Field | Meaning |
|---|---|
| `source_kind` | `"peb_image_base"`, `"module_list_entry"`, `"memory_candidate"`, or `"disk_reference"` |
| `actual_base` | The virtual address the header was actually read at. Never taken from the header itself. |
| `module_identity` | What the source calls this image (§2.1.1). Always present as an object; its `value` is `null` when nothing named the image. A claim of the source, never of the header. |

#### 2.1.1 `module_identity` is a typed value, not a bare string

"The name or the path" is two different fields, and a `truncated` flag
(§10.3.1) has to live somewhere. Both are frozen:

```text
module_identity: {
    value:     str | null,      # bounded and possibly truncated per §10.3.1
    form:      "path" | "name" | null,
    truncated: bool,
}
```

`form` says which of the two `value` is, so a consumer never has to guess
from whether it contains a separator — a module *name* may legitimately
contain one, and an attacker may put one anywhere. `truncated` is a field
of this object rather than of the profile, because a profile can carry
several identities and only one may have been shortened.

Where `value` comes from, per source:

| `source_kind` | `value` | `form` |
|---|---|---|
| `peb_image_base` | The PEB's image path when present, else `null` | `"path"` or `null` |
| `module_list_entry` | The module entry's path when present, else its name | `"path"` or `"name"` |
| `memory_candidate` | Always `null` — a candidate found by scanning is not named by anything | `null` |
| `disk_reference` | The reference path as supplied by the caller | `"path"` |

**The object itself is never `null`.** `module_identity` is always
present; absence is `value: null` inside it. A profile that could encode
the same fact two ways — a `null` object, or an object holding a `null`
value — is not the canonical representation §1.4 requires, and two
implementations would each pick one.

`value` is `null` and `form` is `null` together; `truncated` is `false`
whenever `value` is `null`. A `null` value is not an empty string:
nothing named this image, which is different from something naming it
`""` (§1.3).

`source_kind` is never promoted. A profile acquired from a
`module_list_entry` stays one even when its `actual_base` equals the
PEB-reported image base. The PEB, ModuleList, PE header, MemoryInfo,
disk-reference, and reconstructed-candidate claims remain separately
attributable, exactly as the Recon contract's identity evidence already
keeps them.

`disk_reference` is the one source whose bytes are indexed by **file
offset** rather than virtual address. It carries no `actual_base`, and
§2.3's resolution rule does not apply to it.

### 2.2 Preferred base versus actual base

`preferred_image_base` is the optional header's own `ImageBase` field — a
declaration of where the image asked to be loaded. `actual_base` is where
it is. They are different facts and are stored separately.

`relocation_delta` is `actual_base - preferred_image_base`, signed, and
present only when both are known. It is a plain arithmetic fact.

> A non-zero `relocation_delta` is ASLR working. It is not evidence of
> anything by itself, and no projection may present it as suspicious.

The relocation context a consumer needs alongside the delta is:

- whether `IMAGE_FILE_RELOCS_STRIPPED` (`0x0001`) is set in the COFF
  `Characteristics`;
- whether `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (`0x0040`) is set in the
  optional header's `DllCharacteristics`;
- whether the Base Relocation directory (index 5) is declared present —
  its presence (§4.3), not its descriptor's state.

A non-zero delta on an image whose relocations are stripped, or whose
BASERELOC descriptor is `declared_absent`, is a **conflict observation**
(§8) — a disagreement between two captured facts — and still not a
finding.

### 2.3 Address resolution — the single rule

> Every RVA in a memory-sourced profile resolves as `actual_base + rva`.
> Never `preferred_image_base + rva`.

This is memory-image addressing. It is already what `parse_iat()` does,
and it is why an image loaded away from its preferred base is read
correctly.

Disk-file RVA-to-offset translation through the section table is a
**different** operation. It belongs only to a `disk_reference` profile and
is never applied to a memory-sourced one. It exists today as
`dumpex.core.pe_utils._rva_to_file_offset()`, which translates only RVAs
inside a section's on-disk raw extent: an RVA in a section's virtual-only
tail has no file bytes and translates to `null`, never to a
plausible-but-wrong offset.

### 2.4 Pointer width

`is_pe32_plus` comes from the optional header `Magic`: `0x10b` is PE32,
`0x20b` is PE32+, and any other value makes the optional header
`malformed` — a determined defect (§5.3.1) on `Magic`'s own two bytes, so
it is decided at §5.3's step 3 and does not wait for the rest of the
optional header. A `Magic` this contract cannot read is a different
thing: `is_pe32_plus` is then `null` and the component's state follows
§5.3 from its bytes (§3.3.1). It selects, for the whole profile:

All offsets are relative to the start of the optional header.

| Quantity | PE32 | PE32+ |
|---|---:|---:|
| `ImageBase` width in bytes | `4` | `8` |
| `ImageBase` offset | `+28` | `+24` |
| `NumberOfRvaAndSizes` offset | `+92` | `+108` |
| Directory array offset | `+96` | `+112` |
| Import thunk width in bytes | `4` | `8` |
| Ordinal flag | `0x80000000` | `0x8000000000000000` |

RVAs, directory `Size` fields, every section-header field, and
`SizeOfImage` are 32-bit in **both** formats. Only `ImageBase`, the thunk
values, and the optional header's stack and heap reserve/commit fields
widen.

### 2.5 The Security Directory exception

Data directory index **4** (`IMAGE_DIRECTORY_ENTRY_SECURITY`) is the one
descriptor whose first field is **not** an RVA. It is a **file offset**
into the on-disk image, pointing at the attribute-certificate table.

Consequences, all normative:

1. Index 4 is never resolved as `actual_base + value`. Doing so yields an
   address unrelated to anything in the process.
2. Every profile reports index 4's descriptor — its file offset and size —
   and its state, and nothing more.
3. Index 4's state is decided by §4.3 in full, exactly like every other
   descriptor — the owner-first rule included, so a
   `NumberOfRvaAndSizes` of `4` or less makes index 4 `declared_absent`
   from the count's own bytes, whether or not its eight bytes were read
   (§5.3's step 1). What never changes that state is the certificate
   content the descriptor points at: no read of it, and no failure to
   read it, raises or lowers the descriptor's state. **Why** it is never
   raised differs by source, and the two reasons must not be confused:

   | Source | The certificate bytes are |
   |---|---|
   | Memory-sourced | Not reachable at all. They are not part of the image mapping, so no read could find them wherever it looked. |
   | `disk_reference` | Reachable. `value` is a file offset into a file this profile has open, so a read *could* fetch them — this contract simply does not parse directory contents (§0.2). |

   A future contract extension could parse the certificate table from a
   `disk_reference` profile; none could parse it from a memory-sourced
   one. Writing the memory-source reason as though it were universal
   would freeze an impossibility where only a scope decision exists.
4. No field naming the descriptor's first value may be called `rva`. Each
   descriptor stores its first value as `value` alongside a per-index
   `value_kind` of `"rva"` or `"file_offset"` (§4.1).

### 2.6 Checked arithmetic

Every address computation is 64-bit and checked before use:

- `actual_base + rva` must stay below `1 << 64`. An overflow is a
  resolution failure, not a wrapped address.
- `e_lfanew` must satisfy `e_lfanew >= 4`. Below that the `PE\0\0`
  signature would overlap the `MZ` magic the DOS header already
  established, so the value cannot be an offset to anything: `malformed`.
  There is **no** structural upper bound. `MAX_E_LFANEW` is dumpex's own
  acquisition budget, so `e_lfanew > MAX_E_LFANEW` is a bounded stop
  (§6.2) — a long DOS stub is legal, and reporting one as a defect would
  dress a tool limit up as evidence about the image. Per §6.2 the
  resulting states are: `dos_header` stays `complete`, because `e_lfanew`
  lives inside it and stage 0 read all of it; every later component is
  `unavailable`, because the stop landed before any of their bytes; and
  the profile folds to `unavailable`. What the budget must never produce
  is `malformed`. An `e_lfanew` within budget whose own window runs past
  what was read is `unavailable` for the same reason.
- `NumberOfSections` must satisfy `1 <= n <= _MAX_SECTIONS`.
- `NumberOfRvaAndSizes` yields **two** retained facts, never interchanged:
  `declared_directory_count_raw` is the field exactly as read, and
  `declared_directory_count` is the projected count from §4.5. A raw value
  above `MAX_DIRECTORY_COUNT` is **not** malformed — the format does not
  fix the directory count — it is out of projection scope (§4.5).
- `SizeOfOptionalHeader` bounds the directory array: the array must fit
  inside the optional header the COFF file header declares (§4.5). It is
  also what places the section table, at
  `e_lfanew + 4 + 20 + SizeOfOptionalHeader`, checked for overflow before
  it is used as an index.

`dumpex.core.va_range` already refuses to construct a range outside the
64-bit space. Profile acquisition reuses that refusal rather than
re-implementing bounds checks.

---

## §3 The P0 field matrix

Every P0 field below is frozen: its source structure, its type, what its
value means as an address, and whether the shipped parser retains it
today. `Today` is one of:

- **retained** — `parse_pe_header()` returns it in its result dict;
- **read, discarded** — the parser decodes the bytes and drops the value;
- **not read** — no shipped code reads these bytes.

Address meaning is one of exactly five kinds:

| Kind | Resolution |
|---|---|
| `n/a` | Not an address. Never resolved against anything. |
| `RVA` | Linker-assigned image-relative address. Resolve as `actual_base + value` (§2.3). |
| `mapping offset` | An offset into the mapped image that the loader maps 1:1 with the file. Same arithmetic as an `RVA`, different provenance, so it is named separately rather than being called an RVA it is not. `e_lfanew` is the only one. |
| `VA` | Already absolute. Never resolved further. |
| `file offset` | An offset into the on-disk file. **Never** resolved against `actual_base` (§2.5). Translating one to an address requires the section table and a `disk_reference` profile (§2.3). |

The `mapping offset` and `file offset` kinds are the reason this table is
closed. `e_lfanew` and `PointerToRawData` are both 32-bit offsets, and
resolving the second one the way the first is resolved yields a
plausible-but-wrong address rather than an error.

### 3.1 DOS header — component `dos_header`

| Field | Offset | Type | Address meaning | Today |
|---|---:|---|---|---|
| `e_magic` | `0x00` | `u16` (`MZ`) | n/a | retained as `has_mz` |
| `e_lfanew` | `0x3C` | `u32` | mapping offset | retained |

`e_magic` is a constant the format fixes. Its two bytes read in full and
holding anything but `MZ` make `dos_header` **`malformed`** — a
determined defect (§5.3.1), decided at §5.3's step 3, so it stands
whether or not the rest of the header through `e_lfanew` arrived. Two
bytes short of that, nothing about `e_magic` is established and §5.3's
step 2 or 4 applies as usual.

### 3.2 COFF file header — component `coff_header`

The component is **24 bytes at `e_lfanew`**: the `PE\0\0` signature at
`e_lfanew`, then the twenty COFF bytes at `e_lfanew + 4`. Field offsets
in the table below are relative to `e_lfanew + 4`.

| Field | Offset | Type | Address meaning | Today |
|---|---:|---|---|---|
| `Machine` | `+0` | `u16` | n/a | retained, plus a decoded `machine_name` |
| `NumberOfSections` | `+2` | `u16` | n/a | retained |
| `TimeDateStamp` | `+4` | `u32` | n/a | retained |
| `PointerToSymbolTable` | `+8` | `u32` | file offset | read, discarded |
| `NumberOfSymbols` | `+12` | `u32` | n/a | read, discarded |
| `SizeOfOptionalHeader` | `+16` | `u16` | n/a | read, discarded |
| `Characteristics` | `+18` | `u16` | n/a | read, discarded |

The signature is **part of this component**, not a component of its own,
and is retained as `has_pe_sig`. Its four bytes are the component's
first four, so they decide the component's state before any COFF field
does:

| The signature's four bytes | `coff_header` | `has_pe_sig` |
|---|---|---|
| None was read | `unavailable` | `null` |
| Read in part | `partial`, unread remainder as an unexamined range | `null` |
| Read in full, not `PE\0\0` | `malformed` | `false` |
| Read in full, `PE\0\0` | Decided by the twenty bytes after it | `true` |

Row 3 is a **determined defect** (§5.3.1): the four bytes it rests on
were all read, and no PE image carries anything else there, so it is
decided at §5.3's step 3 — ahead of any gap in the twenty bytes that
follow. A signature read in full and wrong is wrong whether or not the
rest of the component arrived; row 2 is what covers a signature whose own
four bytes are incomplete.

It belongs to this component rather than to one of its own for two
reasons. It carries one boolean and no fields, so a `pe_signature`
component would add a member to §5.4.1's set at every stage from 1
onward to report that boolean, and change every count in §5.4.3. And
§6.1's stage 1 reads through `e_lfanew + 24` — exactly the signature plus
the COFF header — so the two are always acquired by one read and can
never have different byte provenance (§5.1). Splitting them would create
a component that no stage acquires on its own.

`dos_header` is not the alternative: the signature is located *by*
`e_lfanew` and lies outside the DOS header's own bytes, so attributing it
there would make one component's state depend on bytes at an offset
another component supplied.

`TimeDateStamp` is a raw 32-bit value. It is the linker's claim, not a
verified time; it is never rendered as an authoritative build time and a
zero or implausible value is reported as it was read.

`Machine` is retained as the raw `u16` it was read as, always.
`machine_name` is the frozen name for the values this contract names —
`I386` `0x014c`, `IA64` `0x0200`, `ARM` `0x01c0`, `ARMNT` `0x01c4`,
`AMD64` `0x8664`, `ARM64` `0xaa64`, and `EBC` `0x0ebc` — and `null` for
every other value.

> **An unnamed `Machine` value is not `malformed`.** The raw value is
> reported, `machine_name` is `null`, and `coff_header`'s state is
> decided by §5.3 exactly as it would be for a named one.

That list is **projection scope** (§1.5), not a structural constraint:
it is the set of machines this contract assigns a name and an expected
optional-header width to (§8.4), not the set the PE format permits.
`IMAGE_FILE_MACHINE_*` is a larger and growing set — `R4000` `0x0166`,
`THUMB` `0x01c2`, `POWERPC` `0x01f0`, `M32R` `0x9041`, and `CEE`
`0xc0ee` among them — and an image carrying one of those is a legitimate
image this contract has no name for. This is §4.5's distinction applied
to a different field: `raw > MAX_DIRECTORY_COUNT` is out of scope and not
malformed for the same reason.

§1.2's `malformed` requires the decoded bytes to be structurally
impossible. An unnamed machine value contradicts nothing — not another
field, not the format — so calling it `malformed` would report a valid
image as broken, propagate that to a profile-level `malformed` (§5.4.2),
and do it again for every machine type added after this contract was
frozen. A parser's coverage would have been promoted to the format's
legal set.

**This contract names no `Machine` value that a PE image may not carry.**
If a future entry is added, it names the value and cites the format rule
that forbids it, on §5.3.1's terms — not an absence from the table
above.

`NumberOfSections` is the one COFF field this section does constrain. The
format caps an image at `_MAX_SECTIONS` sections and a loadable image
declares at least one, so a fully read value outside `1..96` is one no
image can carry, and `coff_header` is `malformed` (§1.5, §2.6). Those
two bytes are all the defect rests on, so this is the registry's second
entry and §5.3's step 3 decides it — a COFF header truncated after
`NumberOfSections` is `malformed`, not `partial`. It is also the contrast
the `Machine` rule above needs: this constraint cites the format, while a
missing name cites only dumpex.

### 3.3 Optional header, fixed fields — component `optional_header`

At `e_lfanew + 24`. Offsets are relative to that.

| Field | Offset | Type | Address meaning | Today |
|---|---:|---|---|---|
| `Magic` | `+0` | `u16` | n/a | retained as `is_pe32_plus` |
| `AddressOfEntryPoint` | `+16` | `u32` | RVA | retained |
| `BaseOfCode` | `+20` | `u32` | RVA | not read |
| `ImageBase` | `+28` / `+24` | `u32` / `u64` | VA, preferred only | retained as `image_base` |
| `SectionAlignment` | `+32` | `u32` | n/a | not read |
| `FileAlignment` | `+36` | `u32` | n/a | not read |
| `SizeOfImage` | `+56` | `u32` | n/a (byte length) | retained |
| `SizeOfHeaders` | `+60` | `u32` | n/a (byte length) | not read |
| `CheckSum` | `+64` | `u32` | n/a | not read |
| `Subsystem` | `+68` | `u16` | n/a | not read |
| `DllCharacteristics` | `+70` | `u16` | n/a | not read |
| `NumberOfRvaAndSizes` | `+92` / `+108` | `u32` | n/a | retained, capped (§2.6) |

`AddressOfEntryPoint` is an **RVA**. Its absolute address is
`actual_base + AddressOfEntryPoint` (§2.3). An entry point of `0` is a
legitimate value for some images and is reported as read, never as absent.

`ImageBase` is stored as `preferred_image_base` (§2.2) and is never used
to resolve any other field.

#### 3.3.1 Every field is bounded by `SizeOfOptionalHeader`

A field belongs to the optional header only if it fits inside the
optional header:

> A field at offset `o` of width `w` is readable only when
> `o + w <= SizeOfOptionalHeader`. Otherwise it is `unavailable`,
> whatever the acquisition buffer happens to hold at that position.

`SizeOfOptionalHeader` is a COFF field (§3.2), so it is known before any
optional-header field is read. It is not an optimization: the section
table begins at `e_lfanew + 4 + 20 + SizeOfOptionalHeader`, so every byte
past the declared size **is** section-table content. Reading one as an
optional-header field silently substitutes a section header for the field
that was asked for.

The minimum size a stage can be satisfied from follows directly:

| Needed for | PE32 | PE32+ |
|---|---:|---:|
| `Magic` alone | `2` | `2` |
| Every §3.3 fixed field | `72` | `72` |
| `NumberOfRvaAndSizes` | `96` | `112` |
| The full directory array | `224` | `240` |

A `SizeOfOptionalHeader` of `0` or `1` leaves even `Magic` unreadable.
Nothing of the component was decoded, so `optional_header` is
`unavailable`, and the profile has no pointer width — not a guessed one
(§2.4).

##### 3.3.1.1 A header too small for the format it declares

Once `Magic` **is** readable, it names a format whose fixed portion has a
fixed length: it ends at the `NumberOfRvaAndSizes` row above, at `96` for
PE32 and `112` for PE32+. A declared size below that value is not a small
header — it is a header that cannot be the format its own `Magic` says it
is.

> When `Magic` was read and `SizeOfOptionalHeader` is less than its
> format's fixed-portion size, `optional_header` is **`malformed`**.

This is one of §5.3.1's registered determined defects, on the same
terms as §4.4's: two sub-fields, both read in full, that cannot both be
true of one image.
`Magic` and `SizeOfOptionalHeader` are two bytes and two bytes, decided
before any field between them is read.

It is what keeps a partly-decoded short header from having no state it
fits. Take PE32+ with `SizeOfOptionalHeader = 20`: `Magic` and
`AddressOfEntryPoint` are inside the declared size and decode, while
`ImageBase` and `SizeOfImage` are outside it. That component is not
`unavailable` — two fields were decoded. It is not `complete` — several
P0 fields have no value. And it is not `partial`, because `partial`
requires an unexamined range (§5.2), and the bytes past offset 20 are the
section table: they were not "not looked at", they are not this
component's bytes at all. `malformed` is the only state that describes
what was found, and it is the accurate one — the image's own two
declarations disagree.

The fields that did decode are still reported. `malformed` is a state of
the component, not an erasure of its contents (§5.4.4).

Below that threshold the state is decided here and §4.5's capacity bound
never binds separately; at or above it, a header can still be too small
for its declared **array**, which is §4.4's row.

An `unavailable` field is never by itself `malformed`. A header at or
above its format's fixed-portion size that simply stops before the
directory array is entitled to; what is impossible is only the two
self-contradictions this contract names — here, and §4.4.

### 3.4 Section table — component `section_table`

`NumberOfSections` entries of forty bytes each, starting at
`e_lfanew + 4 + 20 + SizeOfOptionalHeader`.

| Field | Offset | Type | Address meaning | Today |
|---|---:|---|---|---|
| `Name` | `+0` | 8 bytes | n/a | retained, `latin1` with replacement |
| `VirtualSize` | `+8` | `u32` | n/a (byte length) | retained |
| `VirtualAddress` | `+12` | `u32` | RVA | retained |
| `SizeOfRawData` | `+16` | `u32` | n/a (byte length) | retained |
| `PointerToRawData` | `+20` | `u32` | file offset | retained |
| `PointerToRelocations` | `+24` | `u32` | file offset | not read |
| `PointerToLinenumbers` | `+28` | `u32` | file offset | not read |
| `NumberOfRelocations` | `+32` | `u16` | n/a | not read |
| `NumberOfLinenumbers` | `+34` | `u16` | n/a | not read |
| `Characteristics` | `+36` | `u32` | n/a | retained, plus decoded R/W/X |

`is_executable`, `is_writable`, and `is_readable` are decoded once from
`Characteristics` (`IMAGE_SCN_MEM_EXECUTE` `0x20000000`,
`IMAGE_SCN_MEM_WRITE` `0x80000000`, `IMAGE_SCN_MEM_READ` `0x40000000`) so
no consumer repeats the bit arithmetic.

A section name is attacker-controlled bytes. It is decoded, never
executed, never used as a path or key, and is bounded and escaped before
it reaches a terminal (§10.3).

`VirtualSize` may exceed `SizeOfRawData`; the tail has no file bytes at
all (§2.3). `SizeOfRawData` may exceed `VirtualSize` because of file
alignment. Neither is malformed.

The section table is `complete` only when all `NumberOfSections` entries
were decoded. A table cut short mid-walk is `partial` with the undecoded
entries named as an unexamined range — the shipped parser already refuses
to call such a header `valid` and marks it `insufficient_data`.

### 3.5 Relocation context — derived facts, not a component

Derived, not a structure of its own, and **not a component**: it holds no
bytes of its own, carries no state of its own, and never enters §5.4's
rollup (§3.5.2). It is the facts a consumer needs together, each
established independently:

| Field | Derived from | Today |
|---|---|---|
| `preferred_image_base` | `optional_header` | retained |
| `actual_base` | acquisition source (§2.1) | retained by the caller, not the parser |
| `relocation_delta` | both of the above | not derived anywhere shared |
| `relocs_stripped` | COFF `Characteristics` bit `0x0001` | not read |
| `dynamic_base` | `DllCharacteristics` bit `0x0040` | not read |
| `basereloc_present` | directory index 5's presence (§4.3) | presence resolved by `_resolve_directory_present()` |
| `basereloc_descriptor_state` | directory index 5 | descriptor retained; state not modelled |

Each field is independently nullable, and a `null` here is §1.3's `null`
with §1.3's single meaning: this fact was not established. Nothing is
ever guessed from a section layout, and no field is defaulted.

#### 3.5.1 Per-fact provenance

A consumer asking *why* a fact is `null` reads the state of the component
that fact's bytes belong to. The bytes are named per fact, so the answer
is always about those bytes and never about an unrelated field of the
same structure:

| Field | Established when | Component whose state explains a `null` |
|---|---|---|
| `preferred_image_base` | `ImageBase`'s own bytes were read (§3.3) | `optional_header` |
| `relocation_delta` | both bases are known (§2.2) | `optional_header`, and §2.1's source for `actual_base` |
| `relocs_stripped` | the COFF `Characteristics` bytes were read (§3.2) | `coff_header` |
| `dynamic_base` | the `DllCharacteristics` bytes were read (§3.3) | `optional_header` |
| `basereloc_present` | index 5's own `value` is read — `bytes_read >= 4` — under a captured count, or the count denies the index (§4.3) | `directory_array`, then index 5's descriptor inside `directory_descriptors` |
| `basereloc_descriptor_state` | always — index 5 has a §4.3 state in every profile | `directory_array`, then index 5's descriptor |

Four rules bind this, and no consumer may relax them:

1. **Each fact is established or `null`, on its own field's bytes.** A
   defect elsewhere in the source component erases nothing. A
   `NumberOfSections` of `200` makes `coff_header` `malformed` (§3.2)
   while `Characteristics` — a different field of the same twenty bytes,
   read in full — still decodes, so `relocs_stripped` is established.
   This is §5.4.4 applied one level down: a `malformed` component is a
   state, not an erasure of its contents.
2. **The component's state is cited, never copied.** These facts carry no
   state of their own to be weakened, so a source component's state is
   read where it lives. A projection that says why `dynamic_base` is
   `null` names `optional_header`'s state; it does not restate that state
   here as though it described this one fact.
3. **An unread flag is `null`, never a default.** `relocs_stripped` and
   `dynamic_base` come from `Characteristics` and `DllCharacteristics`
   (§11.2 lists both as new work). If either field's bytes were not read,
   that flag is `null`. Treating an unread bit as `false` would
   manufacture "relocations are not stripped" from nothing, and §8.3's
   `relocation_expected` would then compare against a fact nobody
   established.
4. **Presence is carried as presence, never inferred from a descriptor's
   state.** `basereloc_present` is §4.3's presence column for index 5,
   read in §4.3's own row order — the owning count first, then the
   descriptor's bytes. A descriptor's *state* is a different fact and
   cannot stand in for it: §4.3 answers presence once four bytes are
   read, so a `partial` index 5 can already have settled it.

   | Index 5 | `basereloc_descriptor_state` | `basereloc_present` |
   |---|---|---|
   | `declared_directory_count` is `null` | `unavailable` | `null` |
   | Denied by the count — `5 >= declared` (§4.3) | `declared_absent` | `false` |
   | `bytes_read < 4` | `partial` or `unavailable` | `null` |
   | `bytes_read` 4 to 7, `value == 0` | `partial` | `false` |
   | `bytes_read` 4 to 7, `value != 0` | `partial` | `true` |
   | `bytes_read == 8`, `value == 0` | `declared_absent` | `false` |
   | `bytes_read == 8`, `value != 0` | `complete` | `true` |

   Rows 4 and 5 are why the state is not enough. Reading "is index 5
   `declared_absent`?" would answer *no* for both, and both have already
   established the presence §8.3's `relocation_expected` asks about — an
   RVA read in full is an RVA, whatever the unread `size` after it says.
   The observation would report `unavailable`, or worse `consistent`,
   over a directory the bytes already settled.

   Row 1 is not the mirror of that, and is not a shortcut past the
   descriptor's bytes: with no captured count, nothing establishes that
   the four bytes at index 5's offset are a declared descriptor's `value`
   rather than whatever follows a shorter array (§4.3, §4.3.1). Four
   bytes read there answer nothing, and presence stays `null`.

   A `null` presence therefore has two different explanations, and rule 2
   cites whichever applies:

   | Why `basereloc_present` is `null` | The component that explains it |
   |---|---|
   | `NumberOfRvaAndSizes`'s own four bytes were not read (row 1) | `directory_array` |
   | The count includes index 5, but fewer than four of its bytes were read (row 3) | Index 5's descriptor, inside `directory_descriptors` |

   Naming only the array would be wrong for the second: a `complete`
   `directory_array` sits beside a `null` presence whenever the
   acquisition stopped between the count and index 5's `value`, and a
   consumer told to read the array's state would find nothing that
   explains the `null`.

#### 3.5.2 Why there is no aggregate state

These facts are reported individually and folded nowhere. A single state
summarising them would have to misreport, and would add nothing if it
did not.

**A fold would have to misreport or grow the vocabulary.** §1.2's five
states are defined over a component's *own bytes*, and these facts have
none. Take the three cases a fold has to answer:

| Image | The facts | What §1.2 offers a fold |
|---|---|---|
| PE32+, `SizeOfOptionalHeader = 40` | `relocation_delta` established — `ImageBase` at `+24` is inside the declared size; `dynamic_base` and index 5 `null`, since `+70` and the array are past the declared end | Nothing fits |
| PE32+, `SizeOfOptionalHeader = 1` | `relocs_stripped` established from the COFF header; every optional-header fact `null` | Nothing fits |
| `NumberOfRvaAndSizes = 200`, `SizeOfOptionalHeader = 240` | Every fact established; index 5's own eight bytes were read in full | `complete`, over an image whose array is `malformed` (§4.4) |

In the first two rows, `partial` needs a byte-precise remainder (§1.2)
and there is none to state: bytes past a declared `SizeOfOptionalHeader`
are section table (§3.3.1), so no unexamined range describes them and
none may be invented. `unavailable` means nothing was decoded, and
something was. `complete` is false. `malformed` would rest on bytes that
were never read, which §1.2's rule 3 forbids — and the second row has no
contradiction anywhere to rest on: a `SizeOfOptionalHeader` of `1` is a
small declaration, not an impossible one, and §3.3.1 already calls that
`optional_header` `unavailable` rather than `malformed`. Reaching
`malformed` there by way of a derived component would also need a
§5.3.1 entry, and the registry could not have one: every entry names
bytes of a component that holds them, and these facts hold none. A
sixth state token invented for these rows would mean only "read the
facts", which is what a consumer does anyway.

**And a fold would add nothing.** Every byte behind these facts belongs
to a component already in the rollup's scope — `coff_header`,
`optional_header`, `directory_array`, and index 5's descriptor inside
`directory_descriptors` (§5.4.1). A fact is never established on bytes
its source component did not deliver, so a fold over these facts can
never be weaker than §5.4.2's fold over those components, and §5.4.2
takes the weakest in-scope state. Adding a derived state to that rollup
therefore cannot change a single profile state, for any image. What it
can do is carry one of the states above, which is the whole of its
effect.

So the rollup folds the components that hold bytes, and the third row is
reported as what it is: established facts, beside a `malformed`
`directory_array` that the rollup already surfaces. A projection that
needs "is the relocation picture whole" answers it from the facts and
their cited components (§3.5.1), which is strictly more than one token
could say.

Two consequences are worth stating on their own:

- **An answered presence is an answer, not a gap.** An image that
  positively declares no relocation directory has answered the question,
  and that answer is exactly what §8.3's `relocation_expected` needs.
  `basereloc_present` carries it, and nothing downgrades the other facts
  for it.
- **A missing `relocation_delta` does not diminish the rest.** A profile
  that knows the BASERELOC state and both flags but not the delta has
  established three facts and says so. What the delta gates is §8.3's
  `relocation_expected`, which is `unavailable` without it under §8.1's
  own rule.

#### 3.5.3 A `disk_reference` profile

A `disk_reference` profile carries these fields like any other. Five are
file facts, established from the file's own bytes exactly as they would
be from memory. `actual_base` and the delta derived from it are the only
difference:

| Field | `disk_reference` |
|---|---|
| `preferred_image_base` | Established from `ImageBase` (§3.3) |
| `relocs_stripped` | Established from COFF `Characteristics` (§3.2) |
| `dynamic_base` | Established from `DllCharacteristics` (§3.3) |
| `basereloc_present` | Established from index 5's `value` (§4.3) |
| `basereloc_descriptor_state` | Index 5's own §4.3 state |
| `actual_base` | `null` — this source has none (§2.1) |
| `relocation_delta` | `null` — §2.2 needs both bases |

That `null` is §1.3's `null`, with no second meaning and no exception to
it. `actual_base` is a fact about where an image is loaded, a file on
disk is not loaded, and so the fact was not established — the same `null`
`module_identity.value` carries for a `memory_candidate`, which nothing
named (§2.1.1).

Nothing here is source-discriminated. There is no variant shape, no field
a `disk_reference` profile omits, and no state meaning "not applicable":
under §9's structured-output rule every field this contract defines is
emitted for every profile, with `null` for the facts that were not
established. A consumer that wants to know *why* the delta is `null`
reads `source_kind` and §3.5.1's provenance — as provenance, never as a
decoder ring for a `null` that would otherwise mean something else here.

---

## §4 Data directories

### 4.1 Descriptor shape

All sixteen indices are always represented, in index order. A descriptor
that was never captured is present with state `unavailable`, not omitted —
omission would make "not captured" indistinguishable from "not declared".

| Field | Meaning |
|---|---|
| `index` | `0..15` |
| `name` | The frozen name from §4.2 |
| `value` | The descriptor's first `u32`, or `null` |
| `value_kind` | `"rva"` for every index except `4`, which is `"file_offset"` (§2.5) |
| `size` | The descriptor's second `u32`, or `null` |
| `bytes_read` | How many of the descriptor's eight bytes were read: `0..8` |
| `state` | §1.2, resolved by §4.3 |

A descriptor is eight bytes — a `u32` value and a `u32` size — and the
two halves can land on opposite sides of where a read stopped. `state` is
therefore resolved from `bytes_read`, never from a count of
fully-decoded descriptors: a descriptor whose `value` was read and whose
`size` was not is a `partial` descriptor that already carries a fact, not
an `unavailable` one that carries none.

### 4.2 The sixteen indices

| Index | Name | `value_kind` | Notes |
|---:|---|---|---|
| 0 | `EXPORT` | `rva` | Descriptor only; export table contents unparsed. |
| 1 | `IMPORT` | `rva` | Walked today by `parse_iat()`. |
| 2 | `RESOURCE` | `rva` | Descriptor only. |
| 3 | `EXCEPTION` | `rva` | Descriptor only. |
| 4 | `SECURITY` | `file_offset` | The §2.5 exception. Never resolved against `actual_base`. |
| 5 | `BASERELOC` | `rva` | Relocation context (§3.5); walked on disk today by `apply_base_relocations()`. |
| 6 | `DEBUG` | `rva` | Descriptor only. |
| 7 | `ARCHITECTURE` | `rva` | Reserved: the format requires this descriptor's value to be zero, and its `size` too. A violation makes the descriptor `malformed` (§4.3.1); the raw value is recorded and never resolved as an address. |
| 8 | `GLOBALPTR` | `rva` | The descriptor's `size` half must be `0` per the format; its `value` is a genuine RVA. A non-zero `size` makes the descriptor `malformed` (§4.3.1); the raw value is recorded and never resolved as an address. |
| 9 | `TLS` | `rva` | Descriptor only. |
| 10 | `LOAD_CONFIG` | `rva` | Descriptor only. |
| 11 | `BOUND_IMPORT` | `rva` | Descriptor only. |
| 12 | `IAT` | `rva` | The slot-bounds range `parse_iat()` checks against. |
| 13 | `DELAY_IMPORT` | `rva` | Descriptor only. Delay-loaded imports stay out of scope. |
| 14 | `COM_DESCRIPTOR` | `rva` | CLR header descriptor only. |
| 15 | `RESERVED` | `rva` | The format requires this descriptor's value to be zero, and its `size` too. A violation makes the descriptor `malformed` (§4.3.1); the raw value is recorded and never resolved as an address. |

Index 1 and index 12 are **different directories** and are never
conflated: index 1 describes the import descriptors, index 12 describes
the address table those descriptors' slots must fall inside.

### 4.3 Descriptor state resolution

This is the shipped three-state presence rule of
`dumpex.core.pe_utils._resolve_directory_present()`, extended to the
five-state component vocabulary and resolved per descriptor from
`bytes_read` (§4.1). `declared` is `declared_directory_count` (§4.5):

| Condition | State | Presence |
|---|---|---|
| `declared is null` | `unavailable` | `null` |
| `index >= declared` | `declared_absent` | `False` |
| `bytes_read == 0` | `unavailable` | `null` |
| `0 < bytes_read < 8` | `partial` | `null` unless `bytes_read >= 4`, then `value != 0` |
| `bytes_read == 8`, `value == 0` | `declared_absent` | `False` |
| `bytes_read == 8`, `value != 0` | `complete` | `True` |

A `partial` descriptor names its unread tail as an unexamined range
(§5.2), and its `size` stays `null` — established-nothing, not
established-zero (§1.3). Once four bytes are in hand the presence
question is answered, because §4.3's own rule below is that `value` alone
decides presence; the descriptor is still `partial`, because its `size`
is not a fact yet.

Two consequences are normative:

1. A zero `value` with a non-zero `size` is still `declared_absent`. The
   `value` field alone decides presence.
2. A non-zero `value` with a zero `size` is still present. A directory
   that declares an address is declared, whatever it says about length.

A descriptor's state describes **the descriptor**. It never describes the
contents it points at. A `complete` index 2 says a resource directory is
declared at a resolvable address; it says nothing about whether those
resource bytes were captured.

#### 4.3.1 Per-index constraints

Three indices carry a format constraint of their own. A constraint is
checked only for a descriptor the image **declared**: `declared` is not
`null` and `index < declared` (§4.3's first two rows). For such a
descriptor, being fully read (`bytes_read == 8`) and violating its
constraint makes its state `malformed`, in precedence to the
`declared_absent` and `complete` rows below it:

| Index | Constraint | `malformed` when |
|---:|---|---|
| 7 | `ARCHITECTURE` is reserved **in full** — both halves zero | `value != 0 or size != 0` |
| 8 | `GLOBALPTR.size` must be zero; its `value` is a real RVA | `size != 0` |
| 15 | `RESERVED` is reserved **in full** — both halves zero | `value != 0 or size != 0` |

This is §1.2's rule 3 with no special pleading: the bytes were all read
and the value is one the format does not permit.

**The declared-first guard is not a formality.** Without it, this table
would outrank §5.3's step 1, and a count that denies the index would lose
to a constraint applied to bytes that are not a descriptor at all. Take
`declared_directory_count = 7` with eight bytes present at index 7's
offset: the image says its array ends at index 6, so those bytes are
whatever follows the array — the section table, at the sizes §4.5
computes, or another header's content. Reading a non-zero `value` there
as a violated `ARCHITECTURE` constraint would report a structural defect
from bytes the image never claimed were a directory entry. The count
denied the index first, and `declared_absent` is the answer (§5.3's
step 1).

The same guard makes `declared is null` decide alone: with no captured
count, nothing establishes that the bytes at an index's offset belong to
a declared descriptor, so the state is `unavailable` and no constraint is
evaluated.

So the two rules compose in one direction only: **the owner decides
whether there is a descriptor, and only then does this table decide
whether it is legal.**

Indices 7 and 15 are reserved descriptors, not descriptors with a
reserved address: the whole eight-byte entry is required to be zero, so a
`size` of `1` under a zero `value` violates the constraint exactly as a
non-zero `value` does. Checking only `value` would let that entry pass as
`declared_absent` — a positive claim that the directory is absent, drawn
from an entry the format says should have been all zeroes.

Index 8 is different and is the one place `size` alone decides a state:
`GLOBALPTR.value` is a genuine RVA the format permits, and only its
`size` is constrained.

A `malformed` descriptor still reports its raw `value` and `size`. What
it does not do is let a violated constraint pass as a `complete`
descriptor, which would leave a rollup calling the image whole on the
strength of a field the contract itself says is illegal. Neither does it
resolve the address: the value is recorded and never turned into a
location to read from.

A descriptor that is not fully read is never `malformed` here, however
its first four bytes look.

**No other index carries a format constraint.** The thirteen not listed
above — including index 5, which §3.5 reads as a derived fact — can
reach `unavailable`, `declared_absent`,
`partial`, or `complete`, and cannot reach `malformed`. This table is the
only source of a `malformed` descriptor state, and it is closed on the
same terms as §5.3.1's registry: a fourth index needs a format
constraint of its own, not an analogy to these three.

### 4.4 Directory array state

The `directory_array` component's state is the first matching row, over
the three bounds §4.5 defines:

| Condition | State |
|---|---|
| `NumberOfRvaAndSizes`'s own four bytes were not read | `unavailable` |
| `SizeOfOptionalHeader` was read and `raw` does not fit within it | `malformed` |
| `raw == 0` | `declared_absent` |
| fewer descriptors reached `bytes_read == 8` than `declared_directory_count` | `partial`, with the shortfall named as an unexamined range |
| otherwise | `complete` |

The `malformed` row is §1.2's rule 3 applied to a genuinely structural
constraint. The optional header's declared size is what places the
section table (§2.6), so an array that does not fit inside it overlaps
the section table — the two cannot both be where the header says they
are. That is impossible in the format, unlike a large
`NumberOfRvaAndSizes`, which is not (§4.5). Both fields were read in
full, so no gap elsewhere in the array softens it — this is one of
§5.3.1's registered determined defects, decided at §5.3's step 3.

`malformed` is assigned in addition to, not instead of, whatever
descriptors were decoded — a malformed array still reports them (§5.4).

### 4.5 How many descriptors are declared, and how many are readable

Three bounds apply, and they produce **three separate counts**. Folding
them into one number destroys the distinction between what the image
claims and what could be read of it:

| Count | Value | Answers |
|---|---|---|
| `declared_directory_count_raw` | The field exactly as read | What does the image claim? |
| `declared_directory_count` | `min(raw, MAX_DIRECTORY_COUNT)` | Of that claim, how much does this contract assign meanings to? |
| `readable_directory_count` | `min(declared_directory_count, optional_header_capacity)` | How many of those could be read from where the header puts them? |

**Only `declared_directory_count` decides `declared_absent`** (§4.3).
`readable_directory_count` decides nothing about presence; a descriptor
inside `declared_directory_count` but past `readable_directory_count`
simply has `bytes_read == 0`, which §4.3 already calls `unavailable`.

Collapsing the capacity bound into the declared count inverts the
evidence. Take `NumberOfRvaAndSizes = 16` with
`SizeOfOptionalHeader = 112` on PE32+: the capacity is `0`, a single
count would be `min(16, 0, 16) = 0`, and §4.3's `index >= declared` row
would report all sixteen directories `declared_absent` — turning a
structural contradiction into sixteen positive claims that the import
table, the relocation table, and every other directory are absent. The
image said the opposite. With the counts separated, that image is:

```text
declared_directory_count_raw = 16
declared_directory_count     = 16
readable_directory_count     = 0
directory_array.state        = malformed      (§4.4)
descriptor[0..15].state      = unavailable    (bytes_read == 0)
```

which is what the bytes support: the array's two declarations contradict
each other, and nothing was learned about any individual directory.

The three bounds themselves:

| Bound | Value | Kind |
|---|---|---|
| The image's own claim | `declared_directory_count_raw` | A fact about the image |
| The optional header's own size | `max(0, floor((SizeOfOptionalHeader - directory_array_offset) / 8))`, using §2.4's offset for the format | A fact about the image |
| dumpex's projection scope | `MAX_DIRECTORY_COUNT` | Projection scope of this contract |

The second bound is clamped at zero. An optional header smaller than the
directory array's own offset yields a negative quotient, and feeding that
into the minimum would produce a negative `declared_directory_count` —
a count of descriptors that is not a count.

The three are never conflated, because they mean different things:

- **`raw > MAX_DIRECTORY_COUNT` is not, on its own, malformed.** The PE
  format does not fix the number of data directories; it requires a
  reader to consult `NumberOfRvaAndSizes` before looking for any specific
  directory. Sixteen is the set of directories this contract assigns
  meanings to (§4.2), not a structural ceiling. An image declaring more,
  in an optional header large enough to hold them, is `complete` at
  sixteen projected descriptors, with the excess recorded as
  `unprojected_directory_count = raw - MAX_DIRECTORY_COUNT` — never as
  evidence that the image is defective, and **not** as a bounded stop
  (§1.5). Descriptors past index 15 carry no meaning this contract
  defines, so declining to project them leaves no question unanswered and
  does not make the array `partial`.
- **`raw` beyond the optional header *is* malformed** (§4.4), because
  that is a self-contradiction inside the image rather than a limit of
  this contract.

The two are independent, and the second decides. A `raw` of `200` with
`SizeOfOptionalHeader = 240` is `malformed`: 240 bytes leave room for
sixteen descriptors, so the image contradicts itself. The same `raw` of
`200` with `SizeOfOptionalHeader = 1712` is `complete` at sixteen
projected descriptors, with `unprojected_directory_count = 184` and **no
bounded stop**: the image is consistent, and only this contract's scope
ran out. Reading the first case as "over sixteen, therefore broken"
happens to reach the right answer for the wrong reason, and reaches the
wrong answer for the second.
- **A bound that holds but whose bytes were not captured is `partial`**,
  and one whose owning field was never read is `unavailable`. Neither is
  ever `malformed`.

A reader that omits the second bound reads whatever follows the optional
header as descriptors. What follows it is the section table, so the first
descriptor's `value` and `size` become the first eight bytes of a section
name. That produces `complete` directory evidence for directories that
were never declared, and sends every downstream consumer — the import
walk, the relocation walk — to an address derived from ASCII text.

The shipped `directories_complete` flag is computed from the **capped**
count and keeps its current meaning: it is the last row, and it is not a
structural-validity claim about `raw`.

---

## §5 Coverage, provenance, and component state

### 5.1 Three independent byte facts

**This subsection applies to memory-sourced profiles only.** §5.1.1 gives
the `disk_reference` equivalent. The rest of §5 applies to both, but not
all of it identically: the state-derivation order (§5.3) and the rollup
(§5.4) are source-independent, while unexamined ranges (§5.2) keep the
same *meaning* for both and take their **type** from the profile's own
address space.

Each acquisition records all three. They are never collapsed into one
number:

| Fact | Meaning | Source |
|---|---|---|
| `requested` | The span the profile asked for | `VirtualRange` |
| `captured` | The prefix of that span the dump's segment table actually backs | `CapturedSlice` |
| `read` | The contiguous run of bytes the read actually returned | `ReadSlice` |

`read <= captured <= requested`, always. `captured < requested` is a
collection gap; `read < captured` is a read failure over bytes that were
present. They have different remedies and are reported separately. The
shipped `MainImagePeClaim.captured_bytes` is today's single-number stand-in
for `read`, and it is why that claim's `checked` flag is enforced to be
true exactly when bytes were read and a parse exists.

#### 5.1.1 A `disk_reference` profile does not use these types

`VirtualRange` is defined over the **target process's virtual address
space**, and `CapturedSlice` is defined over the **dump's segment
table**. A `disk_reference` profile has neither: its offsets index a file
on disk, and its byte availability is decided by that file's length and
by the read that was issued against it, not by anything the dump
recorded.

Putting a file offset into a `VirtualRange` would construct without error
and be wrong in every use: an address formatter would render it as a
process address, a consumer could not tell the two address spaces apart
from the type, and a cache's `requested` span could silently mix them.

A `disk_reference` profile therefore carries file-offset provenance in
its own type, with the same three facts and the same independence:

| Fact | Meaning |
|---|---|
| `requested` | The file-offset span the profile asked for |
| `available` | How much of it the file actually holds |
| `read` | The contiguous run the read returned |

The type is not `VirtualRange`, is not `CapturedSlice`, and is never
compared against one. `dumpex.core.va_range` stays the single model for
the virtual-address space, and gains no file-offset mode.

### 5.2 Unexamined ranges

A component names what it did not examine, byte-precisely, in ascending
base order. `partial` is the state that requires a range and is the usual
carrier of one, but the two are separate facts: a component that is
`malformed` under a registered defect (§5.3.1) and still has unread bytes
names them here too. A range records which bytes were not looked at, and
nothing about the state beside it changes which those are.

The range type follows the profile's own address space (§5.1.1) — it is
not `VirtualRange` for every profile:

| `source_kind` | Address space | Range type |
|---|---|---|
| `peb_image_base`, `module_list_entry`, `memory_candidate` | Target-process virtual addresses | `VirtualRange` |
| `disk_reference` | File offsets | The file-offset range type of §5.1.1 |

The two are never mixed, never merged, and never compared. A file offset
placed in a `VirtualRange` would construct without error and then lie:
`[0x500, 0x1000)` of a reference file would render as a process address
in every projection that formats addresses, and would sort and overlap
against real virtual ranges as though it shared their space. A consumer
must be able to tell the two apart from the value it is handed, not from
knowing which profile it came from.

An unexamined range is a statement about **bytes**, never about contents:

> An unexamined range means dumpex did not look. It never means the image
> is intact there, and it never means the image is damaged there.

Ranges are half-open `[base, end)`, non-overlapping, and merged when
adjacent so a profile's unexamined set is canonical.

### 5.3 Deriving a component's state

For each component, in order:

1. If an owning captured field or descriptor positively denies it →
   `declared_absent`.
2. Else if no byte of the component's own bytes was read → `unavailable`.
3. Else if a **determined defect** applies — one of §5.3.1's registered
   defects, every byte it rests on read in full → `malformed`.
4. Else if some structurally required byte ran past `read` → `partial`,
   with the shortfall recorded per §5.2.
5. Else if the component's bytes are all present and decode to an
   impossible value → `malformed`.
6. Else → `complete`.

`malformed` appears twice because two different things reach it. Step 3
is a defect this contract has named, resting on bytes that were all read;
it fires whether or not other bytes of the component are missing. Step 5
is any other impossible value, and it fires only once nothing is
missing — step 4 has already taken that case.

Three of those orderings are load-bearing:

- **Step 1 precedes step 2.** A captured owner that says the component
  does not exist has answered the question, and the component's own bytes
  can neither add to that answer nor take it away — there is nothing
  there to read. The other order would call `NumberOfRvaAndSizes = 0`
  with descriptor 0 unread `unavailable`: "no evidence" about a directory
  the image positively declared absent, which is exactly the distinction
  §1.2's rule 2 exists to keep. Step 1 can never fire on a gap, because
  §1.2's rule 2 requires the owner's own bytes to have been captured
  before it may deny anything.
- **Step 3 precedes step 4.** A defect whose own bytes were all read is
  established, and bytes missing *elsewhere* in the component neither
  created it nor can soften it — §1.2's rule 3, and the same precedence
  §5.4.2 applies at the profile level, where `malformed` outranks a gap
  sitting beside it. A `PE\0\0` signature read in full and wrong is
  wrong whether or not the twenty COFF bytes after it arrived.
- **Step 4 precedes step 5.** That ordering is what keeps a truncated
  capture from being reported as a defective image: a value that merely
  *looks* impossible while the component's required bytes ran past the
  read is a gap, and only a defect §5.3.1 has named may be decided on a
  partial component.

§4.3's descriptor table is these steps applied to one descriptor, in this
order: `declared is null` is step 2 with no owner to deny anything,
`index >= declared` is step 1, and `bytes_read == 0` is step 2 again. The
first two conditions are disjoint — a denial needs a captured
`NumberOfRvaAndSizes` — so the table and these steps answer identically
for every input.

#### 5.3.1 Determined defects — the closed registry

A **determined defect** is a defect whose every byte was read in full,
so that bytes missing elsewhere in the same component neither created it
nor can soften it. Step 3 decides these, ahead of step 4's gap. This
contract registers exactly six, and they are listed here so no seventh
appears by analogy:

| Component | The bytes it rests on | Rule |
|---|---|---|
| `dos_header` | `e_magic` | §3.1 — read in full and not `MZ` |
| `coff_header` | The four signature bytes at `e_lfanew` | §3.2 — they were read and are not `PE\0\0` |
| `coff_header` | `NumberOfSections` | §3.2 — read in full and outside `1..96` |
| `optional_header` | `Magic` | §2.4 — read in full and neither `0x10b` nor `0x20b` |
| `optional_header` | `Magic`, `SizeOfOptionalHeader` | §3.3.1.1 — the declared size is below the fixed-portion size of the format `Magic` names |
| `directory_array` | `NumberOfRvaAndSizes`, `SizeOfOptionalHeader` | §4.4 — the declared array does not fit the header declaring it |

Four entries rest on one field each and two on a pair that contradicts
itself; both shapes are determined the same way, from bytes that were all
read. Three of the four single-field entries are **format constants** —
`MZ`, `PE\0\0`, and `Magic` — which is the clearest case there is: the
format fixes the value, the bytes holding it were read, and they hold
something else.

The two `optional_header` entries are ordered as §5.3.1's own list is
read: an unreadable `Magic` reaches neither, an unrecognized one reaches
the first, and a recognized one too small for its format reaches the
second (§3.3.1.1). They never disagree, because the first requires
`Magic` to be a value the second's fixed-portion size is not defined for.

Every entry satisfies the same three conditions, and a future entry must
satisfy all three:

1. Every byte the defect rests on was read **in full**, and the rule
   names those bytes, so a reader can check this condition against them.
2. What they decode to cannot be true of any PE image — a structural
   impossibility, never a limit of this contract (§3.2, §4.5).
3. The defect is decidable from those bytes alone, without any byte the
   component may still be missing.

Two things a registered defect does not do. It does not erase what
decoded: an `optional_header` that is `malformed` under §3.3.1.1 still
reports the fields that did decode (§5.4.4). And it does not absorb the
component's gaps — a `malformed` component with unread bytes still
records them as unexamined ranges (§5.2), because a range is a statement
about bytes and does not depend on the state beside it.

A component with no registered defect follows steps 1, 2, 4, 5 and 6
unchanged: its `malformed` needs every byte it requires.

### 5.4 Profile-level rollup

#### 5.4.1 The in-scope component set

The rollup folds over the components the **requested stage** was supposed
to acquire — the cumulative `Yields` of §6.1's stages `0..n`, never all
components:

| Requested stage | In-scope components |
|---:|---|
| 0 | `dos_header` |
| 1 | the above, plus `coff_header` |
| 2 | the above, plus `optional_header`, `directory_array`, `directory_descriptors` |
| 3 | the above, plus `section_table` |

A component outside the requested stage is not `unavailable`; it is not
part of the answer at all. A stage-1 acquisition that answers an identity
question completely is a `complete` profile, and stays distinguishable
from a stage-3 acquisition that failed.

One rule narrows the set further:

1. **`directory_descriptors` folds as one unit.** Its state is §5.4.2
   applied to its own sixteen members, and that single result is what
   enters the profile fold (§5.4.3.1). This is why sixteen
   `declared_absent` descriptors produce one `complete` unit, and that
   unit is the only state the descriptors contribute here.

The set is otherwise the same for every source. A `disk_reference`
profile folds these components too; what differs is the provenance and
range types its coverage is expressed in (§5.1.1), never which
components are asked for. Only components hold bytes, so only components
are folded — §3.5's derived facts are neither in this set nor missing
from it (§3.5.2).

#### 5.4.2 The fold

The profile state is the **first** matching row over the in-scope set:

| Condition | Profile state |
|---|---|
| any in-scope component is `malformed` | `malformed` |
| else any in-scope component is `unavailable` | `unavailable` |
| else any in-scope component is `partial` | `partial` |
| else | `complete` |

> `declared_absent` never participates in the fold. A positively declared
> absence is an answered component, exactly as strong an answer as
> `complete`, and it can never be the profile's own state — "this profile
> does not exist" is not a statement the rollup can make.

`malformed` outranks the two gap states deliberately. A determined
structural defect is a positive result, and hiding it behind a gap
elsewhere in the image would suppress the stronger evidence.

#### 5.4.3 Worked examples

Every row is the fold of §5.4.2 over the in-scope set of §5.4.1. The
states column is a multiset over that exact set, so the counts add up to
its size — 2 at stage 1, 5 at stage 2, and 6 at stage 3, for every
source:

| Requested stage | Source | In-scope component states | Profile state |
|---:|---|---|---|
| 3 | memory | `complete` ×6 | `complete` |
| 1 | memory | `complete` ×2 | `complete` |
| 3 | memory | `complete` ×5, `partial` ×1 | `partial` |
| 3 | memory | `complete` ×5, `unavailable` ×1 | `unavailable` |
| 2 | memory | `complete` ×3, `malformed` ×1, `unavailable` ×1 | `malformed` |
| 2 | memory | `complete` ×4, `declared_absent` ×1 | `complete` |
| 3 | disk | `complete` ×6 | `complete` |

Five rows carry the rules that this fold exists for:

- Row 1 — a structurally perfect image is `complete` ×6, with no
  `declared_absent` anywhere in the multiset, even though §4.2's indices
  7 and 15 are required by the format to be zero. Those two are
  `declared_absent` **descriptors**, and a descriptor state is a member
  state: §5.4.1's unit fold answers it, and what enters this fold is one
  `complete` `directory_descriptors` (§5.4.3.1). A member state never
  appears in this column.
- Row 2 — a deliberately staged read is a completed answer, not a failed
  one, and stays distinguishable from row 4.
- Row 5 — `malformed` outranks a gap sitting beside it.
- Row 6 — the one place a `declared_absent` legitimately enters this
  column: a captured `NumberOfRvaAndSizes` of zero makes
  `directory_array` itself `declared_absent` (§4.4), and its sixteen
  descriptors are then `declared_absent` members that fold to a
  `complete` unit. One top-level component says the array is absent; none
  of the sixteen says anything at this level.
- Row 7 — a fully parsed disk image is `complete` over the same six
  components a memory profile folds. The source changes the provenance
  types (§5.1.1) and leaves `relocation_delta` `null` (§3.5.3); it
  changes neither the in-scope set nor the fold.

##### 5.4.3.1 The two folds, and the boundary between them

The rollup runs §5.4.2 twice, over two different sets, and a state may
only ever cross from the inner one to the outer as the unit's result:

| Fold | Members | Produces |
|---|---|---|
| Inner | The sixteen descriptors (§4.1), each with its §4.3 state | One `directory_descriptors` state |
| Outer | §5.4.1's in-scope components, `directory_descriptors` among them as a single member | The profile state |

Row 1 above is the case that makes the boundary visible. A well-formed
image has `declared_absent` at indices 7 and 15 and `complete` or
`declared_absent` at the rest, so the inner fold — where
`declared_absent` does not participate (§5.4.2) — returns `complete`, and
the outer fold sees one `complete` member.

**The nesting does not change the profile state, and no rule here claims
it does.** §5.4.2 returns the weakest state present and `declared_absent`
participates in neither fold, so folding a subset first and then folding
that result with the rest gives the same answer as folding everything at
once. Flattening the sixteen descriptors into the outer fold yields the
identical profile state for every assignment of states. There is no
weighting in §5.4.2 — no state counts for more by appearing more often,
and a `partial` descriptor never outweighs or under-weighs a `partial`
section table, because neither is weighed.

What the unit rule fixes is the **representation**, and three things rest
on it:

1. **`directory_descriptors` has a state to report.** §5.4.4 and §9's
   `--verbose` surface both promise per-component states. Without the
   inner fold there is no state for the descriptors as a whole, only
   sixteen member states, and the component named in §1.2's table would
   not exist.
2. **§5.4.1's in-scope set stays the size §5.4.1 gives it** — 2, 5, 6 —
   so §5.4.3's states column is a multiset over that set and its counts
   are checkable against it. Flattened, the outer fold would run over 20
   members at stage 2 and 21 at stage 3: §4.1 keeps all sixteen
   descriptors present in every profile, `unavailable` rather than
   omitted, so the flattened count is fixed too — fixed at a number
   §5.4.1 does not define. Every worked example's counts would then be a
   multiset over a set this contract never names.
3. **A member state never stands where a component state belongs.** Row 1
   is `complete` ×6: index 7's `declared_absent` is answered inside the
   unit and does not appear in a column that enumerates §5.4.1's
   components.

Because the two arrangements agree on the profile state, no consumer can
tell them apart from the rollup token alone. The rule is about what the
profile *carries*, and it holds regardless: an implementation that
flattens produces the right summary and the wrong profile.

Nothing else in this contract nests. `directory_descriptors` is the only
component with members of its own, which is why §5.4.1 states its unit
rule there rather than as a general one.

#### 5.4.4 The rollup never replaces its components

A profile-level `malformed` does not suppress the components that did
decode. A malformed optional header and a `complete` COFF header coexist,
and both are reported. The rollup is a summary for a single console line
(§9); every consumer that needs the detail reads the component states.

---

## §6 Staged acquisition and bounded stops

### 6.1 The stages

Acquisition is staged so that a consumer needing only identity does not
pay for a full section table, and so a bounded stop is attributable to a
stage.

| Stage | Reads | Yields | Enough for |
|---:|---|---|---|
| 0 | the first `0x40` bytes of the image | `dos_header` | Is this an image at all |
| 1 | through `e_lfanew + 24` | `coff_header` | Machine, section count, timestamp, `SizeOfOptionalHeader` |
| 2 | through the optional header's fixed fields and the directory array | `optional_header`, `directory_array`, `directory_descriptors` | Bases, entry point, `SizeOfImage`, directory presence |
| 3 | through `NumberOfSections * 40` past the optional header | `section_table` | Section layout and characteristics |

The `Reads` column is expressed relative to the start of the image
because the two source families index it differently: a memory-sourced
profile reads at `actual_base + offset` (§2.3), a `disk_reference`
profile at `file_offset` (§2.1). The stages, their order, and their
yields are the same for both.

Stage 1 stops one byte short of the optional header, so it does **not**
yield PE32 versus PE32+. `Magic` is the optional header's first two bytes
at `e_lfanew + 24`, and reading it needs `e_lfanew + 26`. Pointer width
is a stage-2 fact, which is also where it is first needed: every §2.4
offset it selects is inside the optional header. A stage-1 profile
carries `is_pe32_plus` as `null`, not as a guess from `Machine` — §8.4
compares those two rather than deriving one from the other.

Stage 2 is also where §3.5's relocation facts become derivable, because
every field they read — the optional header's `ImageBase` and
`DllCharacteristics`, the COFF `Characteristics`, and descriptor index 5
— is a stage-2 field. They are not a `Yields` entry: `Yields` names the
components a stage acquires, and derived facts acquire nothing (§3.5.2).
Each is established or `null` on the bytes its own stage delivered.

Stage *n* requires stage *n-1*. A stage that cannot start because the
previous one did not complete is `unavailable`, not `malformed`.

Stages 0 through 3 fit inside the frozen `MAIN_IMAGE_PE_READ_MAX` of 4096
bytes for the overwhelming majority of real images, which is why that is
the codebase's existing single-read header budget. An image whose declared
section table extends past it is `partial` at stage 3, never invalid.

### 6.2 Bounded stops

A **bounded stop** is the acquisition ending because an acquisition
budget (§1.5) was reached, not because the image said so. Running out of
projection scope is not one, because no work was declined (§4.5).

> A bounded stop never yields `malformed`, and never *makes* a component
> `declared_absent`. A budget is a fact about dumpex; those two states are
> claims about the image.

A component may still be `declared_absent` in a profile that stopped on a
budget, when a captured owner denied it before the stop:
`NumberOfRvaAndSizes = 0` read at stage 2 leaves every descriptor
`declared_absent` under §5.3's step 1, whether or not the acquisition
then ran out of budget. That state rests on the owner's bytes, which were
captured; the stop contributed nothing to it. What a stop may never do is
turn its own shortfall into a denial.

What it *does* yield follows §5.3 from how many bytes each component
received, and is therefore `partial` or `unavailable`:

| Where the budget ran out | The affected component |
|---|---|
| Part-way through a component | `partial`, with its unread tail as an unexamined range |
| Before a component's first byte | `unavailable` — nothing of it was read |

The second row is why "a bounded stop yields `partial`" would be too
strong as a blanket rule: a stop landing exactly on a component boundary
leaves that component with no bytes at all, and §5.3 step 1 calls that
`unavailable`. The profile fold (§5.4.2) then reports `unavailable`,
which is accurate — nothing of that component was obtained — and still
carries no claim about the image, because the attribution below names the
budget responsible.

Every bounded stop is attributed: which budget, its limit, and what was
consumed — the shape `IatTruncation` already uses for the directory walk.
Unattributed truncation is not permitted, because "the walk stopped" with
no named budget is indistinguishable from a structural end.

### 6.3 Reads that straddle a boundary

A header may legitimately span two contiguous captured segments, for
instance when a protection change splits it partway through. Acquisition
therefore reads across contiguous segments rather than failing at the
first boundary; a fully present header split across two segments is a
`complete` header, not an unreadable one. This is already what
`read_region_spanning()` exists for.

---

## §7 Cache identity and reuse

### 7.1 The key

A cached profile is keyed on everything that could make two profiles
differ:

| Component of the key | Why it is in the key |
|---|---|
| Dump identity | Two dumps are never interchangeable. |
| `source_kind` | A candidate profile is not a PEB profile (§2.1). |
| `source_identity` | Which source of that kind (§7.1.1). |
| `actual_base` | The whole address model depends on it (§2.3). |
| `requested` span | A 4 KiB request and a targeted request are different evidence. |
| `requested_stage` | It selects the in-scope component set (§5.4.1), so it selects what the profile's own state means. |

**Every component of the key is known before the acquisition it guards.**
A key is computed at lookup time, so nothing an acquisition *produces*
can be part of it: not the highest completed stage, not a bounded stop
(§7.1.2), not the profile's own state. A key built from a result cannot
be used to look up that result.

`requested_stage` is what keeps two profiles apart that would otherwise
be merged. A stage-1 request that succeeded and a stage-3 request that
got no further than stage 1 share a highest completed stage of `1`, but
they asked different questions: the first is `complete` over two
components, the second `unavailable` over six, and they carry different
unexamined ranges and different bounded-stop attributions. They take
different keys, and neither answers for the other — which is what keying
on the request, rather than on how far it got, achieves.

The completed stage is **result metadata** on the cached profile:
`highest_completed_stage` says how far the acquisition got, §5.4's
component states say what was learned, and §6.2's bounded stop says why
it stopped. A consumer reads all three to judge how complete its
evidence is. The match rule reads none of them (§7.2).

#### 7.1.1 `source_identity`

`source_kind` names a **category**; it cannot tell two sources of that
category apart. Each kind therefore contributes a stable identity, and
**none of them is a string taken from the image or the filesystem**:

| `source_kind` | `source_identity` |
|---|---|
| `peb_image_base` | The constant `peb` — a process has one |
| `module_list_entry` | The entry's index in `ModuleListStream` |
| `memory_candidate` | The scanning pass's own id, plus the base address of the region the candidate was found in |
| `disk_reference` | An invocation-local ordinal, assigned when the caller supplies the reference |

Every one is an integer or a fixed token. This is not a stylistic
choice — §10.3 forbids using an attacker-controlled string as a lookup
key, and a module path, a module name, and a reference path are all
attacker-controlled. Putting one in the key would need a frozen maximum
length, a Unicode normalization form, a case rule, a separator rule, and
a collision policy for two long paths that normalize alike, and would
still let a hostile name inflate the cost of a lookup. An index costs
none of that.

Paths and names remain **evidence**: `module_identity` (§2.1) carries
them, projections display them, and observations compare them (§8). They
identify the source to a human. They do not identify it to the cache.

#### 7.1.2 What a `disk_reference` ordinal deliberately does not do

An invocation-local ordinal cannot recognize that two references name the
same file. Requesting one file by two paths yields two keys and two
acquisitions.

That is the intended trade. The failure it forgoes — reading the file
twice — costs one extra read. The failure it prevents is a wrong merge:
two different files answering for each other because their identities
collided, which is unrecoverable evidence corruption.

It also removes an obligation this contract would otherwise have to
freeze. Identifying a file by content requires hashing it, and a hash
computed to *build a cache key* runs before the lookup it guards: an
unbounded read, outside every acquisition budget in §1.5, potentially far
larger than the 4 KiB header it exists to avoid re-reading. It would also
be racy — a file modified between the hash and the header read gives a
key describing content the profile does not have.

A `disk_reference` profile therefore takes its size and its bytes from
**one file handle opened once for the invocation**, and this contract
does not hash reference files for identity. A consumer that needs
content-addressed deduplication across invocations is asking for
something this contract does not provide.

Without it the key collides in two ways that merge separately
attributable claims:

1. A contradictory `ModuleList` can carry two entries claiming different
   names at one base. Both are `module_list_entry` profiles at the same
   `actual_base`, so one consumer would receive the other's module name
   and path attached to its own bytes.
2. A `disk_reference` profile has **no** `actual_base` at all (§2.1).
   Every reference file requested over the same span at the same stage
   would otherwise share one key, and the first file read would answer
   for all of them.

Both collisions break the rule that PEB, ModuleList, PE header,
MemoryInfo, disk-reference, and candidate claims stay separately
attributable (§2.1).

A bounded stop (§6.2) is deliberately **not** a key component, for the
same reason the completed stage is not: it is something an acquisition
produces, and the key exists to be computed before the acquisition runs.
A stage that ended on a budget did not complete; that is recorded on the
profile, where §6.2's attribution needs it. Keying on the truncation
record would let two implementations build caches that miss differently
for the same request.

### 7.2 The reuse rule

> A cached profile satisfies a request when its key covers the request:
> same dump, same `source_kind` **and** `source_identity`, same
> `actual_base`, a requested span that contains the new request, and the
> same `requested_stage`. Otherwise the cache misses.

Every component of §7.1's key appears in this rule, and nothing outside
it does. A key component the match rule does not consult is not a key
component; a match criterion that is not a key component is worse, since
it makes two lookups of the same key disagree.

**An identical request reuses the cached result, whatever that result
is.** A stage-3 request whose acquisition stopped at stage 1 caches a
stage-3 profile that is `partial` or `unavailable`, and the next
identical stage-3 request is answered from it. Re-acquiring instead would
contradict §7.3, and it would do so in the worst place: the requests that
fail are the ones over damaged, truncated, or missing input, so a rule
that re-read them would multiply the cost of exactly the images that
already cost the most, and multiply it once per consumer. Nothing is
bought by the second read either — §10.2 makes acquisition deterministic
over a dump that does not change during an invocation, so it would
return the same bytes, the same states, and the same unexamined ranges.

A cached failure is evidence, not a hole to be retried. `unavailable`
records that these bytes were asked for and did not come back (§1.2); a
consumer that reads it has the answer to its question, and the answer is
that the dump does not carry them.

**Only a different question acquires again.** A request acquires when,
and only when, its key does not match:

| The new request | Result |
|---|---|
| The same key | Reuse, whatever state the cached profile carries |
| A span the cached `requested` contains, same `requested_stage` | Reuse |
| A span the cached `requested` does not contain | Miss — a new key, a new acquisition |
| A higher `requested_stage` | Miss — a question the cached profile was never asked |
| A lower `requested_stage` | Miss — §5.4.1 gives it a different in-scope set, and this contract does not re-project a cached profile onto another stage's set |

The last row is a deliberate cost: one extra read of a prefix already
read, in exchange for a profile state that always means what §5.4.1 says
it means for the stage it was asked for. A consumer that wants a stage-1
answer from a stage-3 profile reads that profile's component states,
which are per-component and unaffected by either rollup.

A partial or targeted profile is therefore never reused as full-scope
evidence — not because its acquisition fell short, but because a narrower
`requested` span and a lower `requested_stage` are a different key. This
is the one rule that prevents a narrow read taken for one consumer from
silently becoming the basis of another consumer's completeness claim.

#### 7.2.1 Choosing among covering entries

More than one cached profile can cover one request. The `requested` span
is part of the key (§7.1), so a 4 KiB acquisition and a 2 KiB
acquisition at the same dump, source, base, and stage are two entries,
and a 1 KiB request is contained by both. They may differ in
`requested`, in profile state, in `highest_completed_stage`, in
bounded-stop attribution, and in unexamined ranges, so which one answers
cannot be left to whichever the cache happens to iterate first (§10.2).

> Among the entries whose keys cover the request, the answer is the one
> with the **shortest `requested` span**; between spans of equal length,
> the one with the **lowest `base_address`**.

Those two keys are a total order over any set of candidates, so the
choice is unique and the same on every run. The tie-break is not
decoration: "contains" is a partial order, and two spans of equal length
can both contain one request at different bases, which length alone does
not separate.

Shortest-covering is the entry closest to what was asked for. It carries
the least evidence beyond the request, so the gap between what a consumer
asked for and what the profile describes is as small as the cache allows.

The chosen profile is returned **as it is**, carrying its own
`requested` span, its own states, and its own unexamined ranges — never
the narrower span that was asked for. A profile's provenance is a record
of the acquisition that produced it (§5.1); restating someone else's
request as its own would make the same bytes describe two different
requests.

### 7.3 One acquisition per invocation

Within one invocation, Recon, Report, Hunt, and PEB consumers share the
profile for a given key — a key made of what was requested and nothing
about how it turned out (§7.1), so an acquisition that fell short is
shared on exactly the terms one that succeeded is. Re-reading the same
header for a second consumer is a defect, not an optimization
opportunity — the shipped `MainImagePeClaim` already carries its parse
forward for exactly this reason, so the `--process` IAT walk consumes it
instead of reading the same bytes again.

A cache hit does not upgrade a profile. A consumer that needs a higher
stage triggers a new acquisition under a new key; it never mutates the
cached one.

---

## §8 Derived main-image consistency observations

### 8.1 What they are

A consistency observation compares two **captured** facts and reports
`consistent`, `conflict`, or `unavailable`. It is a Recon diagnostic in
the sense the Recon contract already fixes: it can never change coverage
status, can never change an exit code, and carries no verdict semantics.

### 8.2 What they may never say

`trusted`, `verified`, `clean`, `malicious`, `suspicious`, `DETECTED`, a
score, or a confidence. Structural validity is not integrity and not
benignness: a perfectly well-formed header proves the bytes parse, nothing
more.

### 8.3 The observation set

Five observations, each with a predicate a consumer can evaluate without
inventing anything. None is a finding, and a consumer renders these, it
does not recompute them.

Every one is evaluated over **established facts only**, three-valued:

| The established facts | Result |
|---|---|
| determine the predicate true | `conflict` |
| determine it false | `consistent` |
| do not determine it | `unavailable` |

"Determine" is the ordinary three-valued reading: a disjunction with one
true operand is true whatever the other is, a conjunction with one false
operand is false, and what neither settles is `unavailable`. So a
predicate may answer without every operand, and "an operand is `null`" is
not on its own an answer in either direction. §8.3.1 states each
observation's operands and short-circuits, so no implementation derives
them itself.

| Observation | Compares | Predicate |
|---|---|---|
| `base_vs_preferred` | `actual_base`, `preferred_image_base` | Never `conflict`. The delta is recorded, not flagged (§2.2). |
| `relocation_expected` | `relocation_delta`, `relocs_stripped`, `basereloc_present` | `conflict` when `relocation_delta != 0` **and** (`relocs_stripped` is true **or** `basereloc_present` is false). |
| `machine_vs_format` | `Machine`, `is_pe32_plus` | `conflict` when §8.4 defines a width for `Machine` and `is_pe32_plus` does not equal it. §8.4 defining none leaves it undetermined. |
| `entry_point_in_section` | `AddressOfEntryPoint`, section table | `conflict` when the entry point is non-zero **and** lies outside every section's mapped interval. See §8.5. |
| `size_vs_image_extent` | `SizeOfImage`, the image's captured extent | See §8.6. |

#### 8.3.1 Operands, short-circuits, and what each absence gives

| Observation | Answers from | Short-circuit | The absences, and their result |
|---|---|---|---|
| `base_vs_preferred` | Both bases | None — the predicate is constant-false | Either base `null` → `unavailable`: there is no delta to record |
| `relocation_expected` | `relocation_delta`, then `relocs_stripped` and `basereloc_present` | `relocation_delta == 0` → `consistent` on the delta alone, since a conflict needs a non-zero one; either disjunct true → `conflict` without the other | Delta `null` → `unavailable`. Delta non-zero with both disjuncts undetermined, or one false and the other undetermined → `unavailable` |
| `machine_vs_format` | `Machine`, `is_pe32_plus` | None. `EBC` relaxes the expectation to "either width" (§8.4); it does not remove the need for a width | Either operand `null`, or §8.4 names no width for the value → `unavailable` — `EBC` included |
| `entry_point_in_section` | `AddressOfEntryPoint`, then the section table | `AddressOfEntryPoint == 0` → `consistent` on the field alone (§8.5); inside a decoded section → `consistent` without the undecoded ones | Entry point `null` → `unavailable`. Non-zero and outside every *decoded* section, with the table `partial` or `unavailable` → `unavailable` (§8.5) |
| `size_vs_image_extent` | `SizeOfImage`, the mapped extent, the captured extent | None | Any of the three missing → `unavailable` (§8.6.3's first two rows) |

Exactly two rows short-circuit — the two whose Short-circuit column
names a value of their own first operand — and both are a conjunction
with that operand false: a zero `relocation_delta` and a zero
`AddressOfEntryPoint` each make their conflict impossible, so the facts
they would have been compared against cannot change the answer.
Reporting `unavailable` there would withhold an answer the established
facts already give.

`EBC` is not among them, and neither is any other relaxed expectation. A
short-circuit needs an established fact that settles the predicate;
`EBC` establishes only what the expectation *is*, leaving the comparison
still to be made against a width nobody read.

### 8.4 `machine_vs_format` — the expected optional-header width

Each `Machine` value this contract names (§3.2) has exactly one
optional-header format, except where the format itself does not
constrain it:

| `Machine` | Value | Expected |
|---|---:|---|
| `I386` | `0x014c` | PE32 |
| `ARM` | `0x01c0` | PE32 |
| `ARMNT` | `0x01c4` | PE32 |
| `IA64` | `0x0200` | PE32+ |
| `AMD64` | `0x8664` | PE32+ |
| `ARM64` | `0xaa64` | PE32+ |
| `EBC` | `0x0ebc` | unconstrained |

`EBC` is `unconstrained` rather than assigned a width: EFI Byte Code
images are produced in both forms by different toolchains, and freezing a
guess here would manufacture a `conflict` for a legitimate image. An
`unconstrained` machine therefore never makes this observation
`conflict`.

It does not make it `consistent` on its own either. "Either width is
correct" is still a claim about a width that was read: with
`is_pe32_plus` `null`, no format has been established for the
expectation to accept, and §8.3's rule gives `unavailable`. `EBC` is not
a short-circuit — it relaxes the expectation, and both operands are still
required.

A `Machine` value this contract does not name (§3.2) is a different case,
and the two are never merged:

| The `Machine` value | The expectation | The observation |
|---|---|---|
| Named, with a width | PE32 or PE32+ | `consistent` or `conflict` by comparison |
| `EBC`, `is_pe32_plus` established | Either width is correct | `consistent`, never `conflict` |
| `EBC`, `is_pe32_plus` `null` | Either width is correct | `unavailable` |
| Not named here | None is defined | `unavailable` |

The second operand of this comparison is an expectation **this contract
supplies**, not a fact read from the image. `EBC` has one — "either" — and
an observed width satisfies it, which is a positive answer. An unnamed
machine has none, so there is nothing to compare the width against, and
§8.1 makes an observation it cannot evaluate `unavailable`. Reporting
`consistent` there would claim an agreement nobody checked, and
`conflict` would claim a disagreement with an expectation that does not
exist.

### 8.5 `entry_point_in_section` — the interval and the zero case

The section interval this observation tests against is
`[VirtualAddress, VirtualAddress + VirtualSize)` — the **mapped** extent.
`SizeOfRawData` is a file-alignment fact and never bounds an in-memory
entry point (§3.4).

The **first matching row**, over both operands:

| `AddressOfEntryPoint` | `section_table` | Result |
|---|---|---|
| `null` | any | `unavailable` |
| `0` | any, including `unavailable` | `consistent` |
| non-zero, inside some **decoded** section's mapped interval | any | `consistent` |
| non-zero, inside no decoded section's interval | `complete` or `declared_absent` | `conflict` |
| non-zero, inside no decoded section's interval | `partial` or `unavailable` | `unavailable` |

Rows 4 and 5 are §8.3's three-valued rule, not a special case: an entry
point outside every section is a `conflict` only when there are no
sections left unexamined. With a `partial` table an undecoded entry could
be the one containing it, so the facts do not determine the predicate,
and §8.3 gives `unavailable`. Row 3 needs no such qualification — a hit
inside a decoded section determines the disjunction whatever the
undecoded entries hold.

An entry point of `0` is `consistent`, not a conflict and not a gap, and
row 2 says so without consulting the section table at all: the conflict
needs a non-zero entry point, so a zero one settles the predicate alone
(§8.3.1).
Resource-only DLLs and `.mui` satellite modules legitimately carry a zero
entry point and are abundant in any real module list; §3.3 already
reports the value as read rather than as absent, and flagging it here
would put a permanent, meaningless conflict line on the default console
(§9) for ordinary processes.

### 8.6 `size_vs_image_extent` — what the size is compared against

`SizeOfImage` is compared against the **union of the image's captured
segments** starting at `actual_base` — not against the single
`CapturedRegion` containing `actual_base`.

The distinction is load-bearing. A normally loaded image is split by the
loader into several regions with different protections, so the region
containing `actual_base` is usually just the header page. Comparing
against it would make every multi-section image conflict.

Telling a short capture apart from an image that really is smaller than
it declares takes **two** tables, and this observation names both:

- `enumerate_captured_regions()` — what `VirtualQuery` recorded as
  mapped, independent of what was written.
- `enumerate_captured_segments()` — what the dump actually wrote.

The mapped extent is the authority on how large the mapping is; the
captured extent is only how much of it reached the dump.

#### 8.6.1 Computing the mapped extent

Address adjacency alone does not delimit an image. A heap, a private
allocation, or the next image can sit immediately after this one, so
merging forward from `actual_base` until the first gap would swallow it.
`AllocationBase` is what actually groups one reservation, so:

1. Enumerate regions. If the enumeration reports any `skipped`
   descriptor, stop: the answer is `unavailable`.
2. Find the region containing `actual_base`. If there is none, the answer
   is `unavailable`.
3. Require that region's `allocation_base` to equal `actual_base`. If it
   is `null`, or names a different address, the answer is `unavailable` —
   the profile's base is not the start of a reservation, so what this
   observation would be measuring is not this image.
4. The mapped extent is the union of every region sharing that
   `allocation_base`. Regions with a different `allocation_base` are
   excluded however adjacent they are.
5. If that union is not contiguous, the answer is `unavailable`. A hole
   in a reservation's own region table is a table this observation cannot
   reason over.

#### 8.6.2 Computing the captured extent

1. Enumerate segments. Any `skipped` descriptor makes the answer
   `unavailable`, for the same reason as above: a descriptor the value
   model could not represent might have been the one that mattered.
2. **Discard every segment disjoint from the mapped extent.** A dump of a
   real process captures a heap, a stack, and other images; those bytes
   are outside this image and say nothing about it. Their existence is
   not a fact about this observation.
3. **Clip every remaining segment to the mapped extent**, then union the
   clipped spans. A segment that crosses the extent's boundary is clipped
   there and its inside part counts in full. Segment boundaries are the
   dump's own storage divisions and are under no obligation to line up
   with `VirtualQuery` region boundaries, so crossing one is ordinary and
   is never a conflict.
4. Only within the mapped extent does disagreement matter: **clipped
   spans that overlap each other** make the answer `unavailable`, because
   two segments claiming the same address is the segment table
   contradicting itself.

The image is **fully captured** exactly when the union of the clipped
spans equals the mapped extent. A gap inside it — a hole the dump did not
write — is a short capture, not a conflict.

> Every `unavailable` above is deliberate. This observation may report
> `conflict` only from two tables it fully understands; every gap,
> overlap, skipped descriptor, and ambiguity is a reason not to answer,
> never a reason to accuse.

#### 8.6.3 The predicate

The **first matching row**, as everywhere else in this contract that a
state is decided by a table (§4.3, §4.4, §5.3, §5.4.2):

| Condition | Result |
|---|---|
| §8.6.1 or §8.6.2 did not produce an extent | `unavailable` |
| The captured extent is shorter than the mapped extent — capture stopped | `unavailable` |
| The mapped extent is fully captured and `SizeOfImage` fits within the single region containing `actual_base` | `consistent` |
| The mapped extent is fully captured, and `SizeOfImage` exceeds that region but fits the extent | `consistent` |
| The mapped extent is fully captured and `SizeOfImage` exceeds it | `conflict` |

Rows 3 to 5 each say **fully captured** in their own condition, so none
of them overlaps row 1 — an extent that was never produced cannot be
fully captured — or row 2. Between themselves they partition what is
left: a region lies inside the extent (§8.6.1), so a declared size either
fits the base's own region, or exceeds that region and fits the whole
extent, or exceeds the extent. No two of those can hold at once. The five
are therefore mutually exclusive, and reading the table first-match or
most-specific-wins gives the same answer for every input.

Row 4 is the row that has to exist. An image mapped across several
regions legitimately declares a `SizeOfImage` larger than any one of
them, so a comparison against the region containing `actual_base` alone
would report `conflict` for an ordinary multi-region image. The extent of
§8.6.1 — every region sharing the reservation's `allocation_base` — is
what the size is measured against, and row 4 says so for the case where
the two differ.

Row 2 is deliberately the stronger claim. The mapped extent alone could
decide rows 3 and 4 without any capture at all, but reporting
`consistent` from a partial capture would say "the declared size agrees
with the mapping" when what dumpex actually holds is less than the
mapping — a completeness claim §5.1 keeps separate everywhere else.

A missing region table is `unavailable`, never `conflict`: without it
nothing establishes how large the mapping is, and a captured extent alone
cannot distinguish "the image is smaller than it claims" from "the dump
stopped writing". A short capture is likewise never a conflict — §1.2's
first rule applied to an observation: uncaptured is a gap, not a
disagreement.

### 8.7 Deferred: module identity versus header identity

Comparing a source's module name against the image's own claimed name is
**not** in the observation set. The only header facts carrying a module
name are the Export Directory's `Name` and the Debug Directory's PDB
path, and §0.2 excludes both directories' contents from parsing. Freezing
it as a mandatory observation would mandate a row that can only ever be
`unavailable`.

Adding it requires extending §0.2 first, and is a separate piece of work.

---

## §9 Projection rules

The same profile drives every surface. Projections differ in **how much**
they show, never in **what they mean**.

| Surface | Shows |
|---|---|
| Default console | Identity, format, machine, actual and preferred base, entry point, section count, profile-level state, any `conflict` observation, and an out-of-band `truncated` indication beside every shortened string |
| `--verbose` console | Additionally the full section table, all sixteen descriptors with their states, per-component states, byte provenance, unexamined ranges, and the `truncated` flag itself |
| Structured output | Every field this contract defines — including `truncated` — with `null` for every fact not established |

Four rules bind all three:

1. **No surface may show a fact the profile does not carry.** A renderer
   never re-reads memory and never recomputes a state.
2. **A hidden fact is not an absent fact.** The default console omitting
   the descriptor table is a density decision; it never renders as
   "no directories".
3. **A shortened string is never shown as a whole one.** §10.3.1 keeps
   the truncation marker out of the value because a marker inside the
   value is forgeable — which only works if every surface carries the
   flag beside the value instead. Hiding `truncated` is rule 2's case
   exactly: it asserts a string is complete, which is a claim the profile
   never made. The default console indicates it out of band — a column, a
   suffix outside the quoted value, a symbol — never by editing the
   string.
4. **Addresses are formatted, never re-derived.** Hex rendering is an
   output concern; the profile stores plain integers.

Rule 3 has a second consumer-visible consequence. §10.3.1 makes any
comparison with a truncated operand `unavailable`, so an analyst looking
at a hidden truncation would see an identity that appears complete beside
an observation that declined to evaluate, with nothing on screen
connecting the two. The flag is what connects them.

This contract does not select a schema version and does not add a field to
a schema file. It fixes the meanings a future schema addition would carry.

---

## §10 Resource and safety constraints

### 10.1 Bounds

- All arithmetic is checked 64-bit (§2.6).
- `e_lfanew` is bounded by `MAX_E_LFANEW`, an **acquisition budget**.
  Descriptors are bounded by `MAX_DIRECTORY_COUNT`, which is
  **projection scope**. Sections are bounded by `_MAX_SECTIONS`, which is
  a **structural constraint** — exceeding it is `malformed`, not a stop.
  §1.5 gives the three kinds and why they must not be interchanged.
- Directory walks are bounded by the two independent cumulative budgets
  and the per-item caps of §1.5.
- Strings are bounded by `MAX_STRING_BYTES` (§10.3.1).
- Retained records are capped, and an **acquisition budget** that binds is
  reported as a bounded stop with its attribution (§6.2), never as a
  silent shortfall. `MAX_DIRECTORY_COUNT` is the one cap here that binds
  without producing a bounded stop: nothing was declined, so the excess is
  reported as `unprojected_directory_count` instead (§4.5). It is still
  never a silent shortfall — the two differ in which record carries the
  number, not in whether one exists.

### 10.2 Determinism

Record order is structural (§1.4). Two runs over the same dump produce the
same profile, the same states, and the same unexamined ranges. Nothing in
acquisition depends on dict insertion order, iteration order of a set, or
wall-clock time.

### 10.3 Hostile input

Every string a profile carries — section names, module identity — is
attacker-controlled. It is decoded with replacement rather than raised
on, escaped before it reaches a terminal, and never used as a filesystem
path, a lookup key, or a format string. Acquisition never raises on
malformed input: an unrepresentable value yields a state, not an
exception.

#### 10.3.1 The length bound, frozen

"Bounded in length" is not a rule an implementation can follow. The bound
is:

| Rule | Value |
|---|---|
| Limit | `MAX_STRING_BYTES` = `4096` |
| Counted in | UTF-8 **bytes** of the decoded string, not code points and not UTF-16 units |
| On exceeding | Keep the prefix that fits; never split a code point, so the kept prefix may be shorter than the limit |
| Recorded as | A `truncated` flag on the field itself |

Bytes rather than characters, because the cost being bounded is memory
and hashing, and a code point can occupy four bytes. Prefix rather than
elision, because a prefix is still evidence of what the string began
with. A flag rather than an ellipsis character, because a marker inside
the value is itself attacker-forgeable: a name ending in `…` must not be
indistinguishable from one dumpex shortened.

`4096` matches `dumpex.core.memory.MAX_HANDLE_STRING_BYTES`, the
codebase's existing ceiling for one dump-derived string, so a profile
does not introduce a second length regime.

Two consequences are normative:

1. **A truncated string is never compared.** Two identities that agree on
   4096 bytes and differ after are not equal, and no §8 observation may
   report `consistent` from one. A comparison with a truncated operand is
   `unavailable`.
2. **A truncated string never becomes an identity.** It cannot reach a
   cache key in any case (§7.1.1), and it must not be used to match a
   module either — `resolve_module_by_base()`-style name matching against
   a truncated name is a match on a prefix, not on a name.

`normalize_windows_path()` deliberately does not truncate: it stores
evidence verbatim. The bound here belongs to the profile that carries the
string onward, not to that normalizer.

The lookup-key half of that rule is what §7.1.1 implements: every
component of the cache key is an integer or a fixed token, so no bound,
normalization form, or collision policy for hostile strings is needed to
make the cache correct. A string that never enters a key needs no
truncation rule to be safe in one.

### 10.4 Evidence boundary

Acquisition reads captured dump bytes only. It never consults the live
system, never opens the image on disk unless the caller explicitly
supplied a `disk_reference` source, and never reaches the network.

---

## §11 What exists today and what is new work

### 11.1 Available now, no new parsing

`parse_pe_header()` already retains: `has_mz`, `has_pe_sig`, `e_lfanew`,
`machine`, `machine_name`, `time_date_stamp`, `is_pe32_plus`,
`number_of_sections`, `size_of_image`, `address_of_entry_point`,
`image_base`, the full section table, the captured data directories,
`declared_directory_count`, `directories_complete`, `valid`, `reason`,
and `insufficient_data`.

Consumers project **different subsets** of that dict, each carrying only
what its own output needs:

| Consumer | Fields | Notably omits |
|---|---:|---|
| `process_info.MainImagePeFacts` | 4 | Everything but the directory facts, `is_pe32_plus`, and `insufficient_data` |
| `hunt.injection.models.PeHeaderInfo` | 7 | Sections, data directories, `e_lfanew`, raw `machine`, `time_date_stamp`, `size_of_image` |
| `hunt.encoding.models.PeHeaderInfo` | 15 | `declared_directory_count`, `directories_complete`, `insufficient_data` |
| `hunt.stomping.models.SectionRef` | Per-section only | Every image-level field |

No consumer projects the whole dict, and no two project the same subset.
A shared profile therefore replaces four projections with different
shapes, not one common one — which is the migration cost, and the reason
§12 keeps every existing projection's fields intact rather than assuming
they can be swapped for a superset.

`_resolve_directory_present()` already implements the three-state presence
resolution §4.3 builds on. `read_region_spanning()` already implements
§6.3. `dumpex.core.va_range` already provides §5.1's three byte facts.

### 11.2 New parsing required

| Need | Where it comes from |
|---|---|
| `relocs_stripped` | COFF `Characteristics`, currently decoded and discarded |
| `SizeOfOptionalHeader` as a retained fact | COFF header, currently decoded and discarded |
| `dynamic_base` | Optional header `DllCharacteristics`, not read |
| `SizeOfHeaders` | Optional header, not read |
| `Subsystem`, `SectionAlignment`, `FileAlignment`, `CheckSum`, `BaseOfCode` | Optional header, not read |
| Raw `NumberOfRvaAndSizes` before capping | Currently only the capped value survives |
| Per-section relocation and line-number fields | Section header, not read |

All of these are additional fields decoded from bytes the current staged
read already covers. None requires a new read.

### 11.2.1 `SizeOfOptionalHeader` is not applied today, at either level

`parse_pe_header()` bounds every optional-header read by `len(data)`
alone — never by `SizeOfOptionalHeader`. Both §3.3.1's field-level bound
and §4.5's array-level bound are therefore not merely unretained; they
are not applied. The field-level half is the more damaging of the two.

#### 11.2.1.1 Field level

Each §3.3 field is read at its fixed offset regardless of where the
optional header was declared to end, so a declared size shorter than the
offset reads section-table bytes as that field. A PE32+ image declaring
`SizeOfOptionalHeader = 20` with one `.text` section parses as `valid`
and yields:

```text
address_of_entry_point = 0x1000              (inside the declared size)
image_base             = 0x200000000074      (section-header bytes)
size_of_image          = 0x60000020          (the section's Characteristics)
```

`size_of_image` is the section's `Characteristics` field read as a length;
`image_base` spans the boundary between two section headers. Neither is a
value the image ever declared.

These are not inert fields. `image_base` is `preferred_image_base`
(§2.2), so it feeds the relocation delta that
`dumpex.hunt.stomping`'s disk-reference comparison normalizes with;
`size_of_image` and `address_of_entry_point` reach
`dumpex.hunt.injection`'s hidden-PE evidence and
`dumpex.hunt.encoding`'s PE classification; and `is_pe32_plus` and the
directory facts reach `MainImagePeClaim`, and through it the `--process`
IAT walk. A corrupted value here is not a wrong number in a report — it
is a wrong address another component reads from.

#### 11.2.1.2 Array level

An optional header declaring `SizeOfOptionalHeader = 112` with
`NumberOfRvaAndSizes = 16` places, for PE32+, the directory array exactly
at the byte after the optional header ends — which is the first byte of
the section table. Today that image parses as `valid`, reports
`directories_complete` true, and projects sixteen descriptors read out of
section headers. Descriptor 0's `value` and `size` come back as the first
eight bytes of the first section's name.

Applying either bound is production work with a behavior change, and is
out of scope here (§0.2). `tests/unit/test_pe_profile_contract_doc.py`
pins the current behavior at both levels — including the two corrupted
values above, by their exact numbers — so the change is visible the
moment it is made.

### 11.3 New correlation required

`relocation_delta`, every §1.2 component state, the §4.1 per-descriptor
`bytes_read`, the §5.2 unexamined-range set, §7's cache key and
`source_identity`, and every §8 observation are new derived work. None of
them re-reads memory; all are computed from an acquisition's own bytes
and the source's own claims.

### 11.4 Not required by this contract

Directory **contents** for indices other than 1 and 12, Authenticode
verification, disassembly, and raw-file reconstruction stay out of scope
(§0.2).

### 11.5 Name bridge — `image_base` means two different things today

This contract names the two base facts `preferred_image_base` and
`actual_base` (§2.2). Shipped code spells both `image_base`, in one
module:

| Contract name | Today's spelling |
|---|---|
| `preferred_image_base` | `parse_pe_header()`'s result key `image_base` — the header's own declared preference |
| `actual_base` | `parse_iat(read, image_base, pe)`'s `image_base` **parameter** — the address the image is actually loaded at |

Passing `pe['image_base']` into `parse_iat()` would satisfy the parameter
name and read every thunk at the wrong address for any relocated image.
Nothing today reaches that: `MainImagePeFacts` deliberately does not
carry `image_base`, and `--process` passes
`snapshot.peb_claim.image_base_address`. A `memory_candidate` profile has
no PEB base and constructs its `actual_base` itself, which is where the
collision becomes reachable, so it is recorded here. Renaming is
production code and out of scope (§0.2).

### 11.6 Vocabulary bridge — the shipped main-image states

`--process` already ships a frozen, exit-code-bearing main-image
vocabulary from `_classify_main_image_state()`. The two vocabularies
coexist on one record (§12), so the mapping is fixed here rather than
left to each consumer. `short` and `io_short` are
`ReadSlice.is_short` / `ReadSlice.is_io_short` (§5.1):

| Shipped state | `checked` | `valid` | `insufficient_data` | Component state |
|---|---|---|---|---|
| `null` | — | — | — | No profile is acquired at all — no `actual_base` to acquire one from |
| `read_failed` | `False` | — | — | `unavailable` for every component |
| `short_read` | `True` | `False` | `True` | `partial` when `io_short` is false; `unavailable` when the read returned nothing past a component's start |
| `pe_invalid` | `True` | `False` | `False` | `malformed` for the component that rejected — never for the whole profile unless §5.4's fold reaches it |
| `ok` | `True` | `True` | `False` | `complete` for every in-scope component |

Two rules govern the coexistence:

1. **The three `PROCESS_MAIN_IMAGE_*` limitation codes stay the sole
   authority for coverage and exit codes.** The profile's own state is
   descriptive and never changes a coverage status or an exit code.
2. **`insufficient_data` alone cannot split `partial` from
   `unavailable`.** That split needs §5.1's three byte facts, because
   `captured < requested` and `read < captured` have the same
   `insufficient_data` value and different remedies. A consumer that has
   only the shipped flag reports `partial` and says so.

One case diverges, and it is named here so no consumer derives either
state from the other. An `e_lfanew` past `MAX_E_LFANEW` is a
deterministic rejection to `parse_pe_header()`, so `insufficient_data` is
false and the shipped state is `pe_invalid`. §2.6 makes the same image a
bounded stop, so its `dos_header` is `complete`, every later component is
`unavailable`, and the profile folds to `unavailable` — a long DOS stub
is legal, and the limit reached was dumpex's own. Both are correct within
their own vocabulary: the shipped state answers "will re-reading these
bytes help?" and the profile state answers "is the image defective?" —
and neither answers `partial`, which is what a blanket "a bounded stop
yields `partial`" would have claimed. The
`PROCESS_MAIN_IMAGE_PE_INVALID` limitation stays authoritative for
coverage under rule 1.

### 11.7 Behaviour bridge — an unnamed `Machine` is a rejection today

`parse_pe_header()` stops at an unrecognized `Machine`: it retains the
raw value, sets `machine_name` to `null`, and then returns `valid:
False` with a `reason` of `unrecognized Machine field` and
`insufficient_data` false. Under §11.6's mapping that is `pe_invalid` —
a structural defect — and every field after `NumberOfSections` is left
unparsed.

§3.2 does not say that. The canonical profile keeps the raw value,
leaves `machine_name` `null`, decides `coff_header` by §5.3, and reads
the remaining seventeen bytes of the COFF header like any other image.
Aligning the shipped parser is new work, listed here rather than in
§11.2 because it changes a decision, not a field that is read:

| Today | Canonical |
|---|---|
| `valid: False`, `reason: unrecognized Machine field` | `coff_header` decided by its bytes, with `machine_name` `null` |
| Parsing stops before the optional header | Parsing continues; §8.4's observation is `unavailable` |
| `pe_invalid` (§11.6) for a legitimate `POWERPC` or `THUMB` image | No state derived from the name being absent |

Until that work lands, a consumer reading the shipped dict must not
promote this rejection to a canonical `malformed`: the flag says the
parser has no name for the machine, which §3.2 makes a limit of dumpex's
projection rather than a fact about the image. This is the second named
divergence between the two vocabularies, on the same terms as §11.6's
`MAX_E_LFANEW` case — dumpex's own limit reported as though the format
had been violated.

---

## §12 Compatibility

- Schema v2.13 and the current `--process` behavior are preserved.
  `main_image_pe` and `iat` keep their shipped shapes and their §3.4.4 and
  §3.5 semantics.
- The injection, stomping, and obfuscation PE projections keep their
  current fields. Their existing wire content does not shrink.
- Historical schemas stay frozen. This contract adds no field to any
  schema file and selects no schema version.
- A future implementation may add fields; it may not redefine a field this
  contract has already defined, and it may not narrow a state's meaning.

Structure and vocabulary checks for this document live in
`tests/unit/test_pe_profile_contract_doc.py`, which binds the frozen
constants, the directory table, and the "available now" field list to the
shipped parser rather than to this document's prose.
