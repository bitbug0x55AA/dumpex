# SOC / DFIR Quick Start

A field guide for reading `dumpex --hunt` output as a triage analyst —
what the fields mean, what to do (and not do) with each result, and what
each hunter can and cannot actually tell you. This is not a tool
reference (see the [CLI Reference](CLI_REFERENCE.md) for flags); it's a
disposition guide.

## Minimum viable workflow

```bash
python -m dumpex sample.dmp --hunt all --json result.json --case-id CASE-1234 --analyst your-handle
```

`--hunt all` runs every TTP hunter and prints a summary table plus a
per-TTP deep dive. `--json` captures the same result as structured data —
carry that file forward into the case record; it's what the rest of this
guide is about reading correctly. Add `--redact-paths` before sharing
the JSON outside your own
machine — see [Evidence handling](#evidence-handling-hashes-reproducing-a-run) below.

Module Stomping's score-producing check needs a reference DLL/EXE
directory (`--ref-dir DIR`) to run at all — see
[Module Stomping](#module-stomping) below before concluding a "no
stomping" result actually checked anything.

## Reading recon evidence (`--process`, `--handles`)

Recon commands report what the dump **recorded at capture time**. They
never query a live process, and nothing they print should be read as a
statement about the machine you are running on.

Two console conventions are worth knowing before you read either
command's output:

- **`--verbose` changes the console only.** The records, coverage,
  limitation codes and exit code are identical with and without it, so
  `--json` is always the complete inventory. If a console line says
  something is "not shown", it is still in the JSON.
- **`(unnamed)` and `(unreadable)` are different facts.** `(unnamed)`
  means the descriptor records no name — nothing was lost. `(unreadable)`
  means a name should have been there and the bounded read failed —
  evidence was lost, and it is reported as a coverage limitation.

`--handles` folds anonymous rows — every row whose descriptor recorded no
object name — into per-type counts, naming each type and its exact count,
and tells you how many it folded; run it again with `--verbose` for the
full inventory. Anonymous `Process`, `Thread`, `Token`, `Section` and `Job`
handles are never folded — those are the ones a cross-process access
question turns on. A name like `\KnownDlls` is a real NT Object Manager
**directory**, not a filesystem path; the descriptor records the
directory's name, and the objects inside it are not in the dump.

`--process --verbose` prints the import table as
`IAT Slot VA -> Resolved Target VA` — where the import pointer is
stored, and what is stored there — followed by an `Identity
Verification` block that states, per check, whether the PEB and
ModuleListStream agreed (`[OK]`), conflicted (`[!!]`), or could not be
compared (`[--]`). **A conflict is an observation, not a verdict.** A
PEB/ModuleList disagreement is a lead worth pulling, and it is also
something benign software produces; use `--hunt hollowing` and
`--hunt injection` for the questions that carry a disposition.

## The four fields that matter

`--json` wraps every hunter's result in dumpex's shared v2.12
envelope: `result.kind` is `"hunt"`, and each hunter you selected gets
its own entry in `result.data.records[]` (`hunter` names which TTP —
`injection`, `hollowing`, `stomping`, `pipe`, `cs-beacon`, `yara`, or
`obfuscation`). Every entry reports `status`, `coverage.status`, and
`verdict_level`. Six of the seven (all but `yara`) additionally report
`confidence` and structured `findings` — `yara` reports its own
`matches`/`rules_hit` shape instead, under `details` (see
[YARA](#yara-yara) below). Read these in this order:

| Field | Values | What it answers |
|---|---|---|
| `status` | `DETECTED` / `NOT_DETECTED_IN_SCANNED_SCOPE` / `INCONCLUSIVE` / `NOT_EVALUATED` | Did this hunter find something, and did it actually get to look? |
| `coverage.status` | `complete` / `partial` / `not_evaluated` | How much of what it was supposed to scan did it actually get through? |
| `verdict_level` | `clean` / `possible` / `likely` / `high` / `inconclusive` / `not_evaluated` | The hunter's own severity read on its own result — always mirrors `status` when `status` isn't `DETECTED`/`NOT_DETECTED_IN_SCANNED_SCOPE`. |
| `confidence` | `none` / `low` / `medium` / `high` | How much weight to put on the *strongest* individual finding, independent of how many were found. |

**`status` and `coverage.status` are orthogonal.** A hunter can have
`status: DETECTED` and `coverage.status: partial` at the same time — it
found a genuine, verified hit in the part of the dump it *could* check,
while some other part (another module, another region) couldn't be
checked at all. That is not a weaker detection; it means there could be
more you haven't seen yet. Check `coverage.reasons` for exactly what
was skipped.

This same `status`/`coverage.status`/`verdict_level` shape also drives
`result.coverage.status` (the run-wide rollup across every hunter you
selected) and, from there, the process exit code — see
[Exit codes](#exit-codes-for-scripting) below.

## Disposition by status combination

| `status` | `coverage.status` | What actually happened | What to do |
|---|---|---|---|
| `DETECTED` | `complete` | Found something; every eligible region/section/segment was checked | Escalate per your normal process for that TTP |
| `DETECTED` | `partial` | Found something real, but *other* parts of the dump were unreadable/skipped/unavailable | Escalate — the finding stands — **and** re-run with whatever would close the gap (`--ref-dir`, a dump captured with `MiniDumpWithHandleData`, ...) before declaring the rest of the dump clean |
| `NOT_DETECTED_IN_SCANNED_SCOPE` | `complete` | Ran to completion, found nothing | Genuinely clean *for this TTP, in this scope* — see the [scope disclaimer](#scope-disclaimer) below |
| `INCONCLUSIVE` | `partial` | Ran, but hit read failures / oversized regions / missing sub-streams / a missing required input (e.g. no `--ref-dir`), and found nothing in what it *did* see | Not a clean result — treat as "didn't finish looking," not "looked and it's fine." Address the coverage gap and re-run if practical. |
| `NOT_EVALUATED` | `not_evaluated` | The hunter never ran at all — a required stream was missing from the dump (wrong capture flags, truncated dump, ...) | This TTP was **not checked**. Don't fold it into an overall "clean" summary. |

`verdict_level` is never `clean` when `status` is `INCONCLUSIVE` or
`NOT_EVALUATED` — if you see `verdict_level: inconclusive` or
`not_evaluated`, that is the tool telling you it could not verify a
clean result, not a milder form of "clean."

### Closing an oversized-region coverage gap

When a hunter skipped memory for exceeding its scan size cap, the
`SCAN_REGION_OVERSIZED_SKIPPED` entry in `result.coverage.limitations[]`
names each skipped region/segment under `targets[]` — virtual address,
size, dump-file offset, and (for a MemoryInfo region) allocation
base/state/type/protection. Work the gap from there:

1. `type: "MEM_PRIVATE"` with an executable `protection` is worth looking
   at first; a large `MEM_MAPPED`/heap region usually is not.
2. `file_offset: null` means those bytes were never written to this dump
   at all — no local extraction will recover them, so recollect with
   broader capture coverage.
3. Otherwise pull the region directly:
   `dumpex suspect.dmp --extract <base_address> --size <size>`, or
   `--strings <base_address>`, and rescan the extracted file with YARA or
   another tool.

`affected_count` equals the number of entries in `targets[]`. For
`--hunt obfuscation`, each limitation's `scope` names the scan layer
(`sleep_mask`/`entropy`/`decode`) whose own cap did the skipping — the
same physical region can appear under more than one layer, so
deduplicate on `targets[*].base_address` before counting regions. The
console prints the first few targets and points at `--json` for the
rest; the JSON list is always complete.

## Skipped-target investigation queue (hunt all)

`--hunt all` automates the manual workflow above: `result.summary.
investigation_actions` is a deduplicated, priority-ordered list built
from the coverage metadata every hunter already collected — **no
additional bytes are read from the dump to build it.** One physical
region/segment skipped by several hunters or scan layers is one entry,
with every `(hunter, source, scope, cause)` that skipped it listed under
`skipped_by`. It is only ever populated for `--hunt all`; a single-hunter
run (`--hunt pipe`, `--hunt stomping`, ...) always shows `[]` here — see
the two single-hunter examples below.

Each entry:

- `priority` (`low`/`medium`/`high`) and `priority_reason_codes` are
  derived from two independent, deterministic facts: the target's own
  MemoryInfo facts (`PRIVATE_EXECUTABLE_MEMORY`/`RWX_PROTECTION`) and
  whether it was skipped by more than one scope or coincides with an
  existing multi-hunter `CORRELATED REGIONS` entry
  (`MULTIPLE_SCOPES_SKIPPED`/`CORRELATED_REGION_EVIDENCE`).
- `evidence_availability` (`captured`/`not_captured`) is a **separate**
  axis from priority — it only says whether the bytes are in this dump
  file at all (`targets[].file_offset` not null). A `not_captured`
  target is not thereby more suspicious; it means the next step is
  recollection, not extraction.
- `triage` records what analysis actually ran — by default (no
  `--triage-skipped`) always `{"mode": "metadata", "status": "completed",
  "bytes_examined": 0, "region_fully_examined": false,
  "content_reason_codes": [], "findings": [], "finding_count": 0,
  "findings_truncated": false}`, the schema-enforced proof that this
  default pass never reads region content.
- `recommended_actions` are structured action objects
  (`inspect_metadata`/`extract_captured_range`/`targeted_hunter_rescan`/
  `recollect_dump`/`preserve_artifact`/`chunked_analysis`), not prose or a
  shell command — a renderer may turn `targeted_hunter_rescan.hunters` +
  the target's own `base_address`/`size` into a real
  `--extract`/`--strings` invocation itself.
- `coverage_effect` is always `"original_hunter_gap_not_resolved"`: this
  queue is advisory. It never upgrades a hunter's own `score`,
  `verdict_level`, or `coverage.status` — only a real rerun of the
  hunter that skipped the target (not yet automated) closes that gap.

The console mirrors this as a bounded `SKIPPED TARGET ACTIONS` section
in the `HUNT SUMMARY` card (priority-ordered, capped with an omission
notice pointing at `--json`); `--verbose` only expands how much of each
entry's own already-computed detail is shown — it never changes which
entries exist, their order, or anything in `--json`.

### Reading a deep-triaged entry (`--triage-skipped`)

`--hunt all --triage-skipped` performs a REAL, budgeted content read of
each queue entry above — reusing `--report`'s own triage collector under
an explicit per-target/whole-run/target-count budget, never `--report`'s
own unbounded (up to 256 MiB per region) default. This is genuinely more
expensive than the default pass, which is why it's opt-in: expect real,
bounded additional I/O time proportional to the queue.

`triage.mode` becomes `"deep"` and `triage.status` tells you what
actually happened:

| `status` | Meaning |
|---|---|
| `completed` | The whole target was read (`region_fully_examined: true`). |
| `partial` | Fewer bytes than requested were actually in the dump — a real evidence gap, not a policy choice. |
| `clamped` | Deep triage's own budget (per-target cap, whole-run cap, or target-count cutoff) intentionally stopped the read short. |
| `unreadable` | The read itself failed. |
| `not_captured` | Same meaning as the metadata pass — the bytes were never captured, so nothing was attempted. |
| `budget_deferred` | The whole-run budget or target-count cutoff was already exhausted by higher-priority targets before this one was reached. |

`triage.content_reason_codes` is the structured SUMMARY of what the read
itself found in the examined bytes: `IOC_PATTERN_STRING_MATCH`,
`NETWORK_PATTERN_STRING_MATCH`, `MZ_HEADER_DETECTED` (an MZ header at the
read's own start), and/or `INJECTED_PE_HEADER` (that MZ header CONFIRMED
to sit in memory not backed by any known module — a strictly stronger
fact; if module classification itself is unavailable, e.g. no
`ModuleListStream`, only `MZ_HEADER_DETECTED` is reachable, and it still
surfaces rather than being silently dropped). **Read
`content_reason_codes: []` as "no generic indicators in the examined
bytes" — never as "clean."** A generic string/header scan is not the
hunter-specific logic (pipe's C2 pattern matching, YARA's rule set,
obfuscation's decode attempts, ...) that originally skipped this target;
it cannot substitute for a real targeted rescan of that hunter, and
`coverage_effect` stays `"original_hunter_gap_not_resolved"` regardless
of what the deep read found.

`triage.findings` is the actual EVIDENCE behind that summary — up to 20
entries, each either an `ioc_string` (with `offset`/`encoding`/`value`,
the matched text truncated to 256 characters/`is_network_pattern`) or an
`mz_header` (with `module_context`). Treat a populated `findings` (or
`content_reason_codes`) as a lead to pull on with `--report --report-addr
<base_address>` (for the full triage card, complete string text, and
hexdump context), not as a finished disposition.

When a target produces more than 20 findings, the array does not simply
stop at whichever 20 came first in memory offset order — it fills
representative-first: the MZ finding (if any) first, then one
network-pattern IOC finding, then one plain IOC finding, then the rest in
offset order up to the cap. That way a code in `content_reason_codes`
(e.g. `NETWORK_PATTERN_STRING_MATCH`) is never left with zero backing
evidence just because 20+ plain IOC hits happened to come first.
`triage.finding_count` is the TRUE total the read produced (before that
cap); `triage.findings_truncated` is `true` exactly when `finding_count`
is larger than `findings.length` — check it before assuming `findings`
is the complete picture for a string-dense target.

A target whose `status` is anything other than `completed` also gets a
`chunked_analysis` entry appended to `recommended_actions` — the queue's
own way of saying "this needs a follow-up read beyond what the budgeted
pass covered."

The console mirrors `triage.findings` too, not just the reason-code
summary: each entry with a real signal prints up to 3 representative
findings by default (the actual IOC value/address/encoding, or the MZ
finding's own `module_context`) — `MZ_HEADER_DETECTED` and
`INJECTED_PE_HEADER` each get their own distinct wording, never the raw
enum name. `--verbose` expands that preview to every retained finding
(still at most 20). If the read actually produced more findings than
the JSON's 20-entry cap kept, a `Showing 20 of 47 deep-triage findings.`
line appears either way — that's a data-level truncation
(`finding_count` vs. `len(findings)`), independent of `--verbose`'s own
console-only preview cap.

## CORRELATED REGIONS (console and TXT output only)

`--hunt all`'s printed `HUNT SUMMARY` card can end with a `CORRELATED
REGIONS` section, listed after `OTHER HUNTERS` and before `NEXT
INVESTIGATION`. It appears only when **two or more different hunters**
each found real evidence that resolves to the exact same normalized
memory region — the same `(BaseAddress, RegionSize)` pair from the
dump's own MemoryInfo list. `--txt` is a plain-text copy of the console
output, so whatever you see there is exactly what lands in the `.txt`
file too.

What it means, and what it doesn't:

- **It is a location fact, not a verdict.** Two hunters landing on the
  same region says their evidence is co-located in memory — nothing
  about *why*. It never changes any hunter's own `score`, `confidence`,
  `verdict_level`, or `coverage.status`, and it is not itself scored.
  Keep reading each hunter's own `status`/`verdict_level` for the actual
  disposition.
- **It requires genuinely different hunters.** One hunter with several
  pieces of evidence in one region does not produce an entry here — that
  is normal for a single detection, not a correlation.
- **Same allocation is not the same region.** A single `VirtualAlloc`
  call is routinely split into several MemoryInfo sub-regions after
  `VirtualProtect` (a header page, a reprotected code page, a guard
  page, ...). This section keys strictly on each sub-region's own
  `BaseAddress`/`RegionSize` — two hunters that only share an
  `AllocationBase` are not correlated; the sub-region's own base address
  is shown as `Region`, with the shared allocation (when known) shown
  separately as supplementary context under `Allocation`.
- **No entry doesn't mean no malicious evidence.** It only means no
  *reliable, same-region* overlap was found between two different
  hunters — every hunter's own individual findings above this section
  (in `REVIEW FIRST`/`NEEDS ATTENTION`) still stand on their own and
  need the same triage attention whether or not anything correlates.

This section never appears in `--json`/`--csv` — it is a `--hunt all`
console/`--txt` presentation convenience only, never part of
`result.data.records`, `schema_version`, or any finding id. If you're
carrying `--json` forward into a case record per the workflow above,
re-derive any region-level correlation you need from the structured
`details` fields already in that JSON yourself.

## Exit codes for scripting

`--hunt`'s process exit code is derived from `result.coverage.status` —
the same coverage-based convention every other v2-routed command uses —
so a SOC script checking `$?` right after `dumpex ... --hunt all` can
detect incomplete coverage without parsing JSON at all:

| Exit code | `result.coverage.status` | Meaning |
|---|---|---|
| `0` | `complete` | Every selected hunter's evidence was fully covered — findings (if any) are still yours to disposition, but nothing was skipped |
| `3` | `partial` | At least one selected hunter had a coverage gap (a stream was unreadable, `--ref-dir` was missing, a scan budget was hit, ...) — re-run to close the gap before treating this as a full sweep |
| `4` | `not_evaluated` | No selected hunter could evaluate at all (e.g. every required stream is missing from the dump) |

This is independent of whether `--json` was even passed — a bare
`dumpex sample.dmp --hunt all` still exits `0`/`3`/`4` accordingly. It is
also independent of whether anything was actually *detected*: a fully
clean, fully covered run still exits `0`; a `DETECTED` result with a
coverage gap elsewhere in the same `--hunt all` run exits `3`, not `0` —
exit code tracks *coverage*, not *verdict*. Always read the JSON
`status`/`verdict_level` fields for the actual disposition; use the exit
code only to gate "was this a complete look."

**`possible` is a triage priority, not an attribution.** It means one
uncorroborated signal was observed — worth a human look, not a
conclusion. Don't write "possible injection" into a report as if it were
confirmed; write what the specific finding's `facts`/`inference`/
`rationale` actually say (see below).

## Reading a Finding

Where a hunter reports structured findings (each entry's own `findings`
array in `result.data.records[]` in JSON),
each entry has five fields — read all five before acting on any one of
them:

- `facts` — what was directly observed (addresses, sizes, hashes,
  protection flags). Not a judgment call.
- `inference` — the claim this specific finding supports.
- `confidence` — `low` / `medium` / `high` for *this* finding.
- `rationale` — why that confidence and not another; what would raise or
  lower it.
- `limitations` — known gaps or caveats specific to this finding.

`tag` distinguishes an `observation` (raw signal — entropy, a bare
string match — never scored on its own) from a `lead` (suggestive,
unverified) from a `detection` (structurally corroborated; the only tag
that can drive a nonzero score). A hunter's overall `confidence` field is
the highest confidence among its own `detection`-tagged findings — it is
never inflated by a hunter's own `score`/`max_score` arithmetic.

Each finding also carries seven fields for feeding a SIEM/case-management
pipeline directly, without hand-mapping this shape onto a generic alert
first:

- `id` — deterministic (a 128-bit hash covering check, rule id, rule
  version, tag, confidence, technique ids, evidence refs, iocs, and
  facts, unambiguously encoded so two findings that differ in ANY of
  those — not just facts — get different ids; 128 bits of SHA-256 is
  collision-resistant for genuinely different content, not an absolute
  "never collides" guarantee), so re-running `--hunt` against the same
  dump reproduces the same id — safe to use as a re-scan dedup key
  for THAT dump. It is content-only, not evidence-scoped: two dumps that
  happen to produce byte-identical hashed fields (check, rule id, rule
  version, tag, confidence, technique ids, evidence refs, iocs, and
  facts — e.g. the same malware family hitting the same address on two
  different hosts, with the same rules.yaml in effect) get the SAME id
  on purpose. If you need a key that's unique across dumps/cases, combine it with
  `meta.evidence[].sha256` from the same document (e.g.
  `sha256(evidence_sha256 + finding_id)`) — do not treat `id` alone as
  globally unique.
- `severity` — `info` / `low` / `medium` / `high` / `critical`, always
  derived from `tag` + `confidence` — a producer cannot set it
  independently, and the schema itself pins the exact mapping (see
  `dumpex-output-v2.12.schema.json`'s own `finding.allOf`, unchanged since v2.5): every
  `observation` is `info`; every `lead` tops out at `medium`; only a
  `detection` at `confidence: high` reaches `critical`.
- `technique_ids` — MITRE ATT&CK technique/sub-technique IDs (e.g.
  `"T1559.001"`), populated only where a hunter has an actual mapping to
  attach (today: `pipe`'s own `rules.yaml`-driven framework matches) —
  empty, not guessed, everywhere else.
- `evidence_refs` — structured pointers (e.g. a region or thread
  reference) into that hunter's own `details` object, for cross-
  referencing this finding against the fuller evidence there.
- `iocs` — indicator-of-compromise values (an IP, a beacon pipe name)
  this finding's facts embed, when a hunter has extracted one.
- `rule_id` / `rule_version` — detection-logic provenance. `rule_id`
  defaults to `check`; `rule_version` stays `null` unless a real
  versioned rule source produced this specific finding — for a
  `rules.yaml`-driven finding (today: `pipe`'s framework matches) this is
  that ruleset's own *content* sha256 (`meta.rules.sha256`), never
  `rules.yaml`'s own top-level `version:` field, which is a format/schema
  version that doesn't change when a pattern or MITRE mapping does.

## Per-hunter evidence requirements and limits

### Process Injection (`injection`)

Requires `MemoryInfoListStream` and/or `ThreadInfoListStream` to run at
all; `ModuleListStream` and `ThreadListStream` (for live RIP/EIP) are
needed for full coverage — their absence is reported in
`coverage.reasons`, not silently ignored. Score 3 ("high") requires a
thread's *current* RIP/EIP to execute inside an allocation that
independently carries both RWX protection and a structurally-validated
hidden PE header. Score 1 ("possible") means raw signals (RWX regions,
an MZ-prefixed region) exist but never converged on one allocation and no
thread executes inside one — this is the tier most likely to be a JIT
engine, a debugger, or a legitimate self-modifying-code use case, not
injection.

### Module Stomping (`stomping`)

**The only scored signal requires `--ref-dir`.** Without it, `score` is
always `0` and `status` is `INCONCLUSIVE` — this is not a clean result,
it means the verified content-diff check never ran. The reference file
you supply must match the **exact same build** as what's loaded in the
dump: Machine type, `SizeOfImage`, and `TimeDateStamp` are checked before
any byte comparison runs, and a mismatch on any of those causes the
comparison to be skipped for that module (reported as a coverage gap,
not a false negative) rather than risk comparing against the wrong
build. In practice this means the reference DLL/EXE needs to come from
the **same OS build/architecture/patch level** as the process that was
dumped — a reference file pulled from a different Windows version or
service pack will not match and the module will show as unverified, not
clean.

Relocation (ASLR) normalization is only performed for **x86/x64**
(`I386`/`AMD64`) modules using the standard `HIGHLOW`/`DIR64` fixup
types; if normalization can't be completed for a section that needs it
(unsupported machine type, a malformed relocation table), that section's
comparison is aborted rather than compared unnormalized (which would
misreport ordinary relocation as tampering) — it's counted under a
`coverage.limitations[]` entry with `code: "STOMPING_RELOCATION_FAILED"`.

score 1 ("possible" as of the current wording) is a verified,
relocation-normalized byte difference with **no** corroborating live
execution in the changed range — this is deliberately reported as
neutral "verified module code modification," not "stomping," because a
legitimate hotpatch or an EDR inline hook can produce the exact same
signature. score 2 ("high") additionally requires a thread's current
RIP/EIP to execute inside the changed bytes.

The **IOC-string scan** over executable `MEM_IMAGE` regions is an
unscored lead, and it skips any region larger than 5 MB; a region it
tries to read but gets fewer bytes back than declared is a separate gap
(`code: "SCAN_REGION_SHORT_READ"` — the readable prefix is still scanned,
so a real hit there still shows up, but the region isn't fully covered).
Either way the check reports `INCOMPLETE` instead of `CLEAN`, and a
`coverage.limitations[]` entry (`source: "ioc_string_scan"`; oversized
skips additionally carry `code: "SCAN_REGION_OVERSIZED_SKIPPED"` with
each region's VA, size, protection, and dump-file offset, so you can
`--extract`/`--strings` it or hand the address to another scanner) names
the gap.

`coverage.status` for this gap is normally `partial`: a score-0 run is
`INCONCLUSIVE`, not `NOT_DETECTED_IN_SCANNED_SCOPE`, and a detection is
still `DETECTED` with `coverage.status: partial` telling you the
supporting IOC evidence may be under-reported. The one exception: if
`ModuleListStream` is missing from the dump, the hunter as a whole is
`NOT_EVALUATED` (its scored content-diff check needs that stream and
never runs) — the IOC scan only needs `MemoryInfoListStream`, so it can
still run and still find a real gap, which is reported as a
`coverage.limitations[]` entry alongside the otherwise-unrelated
`NOT_EVALUATED` result rather than silently dropped.

### Named Pipe C2 / Lateral Movement (`pipe`)

The primary, scored signal is a **handle object** from `HandleDataStream`
— proof the process actually opened that pipe (as opposed to the bytes
`\pipe\...` merely existing somewhere in memory, which could be freed
heap, a copy-pasted string, or unrelated data). `HandleDataStream` is
only present in a dump captured with `MiniDumpWithHandleData`; without
it, `coverage.status` is `partial` and only unscored string leads are
available. A bare string match on its own is always reported as a
`tag: lead`, low-confidence finding and never contributes to score.

### Cobalt Strike Beacon (`cs-beacon`)

A decoded, structurally-valid config (TLV wire format, a recognized
`BeaconType`, an ASN.1-shaped public key) is score 1 ("likely") on its
own — finding *more* configs does not raise this; the count is reported
as a fact (`config_count`), not folded into confidence. Score 2 ("high")
additionally requires independent memory-context corroboration: the
enclosing region is executable+private memory, or a thread's current
RIP/EIP executes within the same allocation as the config.

**A decoded config does not prove the beacon is currently, actively
calling out.** It proves a beacon payload existed in this process's
memory at (or before) dump time. Whether it was maintaining live network
callbacks at the moment of capture cannot be established from static
memory content alone — dumpex does not report a dormant/live activity
label for exactly this reason. The reported CS version is an *estimate*
derived from the highest recognized config field ID, not a confirmed
build fingerprint.

### Obfuscation / Encoded Payloads (`obfuscation`)

Shannon entropy, a Base64-looking run, and a bare GZIP magic byte are
always reported as `tag: observation` and never drive score on their
own — all three occur naturally in legitimate compressed/encoded data.
The only scored signals are a confirmed CS Sleep Mask XOR decode and a
validated structural PE payload (real DOS/COFF/optional headers, not
just a file-type guess).

### Process Hollowing (`hollowing`)

Same shape as injection/stomping/pipe/cs-beacon/obfuscation above:
`status`/`coverage.status`/`verdict_level`/`confidence`/structured
`findings` are always present. DETECTED requires the MEM_PRIVATE anchor
correlated with either a missing/wiped MZ header or RWX protection at the
image base — a single anomaly alone (including a bare MZ-wipe) is a
`tag: lead`, not a detection. A failed read of the image base's MZ header
(not just a missing region) is its own coverage gap and yields
`coverage.status: partial` / `status: INCONCLUSIVE`, not a false CLEAN.

### YARA (`yara`)

Reports `status`/`coverage.status`/`verdict_level` like every other
hunter, but **not** `confidence`/structured `findings`/`lead_count`/
`review_priority` (all `null` on its `result.data.records[]` entry) — it
uses its own `matches`/`rules_hit` model instead, under `details` (see
[Output and Evidence Schema](OUTPUT_SCHEMA.md#json-schema)). Treat
`details.matches`, `details.rules_hit`, and `coverage` itself (per-gap-
reason detail: rule compile failures, unread/short-read/oversized
segments, `match()` timeouts/failures, the hit cap, and the whole-scan
time/byte budget) as the source of truth for what actually ran. A
`PE_In_Private_Memory` hit is only a confirmed detection when it's
corroborated as private memory by ModuleList or MemoryInfo; with neither
source available the hit is `context_unverified` and the result is
INCONCLUSIVE rather than a confirmed DETECTED.

## Evidence handling: hashes, reproducing a run

`--json` output carries `meta.evidence` as an array — one entry per dump
dumpex analyzed. Single-dump commands use `role: "primary"`; `--diff` is
the only command with two entries. For
`dumpex suspect.dmp --diff clean-reference.dmp`, `suspect.dmp` has
`role: "target"` and `clean-reference.dmp` has `role: "baseline"`. Each
entry's `sha256` is
computed by streaming the dump file (never loaded fully into memory),
deterministic over file content only. The same dump file produces the
same hash regardless of which command or how many times you run it, so
it's safe to use as the evidence identifier in a case record.
`meta.execution` records the exact options used (`command`, a curated set
of the relevant CLI flags) and UTC `started_at`/`finished_at`/
`duration_seconds` timestamps, plus whatever `--case-id`/`--analyst` you
passed. `meta.rules` records which `rules.yaml` actually produced any TTP
verdicts (path, content hash, whether it was an explicit `--rules-file`
override) — useful if `rules.yaml` changes later and you need to know
exactly what ruleset produced a given finding.

Pass `--redact-paths` before sharing a `--json` result outside your own
machine — it reduces each `meta.evidence[].path` and any `--ref-dir`/
`--yara-dir`/`--rules-file` path down to their basename, so the JSON
doesn't leak local usernames or directory layout. It never changes
console or `--txt` output.

A failure computing any one piece of metadata (e.g. the dump became
unreadable between opening it and writing `--json`) never aborts the
write or discards completed analysis — that piece gets an `"error"`
string in its own place instead.

### Sanitized `--json` examples

Both examples below are complete, valid v2.12 documents — each validates
as-is against `dumpex-output-v2.12.schema.json` (see
`tests/integration/test_soc_quickstart_json_examples.py`, which extracts
these exact fenced blocks and validates them in CI, so this doc can't
silently drift out of sync with the schema again). A real `--hunt all`
run's `result.data.records` always has exactly 7 entries, one per hunter
in a fixed order (`injection`, `hollowing`, `stomping`, `pipe`,
`cs-beacon`, `yara`, `obfuscation`) — that full-envelope shape is long
enough that showing it here would bury the point, so instead these are
two genuine single-hunter runs (`--hunt pipe`, `--hunt stomping`), each
with `summary.hunter_count: 1` and one matching record. Every command's
`meta.execution.options` always carries `hunt`/`yara_dir`/`ref_dir`/
`rules_file`/`triage_skipped` together, regardless of which hunter was
selected (see `_build_options()` in `dumpex/cli.py`) — both examples show
all five. `summary.investigation_actions` (the default, metadata-only
skipped-target queue — see [Skipped-target investigation queue](#skipped-target-investigation-queue-hunt-all)
below) is only ever populated for `--hunt all`; both single-hunter
examples below correctly show it as `[]`.

#### `--hunt pipe` — a genuine, fully-covered detection

```json
{
  "meta": {
    "schema_version": "2.13",
    "tool": { "name": "dumpex", "version": "<installed version>" },
    "execution": {
      "started_at": "2026-03-14T09:12:01Z",
      "finished_at": "2026-03-14T09:12:02Z",
      "duration_seconds": 1.114,
      "command": "hunt_pipe",
      "options": { "verbose": false, "hunt": "pipe", "yara_dir": null, "ref_dir": null, "rules_file": null, "triage_skipped": false },
      "case_id": "CASE-1234",
      "analyst": "your-handle"
    },
    "evidence": [
      {
        "id": "primary",
        "role": "primary",
        "file_name": "sample.dmp",
        "size_bytes": 214748364,
        "sha256": "3a7bd3e2360a3d..."
      }
    ],
    "runtime": { "python_version": "3.11.9", "minidump_version": "0.0.24" }
  },
  "result": {
    "kind": "hunt",
    "execution_status": "completed",
    "coverage": { "status": "complete", "reasons": [] },
    "summary": {
      "selected": "pipe",
      "hunter_count": 1,
      "detected_count": 1,
      "inconclusive_count": 0,
      "not_evaluated_count": 0,
      "overall_status": "DETECTED",
      "highest_verdict_level": "high",
      "lead_count": 0,
      "investigation_actions": []
    },
    "data": {
      "records": [
        {
          "hunter": "pipe",
          "score": 3,
          "max_score": 3,
          "status": "DETECTED",
          "verdict_level": "high",
          "confidence": "high",
          "lead_count": 0,
          "review_priority": "high",
          "coverage": { "status": "complete", "reasons": [] },
          "findings": [
            {
              "id": "finding-7a60fc5e1e2838a5ed86a9032de79892",
              "check": "pipe.corroboration",
              "tag": "detection",
              "severity": "critical",
              "confidence": "high",
              "facts": ["handle=0x88 pipe=\\Device\\NamedPipe\\msagent_1337 rip_hit=true"],
              "inference": "OS-confirmed pipe handle corroborated by both nearby C2-context and live RIP execution.",
              "rationale": "Handle object plus proximate, live execution — the strongest signal this hunter produces.",
              "limitations": [],
              "technique_ids": [],
              "evidence_refs": [],
              "iocs": [],
              "rule_id": "pipe.corroboration",
              "rule_version": null
            }
          ],
          "details": {
            "handle_pipes": [
              { "handle": "0x88", "pipe_name": "\\Device\\NamedPipe\\msagent_1337",
                "granted_access": "0x0012019f", "rip_hit": true }
            ],
            "private_pipes": [],
            "c2_context": [
              { "name": "\\.\\pipe\\msagent_1337",
                "region": { "base_address": "0x0000000001230000", "size": 4096 },
                "records": [{ "match": "http://", "va": "0x0000000001230116" }] }
            ],
            "framework_pipes": [],
            "unbacked_in_rgn": []
          }
        }
      ]
    }
  },
  "artifacts": [],
  "diagnostics": { "warnings": [] }
}
```

`result.coverage.status: "complete"` (mirroring the one selected
hunter's own `coverage.status`) is what makes this run exit `0` — see
[Exit codes](#exit-codes-for-scripting) above.

#### `--hunt stomping` — scored `0` for a coverage reason, not a clean result

```json
{
  "meta": {
    "schema_version": "2.13",
    "tool": { "name": "dumpex", "version": "<installed version>" },
    "execution": {
      "started_at": "2026-03-14T09:14:01Z",
      "finished_at": "2026-03-14T09:14:02Z",
      "duration_seconds": 0.842,
      "command": "hunt_stomping",
      "options": { "verbose": false, "hunt": "stomping", "yara_dir": null, "ref_dir": null, "rules_file": null, "triage_skipped": false },
      "case_id": "CASE-1234",
      "analyst": "your-handle"
    },
    "evidence": [
      {
        "id": "primary",
        "role": "primary",
        "file_name": "sample.dmp",
        "size_bytes": 214748364,
        "sha256": "3a7bd3e2360a3d..."
      }
    ],
    "runtime": { "python_version": "3.11.9", "minidump_version": "0.0.24" }
  },
  "result": {
    "kind": "hunt",
    "execution_status": "completed",
    "coverage": {
      "status": "partial",
      "reasons": ["--ref-dir not supplied — verified content comparison (the only scored signal) was not performed for any module"]
    },
    "summary": {
      "selected": "stomping",
      "hunter_count": 1,
      "detected_count": 0,
      "inconclusive_count": 1,
      "not_evaluated_count": 0,
      "overall_status": "INCONCLUSIVE",
      "highest_verdict_level": "inconclusive",
      "lead_count": 0,
      "investigation_actions": []
    },
    "data": {
      "records": [
        {
          "hunter": "stomping",
          "score": 0,
          "max_score": 2,
          "status": "INCONCLUSIVE",
          "verdict_level": "inconclusive",
          "confidence": "none",
          "lead_count": 0,
          "review_priority": "none",
          "coverage": {
            "status": "partial",
            "reasons": ["--ref-dir not supplied — verified content comparison (the only scored signal) was not performed for any module"]
          },
          "findings": [],
          "details": { "protection_leads": [], "verified_changes": [] }
        }
      ]
    }
  },
  "artifacts": [],
  "diagnostics": { "warnings": [] }
}
```

`options.ref_dir: null` here is deliberate — `--ref-dir` was never
passed on this run, which is exactly why `coverage.reasons` says
"not supplied" and `score` stayed `0`. That coverage gap is also what
makes this run exit `3`, not `0` — re-run with `--ref-dir` before
treating this hunter as clean. `score: 0` here does **not** mean
"nothing to report" the way it might for a hunter that ran to completion
and found nothing — `status: INCONCLUSIVE` is what marks the difference
from a genuine `NOT_DETECTED_IN_SCANNED_SCOPE` clean result.

## Scope disclaimer

**"Dumpex found nothing" is not the same claim as "this host is clean."**
Every result above is scoped to exactly what a hunter actually scanned in
this one dump: the TTPs `dumpex` implements, the streams present in this
particular capture, and the coverage that capture allowed. It cannot see
what wasn't captured (a narrower `MiniDumpWriteDump` flag set, a process
that had already exited, activity that happened before or after the
capture window), and a clean result for one TTP says nothing about the
others. Treat a full `--hunt all` run with every `status` at
`NOT_DETECTED_IN_SCANNED_SCOPE` and `coverage.status: complete` as "no
indicators found in what could be checked here" — one input to a broader
investigation, not a certification.
