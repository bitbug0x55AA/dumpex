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
guide is about reading correctly. Add `--csv output/` alongside `--json`
if you want per-table CSVs for a SIEM/spreadsheet import; both draw from
the same underlying result, so they will never disagree with each other
or with the console output on `status`/`verdict_level` for the same
finding. Add `--redact-paths` before sharing the JSON outside your own
machine — see [Evidence handling](#evidence-handling-hashes-reproducing-a-run) below.

Module Stomping's score-producing check needs a reference DLL/EXE
directory (`--ref-dir DIR`) to run at all — see
[Module Stomping](#module-stomping) below before concluding a "no
stomping" result actually checked anything.

## The four fields that matter

Every hunter (`injection`, `hollowing`, `stomping`, `pipe`, `cs-beacon`,
`yara`, `obfuscation`) reports `status`, `coverage_status`, and
`verdict_level`. Six of the seven (all but `yara`) additionally report
`confidence` and structured `findings` — `yara` reports its own
`matches`/`rules_hit` shape instead (see [YARA](#yara-yara) below). Read
these in this order:

| Field | Values | What it answers |
|---|---|---|
| `status` | `DETECTED` / `NOT_DETECTED_IN_SCANNED_SCOPE` / `INCONCLUSIVE` / `NOT_EVALUATED` | Did this hunter find something, and did it actually get to look? |
| `coverage_status` | `complete` / `partial` / `not_evaluated` | How much of what it was supposed to scan did it actually get through? |
| `verdict_level` | `clean` / `possible` / `likely` / `high` / `inconclusive` / `not_evaluated` | The hunter's own severity read on its own result — always mirrors `status` when `status` isn't `DETECTED`/`NOT_DETECTED_IN_SCANNED_SCOPE`. |
| `confidence` | `none` / `low` / `medium` / `high` | How much weight to put on the *strongest* individual finding, independent of how many were found. |

**`status` and `coverage_status` are orthogonal.** A hunter can have
`status: DETECTED` and `coverage_status: partial` at the same time — it
found a genuine, verified hit in the part of the dump it *could* check,
while some other part (another module, another region) couldn't be
checked at all. That is not a weaker detection; it means there could be
more you haven't seen yet. Check `coverage_reasons` for exactly what
was skipped.

## Disposition by status combination

| `status` | `coverage_status` | What actually happened | What to do |
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

**`possible` is a triage priority, not an attribution.** It means one
uncorroborated signal was observed — worth a human look, not a
conclusion. Don't write "possible injection" into a report as if it were
confirmed; write what the specific finding's `facts`/`inference`/
`rationale` actually say (see below).

## Reading a Finding

Where a hunter reports structured findings (`findings["findings"]` in
JSON, the `finding_details` table in CSV), each entry has five fields —
read all five before acting on any one of them:

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

## Per-hunter evidence requirements and limits

### Process Injection (`injection`)

Requires `MemoryInfoListStream` and/or `ThreadInfoListStream` to run at
all; `ModuleListStream` and `ThreadListStream` (for live RIP/EIP) are
needed for full coverage — their absence is reported in
`coverage_reasons`, not silently ignored. Score 3 ("high") requires a
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
misreport ordinary relocation as tampering) — it's counted under
`coverage_counts.relocation_failed`.

score 1 ("possible" as of the current wording) is a verified,
relocation-normalized byte difference with **no** corroborating live
execution in the changed range — this is deliberately reported as
neutral "verified module code modification," not "stomping," because a
legitimate hotpatch or an EDR inline hook can produce the exact same
signature. score 2 ("high") additionally requires a thread's current
RIP/EIP to execute inside the changed bytes.

### Named Pipe C2 / Lateral Movement (`pipe`)

The primary, scored signal is a **handle object** from `HandleDataStream`
— proof the process actually opened that pipe (as opposed to the bytes
`\pipe\...` merely existing somewhere in memory, which could be freed
heap, a copy-pasted string, or unrelated data). `HandleDataStream` is
only present in a dump captured with `MiniDumpWithHandleData`; without
it, `coverage_status` is `partial` and only unscored string leads are
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
`status`/`coverage_status`/`verdict_level`/`confidence`/structured
`findings` are always present. DETECTED requires the MEM_PRIVATE anchor
correlated with either a missing/wiped MZ header or RWX protection at the
image base — a single anomaly alone (including a bare MZ-wipe) is a
`tag: lead`, not a detection. A failed read of the image base's MZ header
(not just a missing region) is its own coverage gap and yields
`coverage_status: partial` / `status: INCONCLUSIVE`, not a false CLEAN.

### YARA (`yara`)

Reports `status`/`coverage_status`/`verdict_level` like every other
hunter, but **not** `confidence`/structured `findings`/`lead_count`/
`review_priority` — it uses its own `matches`/`rules_hit` model instead
(see [Output and Evidence Schema](OUTPUT_SCHEMA.md#json-schema)). Treat
`matches`, `rules_hit`, and the `coverage` sub-object (per-gap-reason
booleans: rule compile failures, unread/short-read/oversized segments,
`match()` timeouts/failures, the hit cap, and the whole-scan time/byte
budget) as the source of truth for what actually ran. A
`PE_In_Private_Memory` hit is only a confirmed detection when it's
corroborated as private memory by ModuleList or MemoryInfo; with neither
source available the hit is `context_unverified` and the result is
INCONCLUSIVE rather than a confirmed DETECTED.

## Evidence handling: hashes, reproducing a run

`--json` output carries a `meta.evidence.sha256` — computed by streaming
the dump file (never loaded fully into memory), deterministic over file
content only. The same dump file produces the same hash regardless of
which command or how many times you run it, so it's safe to use as the
evidence identifier in a case record. `meta.execution` records the exact
options used (`command`, a curated set of the relevant CLI flags) and
UTC `started_at`/`finished_at`/`duration_seconds` timestamps, plus
whatever `--case-id`/`--analyst` you passed. `meta.rules` records which
`rules.yaml` actually produced any TTP verdicts (path, content hash,
whether it was an explicit `--rules-file` override) — useful if
`rules.yaml` changes later and you need to know exactly what ruleset
produced a given finding.

Pass `--redact-paths` before sharing a `--json` result outside your own
machine — it reduces `meta.evidence.path` and any `--ref-dir`/
`--yara-dir`/`--rules-file` path down to their basename, so the JSON
doesn't leak local usernames or directory layout. It never changes
console, `--txt`, or `--csv` output.

A failure computing any one piece of metadata (e.g. the dump became
unreadable between opening it and writing `--json`) never aborts the
write or discards completed analysis — that piece gets an `"error"`
string in its own place instead.

### Sanitized `--json` example

```json
{
  "meta": {
    "schema_version": "1.1",
    "tool": { "name": "dumpex", "version": "3.0.1" },
    "execution": {
      "started_at": "2026-03-14T09:12:01Z",
      "finished_at": "2026-03-14T09:12:03Z",
      "duration_seconds": 2.114,
      "command": "hunt_all",
      "options": { "verbose": false, "hunt": "all", "ref_dir": "./ref_dlls" },
      "case_id": "CASE-1234",
      "analyst": "your-handle"
    },
    "evidence": {
      "file_name": "sample.dmp",
      "size_bytes": 214748364,
      "sha256": "3a7bd3e2360a3d..."
    },
    "runtime": { "python_version": "3.11.9", "minidump_version": "0.0.24" }
  },
  "hunt": {
    "pipe": {
      "score": 3,
      "max_score": 3,
      "status": "DETECTED",
      "verdict_level": "high",
      "confidence": "high",
      "coverage_status": "complete",
      "coverage_reasons": [],
      "findings": [
        {
          "check": "pipe.corroboration",
          "tag": "detection",
          "confidence": "high",
          "facts": ["handle=0x88 pipe=\\Device\\NamedPipe\\msagent_1337 rip_hit=true"],
          "inference": "OS-confirmed pipe handle corroborated by both nearby C2-context and live RIP execution.",
          "rationale": "Handle object plus proximate, live execution — the strongest signal this hunter produces.",
          "limitations": []
        }
      ]
    },
    "stomping": {
      "score": 0,
      "max_score": 2,
      "status": "INCONCLUSIVE",
      "verdict_level": "inconclusive",
      "confidence": "none",
      "coverage_status": "partial",
      "coverage_reasons": ["--ref-dir not supplied — verified content comparison (the only scored signal) was not performed for any module"]
    }
  }
}
```

Note the two results above side by side: `pipe` is a genuine, fully-
covered detection; `stomping` scored `0` for an entirely different
reason (it never got the reference files it needed) — the `status`/
`coverage_status` pair is what tells them apart, not `score` alone.

## Scope disclaimer

**"Dumpex found nothing" is not the same claim as "this host is clean."**
Every result above is scoped to exactly what a hunter actually scanned in
this one dump: the TTPs `dumpex` implements, the streams present in this
particular capture, and the coverage that capture allowed. It cannot see
what wasn't captured (a narrower `MiniDumpWriteDump` flag set, a process
that had already exited, activity that happened before or after the
capture window), and a clean result for one TTP says nothing about the
others. Treat a full `--hunt all` run with every `status` at
`NOT_DETECTED_IN_SCANNED_SCOPE` and `coverage_status: complete` as "no
indicators found in what could be checked here" — one input to a broader
investigation, not a certification.
