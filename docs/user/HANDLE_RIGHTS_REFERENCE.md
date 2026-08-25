# Handle Access Rights Reference

This reference explains how to read the access-right names printed by
`dumpex --handles`. For the command syntax and output options, see the
[CLI Reference](CLI_REFERENCE.md). For investigation workflow, see the
[SOC / DFIR Quick Start](SOC_QUICKSTART.md).

## Captured evidence and console projection

The JSON `granted_access` field is the raw integer captured in the handle
descriptor. Human-readable rights are derived console text; they never replace
or alter the captured mask.

`--verbose` changes only console presentation. The full handle inventory,
coverage, limitations, raw access masks, and summary remain identical in JSON.

The default console folds routine anonymous handles into exact per-type counts.
Anonymous `Process`, `Thread`, `Token`, `Section`, and `Job` handles remain
visible because cross-process assessment often depends on them. Rows with an
unreadable type or object name also remain visible.

## Name states

- `(unnamed)`: the descriptor positively recorded no object name; nothing was
  lost during parsing.
- `(unreadable)`: a recorded name could not be read or decoded; this is an
  evidence gap and appears in coverage.

Object Manager names are not automatically filesystem paths. For example,
`\KnownDlls` can name an NT Object Manager directory; the descriptor does not
contain a recursive inventory of the objects inside it.

## Rights are object-type-specific

The same bit can mean different capabilities for different object types:

| Bit | Example type | Meaning |
|---|---|---|
| `0x0001` | `File` | `ReadData` |
| `0x0001` | `Process` | `Terminate` |
| `0x0001` | `Token` | `AssignPrimary` |
| `0x0001` | `Section` | `Query` |

Always interpret the mask using the `Type` recorded on that row. If the type is
unknown or dumpex has no authoritative rights table for it, the undecoded bits
remain visible rather than being guessed.

Example console rows:

```text
  0x000000000000005c  Key             0x00020019    2  65536  \REGISTRY\...\Versions
      └─ Rights   KeyRead
  0x00000000000001dc  Thread          0x001fffff    6  131062  (unnamed)
      └─ Rights   AllAccess
```

`KeyRead` is dumpex's display spelling for the documented `KEY_READ`
combination. Display names keep output compact while the raw mask remains the
source evidence.

## Composite aliases

Where Windows defines a combination such as `KEY_READ`, `TOKEN_WRITE`, or a
type's `*_ALL_ACCESS`, dumpex prints a short display alias. An `Aliases used`
block expands every alias used in that table so the component capabilities
remain searchable in a transcript:

```text
  Aliases used
      Key      KeyRead    = QueryValue · EnumerateSubKeys · Notify · ReadControl
      Token    TokenWrite = AdjustPrivileges · AdjustGroups · AdjustDefault · ReadControl
```

`AllAccess` is qualified by object type. `AllAccess` on a `Process` is not the
same capability set as `AllAccess` on an `Event`.

An alias expansion ending in `UnknownBits(0x...)` means the named Windows
constant includes bits for which no individual right name is available. It
does not mean the descriptor mask was unreadable.

## Source confidence markers

Most decoded constants are defined by the Windows SDK (`winnt.h`, and
`winuser.h` for desktop/window-station rights). Some native object rights are
documented only by the WDK or have no confirmed Microsoft header definition.

- `[source unconfirmed]` on an alias expansion means at least one component
  lacks a confirmed authoritative header source.
- `[?]` on a bare right marks the same source uncertainty when no alias is
  involved.

These markers describe definition provenance, not whether the captured handle
is suspicious.

## Process and thread `AllAccess` by Windows version

Windows widened the `PROCESS_ALL_ACCESS` and `THREAD_ALL_ACCESS` masks in
Vista. dumpex uses the dump's captured Windows major version when selecting the
display alias:

| Type | Pre-Vista | Vista and later |
|---|---|---|
| Process | `0x001f0fff` | `0x001fffff` |
| Thread | `0x001f03ff` | `0x001fffff` |

This affects the decoded display name only. The JSON mask remains the captured
integer. When the dump's Windows version cannot be recovered, the modern values
are used.

## Undecoded and missing masks

- `(no rights)` means the dump captured a mask of zero.
- `(unknown)` means the descriptor did not provide a mask; no `Rights` line is
  printed.
- `UnknownBits(0x...)` means bits were captured but not documented for that
  object type.
- `TypeSpecificUnavailable(0x...)` means dumpex has no rights table for the
  captured type.

The following types have dedicated decoding tables: `File`, `Process`,
`Thread`, `Token`, `Section`, `Job`, `Directory`, `SymbolicLink`, `Event`,
`Mutant`, `Semaphore`, `Timer`, `Key`, `IoCompletion`, `Desktop`, and
`WindowStation`.

## Analyst interpretation

A decoded right is an observation about capability at capture time. It does not
prove the handle was used, an operation succeeded, or the process is malicious.
Prioritize powerful cross-process rights when they align with suspicious
process ancestry, thread execution, memory findings, or endpoint telemetry.
