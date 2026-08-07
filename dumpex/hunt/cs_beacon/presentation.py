"""All console rendering for the CS beacon hunter. Reads only from the
aggregate.Report the caller already built — never recomputes score/status/
coverage itself. Scan-progress announcements ("Scanning N segment(s)...",
"Scan complete...") are NOT here — they print in __init__.py immediately
before/after the scan itself runs, the same way encoding's Layer N
announcements do (see dumpex/hunt/encoding/__init__.py), so the console
shows activity during a scan that can run for tens of seconds instead of
going silent until everything is done.
"""
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.core.memory import prot_str
from dumpex.hunt._ui import _print_check, _status_text, NOT_EVALUATED, INCONCLUSIVE
from dumpex.hunt._finding import DetailLevel, leads_suffix
from dumpex.hunt.cs_beacon.schema import (
    CS_BEACON_TYPES, CS_PROXY_TYPES, CS_INJECT_PERMS, CS_FIELD_TYPE_NAMES,
)
from dumpex.hunt.cs_beacon.parser import (
    _cs_guess_version, _cs_decode_instructions, _cs_decode_type3_value,
)


def render_not_evaluated():
    print(YELLOW("  [~] No memory segments in dump — cannot scan for beacon config.\n"))
    print(f"  {BOLD('[ VERDICT ]')}  "
          f"{_status_text(NOT_EVALUATED, 'Memory64ListStream missing from this dump')}\n")


def _field_display_value(rec: dict) -> str:
    """Render one TLV field's `value` for console display -- the ONE
    place both the 'Process Injection' inline section and the
    `--verbose` Full Config Field Table decide how to show a type-3
    (bytes) field, so neither can drift onto a different binary/text
    rule or show `value` alongside a separate `raw` preview that says
    the same thing twice. Printable text -> `repr(value)` (repr, not the
    bare string, since tab/CR/LF count as printable here -- see
    `_cs_decode_type3_value`'s own docstring -- and an embedded newline
    would otherwise break the one-field-per-line layout). Binary -> a
    truncated hex encoding of the field's FULL raw bytes, not `value`
    itself (a NUL-stripped hex string for a binary field -- see that same
    docstring for why the two differ)."""
    if rec['type'] != 3:
        return str(rec['value'])
    _, is_text = _cs_decode_type3_value(rec['raw'])
    if is_text:
        return repr(rec['value'])
    hexs = rec['raw'].hex()
    return f"{hexs[:64]}{'...' if len(hexs) > 64 else ''}"


def render(report, verbose: bool = False):
    """Render the full result: NOT_EVALUATED / clean / detected, whichever
    `report.status` says happened."""
    level = DetailLevel.VERBOSE if verbose else DetailLevel.NORMAL
    if report.status == NOT_EVALUATED:
        render_not_evaluated()
        return

    if not report.hit_records:
        if report.status == INCONCLUSIVE:
            _print_check("Cobalt Strike beacon config",
                         _status_text(INCONCLUSIVE,
                                      ("; ".join(report.coverage_reasons) or "partial coverage")
                                      + leads_suffix(report.findings_list)))
        else:
            _print_check("Cobalt Strike beacon config",
                         GREEN("CLEAN — no beacon config found in memory")
                         + leads_suffix(report.findings_list))
        print()
        for f in report.findings_list:
            f.print(level=level)
        return

    # aggregate.py appends exactly one "cs_beacon.structural_config" Finding
    # per hit_record, in the same order it iterates report.hit_records --
    # zipping positionally here (rather than matching on VA/check name
    # alone) stays correct even with multiple configs in one dump. Checked
    # explicitly (rather than trusting plain zip()) because a silent
    # mismatch here would silently drop a Beacon config's own console
    # detail -- exactly the failure mode this whole rendering pass exists
    # to eliminate, and the worst possible one to have fail quietly.
    structural_config_findings = [f for f in report.findings_list
                                   if f.check == "cs_beacon.structural_config"]
    if len(structural_config_findings) != len(report.hit_records):
        raise ValueError(
            "cs_beacon report invariant violated: "
            f"{len(report.hit_records)} hit record(s) but "
            f"{len(structural_config_findings)} cs_beacon.structural_config finding(s) -- "
            "aggregate.py must append exactly one per hit_record")

    print()
    for idx, (hr, finding) in enumerate(
            zip(report.hit_records, structural_config_findings, strict=True), 1):
        c = hr.candidate
        region = hr.region
        cs_ver = _cs_guess_version(c.fields)
        key_desc = {0x69: "0x69 'i'  (CS3 encoding)",
                    0x2e: "0x2E '.'  (CS4 encoding)"}.get(c.xor_key, f'0x{c.xor_key:02x}')

        print(RED(f"  [!] Beacon config #{idx}  ──────────────────────────────────────────────"))
        print(f"  {'VA (process)':<26} 0x{c.hit_va:016x}  {DIM('← virtual address in target process')}")
        print(f"  {'File offset (.dmp)':<26} 0x{c.hit_fo:016x}  {DIM('← byte offset inside .dmp file')}")
        if region is not None:
            print(f"  {'Region base (VA)':<26} 0x{region.BaseAddress:016x}  {DIM('← for cross-referencing with --hunt injection')}")
            print(f"  {'Region size':<26} 0x{region.RegionSize:x}")
            print(f"  {'Region protect':<26} {prot_str(region.Protect)}")
        else:
            print(f"  {'Region base (VA)':<26} {DIM('(not covered by MemoryInfoListStream)')}")
        print(f"  {'XOR key':<26} {key_desc}")
        print(f"  {'CS version (estimated)':<26} {YELLOW(cs_ver)}")
        if hr.corroborated:
            print(f"  {'Context corroboration':<26} {RED('YES')}  — {'; '.join(hr.corrob_reasons)}")
        else:
            print(f"  {'Context corroboration':<26} {DIM('none')}  — structural validity only")
        print()

        # inference/confidence/rationale/limitations for this exact hit --
        # previously --json-only; the field-by-field TLV dump below is raw
        # evidence, not a restatement of this narrative. See Finding.print()
        # for how `level` gates its own fact-list expansion.
        finding.print(level=level)

        f = c.fields

        # ── C2 / Identity / Transport ──────────────────────────────────
        print(f"  {BOLD('── C2 / Identity / Transport ──────────────────────────────────────')}")

        if 0x0001 in f:
            btype     = f[0x0001]['value']
            btype_str = CS_BEACON_TYPES.get(btype, f'unknown ({btype})')
            color     = RED if btype in (1, 2) else YELLOW   # DNS/SMB = more covert
            print(f"  {'BeaconType':<26} {color(btype_str)}")

        if 0x0008 in f:
            c2raw = (f[0x0008]['value'] or '').strip('\x00')
            if ',' in c2raw:
                host, uri = c2raw.split(',', 1)
                print(f"  {'C2 Host':<26} {RED(host.strip())}")
                print(f"  {'C2 GET URI':<26} {uri.strip()}")
            else:
                print(f"  {'C2 Server':<26} {RED(c2raw)}")

        if 0x0002 in f:
            print(f"  {'Port':<26} {f[0x0002]['value']}")

        if 0x000a in f:
            v = (f[0x000a]['value'] or '').strip('\x00')
            if v: print(f"  {'HTTP POST URI':<26} {v}")

        if 0x0009 in f:
            ua = (f[0x0009]['value'] or '').strip('\x00')
            if ua: print(f"  {'UserAgent':<26} {ua}")

        if 0x0036 in f:
            hh = (f[0x0036]['value'] or '').strip('\x00')
            if hh: print(f"  {'HostHeader':<26} {hh}")

        if 0x000f in f:
            pipe = (f[0x000f]['value'] or '').strip('\x00')
            if pipe: print(f"  {'PipeName':<26} {RED(pipe)}")

        if 0x0025 in f:
            print(f"  {'LicenseID':<26} {YELLOW(str(f[0x0025]['value']))}")

        if 0x0003 in f:
            sleep_ms = f[0x0003]['value'] or 0
            jitter   = f[0x0005]['value'] if 0x0005 in f else 0
            print(f"  {'Sleep / Jitter':<26} {sleep_ms} ms / {jitter}%")

        if 0x0028 in f and f[0x0028]['value']:
            print(f"  {'KillDate':<26} {f[0x0028]['value']}")

        if 0x001a in f:
            v = (f[0x001a]['value'] or '').strip('\x00')
            if v: print(f"  {'HTTP GET Verb':<26} {v}")
        if 0x001b in f:
            v = (f[0x001b]['value'] or '').strip('\x00')
            if v: print(f"  {'HTTP POST Verb':<26} {v}")

        if 0x001d in f:
            v = (f[0x001d]['value'] or '').strip('\x00')
            if v: print(f"  {'SpawnTo x86':<26} {v}")
        if 0x001e in f:
            v = (f[0x001e]['value'] or '').strip('\x00')
            if v: print(f"  {'SpawnTo x64':<26} {v}")

        if 0x0020 in f:
            proxy = (f[0x0020]['value'] or '').strip('\x00')
            ptype = CS_PROXY_TYPES.get(f[0x0023]['value'] if 0x0023 in f else 0, '')
            if proxy: print(f"  {'Proxy':<26} {proxy}  [{ptype}]")

        # ── Process injection ──────────────────────────────────────────
        inj_ids = {0x002b, 0x002c, 0x002d, 0x002e, 0x002f, 0x0033, 0x0034, 0x0035}
        inj = {k: f[k] for k in inj_ids if k in f}
        if inj:
            print(f"\n  {BOLD('── Process Injection ──────────────────────────────────────────────')}")
            for fid in sorted(inj):
                rec = inj[fid]
                if fid in (0x002b, 0x002c):
                    val = CS_INJECT_PERMS.get(rec['value'], str(rec['value']))
                else:
                    val = _field_display_value(rec)
                print(f"  {rec['name']:<26} {val}")

        # ── Malleable C2 / GET / POST transforms ───────────────────────
        for fid, label, itype in (
            (0x000b, 'Malleable C2  (server→client transform)', 1),
            (0x000c, 'HTTP GET  header transforms',             2),
            (0x000d, 'HTTP POST header transforms',             3),
        ):
            if fid in f and f[fid]['raw']:
                try:
                    instrs = _cs_decode_instructions(f[fid]['raw'], itype)
                    if instrs:
                        print(f"\n  {BOLD(f'── {label}')}")
                        for step in instrs:
                            print(f"    {DIM('›')} {step}")
                except Exception:
                    pass

        # ── SSH transport ──────────────────────────────────────────────
        ssh_ids = (0x0015, 0x0016, 0x0017, 0x0018, 0x0038)
        ssh = {k: f[k] for k in ssh_ids if k in f}
        if ssh:
            print(f"\n  {BOLD('── SSH Transport ──────────────────────────────────────────────────')}")
            for fid, rec in sorted(ssh.items()):
                val = (rec['value'] or '').strip('\x00') if rec['type'] == 3 else str(rec['value'])
                if val: print(f"  {rec['name']:<26} {val}")

        # ── DNS transport ──────────────────────────────────────────────
        dns_ids = range(0x003c, 0x0047)
        dns = {k: f[k] for k in dns_ids if k in f}
        if dns:
            print(f"\n  {BOLD('── DNS Transport ──────────────────────────────────────────────────')}")
            for fid, rec in sorted(dns.items()):
                val = (rec['value'] or '').strip('\x00') if rec['type'] == 3 else str(rec['value'])
                if val: print(f"  {rec['name']:<26} {val}")

        # ── Full field table (--verbose only) ──────────────────────────
        # No field-ID column -- once `fields` is name-keyed (schema_version
        # 2.7, see collect.py), the numeric ID is redundant for a console
        # reader; `fid` is still the internal sort key (stable output
        # order), just never printed. Each field prints exactly once: a
        # printable type-3 field shows its decoded text, a binary one
        # shows a truncated hex encoding of its FULL raw bytes -- never
        # both `value` and a separate `raw` preview that say the same
        # thing (see _field_display_value's own docstring).
        if verbose:
            print(f"\n  {BOLD('── Full Config Field Table ────────────────────────────────────────')}")
            name_w = max((len(v['name']) for v in f.values()), default=20)
            type_w = max((len(CS_FIELD_TYPE_NAMES.get(v['type'], str(v['type'])))
                          for v in f.values()), default=6)
            print(f"    {'Field':<{name_w}}  {'Type':<{type_w}}  Value")
            for fid in sorted(f.keys()):
                rec = f[fid]
                type_name = CS_FIELD_TYPE_NAMES.get(rec['type'], str(rec['type']))
                print(f"    {rec['name']:<{name_w}}  {type_name:<{type_w}}  {_field_display_value(rec)}")

        print()

    corrob_note = ("  (context-corroborated)" if report.any_corroborated else
                   "  (structural validity only — no independent memory-context corroboration)")
    print(f"  {BOLD('[ VERDICT ]')}  "
          f"{RED(f'COBALT STRIKE — {len(report.hit_records)} beacon config(s) found in memory')}{corrob_note}\n")
    if not verbose:
        print(DIM("  Use --verbose to dump all config fields.\n"))
