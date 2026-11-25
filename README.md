# MemSeeker — Process Memory Scanner

**MemSeeker** is a cross-platform Python CLI tool that scans the memory
of a running process you own and hunts for byte patterns — injected
markers, leaked secrets, suspicious strings — using rules you write
yourself. It also scans raw memory dump files, so a capture taken on
one machine can be analysed on another.

What a program hides in memory is invisible to disk forensics. This
tool looks where the disk never sees. It only ever **reads** memory;
it never writes to another process.

- **Author:** CyberBoy50
- **Version:** 1.2
- **Platform:** Linux, Windows and macOS (see the platform matrix
  below). The project spec is Linux — the PDF asked for a Linux tool —
  and the Windows/macOS backends are added on top of that spec, not
  instead of it.
- **Dependencies:** none — Python 3 standard library only

## What it does

You give it a process ID and a rule file:

```
python3 memseeker.py 1234 --rules rules_lab.txt
```

It then:

1. **Checks ownership** — refuses any process owned by another user
   (on Windows: refuses any process it cannot open for reading).
2. **Parses the memory map** and lists every readable region with its
   address range and name (Linux: `/proc/<pid>/maps`; Windows:
   `VirtualQueryEx`; macOS: `vm_region_64`).
3. **Reads each region in chunks** (64 KiB default) keeping an overlap
   window so a pattern split across a chunk boundary is never missed.
   A guarded or unreadable page is skipped with a note — never a
   crash.
4. **Matches every chunk against every rule** — plain strings, hex
   byte sequences and regular expressions, in one pass.
5. **Reports each hit** with the rule name, region name, offset inside
   the region, absolute address and surrounding context bytes.
6. **Saves the report** to a file (text, or JSON with `--json`).

v1.2 change (text only — no detection logic changed): an explicit
authorized-use responsibility disclaimer is now shown in the banner
and carried in every generated report (text header and JSON
`disclaimer` field). See the Legal section below for the exact
wording.

v1.1 additions:

- **Multi-PID scan** (`--all`, `--pids 1234,5678`) — scan every
  process you own in one run, or several PIDs at once. Unreadable
  processes are skipped with a one-line note, never a crash. The
  report is grouped per process (PID + process name).
- **Memory image scan** (`--image <file> [--base 0x...]`) — scan a raw
  memory dump file as if it were memory, with the same chunked reader,
  matchers and entropy scan. Hits report the file offset as the
  address. Works on every OS — the portable fallback that needs no
  live-process access.
- **Region dump** (`--dump <dir>`) — for every region that contains at
  least one hit, save that region's full bytes to
  `<pid>_<start>-<end>_<region>.bin` in the directory, and record the
  dump path in the hit's report entry (text and JSON). Regions
  without hits are never dumped.
- **Rule conditions / groups** — a rule file may define
  `[Group:Name]` sections with `condition = 2 of (A, B, C)` /
  `all of (...)` / `any of (...)`, evaluated per region. A group fires
  as ONE finding (rule name = the group name) when its condition is
  met by the rules that fired in that region. See the rule file
  section below.
- **Cross-platform backends** — one reader interface with three
  backends (Linux `/proc`, Windows kernel32, macOS mach), same CLI,
  same menu, same rule file, same report format on all three.

Stretch features, all included:

- **Entropy scan** (`--entropy`) — flags chunks above ~7.5 bits/byte
  of Shannon entropy as possibly packed or encrypted data.
- **String extraction** (`--strings`) — prints the readable strings
  around each hit for context.
- **Watch mode** (`--watch N`) — rescans every N seconds and reports
  only NEW hits.

## Platform matrix

| Platform | Live scan | How it reads | Privilege needed |
|---|---|---|---|
| Linux | Yes | `/proc/<pid>/maps` + `/proc/<pid>/mem` | Same user; root (Kali) reads any own process. On a normal desktop, Yama `ptrace_scope=1` means only a parent may read its children unless the reader has `CAP_SYS_PTRACE` — see the Yama note below |
| Windows | Yes | `kernel32.OpenProcess` + `VirtualQueryEx` + `ReadProcessMemory` (stdlib `ctypes` only) | Same user; a process owned by another user, or a protected process, refuses with access denied. Run as Administrator to read system processes |
| macOS | Yes | `task_for_pid` + `vm_region_64` + `vm_read` (stdlib `ctypes` only) | Root, or the debugger entitlement; without it, `task_for_pid` fails and the tool says so plainly |
| Any OS | `--image` | Reads a dump file | None — no live-process access at all |

**Testing honesty:** the Windows and macOS backends are covered by
mocked tests (fake kernel32/mach calls returning canned regions and
bytes — Step 10 of the test suite). Live Windows testing needs a real
Windows run (a Windows 11 host), and live macOS testing needs a real
Mac — the mocked tests cover the logic, not the real OS calls. The
Linux backend keeps its full live tests.

## Quick start (the lab)

The lab is a small program that holds planted markers in memory. The
easiest scan starts it and scans it in one step:

```
python run.py setup      # first time only (creates the venv)
python run.py labscan    # start the lab AND scan it
```

Or step by step:

```
python run.py lab        # terminal 1: starts the lab, prints its PID
python run.py scan <pid> --rules rules_lab.txt --entropy --strings
```

Scan everything you own, or several PIDs at once:

```
python run.py scanall
python3 memseeker.py --pids 1234,5678 --rules rules_lab.txt
```

Scan a memory dump file (works on any OS):

```
python3 memseeker.py --image heap.bin --rules rules_lab.txt
python3 memseeker.py --image heap.bin --base 0x100000 --rules rules_lab.txt
```

Dump the hit regions to files while you scan:

```
python3 memseeker.py <pid> --rules rules_lab.txt --dump dumps/
```

Or open the menu:

```
python run.py menu
```

Menu options: [1] Scan a process · [2] Quick scan: lab process ·
[3] Show the memory map of a process · [4] List all rules ·
[5] Run the step tests · [6] Check setup (doctor) · [7] Watch a
process · [8] Scan all my processes · [9] Scan a memory image file ·
[0] Exit.

## Rule file format

One `[RuleName]` section per rule (INI format, standard library
`configparser`):

```ini
[LeakedPassword]
type = string
pattern = hunter2
description = Plaintext password left in process memory

[InjectedBytes]
type = hex
pattern = de ad be ef 00 11 22 33
description = Known injected marker bytes

[ApiKeyPattern]
type = regex
pattern = sk-[A-Za-z0-9]{20,}
description = API key pattern (sk- followed by 20+ characters)
```

| Type | What it matches | Example |
|---|---|---|
| `string` | Plain bytes, exactly, case-sensitive | `hunter2` |
| `hex` | Byte pairs, spaces allowed | `de ad be ef 00 11 22 33` |
| `regex` | A regular expression on the raw bytes | `sk-[A-Za-z0-9]{20,}` |

A bad rule (unknown type, bad hex, bad regex, empty pattern) is a
clean error that **names the rule** — before any scanning starts.

### Rule groups (conditions)

A `[Group:Name]` section combines rules with a YARA-style condition,
evaluated **per region**. The group fires as one finding (rule name =
the group name) when its condition is met by the rules that fired in
that region:

```ini
[Group:SecretPair]
condition = 2 of (MemMarkerAlpha, LeakedPassword, ApiKeyPattern)

[Group:AllSecrets]
condition = all of (MemMarkerAlpha, LeakedPassword, ApiKeyPattern)

[Group:AnySecret]
condition = any of (MemMarkerAlpha, LeakedPassword, ApiKeyPattern)
```

- `2 of (...)` — at least 2 of the named rules fired in the region
  (any number `n of (...)` works, `1 <= n <= number of members`).
- `all of (...)` — every named rule fired in the region.
- `any of (...)` — at least one named rule fired in the region.

A bad group (unknown member rule, a count larger than the member
list, bad syntax, a name that collides with a rule) is a clean error
that **names the group** — before any scanning starts. Groups are
listed by `--list-rules` alongside the rules.

- `rules_lab.txt` — the 5 rules for the lab markers (used by the demo
  and the tests).
- `rules_groups.txt` — 3 lab rules plus 3 groups (`SecretPair`,
  `AnySecret`, `AllSecrets`); scanning the lab with it gives 3 member
  hits + 3 group hits = 6 hits, all in the anonymous heap.
- `rules_default.txt` — general-purpose rules for real use (passwords,
  API keys, private-key headers, AWS keys, bearer tokens).

## CLI reference

```
python3 memseeker.py <pid> --rules <file> [-o report] [--json]
    [--entropy] [--strings] [--watch N] [--rounds N]
    [--chunk-size N] [--map] [--list-rules] [--all] [--pids PIDS]
    [--image FILE] [--base ADDR] [--dump DIR]
    [-q] [--batch] [-i/--menu] [--version] [--no-color]
```

| Flag | What it does |
|---|---|
| `<pid>` | Process ID to scan (repeatable — several PIDs at once) |
| `--all` | Scan every process owned by the current user |
| `--pids 1234,5678` | Scan these PIDs (comma-separated) |
| `--image FILE` | Scan a raw memory dump file instead of a live process |
| `--base ADDR` | Base address for `--image` (e.g. `0x100000`, default 0) |
| `--dump DIR` | Dump every region with at least one hit into DIR |
| `--rules FILE` | Rule file (default: `rules_lab.txt`) |
| `-o, --output FILE` | Report file (default: `memseeker_report.txt`) |
| `--json` | Write the report as JSON instead of text |
| `--entropy` | Flag high-entropy chunks (>= 7.5 bits/byte) |
| `--strings` | Extract printable strings around each hit |
| `--watch N` | Rescan every N seconds, report only NEW hits |
| `--rounds N` | Watch mode: stop after N rounds (0 = forever) |
| `--chunk-size N` | Bytes read per chunk (default: 65536) |
| `--map` | Only print the process memory map, do not scan |
| `--list-rules` | Only list the rules (and groups) in the rule file |
| `--lab` | Start the lab as this tool's child and scan it |
| `--doctor` | Check the setup and exit |
| `-q, --quiet` | Only print errors and the summary |
| `--batch` | Never ask, use defaults (for scripts) |
| `-i, --menu` | Open the numbered menu |
| `--version` | Print the version and exit |
| `--no-color` | Disable coloured output |

Exit codes: **0** = clean (no hits) · **1** = hits found ·
**2** = error or refusal (wrong owner, no such process, bad rule,
no process could be scanned at all).

## The Yama / ptrace_scope note — read this before you scan (Linux)

The Linux kernel gates `/proc/<pid>/mem` behind a ptrace access check,
and Yama's `ptrace_scope` setting shrinks it:

| Scope | What it means |
|---|---|
| 0 | Any same-user process may be read |
| 1 (Ubuntu default) | Only a **parent** may read its descendants (unless the reader has `CAP_SYS_PTRACE`) |
| 2 / 3 | Stricter still |

So on a normal Ubuntu desktop, running as a normal user, scanning an
arbitrary same-user PID fails with *Permission denied* — even though
the process is yours. Three honest ways around it:

1. **Run as root / with sudo** — the normal case on Kali Linux, where
   you are root and hold `CAP_SYS_PTRACE`.
2. **Start the process from the tool** — `python3 memseeker.py --lab`
   or menu option 2 starts the lab as the tool's own child, so scope 1
   allows the read. (This is also how the test suite scans the lab.)
3. **Set `ptrace_scope=0`** — needs root, system-wide change:
   `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`.

If the kernel blocks a read, the tool says so plainly (with these
options) instead of printing a traceback. The same spirit applies on
the other platforms: a Windows access-denied open and a macOS
`task_for_pid` failure are both clean refusals with a clear message,
never a traceback.

## Lab results (real run)

```
Lab process started: PID 11116 (python3)
Regions read: 58 (2 skipped) — 61 total
Bytes read:   17,866,752 in 0.91 s
Hits:         5 (one per rule)
Entropy:      5 high-entropy chunks flagged
```

| Rule | Type | Hit |
|---|---|---|
| MemMarkerAlpha | string | `MEMSEEKER_MARKER_ALPHA` in `[anon]` heap |
| LeakedPassword | string | `hunter2` in `[anon]` heap |
| InjectedBytes | hex | `de ad be ef 00 11 22 33` in `[anon]` heap |
| ApiKeyPattern | regex | `sk-ABCDEFGH12345678XYZABCDE` in `[anon]` heap |
| StraddleMarker | string | `MEMSEEKER_STRADDLE_MARKER` in `[anon]` heap |

Sample reports: `report_lab.txt` (text) and `report_lab.json` (JSON).

With the group rule file (`--rules rules_groups.txt`) the same lab
scan gives 6 hits — the 3 member rules plus the 3 groups
(`SecretPair`, `AnySecret`, `AllSecrets`), all in the anonymous heap.
See `DEMO.md` for the full run.

## Testing

```
python run.py test
```

121 checks, all passing — one function per PDF build-plan step
(Steps 1–7) plus Step 8 for the stretch items (entropy, strings,
watch), the CLI bits (`--map`, `--list-rules`, `--version`, doctor),
Step 9 for the v1.1 features (multi-PID, image, dump, groups) and
Step 10 for the cross-platform backends (mocked Windows/macOS).
See `STEP_BY_STEP_GUIDE.md` for what each step proves.

## Files

| File | What it is |
|---|---|
| `memseeker.py` | The tool itself — scanning, rules, reports, menu |
| `lab_proc.py` | The lab process — holds planted markers, then sleeps |
| `test_memseeker.py` | Step tests (121 checks) |
| `run.py` | Launcher — setup, lab, scan, scanall, image, labscan, test, doctor, menu |
| `run.sh` / `run.bat` | One-click launchers (macOS/Linux, Windows) |
| `rules_lab.txt` | Rules for the lab markers |
| `rules_groups.txt` | Lab rules + group conditions (v1.1) |
| `rules_default.txt` | General-purpose secret-hunting rules |
| `requirements.txt` | Empty — standard library only |
| `report_lab.txt` / `report_lab.json` | Sample reports from the lab scan |
| `RESEARCH_CLI_TOOLS.md` | Research: YARA, Volatility, HackByte, and the rest |
| `RESEARCH_IMPLEMENTATION.md` | Research: how the tool is implemented |
| `README.md` | This file |
| `DEMO.md` | Demo and write-up with real run output |
| `STEP_BY_STEP_GUIDE.md` | The 10 build steps, each with its test |

## Notes (design, not limitations)

- **Linux is the project spec** — the PDF asked for a Linux tool.
  The Windows and macOS backends are extra; the tool's home platform
  is still Linux.
- **Reads only your own processes** — by design (ownership check),
  and the kernel additionally enforces Yama on Linux (see above).
- **No YARA rules** — the rule format is deliberately simple (three
  types plus group conditions, no YARA engine to install); YARA's full
  language is out of scope.
- **Entropy flags are leads, not verdicts** — dense system libraries
  (e.g. `libm.so.6` at 7.51 bits/byte) can trip the 7.5 threshold.
- **Regex matches are bounded by the overlap window** — a regex match
  longer than ~512 bytes that straddles a chunk boundary could be
  missed; string/hex patterns are exact.
- **A process can change while it is scanned** — regions can appear,
  disappear or be rewritten mid-scan; a hit is a snapshot of one
  moment, not proof the bytes are still there.
- **Windows/macOS live testing still needed** — the backends are
  covered by mocked tests; a real Windows run and a real Mac run are
  the remaining verification (see the platform matrix).

## Legal

**AUTHORIZED USE ONLY.** Only scan processes you own or have written
permission to test — your own lab, your own machine. Reading another
person's process memory without permission is unauthorized access
(Prevention of Electronic Crimes Act, 2016, Pakistan). The tool
refuses other users' processes on purpose, and it never writes to
another process.

The tool states this responsibility explicitly, in the banner and in
every report it writes:

> DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for ethical, authorized security testing only. You are using it on your own responsibility. The authors are not responsible for how you use it, or for anything that happens because of your use. Only test systems, code, and data you own or have explicit written permission to test — testing anything else may be illegal (for example, PECA 2016 in Pakistan).
