# MemSeeker — Process Memory Scanner

**MemSeeker** is a Linux-only Python CLI tool that scans the memory of a
running process you own and hunts for byte patterns — injected markers,
leaked secrets, suspicious strings — using rules you write yourself.

What a program hides in memory is invisible to disk forensics. This tool
looks where the disk never sees. It only ever **reads** memory; it never
writes to another process.

- **Author:** CyberBoy50
- **Version:** 1.0
- **Platform:** Linux only (it reads `/proc/<pid>/maps` and
  `/proc/<pid>/mem`, which Windows and macOS do not have)
- **Dependencies:** none — Python 3 standard library only

## What it does

You give it a process ID and a rule file:

```
python3 memseeker.py 1234 --rules rules_lab.txt
```

It then:

1. **Checks ownership** — refuses any process owned by another user.
2. **Parses the memory map** (`/proc/<pid>/maps`) and lists every
   readable region with its address range and name.
3. **Reads each region in chunks** (64 KiB default) from
   `/proc/<pid>/mem`, keeping an overlap window so a pattern split
   across a chunk boundary is never missed. A guarded or unreadable
   page is skipped with a note — never a crash.
4. **Matches every chunk against every rule** — plain strings, hex byte
   sequences and regular expressions, in one pass.
5. **Reports each hit** with the rule name, region name, offset inside
   the region, absolute address and surrounding context bytes.
6. **Saves the report** to a file (text, or JSON with `--json`).

Stretch features, all included:

- **Entropy scan** (`--entropy`) — flags chunks above ~7.5 bits/byte of
  Shannon entropy as possibly packed or encrypted data.
- **String extraction** (`--strings`) — prints the readable strings
  around each hit for context.
- **Watch mode** (`--watch N`) — rescans every N seconds and reports
  only NEW hits.

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

Or open the menu:

```
python run.py menu
```

Menu options: [1] Scan a process · [2] Quick scan: lab process ·
[3] Show the memory map of a process · [4] List all rules ·
[5] Run the step tests · [6] Check setup (doctor) · [7] Watch a
process · [0] Exit.

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

- `rules_lab.txt` — the 5 rules for the lab markers (used by the demo
  and the tests).
- `rules_default.txt` — general-purpose rules for real use (passwords,
  API keys, private-key headers, AWS keys, bearer tokens).

## CLI reference

```
python3 memseeker.py <pid> --rules <file> [-o report] [--json]
    [--entropy] [--strings] [--watch N] [--rounds N]
    [--chunk-size N] [--map] [--list-rules] [-q] [--batch]
    [-i/--menu] [--version] [--no-color]
```

| Flag | What it does |
|---|---|
| `<pid>` | Process ID to scan |
| `--rules FILE` | Rule file (default: `rules_lab.txt`) |
| `-o, --output FILE` | Report file (default: `memseeker_report.txt`) |
| `--json` | Write the report as JSON instead of text |
| `--entropy` | Flag high-entropy chunks (>= 7.5 bits/byte) |
| `--strings` | Extract printable strings around each hit |
| `--watch N` | Rescan every N seconds, report only NEW hits |
| `--rounds N` | Watch mode: stop after N rounds (0 = forever) |
| `--chunk-size N` | Bytes read per chunk (default: 65536) |
| `--map` | Only print the process memory map, do not scan |
| `--list-rules` | Only list the rules in the rule file |
| `--lab` | Start the lab as this tool's child and scan it |
| `--doctor` | Check the setup and exit |
| `-q, --quiet` | Only print errors and the summary |
| `--batch` | Never ask, use defaults (for scripts) |
| `-i, --menu` | Open the numbered menu |
| `--version` | Print the version and exit |
| `--no-color` | Disable coloured output |

Exit codes: **0** = clean (no hits) · **1** = hits found ·
**2** = error or refusal (wrong owner, no such process, bad rule).

## The Yama / ptrace_scope note — read this before you scan

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
options) instead of printing a traceback.

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

## Testing

```
python run.py test
```

61 checks, all passing — one function per PDF build-plan step
(Steps 1–7) plus Step 8 for the stretch items (entropy, strings,
watch) and the CLI bits (`--map`, `--list-rules`, `--version`,
doctor). See `STEP_BY_STEP_GUIDE.md` for what each step proves.

## Files

| File | What it is |
|---|---|
| `memseeker.py` | The tool itself — scanning, rules, reports, menu |
| `lab_proc.py` | The lab process — holds planted markers, then sleeps |
| `test_memseeker.py` | Step tests (61 checks) |
| `run.py` | Launcher — setup, lab, scan, labscan, test, doctor, menu |
| `run.sh` / `run.bat` | One-click launchers (Linux / Windows note) |
| `rules_lab.txt` | Rules for the lab markers |
| `rules_default.txt` | General-purpose secret-hunting rules |
| `requirements.txt` | Empty — standard library only |
| `report_lab.txt` / `report_lab.json` | Sample reports from the lab scan |
| `RESEARCH_CLI_TOOLS.md` | Research: YARA, Volatility, HackByte, and the rest |
| `RESEARCH_IMPLEMENTATION.md` | Research: how the tool is implemented |
| `README.md` | This file |
| `DEMO.md` | Demo and write-up with real run output |
| `STEP_BY_STEP_GUIDE.md` | The 8 build steps, each with its test |

## Limits (honest list)

- **Linux only** — it reads `/proc`. Windows and macOS cannot run it.
- **Reads only your own processes** — by design (ownership check),
  and the kernel additionally enforces Yama (see above).
- **Regex matches are bounded by the overlap window** — a regex match
  longer than ~512 bytes that straddles a chunk boundary could be
  missed; string/hex patterns are exact.
- **Entropy flags are leads, not verdicts** — dense system libraries
  (e.g. `libm.so.6` at 7.51 bits/byte) can trip the 7.5 threshold.
- **No memory dump, no image analysis** — the tool scans a live
  process; for a dead memory image, use Volatility.
- **No YARA rules** — the rule format is deliberately simple (three
  types, no YARA engine to install); YARA's full language is out of
  scope.
- **A process can change while it is scanned** — regions can appear,
  disappear or be rewritten mid-scan; a hit is a snapshot of one
  moment, not proof the bytes are still there.

## Legal

**AUTHORIZED USE ONLY.** Only scan processes you own or have written
permission to test — your own lab, your own machine. Reading another
person's process memory without permission is unauthorized access
(Prevention of Electronic Crimes Act, 2016, Pakistan). The tool
refuses other users' processes on purpose, and it never writes to
another process.
