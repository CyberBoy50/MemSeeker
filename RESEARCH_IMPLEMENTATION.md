# MemSeeker — Research: How to Implement It

Design notes from the research (Wed 2026-11-25). All of this was verified
against the tools found in RESEARCH_CLI_TOOLS.md and a live test in this VM
(root, ptrace_scope=1: `/proc/self/maps` gave 44 lines / 43 readable regions
and 4096 bytes were read back from `/proc/self/mem`).

## 1. The two /proc files

- `/proc/<pid>/maps` — one line per region:
  `address perms offset dev inode pathname`
  e.g. `55fa9f70a000-55fa9f72b000 rw-p 00000000 00:00 0  [heap]`
  Parse with a regex on `([0-9a-f]+)-([0-9a-f]+) ([rwxps-]{4}) ...`.
  A region is readable when `perms[0] == 'r'`. Keep: start, end, perms,
  pathname (may be empty for anonymous regions; `[heap]`, `[stack]`,
  `[vdso]`, `[vvar]` are named).
- `/proc/<pid>/mem` — the memory itself. Open `'rb'`, `buffering=0`, then
  `seek(address)` + `read(n)`. It is NOT a normal file: reads past a region
  end, or on a guarded page, raise `OSError` — so every region read must be
  wrapped in try/except and a failed region is SKIPPED with a note, never a
  crash (PDF Step 2: "the read must never crash on a guarded page").

## 2. Ownership check (PDF must-have 1)

- `os.stat(f"/proc/{pid}").st_uid` is the owner's UID.
  Refuse when `st_uid != os.getuid()`. This works for root too (root's UID is
  0; another user's process has a different st_uid, so it is refused).
- Process does not exist → `FileNotFoundError` on the maps open → clean
  error "no such process", not a traceback.
- Permission denied opening `maps`/`mem` → clean error explaining why
  (see §7 Yama) and what to do (sudo, or start the process from the tool).

## 3. Chunked reading + overlap window (PDF must-haves 3, Step 5)

- Read each region in fixed chunks (64 KiB is a good default). A 2 GB region
  then never uses more than ~64 KiB + overlap of RAM.
- Overlap: keep the last `max_pattern_len - 1` bytes of the previous chunk
  and prepend them to the next chunk, so a pattern straddling a chunk
  boundary is still found. Simplest correct scheme: `overlap = max_len - 1`
  over all compiled rules (cap it, e.g. at 4096, and refuse absurdly long
  patterns with a clear error). Offsets must be computed against the
  ABSOLUTE address: `hit_addr = chunk_start - len(overlap_prefix) + local_offset`.
- Step 5 test: plant a marker so it straddles a boundary (choose the chunk
  size small in the test, e.g. 64 bytes, and place the marker at
  `boundary - 2`) and assert it is still found.

## 4. Rule file format (PDF must-have 4)

Design (INI-style, parsed with stdlib `configparser` — no new dependency):

```ini
[LeakedPassword]
type = string
pattern = hunter2
description = Plaintext password left in memory

[InjectedMarker]
type = hex
pattern = de ad be ef 00 11
description = Known injected marker bytes

[ApiKey]
type = regex
pattern = sk-[A-Za-z0-9]{20,}
description = API key pattern
```

- Compile: `string` → `pattern.encode("utf-8")`, matched with `bytes.find`
  in a loop (all offsets, not just the first); `hex` → `bytes.fromhex`
  (spaces allowed, must be even-length after stripping); `regex` →
  `re.compile(pattern.encode())`, matched with `finditer` on bytes.
- A rule file with one rule of each type must fire on its prepared marker and
  stay silent otherwise (PDF Step 4 test).
- Rule names become the finding's rule name in the report. Invalid rule
  (bad hex, bad regex, unknown type) → clear error naming the rule and the
  line, before any scanning starts.

## 5. Hit reporting (PDF must-haves 5–6)

Each hit records: rule name, region name (pathname or `[anon]`), region
start/end, absolute address of the hit, offset inside the region, and
context bytes (e.g. 16 bytes before + 16 bytes after the match, shown as hex
and as printable ASCII with `.` for non-printables).
- Text report: one section per hit, plus a summary (regions scanned, bytes
  read, rules loaded, hits per rule). JSON report: same data as a list of
  hit objects (machine-readable, like RBACLens/PipeSentry `--json`).

## 6. Entropy scan (stretch 1)

- Shannon entropy over a chunk: histogram of the 256 byte values,
  `H = -sum(p * log2(p))`. Range 0–8 bits/byte.
- Threshold: flag a region when its mean chunk entropy is above ~7.5
  bits/byte (packed/encrypted data sits near 8.0; normal code/text sits
  around 4–7). Report the entropy value with the region; it is a *flag*,
  not a finding with a rule name. Cheap to compute on the same chunks the
  matcher already reads — no second pass.

## 7. String extraction (stretch 2)

- Printable ASCII runs of length >= 4 (`[ -~]{4,}`) around each hit
  (e.g. 64 bytes either side) — the `strings` idea, but scoped to the hit's
  context instead of the whole process. Printed in the report next to the
  hit so the analyst sees what the bytes around it say.

## 8. Watch mode (stretch 3)

- Scan, keep a set of hit keys `(rule, absolute_address)`, sleep N seconds,
  scan again, print only keys not seen before. Ctrl+C stops cleanly.
  Re-read the maps each round (regions can appear/disappear). Note: a
  process that exits mid-watch ends the mode with a clean message.

## 9. Yama / ptrace_scope — the one real-world gotcha

- The kernel gates `/proc/<pid>/mem` behind a ptrace access check. Yama
  `ptrace_scope`: 0 = any same-user process may be read; 1 (Ubuntu default)
  = only a PARENT may read its descendants (unless the reader has
  `CAP_SYS_PTRACE`); 2/3 = stricter still.
- Consequence: on a normal Ubuntu desktop, running as a normal user, scanning
  an arbitrary same-user PID FAILS with Permission denied — even though the
  process is "yours". Three honest ways around it, all to be documented:
  1. Run the tool as root / with sudo (the user's Kali VM runs as root, so
     this is the normal case for him).
  2. Start the lab process FROM the tool (menu option "start lab process"):
     the tool spawns it as its child, so scope 1 allows the read.
  3. Set `ptrace_scope=0` (needs root; system-wide change, document it as
     an option, not a default).
- The tool must surface a clear error when Yama blocks a read ("Permission
  denied — ...") instead of a raw traceback.

## 10. Lab program + test design (PDF Step 7)

- `lab_proc.py`: a small program that holds markers in memory and sleeps.
  It prints its PID and waits. Markers: one plain string, one hex byte
  sequence, one regex-matching string, plus a high-entropy blob (random
  bytes) for the entropy check and a marker placed to straddle a chunk
  boundary for the overlap test.
- **Trap to avoid:** if a marker literal appears in `lab_proc.py`'s source,
  it ALSO matches in the file-backed region where the source is mapped.
  Build markers at runtime instead (e.g. `b"MEMSEEKER_" + b"MARKER_" +
  b"ALPHA"`, or `base64.b64decode(...)`) so the literal never sits in the
  `.py` file. Tests then assert the hit is in the anonymous heap region.
- Test suite (`test_memseeker.py`, one function per PDF step): Step 1 maps
  match a manual read; Step 2 total bytes read == region size; Step 3 marker
  offset reported; Step 4 one rule of each type fires and stays silent
  otherwise; Step 5 straddling marker found; Step 6 ownership refusal on
  another user's process (run as non-root against a root process, or mock
  the UID check — the real check is exercised in the VM as root against a
  non-root user's process if one exists); Step 7 full scan finds every
  planted marker with the right region and offset.
- The test suite starts the lab process as a subprocess, scans it, asserts,
  then kills it. Everything runs in this VM (Linux, root) end to end.

## 11. Interface (same family as SSTIProbe / RBACLens / PipeSentry)

- TraceRecon colour class + clear/sep/header/ok/warn/err/info helpers,
  LEGAL DISCLAIMER + box in the banner, Gobuster-style SCAN config block,
  numbered menu with `[?] Select option:` prompt, `--batch`, `-q`, `--version`,
  `--no-color`, `-i/--interactive/--menu`.
- CLI: `memseeker.py <pid> --rules rules.txt [-o report] [--json]
  [--entropy] [--strings] [--watch N] [--chunk-size N] [--min-severity ...]`
  (no scoring in the PDF — follow the PDF, no score/grade).
- `run.py` launcher (venv auto-create + install), `run.bat`/`run.sh`,
  `run.py lab` (starts the lab process), `run.py test`, `run.py doctor`
  (checks /proc access, ptrace_scope, python version).
- Author "CyberBoy50" only — no real names anywhere (student name Fakhir
  and instructor name go only in the REPORT document, like the other three
  tools).
- Linux-only tool (uses /proc). Windows/macOS cannot run it — say so in the
  README and the doctor check; the user runs it on his Kali VM.
