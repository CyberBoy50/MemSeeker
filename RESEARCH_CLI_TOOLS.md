# MemScope — Research: Similar Tools on the Internet / GitHub

Researched Wed 2026-11-25, before building. Sources are the web searches run
that day; claims below come only from those results and the tools' own pages.

## Name check (GitHub, search_repositories, `in:name`)

The PDF's name **MemScope is TAKEN** (same name, different projects):
- `090TYPE/memscope` — real-time heap memory visualizer for C++ (live heap map,
  leak/double-free/churn flags, SDL2 + ImGui GUI).
- `akketix/memscope` — MemScope RAM/VRAM Pressure Monitor & AI Watchdog (Windows,
  DXGI VRAM tracking, Python 3.11+, Apache 2.0).
- `TimWood0x10/memscope-rs` — Rust memory analysis toolkit (allocation tracking,
  leak detection, HTML reports).

First batch of alternatives — ALL taken in the same/adjacent domain:
- MemLens (27) — memory monitoring/analytics platform; MemSentry (11) —
  `vusec/memsentry` (EuroSys'17 memory-safety research); ProcScope (20) —
  `Mutasem-mk4/procscope` eBPF process tracer for malware triage;
  HeapLens (10) — heap-dump analysis; MemProbe (10); MemHound (3) —
  `david-zaletanski/MemHound` searches and writes other processes' memory.

Second batch — **FREE (0 results): MemXray, MemSeeker**. Taken: HeapScope (11),
MemHunter (12 — `marcosd4h/memhunter`, live hunting of code injection),
RamScope (8), PidScope (2 — industrial PID loops, different domain).

## 1. YARA (VirusTotal) — the standard pattern matcher

- Rule-based matching: text strings, hex byte sequences, regular expressions,
  with `meta` / `strings` / `condition` sections. Compiled with `yarac` or used
  as text rules.
- Scans files, directories, memory dumps — and **live process memory**:
  `yara -p PID rules.yar` (Linux, root required) and the Python API
  `rule.match(pid=1234)` (yara-python).
- Volatility's `yarascan` plugin scans a memory image with a YARA rule
  (`vol.py -f memory.raw yarascan -U "<pattern>"`).
- Community rules: Yara-Rules/rules on GitHub (thousands of signatures).
- Limits: YARA must be installed (`apt install yara`, C library + Python
  bindings); it is a matcher, not a memory tool — no ownership check, no
  memory-map listing, no entropy scan, no watch mode, no report file of its own.
- What MemSeeker takes from it: the three pattern types (string / hex / regex)
  and the idea of a rule file. What MemSeeker does differently: **zero
  dependencies** (pure Python stdlib, no YARA install), a simpler rule format,
  plus the ownership check, chunked reading, entropy, strings and watch mode
  that YARA does not provide.

## 2. Volatility 3 — memory forensics framework

- Analyses a captured memory IMAGE (offline), not a live process. Plugins:
  `linux.proc_maps` (process memory maps, with `--dump`), `yarascan`,
  `procdump`.
- Needs a full RAM capture first (LiME, DumpIt, Magnet RAM Capture, FTK Imager).
- Heavy framework (Python, many plugins, profiles/symbols); built for incident
  response on a dead image, not for "scan this PID right now".
- What MemSeeker takes from it: the concepts of regions/maps and dumping a
  process's memory. What MemSeeker does differently: live, one-PID, one-command
  scanning with no image capture and no framework install.

## 3. HackByte (DX4GREY/hackbyte, PyPI `hackbyte`)

- Python CLI memory scanner/editor for Linux (also Termux/Android NetHunter),
  root required. Features: search memory values (int, float, string), **edit**
  memory addresses, **freeze** values, attach by PID or name, interactive
  shell (`cmdloop`).
- Needs `/proc/[pid]/mem` and `/proc/[pid]/maps`, ptrace or
  `process_vm_readv` support.
- Limits: game-hacking oriented; it WRITES to other processes (edit/freeze) —
  the opposite of MemSeeker's read-only design. No rule file, no hex/regex
  patterns, no ownership check, no report file, no entropy, no watch mode.
- What MemSeeker takes from it: the CLI + `/proc` attach-by-PID pattern.
  What MemSeeker does differently: read-only by design, rule-file matching,
  ownership check, reports.

## 4. memscan.py (blog.omardib.com — game memory scanning)

- ~80 lines of Python, no dependencies, Linux only. Reads `maps`, keeps
  writable non-file-backed regions, reads each region in chunks, finds a
  4-byte value (`first` / `next` filtering), can also write/freeze.
- Key facts from the article: `/proc/<pid>/maps` lists regions (address range,
  permissions, offset, device, inode, path); `/proc/<pid>/mem` is the memory
  itself (seek + read); the kernel gates `mem` behind a ptrace access check —
  a process running as the same user passes it, but Yama `ptrace_scope`
  shrinks that: at scope 1 only a parent may attach to its descendants unless
  the reader holds `CAP_SYS_PTRACE`.
- Limits: value search only (no strings/hex/regex rules), no report, no
  ownership check, no entropy/strings/watch.
- What MemSeeker takes from it: the chunked-read loop and the Yama caveat
  (see RESEARCH_IMPLEMENTATION.md — parent-child trick and the sudo note).

## 5. Simple dump scripts (GitHub gist LAripping, Dbof's blog)

- One-file Python scripts: parse `maps` with a regex, open `mem`, read each
  readable region and write it to a `.dump` file. `python3 memdump.py <PID>`.
- Limits: they read **whole regions into memory at once** (no chunking — a
  multi-GB region can OOM the tool), they dump instead of matching, no rules,
  no report, no ownership check, and they crash on guarded/unreadable pages
  (no per-region error handling).
- What MemSeeker takes from it: the basic maps+mem loop. What MemSeeker does
  differently: chunked reading with an overlap window, per-region error
  handling (skip guarded pages, never crash), pattern matching instead of
  dumping.

## 6. LiME — Linux Memory Extractor

- Kernel module that captures the FULL physical memory of a Linux machine to a
  file. The capture step for Volatility-style analysis.
- Limits: whole-system capture, needs a kernel module + root, not per-process,
  no pattern matching.
- Not a competitor — a different layer. MemSeeker works live per-process and
  never needs a kernel module.

## 7. gcore / pmap / strings / bulk_extractor / pmemstat

- `gcore -o dump <PID>` — dumps a process's memory to a core file. No
  matching, no rules, no report.
- `pmap <PID>` — shows the memory map only. No reading, no matching.
- `strings /proc/<PID>/mem` — extracts readable strings; the standard
  one-liner for hunting secrets in memory (`strings ... | grep -iE
  "password|secret|token|key"`). No rules, no offsets, no regions, no report.
- `bulk_extractor` — scans disk/memory IMAGES for features (emails, credit
  cards, URLs). Image-based, not live per-process.
- `pmemstat` — proportional memory statistics from `/proc/<PID>/smaps`.
  Statistics, not a scanner.

## Comparison table

| Tool | Live PID scan | Rule file (str/hex/regex) | Ownership check | Chunked+overlap | Entropy | Strings ctx | Watch mode | Report file | Zero-dep | Read-only |
|---|---|---|---|---|---|---|---|---|---|---|
| YARA | yes | yes (YARA rules) | no | n/a | no | no | no | no | no | yes |
| Volatility 3 | no (image) | yes (yarascan) | n/a | n/a | no | no | no | yes | no | yes |
| HackByte | yes | no | no | ? | no | no | no | no | yes | **no (writes)** |
| memscan.py | yes | no | no | yes | no | no | no | no | yes | no (writes) |
| dump scripts | yes | no | no | no | no | no | no | no | yes | yes |
| LiME | no (capture) | no | n/a | n/a | no | no | no | no | no | yes |
| gcore/pmap/strings | partial | no | no | n/a | no | partial | no | no | yes | yes |
| **MemSeeker (planned)** | **yes** | **yes (simple format)** | **yes** | **yes** | **yes** | **yes** | **yes** | **yes (text+JSON)** | **yes** | **yes** |

## What MemSeeker adds over everything found

1. **YARA-style rules with zero dependencies** — string, hex and regex in one
   simple rule file, pure Python stdlib; no YARA install, no C library.
2. **Ownership check** — refuses any process owned by another user (none of
   the small tools do this; it is a PDF must-have and a safety feature).
3. **Chunked reading + overlap window** — large regions never load fully into
   memory, and a pattern split across a chunk boundary is never missed (the
   dump scripts read whole regions; memscan.py has no overlap concept).
4. **Entropy scan** — flags high-entropy regions that may hold packed or
   encrypted data (none of the small tools do this).
5. **String extraction around hits** — readable context, not just an offset.
6. **Watch mode** — rescan every N seconds, report only NEW hits.
7. **Menu + full CLI + text/JSON reports** — same interface family as
   SSTIProbe / RBACLens / PipeSentry (menu, config block, `[?]` prompts).
8. **Read-only by design** — never writes to another process (unlike HackByte
   and memscan.py, which edit/freeze memory).
