# MemSeeker — Step-by-Step Guide

Build the tool one step at a time, test each step before moving on.
Every step below is a function in `test_memseeker.py` — run the whole
suite with `python run.py test` (151 checks, all passing).

Setup first (once):

```
python run.py setup
```

The lab process (`lab_proc.py`) holds the planted markers in memory
and prints one JSON line with its PID and marker addresses, then
sleeps. The test suite starts it as its own child; you can do the
same in one step with `python run.py labscan`.

## Step 1 — Read the memory map

**Write:** open `/proc/<pid>/maps` of a process you own and print
every region with its range and permissions.

**Run:**

```
python3 memseeker.py <pid> --map
```

**Expected output** (real run, lab process):

```
Memory map — PID 11116 (python3)
Regions: 61 total, 58 readable

 RANGE                      PERM   SIZE        NAME
  55c...-55c...             r--p  ...
  ...
  7fb61bfe1000-7fb61c243000  rw-p  2596864     [anon]
  ...
  7fb61bfe1000-...          rw-p  ...         [heap]
```

**Test it:** the printed regions must match the map you read manually
(`cat /proc/<pid>/maps`) — same count, same first range. The test
(`step1`) checks exactly that.

## Step 2 — Read one region

**Write:** read the bytes of one readable region in chunks and print
the total bytes read.

**Run:**

```
python run.py test   # step2: reads the heap region in 4 KiB chunks
```

**Expected output:**

```
Step 2 — Read one region
  [PASS] read: alpha marker lives in a region
  [PASS] read: total bytes read == region size
  [PASS] read: full scan completes without crashing
  [PASS] read: skipped regions are recorded, not fatal
```

**Test it:** the total must match the region size from the map, and
the read must never crash on a guarded page — a full scan completes
and records skipped regions instead of dying.

## Step 3 — One pattern match

**Write:** match a plain-string pattern against a region's bytes and
print the offset of every hit.

**Run:**

```
python run.py test   # step3: one rule, MemMarkerAlpha, against the lab
```

**Expected output:**

```
Step 3 — One pattern match
  [PASS] match: exactly one hit for the string marker
  [PASS] match: hit address == the address the lab printed
  [PASS] match: offset == address - region start
  [PASS] match: hit is in the anonymous heap region
  [PASS] match: context bytes surround the hit
```

**Test it:** run the lab program holding a marker string — the
marker's offset must be reported, and the hit must be in the
anonymous heap region (not in the file-backed copy of the source).

## Step 4 — The rule file

**Write:** load rules from a file with all three pattern types and
match them all in one pass.

**Run:**

```
python run.py test   # step4: string + hex + regex, one file
```

**Expected output:**

```
Step 4 — The rule file (string, hex, regex)
  [PASS] rules: three rules loaded from the file
  [PASS] rules: types are string, hex, regex
  [PASS] rules: string rule fires once on its marker
  [PASS] rules: hex rule fires once on its marker
  [PASS] rules: regex rule fires once on its marker
  [PASS] rules: string hit is at the lab's alpha address
  [PASS] rules: hex hit is at the lab's hex address
  [PASS] rules: regex hit is at the lab's apikey address
  [PASS] rules: decoy markers stay silent (no hit on their addresses)
```

**Test it:** use a rule file with one rule of each type — each must
fire on its prepared marker and stay silent otherwise. The two decoy
markers (`MEMSEEKER_MARKER_BETA`, the short `sk-` key) must produce
zero hits.

## Step 5 — Overlap window

**Write:** keep an overlap between chunks and test a pattern placed
so it straddles a chunk boundary.

**Run:**

```
python run.py test   # step5: chunk size chosen so the marker straddles
```

**Expected output:**

```
Step 5 — Overlap window (straddling pattern)
  [PASS] overlap: a straddling chunk size exists for this run
  [PASS] overlap: straddling marker found with chunk size 32
  [PASS] overlap: straddle marker also found with default chunks
```

**Test it:** the straddling pattern must still be found — a missed
boundary hit is a failed test. The test reads the marker's address
from the lab, picks a chunk size that puts the marker across a
boundary, and asserts the hit is found exactly once.

## Step 6 — CLI, ownership check and report

**Write:** use argparse for the process ID and rule file, enforce the
ownership check, and save the full report.

**Run:**

```
python run.py test   # step6: nobody's process, bad PIDs, bad rules
```

**Expected output:**

```
Step 6 — CLI, ownership check and report
  [PASS] ownership: tool refuses another user's process
  [PASS] ownership: refusal names the owner, no traceback
  [PASS] ownership: nonexistent PID is a clean error (exit 2)
  [PASS] rules: bad hex errors cleanly and names the rule
  [PASS] rules: bad regex errors cleanly and names the rule
  [PASS] rules: unknown type errors cleanly and names the rule
  [PASS] rules: empty pattern errors cleanly and names the rule
  [PASS] rules: missing rule file is a clean error (exit 2)
  [PASS] cli: separate-process scan refused cleanly by Yama
```

**Test it:** try the tool on a process owned by another user — it
must refuse cleanly:

```
$ su nobody -s /bin/sh -c 'echo $$; exec sleep 60'
12345
$ python3 memseeker.py 12345 --rules rules_lab.txt
[x] Refusing PID 12345: it is owned by UID 65534, not by you (UID 0).
    MemSeeker only scans processes you own.
```

Exit code 2, no traceback. A bad rule file is the same kind of clean
error — it names the rule (`Rule 'BadHex' ... has bad hex`) before any
scanning starts.

## Step 7 — Full scan of a lab process

**Write:** run the complete tool against a lab process holding several
planted markers.

**Run:**

```
python run.py labscan
```

**Expected output:**

```
Lab process started: PID 11116 (python3)
Regions read: 58 (2 skipped)
Bytes read:   17866752 in 0.91 s
Hits:         5 (one per rule)
Entropy flags: 5
```

**Test it:** read the saved report from start to finish — every
planted marker must appear with the right region and offset
(`report_lab.txt`):

```
Hit 4: rule LeakedPassword (string)
  Region:  [anon] (7fb61bfe1000-7fb61c243000, rw-p)
  Address: 0x7fb61c1bc690 (offset 0x1db690 in region)
  Match:   68 75 6e 74 65 72 32 ('hunter2')
```

The test (`step7`) checks all five markers at the lab's printed
addresses, one hit per rule, all in the anonymous heap region, and
that the text and JSON reports contain every rule name and offset.

## Step 8 — Stretch: entropy, strings, watch

**Write:** flag high-entropy regions, print strings around each hit,
and rescan every N seconds reporting only new hits.

**Run:**

```
python run.py test   # step8
python3 memseeker.py <pid> --rules rules_lab.txt --entropy --strings
python3 memseeker.py <pid> --rules rules_lab.txt --watch 5
```

**Expected output:**

```
Step 8 — Stretch: entropy, strings, watch
  [PASS] entropy: high-entropy chunks flagged inside the random blob
  [PASS] entropy: flagged chunks are ~8.0 bits/byte
  [PASS] entropy: flagged chunks are in the anonymous region
  [PASS] strings: strings around the password hit include it
  [PASS] watch: watch mode ends cleanly after 3 rounds
  [PASS] watch: the ApiKey hit appears as NEW in round 2
  [PASS] watch: round 3 reports no new hits
```

**Test it:** the 256 KiB random blob must flag chunks at ~8.0
bits/byte; the strings around the `hunter2` hit must include
`hunter2`; and in watch mode a rule added between rounds must appear
as a NEW hit in the next round only.

## Step 9 — v1.1: multi-PID, image, dump, groups

**Write:** scan every process you own (`--all`) and several PIDs at
once (`--pids`); scan a raw memory dump file (`--image`, `--base`);
dump every region that holds a hit (`--dump`); and evaluate
YARA-style group conditions per region (`[Group:Name]`).

**Run:**

```
python run.py test   # step9
python3 memseeker.py --all --rules rules_lab.txt
python3 memseeker.py --pids 1234,5678 --rules rules_lab.txt
python3 memseeker.py --image heap.bin --rules rules_lab.txt
python3 memseeker.py <pid> --rules rules_lab.txt --dump dumps/
python3 memseeker.py --lab --rules rules_groups.txt
```

**Expected output:**

```
Step 9 — v1.1: multi-PID, image, dump, groups
  [PASS] all: both lab processes appear in the --all results
  [PASS] all: lab 1 has all five lab hits
  [PASS] all: lab 1 hits are in the anonymous heap
  [PASS] all: lab 2 has all five lab hits
  [PASS] all: lab 2 hits are in the anonymous heap
  [PASS] all: unreadable processes are skipped, not fatal
  [PASS] pids: scan_pids returns one result per PID
  [PASS] pids: both results have five hits each
  [PASS] multi: text report lists both PIDs
  [PASS] multi: text report lists every hit offset
  [PASS] multi: JSON report has one entry per process
  [PASS] pids: CLI --pids refused cleanly by Yama (no CAP_SYS_PTRACE here)
  [PASS] image: alpha marker lives in a region
  [PASS] image: the heap region dumps to a file
  [PASS] image: the dump scan finds the region's markers
  [PASS] image: MemMarkerAlpha at the same offset as the live scan
  [PASS] image: LeakedPassword at the same offset as the live scan
  [PASS] image: InjectedBytes at the same offset as the live scan
  [PASS] image: ApiKeyPattern at the same offset as the live scan
  [PASS] image: StraddleMarker at the same offset as the live scan
  [PASS] image: --base shifts every hit address by the base
  [PASS] image: CLI --image finds the markers (exit 1)
  [PASS] dump: exactly the hit regions are dumped (one file)
  [PASS] dump: the file name carries PID, range and region
  [PASS] dump: the dumped file holds the region bytes
  [PASS] dump: every hit names its dump file
  [PASS] dump: the JSON report names the dump file
  [PASS] dump: CLI --image --dump writes the region file
  [PASS] groups: one group loaded from the file
  [PASS] groups: '2 of' fires once when all three members fire
  [PASS] groups: the group hit is in the anonymous heap
  [PASS] groups: '2 of' stays silent when only one member fires
  [PASS] groups: two groups loaded (all of + any of)
  [PASS] groups: 'all of' and 'any of' both fire when all members fire
  [PASS] groups: 'all of' stays silent, 'any of' fires, when one member is missing
  [PASS] groups: unknown member errors cleanly and names the group
  [PASS] groups: impossible count errors cleanly and names the group
  [PASS] groups: bad syntax errors cleanly and names the group
  [PASS] groups: --list-rules shows the group names and conditions
```

**Test it:** start two lab processes and scan all — both must appear
with 5 hits each; dump one lab's heap region to a file and scan the
file — the same markers at the same offsets; scan with a dump
directory — exactly one file (all five hits live in one region) and
every hit names it; and write group files where 2 of 3, all of, and
any of are each checked in both directions (fires when the condition
is met, silent when it is not).

## Step 10 — v1.1 cross-platform backends (mocked Windows/macOS)

**Write:** a backend abstraction — one reader interface with three
backends (Linux `/proc`, Windows kernel32 via `ctypes`, macOS mach
via `ctypes`) — and test the Windows/macOS backends with mocked
`ctypes` calls, since this VM is Linux only and the real OS calls
cannot run here.

**Run:**

```
python run.py test   # step10
```

**Expected output:**

```
Step 10 — Cross-platform backends (mocked Windows/macOS)
  [PASS] win: mocked VirtualQueryEx lists the readable regions
  [PASS] win: NOACCESS and GUARD regions are skipped
  [PASS] win: mapped file name becomes the region name
  [PASS] win: process name comes from the image name
  [PASS] win: mocked scan finds the alpha marker
  [PASS] win: mocked scan finds the boundary-straddling marker
  [PASS] win: mocked hit address is the marker's address
  [PASS] win: access denied is a clean refusal, not a traceback
  [PASS] mac: mocked vm_region_64 lists the readable regions
  [PASS] mac: a region without read permission is skipped
  [PASS] mac: permissions map to the rwxp string
  [PASS] mac: mocked scan finds the alpha marker
  [PASS] mac: mocked hit address is the marker's address
  [PASS] mac: task_for_pid refusal is clean and names the privilege
  [PASS] image: ImageFile reads at base + offset
  [PASS] image: an address below the base is refused
  [PASS] backends: get_backend() is the Linux backend on this VM
  [PASS] backends: named backends construct on any platform
```

**Test it:** stub the kernel32/mach functions with
`unittest.mock.patch` on the module-level `_win_*` / `_mac_*`
functions — fake `VirtualQueryEx` returning canned regions
(readable READWRITE + READONLY, NOACCESS and GUARD skipped),
fake `ReadProcessMemory` from a canned memory dict holding the
alpha marker and a marker straddling a 64-byte chunk boundary, and
an access-denied case (`OpenProcess` → None, error 5) that must be
a clean refusal. Same for macOS: fake `task_for_pid` /
`vm_region_64` / `vm_read`, plus the denied case. The mocked tests
cover the logic, not the real OS calls — a real Windows run and a
real Mac run are still needed for live verification.

## Step 11 — v1.3: long regex, modifiers, entropy threshold, map change, watch groups

**Write:** raise the regex overlap to 8192 bytes; add `nocase` /
`wide` modifiers to string rules; make the entropy threshold a
`--entropy-threshold` flag; re-read the memory map after every scan
and record a change; reload rule groups every watch round; route
`--map` through the platform backend.

**Run:**

```
python run.py test   # step11
python3 memseeker.py --image long.bin --rules long_rules.txt --chunk-size 4096
python3 memseeker.py --lab --rules rules_lab.txt --entropy --entropy-threshold 7.9
```

**Expected output:**

```
Step 11 — v1.3: regex overlap, modifiers, entropy, map change, watch groups
  [PASS] regex: a regex rule keeps 8191 bytes of overlap (default chunk)
  [PASS] regex: the overlap is capped by the chunk size
  [PASS] regex: a 2000-byte match straddling a chunk boundary is found (past the old 512 bound)
  [PASS] regex: a 1500-byte match inside one chunk is found
  [PASS] regex: each long match is found exactly once
  [PASS] regex: the reported matches are 2000 and 1500 bytes
  [PASS] mods: nocase matches the mixed-case and plain forms
  [PASS] mods: the nocase hit keeps its original case
  [PASS] mods: wide matches the UTF-16LE encoding
  [PASS] mods: wide match bytes are the UTF-16LE encoding
  [PASS] mods: a plain rule matches neither mixed-case nor wide
  [PASS] mods: --list-rules shows nocase and wide
  [PASS] mods: nocase on a hex rule errors cleanly and names the rule
  [PASS] mods: bad nocase value errors cleanly and names the rule
  [PASS] entropy: default threshold 7.5 flags the random chunk
  [PASS] entropy: the report names the 7.5 threshold
  [PASS] entropy: threshold 8.0 flags nothing (random data is below 8.0 bits/byte)
  [PASS] entropy: the result and report carry the 8.0 threshold
  [PASS] entropy: the JSON report carries the threshold
  [PASS] entropy: CLI threshold 9 is a clean error (exit 2)
  [PASS] entropy: CLI --entropy-threshold 8.0 writes the threshold into the report
  [PASS] mapchange: a changed map is detected after the scan
  [PASS] mapchange: the text report says the map changed
  [PASS] mapchange: the JSON report carries map_changed=true
  [PASS] mapchange: a map that cannot be re-read is reported, not a crash
  [PASS] mapchange: an unchanged map is not flagged
  [PASS] watch: watch mode ends cleanly after 1 round
  [PASS] watch: the group fires inside watch mode (groups are no longer ignored)
  [PASS] map: --map works through the platform backend (Windows regions listed)
  [PASS] map: the backend's ownership check was used
```

**Test it:** build a dump file with a 2000-byte regex match
straddling a 4096-byte chunk boundary — it must be found exactly
once (the old 512-byte bound would have missed it); build a file
with `HuNtEr2`, UTF-16LE `hunter2` and plain `hunter2` — the nocase
rule must hit the first two forms, the wide rule the UTF-16LE one,
the plain rule only the plain one; scan a file that is half random
bytes, half plain text — threshold 7.5 flags the random chunk,
threshold 8.0 flags nothing; mock the backend's second map read to
return a changed map — the report must say so, and a re-read that
fails must be reported, not a crash; run watch mode for one round
with a group file — the group must fire; and drive `--map` through
a mocked Windows backend — the regions must be listed.

## Full test suite

```
$ python run.py test
MemSeeker step tests
==========================================================
Step 1 — Read the memory map
...
PASSED: 151   FAILED: 0
ALL CHECKS PASSED
```

Exit code 0. Any failure prints `[FAIL]` with the check name — fix
it, re-run, and do not ship a version with a failing check.
