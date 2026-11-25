# MemSeeker — Step-by-Step Guide

Build the tool one step at a time, test each step before moving on.
Every step below is a function in `test_memseeker.py` — run the whole
suite with `python run.py test` (61 checks, all passing).

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

## Full test suite

```
$ python run.py test
MemSeeker step tests
==========================================================
Step 1 — Read the memory map
...
PASSED: 61   FAILED: 0
ALL CHECKS PASSED
```

Exit code 0. Any failure prints `[FAIL]` with the check name — fix
it, re-run, and do not ship a version with a failing check.
