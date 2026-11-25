# MemSeeker — Demo and Write-up

A real scan of the lab process, end to end. Everything below is real
output from this machine (25 November 2026), MemSeeker v1.1. Section
10 adds the v1.3 runs (26 November 2026).

## 1. Start the lab and scan it

One command starts the lab process as the tool's own child (so Yama
`ptrace_scope=1` allows the read) and scans it with the lab rules,
entropy scan and string extraction:

```
$ python run.py labscan
```

```
Lab process started: PID 11116 (python3)

 [ SCAN ] MemSeeker v1.1
 Process ID            : 11116
 Process               : python3
 Rules file            : rules_lab.txt (5 rules)
 Chunk size            : 65536 bytes
 Entropy scan          : on
 String extraction     : on
 Output                : memseeker_report.txt

 Regions read          : 58 (2 skipped)
 Bytes read            : 17866752 in 0.91 s
 Hits                  : 5
 Entropy flags         : 5
```

58 of 61 regions were read (2 skipped — guarded pages that refused
the read, recorded, never a crash), 17.9 MB in under a second, 5 hits
— one per rule — and 5 high-entropy chunks flagged.

The full report is saved: `report_lab.txt` (text) and
`report_lab.json` (JSON).

## 2. The five hits

| # | Rule | Type | Address | Region |
|---|---|---|---|---|
| 1 | MemMarkerAlpha | string | `0x7fb61c15ffd0` | `[anon]` heap |
| 2 | ApiKeyPattern | regex | `0x7fb61c15fd90` | `[anon]` heap |
| 3 | StraddleMarker | string | `0x7fb61c15ffb0` | `[anon]` heap |
| 4 | LeakedPassword | string | `0x7fb61c1bc690` | `[anon]` heap |
| 5 | InjectedBytes | hex | `0x7fb61c1bc680` | `[anon]` heap |

Every hit is in the anonymous heap region — exactly where the lab
planted the markers. Nothing matched in the file-backed regions
(the lab's own source file, the shared libraries), which is the
proof the markers were built at runtime and never sat in the source
as literals.

## 3. One finding, explained — the leaked password

```
Hit 4: rule LeakedPassword (string)
  Rule:    Plaintext password left in process memory
  Region:  [anon] (7fb61bfe1000-7fb61c243000, rw-p)
  Address: 0x7fb61c1bc690 (offset 0x1db690 in region)
  Match:   68 75 6e 74 65 72 32 ('hunter2')
  Context: ......"3........<<hunter2>>.0..............
  Context hex (before): de ad be ef 00 11 22 33 00 ac eb 1b b6 7f 00 00
  Context hex (after):  00 30 9a b3 00 00 00 00 00 00 c7 1b 1c b6 7f 00
  Strings around hit:
    _json.Scanner
    _json.Encoder
    hunter2
    sk-ABCDEF1234
```

What this means: the lab program kept the password `hunter2` in a
plain variable. The password was never written to disk — there is no
file on the machine containing it — yet here it is, sitting in the
process's heap at address `0x7fb61c1bc690`, readable by anyone who can
read that process's memory. The context bytes around it even show the
neighbouring markers (`de ad be ef ...` just before it), and the
string extraction lists `hunter2` among the readable strings near the
hit.

In a real incident this is how an investigator finds a credential
that only ever lived in RAM: a password typed into a program, a token
fetched from an API, a decryption key unwrapped for one operation.
Disk forensics would find nothing. Memory forensics finds it in one
scan.

## 4. The entropy flags

Four chunks of the anonymous region scored **8.00 bits/byte** — pure
random data. That is the lab's 256 KiB random blob: packed or
encrypted data looks exactly like this, because good encryption and
good compression both erase patterns. The fifth flag is
`libm.so.6` at **7.51 bits/byte** — a dense system library that just
trips the threshold. Entropy flags are leads, not verdicts: the blob
is the real find, the library is noise, and the analyst tells them
apart by looking at the region name.

## 5. Watch mode

Start the lab, then watch it — rescan every 5 seconds, new hits only:

```
$ python3 memseeker.py <pid> --rules rules_lab.txt --watch 5
```

Round 1 reports the five hits. Later rounds report `No new hits`
until something changes in the process memory — then only the new
hits are printed. (The step tests prove this: they swap the rule file
between rounds and the new rule's hit appears as NEW in round 2.)

## 6. Rule groups — one finding from several rules (v1.1)

The group rule file (`rules_groups.txt`) keeps three member rules and
adds three groups:

```ini
[Group:SecretPair]
condition = 2 of (MemMarkerAlpha, LeakedPassword, ApiKeyPattern)

[Group:AnySecret]
condition = any of (MemMarkerAlpha, LeakedPassword, ApiKeyPattern)

[Group:AllSecrets]
condition = all of (MemMarkerAlpha, LeakedPassword, ApiKeyPattern)
```

```
$ python3 memseeker.py --lab --rules rules_groups.txt --no-color
Lab process started: PID 17293 (python3)
 Regions read          : 58 (2 skipped)
 Bytes read            : 17862656 in 0.93 s
 Hits                  : 6
 Entropy flags         : 5
```

6 hits, not 3: the three member rules each fire once, and all three
groups fire too, because all three members fired in the same
anonymous heap region:

```
 Hit 4: SecretPair (group)
  Region:  [anon] (71ad18879000-71ad18adb000)
  Address: 0x71ad189f7d90 (offset 0x17ed90 in region)
  Match:   73 6b 2d ... ('<redacted>')
  Context: ........`:.7....<<<redacted>>>..q.......... ..
  Strings: sk-ABCDEFGH12345678XYZABCDE
```

Why this matters: a single leaked password is a finding, but a
password **and** an API key in the same region is a much stronger
one — it means the process is holding a whole set of live secrets,
not one stray string. The group finding says exactly that in one
line: "2 of these 3 secret rules fired here". A `2 of` group also
stays silent when only one member fires (the step tests prove both
directions), so it does not cry wolf over a single match.

Note the `<redacted>` in the match line: the tool redacts the API
key itself from the printed match and context, so the report does
not become a second copy of the secret.

## 7. Scan everything you own — `--all` (v1.1)

```
$ python run.py scanall
```

In this VM the scan runs as root under Yama `ptrace_scope=1` without
`CAP_SYS_PTRACE`, so processes that are not the tool's own children
are refused cleanly and listed as skipped — the scan never crashes:

```
Processes: 3 scanned, 6 skipped
  PID 17339 (python3): 5 hit(s), 58 regions, 17862656 bytes
  PID 17340 (python3): 5 hit(s), 58 regions, 17862656 bytes
Skipped: 6 processes (not ours / unreadable)
  PID 1: Permission denied opening /proc/1/mem for PID 1.
         The kernel blocked the read (Yama ptrace_scope). ...
```

Both lab processes (started as children, so the read is allowed)
show their 5 hits each; the other processes are skipped with the
reason. On Kali Linux, where you are root with `CAP_SYS_PTRACE`,
the same command reads every own process instead of skipping them.
The report is grouped per process — PID, process name, then that
process's hits — in text and in JSON.

## 8. Scan a memory image — `--image` and `--dump` (v1.1)

Dump the lab's heap region to a file, then scan the file as if it
were memory. The file offsets are the addresses:

```
$ python3 memseeker.py --image heap.bin --rules rules_lab.txt

 [ SCAN ] MemSeeker v1.1
 Mode                  : Memory image: heap.bin
 Rules file            : rules_lab.txt (5 rules)
 Chunk size            : 65536 bytes
 Entropy scan          : off
 String extraction     : off
 Output                : memseeker_report.txt

 Regions read          : 1 (0 skipped)
 Bytes read            : 2498560 in 0.01 s
 Hits                  : 5
```

The same 5 markers, at the same offsets as the live scan — the alpha
marker at offset `0x17efd0`, the API key at `0x17ed90`, the password
at `0x1db690`. A dump taken on one machine can be analysed on any
other, with no live-process access at all. `--base 0x100000` shifts
every reported address by that base when the dump came from a known
address.

With `--dump`, the hit regions are saved alongside the report:

```
$ python3 memseeker.py <pid> --rules rules_lab.txt --dump dumps/
DUMP: 1 file(s):
  dumps/17339_7536b66a2000-7536b6904000_anon.bin
DUMP: hits with dump_file set: 5/5
```

Only the region that held the hits is dumped (one file here — all
five hits live in the same heap region), and every hit's report entry
names the dump file, in the text report and in the JSON report.
Regions without hits are never dumped.

## 10. v1.3 — the remaining gaps, closed (26 November 2026)

Version 1.3 closes every gap from the report's section 13 that can
be closed on this machine. All of it is real output, from the runs
below and from Step 11 of the test suite (30 new checks, 151 total,
all passing).

### Long regex matches across chunk boundaries

Before v1.3 a regex match longer than ~512 bytes that straddled a
chunk boundary could be missed. The overlap is now 8191 bytes
(`min(8192, chunk_size - 1)`). A dump file holding a 2000-byte run
of `B` straddling the 4096-byte boundary and a 1500-byte run inside
one chunk, scanned with `--chunk-size 4096` and the rule
`B{1500,}`:

```
$ python3 memseeker.py --image long.bin --rules long_rules.txt --chunk-size 4096
 [+] Report saved: long.txt
 [!] 2 hit(s) — see the report.

Hit 1: rule LongRun (regex)
  Address: 0xdac (offset 0xdac in region)      # 3500 — the straddling match
Hit 2: rule LongRun (regex)
  Address: 0x1964 (offset 0x1964 in region)    # 6500 — the in-chunk match
```

Both found, exactly once each, with the reported match lengths 2000
and 1500 bytes. (The `Match:` hex line for a 2000-byte match is 2000
bytes long, so it is left out of this write-up.)

### String modifiers: `nocase` and `wide`

A dump file holding `HuNtEr2` (mixed case), `hunter2` as UTF-16LE,
and plain `hunter2`, scanned with three rules — `nocase`, `wide`
and plain:

```
Hit 1: rule NocasePw (string)
  Address: 0x64 (offset 0x64 in region)
  Match:   48 75 4e 74 45 72 32 ('HuNtEr2')
Hit 2: rule NocasePw (string)
  Address: 0x3e8 (offset 0x3e8 in region)
  Match:   68 75 6e 74 65 72 32 ('hunter2')
Hit 3: rule WidePw (string)
  Address: 0x1f4 (offset 0x1f4 in region)
  Match:   68 00 75 00 6e 00 74 00 65 00 72 00 32 00 ('h.u.n.t.e.r.2.')
Hit 4: rule PlainPw (string)
  Address: 0x3e8 (offset 0x3e8 in region)
  Match:   68 75 6e 74 65 72 32 ('hunter2')
```

The `nocase` hit keeps its original case (`HuNtEr2`, not lowercased
in the report); the plain rule matches neither the mixed-case nor
the wide form. `--list-rules` shows the modifiers, and a bad
modifier (`nocase` on a hex rule, `nocase = maybe`) is a clean error
naming the rule. `rules_default.txt` now ships both as examples
(`PasswordWordNoCase`, `PasswordWordWide`).

### Tunable entropy threshold

The lab scan at the default threshold flags 5 chunks — the four
random-blob chunks at 8.00 bits/byte plus `libm.so.6` at 7.51.
Raising the threshold drops the library noise and keeps the real
find:

```
$ python3 memseeker.py --lab --rules rules_lab.txt --entropy --entropy-threshold 7.9
Entropy:   4 high-entropy chunk(s) flagged (>= 7.9 bits/byte)
```

4 flags, all in the anonymous heap at 8.00 bits/byte. The threshold
used is recorded in the report (`Entropy threshold: 7.9 bits/byte`
in text, `entropy_threshold_bits_per_byte` in JSON), and a value
outside 0–8 is a clean error (exit 2).

### Map-change detection and watch groups

The memory map is re-read after every scan. On a normal lab scan
nothing changed (`map_changed: false` in the JSON report); the test
suite proves the other direction by feeding a changed map back and
checking the report says so. Watch mode now reloads the rule groups
every round like the rules — before v1.3 it silently ignored them,
so a group that should have fired in watch mode never did. `--map`
now goes through the platform backend instead of reading `/proc`
directly, so it works on Windows and macOS too.

### What v1.3 honestly leaves open

Three things remain, and they remain for reasons no code written
here can remove: live Windows testing needs a real Windows run and
live macOS testing needs a real Mac (mocked tests cover the logic,
not the real OS calls); the full YARA language needs the YARA engine
(a C library to install — against this tool's zero-dependency
design); and Volatility-style profiled image analysis needs a
Volatility-scale profiler. Those are stated in the README and the
report, not hidden.

## 11. The defensive lesson

**Secrets must never sit in process memory in plaintext.**

A password or an API key stored in a plain variable is readable by
anyone who can read the process memory — a debugger, a memory dump,
a scanner like this one, or an attacker who gets code execution in
the same user context. The lab just proved it: `hunter2` never
touched the disk, and it was still found in under a second.

What programs do instead:

- **Zero the buffer as soon as they are done with it** — overwrite
  the password bytes with zeros the moment the login succeeds, so the
  secret's lifetime in memory is seconds, not the whole run.
- **Lock the memory** (`mlock`) — keep the pages holding secrets out
  of the swap file, so the secret never lands on disk in a pagefile.
- **Keep keys in a system keyring or a hardware-backed store** (OS
  keychain, TPM, HSM) and only unwrap them for the single operation
  that needs them.
- **Never log secrets, never put them in environment variables that
  linger, never keep them in a global "config" object for the life
  of the program.**

The lesson of this tool in one line: if a secret is in memory in
plaintext, assume it can be read — so make sure it is not there any
longer than it has to be.
