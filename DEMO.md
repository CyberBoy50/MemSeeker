# MemSeeker — Demo and Write-up

A real scan of the lab process, end to end. Everything below is real
output from this machine (25 November 2026).

## 1. Start the lab and scan it

One command starts the lab process as the tool's own child (so Yama
`ptrace_scope=1` allows the read) and scans it with the lab rules,
entropy scan and string extraction:

```
$ python run.py labscan
```

```
Lab process started: PID 11116 (python3)

 [ SCAN ] MemSeeker v1.0
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

## 6. The defensive lesson

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
