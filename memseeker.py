#!/usr/bin/env python3
"""
MemSeeker — Process Memory Scanner (read-only)
PNY Trainings, Memory Forensics — Final Project

WHAT IT DOES
  You give it a process ID and a rule file. It reads the process memory
  map (/proc/<pid>/maps), takes every readable region, reads each region
  in chunks from the process memory file (/proc/<pid>/mem), and matches
  every chunk against the rules — plain strings, hex byte sequences and
  regular expressions. Every hit is reported with the region name, the
  offset inside the region, the absolute address and the surrounding
  context bytes, and saved to a report file. It only ever READS memory;
  it never writes to another process.

  What a program hides in memory is invisible to disk forensics. This
  tool looks where the disk never sees: injected markers, leaked
  secrets, suspicious strings — using rules you write yourself.

THE 6 MUST-HAVE FEATURES (PDF) — all in this file:
  1. Process ID input with an ownership check — refuses any process
     owned by another user
     -> check_ownership()
  2. Memory map parsing: every readable region with address range + name
     -> parse_maps()
  3. Chunked reading of each readable region (64 KiB default), so large
     regions never load fully into memory; a guarded page is skipped,
     never a crash
     -> read_region_chunks() + scan_region()
  4. Rule file with three pattern types: plain string, hex, regex
     -> load_rules()
  5. Hit reporting with region name, offset and surrounding context bytes
     -> scan_process() + Hit
  6. Report saved to a file: every hit with rule name, region and offset
     -> build_text_report() / build_json_report() + write_report()

STRETCH ITEMS (PDF — "if you finish early") — all in this file:
  * Entropy scan: Shannon entropy per chunk; a chunk above ~7.5 bits/byte
    is flagged as possibly packed or encrypted data
    -> shannon_entropy(), --entropy
  * String extraction: printable strings around each hit for context
    -> extract_strings(), --strings
  * Watch mode: rescan every N seconds, report only NEW hits
    -> watch_process(), --watch N

INSTALL — the scanner needs NOTHING installed:
  plain Python 3 is enough (standard library only). No pip, no venv,
  no YARA. Linux only — it reads /proc, which Windows and macOS do not
  have:
    python3 memseeker.py <pid> --rules rules_lab.txt

USAGE — three ways, same tool:
  Menu (SSTIProbe / TraceRecon style — default when run with no args):
    python run.py menu
    python3 memseeker.py --menu
      [ 1] Scan a process (enter PID, rules file)
      [ 2] Quick scan: lab process (starts the lab, scans it)
      [ 3] Show the memory map of a process
      [ 4] List all rules in a rule file
      [ 5] Run the step tests
      [ 6] Check setup (doctor)
      [ 7] Watch a process (rescan every N seconds, new hits only)
      [ 0] Exit
      [ ? ] Select option :

  Interactive prompts (option 1 in the menu asks the same questions):
    python3 memseeker.py -i
      [?] ENTER PROCESS ID (PID): 1234
      [?] ENTER RULE FILE [rules_lab.txt]: rules_lab.txt

  With arguments (for scripts / demo):
    python3 memseeker.py 1234 --rules rules_lab.txt
    python3 memseeker.py --lab   # start the lab as our child, scan it
    python3 memseeker.py 1234 --rules rules_lab.txt --entropy --strings
    python3 memseeker.py 1234 --rules rules_lab.txt --json -o report.json
    python3 memseeker.py 1234 --rules rules_lab.txt --watch 5
    python3 memseeker.py 1234 --map
    python3 memseeker.py --list-rules --rules rules_lab.txt
    python3 memseeker.py --version
    python3 memseeker.py 1234 --rules rules_lab.txt --no-color
    python3 memseeker.py 1234 --rules rules_lab.txt --batch
    python3 memseeker.py 1234 --rules rules_lab.txt -q   # quiet
"""

import argparse
import configparser
import json
import math
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime

VERSION = "1.0"
AUTHOR = "CyberBoy50"
QUIET = False

# Tunables (change here, nowhere else).
DEFAULT_CHUNK_SIZE = 65536      # 64 KiB per read — a region never loads whole
CONTEXT_BYTES = 16              # context bytes shown on each side of a hit
STRINGS_WINDOW = 64             # bytes scanned for strings around a hit
STRINGS_MIN_LEN = 4             # shortest printable run kept as a "string"
ENTROPY_THRESHOLD = 7.5         # bits/byte above this = possibly packed/encrypted
REGEX_MAX_LEN = 512             # assumed max length of a regex match (overlap)
MAX_OVERLAP = 4096              # overlap window is never bigger than this
MAX_HITS_PER_RULE = 10000       # safety cap so one wild rule cannot flood the report
DEFAULT_RULES = "rules_lab.txt"
DEFAULT_OUTPUT = "memseeker_report.txt"

# --- Colours (ANSI: works on Kali/macOS/Windows 10+ terminals) ----------
try:
    import colorama

    colorama.init()
except Exception:  # noqa: BLE001 - colour is cosmetic, never fatal
    pass


# --- Colours, TraceRecon style: one class, short names ------------------
class C:
    RST = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[1;31m"
    GRN = "\033[1;32m"
    YEL = "\033[1;33m"
    BLU = "\033[1;34m"
    MAG = "\033[1;35m"
    CYN = "\033[1;36m"
    WHT = "\033[1;37m"


RED = C.RED
GREEN = C.GRN
YELLOW = C.YEL
CYAN = C.CYN
BOLD = C.BLD
RESET = C.RST


def clear():
    """Clear the screen — GhostTrack / TraceRecon pattern."""
    os.system("cls" if os.name == "nt" else "clear")


def sep(color=C.GRN, char="─", width=58):
    """A rule line, TraceRecon style."""
    print(f"{color}{char * width}{C.RST}")


def header(title, color=C.GRN):
    """A titled section header with rule lines above and below."""
    sep(color)
    print(f"{color} {title}{C.RST}")
    sep(color)


def ok(msg):
    """[+] success line: ' [+] message' — white brackets, green plus."""
    print(f" {C.WHT}[{C.GRN}+{C.WHT}]{C.RST} {msg}")


def warn(msg):
    """[!] warning line, yellow."""
    print(f" {C.WHT}[{C.YEL}!{C.WHT}]{C.RST} {C.YEL}{msg}{C.RST}")


def err(msg):
    """[x] error line, red."""
    print(f" {C.WHT}[{C.RED}x{C.WHT}]{C.RST} {C.RED}{msg}{C.RST}")


def info(label, value, label_color=C.WHT, val_color=C.GRN):
    """One aligned field — TraceRecon style (label 22 chars)."""
    print(f" {label_color}{label:<22}{C.RST}: {val_color}{value}{C.RST}")


BANNER = r"""
 __  __               ____            _
|  \/  | ___ _ __ ___/ ___|  ___  ___| | _____ _ __
| |\/| |/ _ \ '_ ` _ \___ \ / _ \/ _ \ |/ / _ \ '__|
| |  | |  __/ | | | | |___) |  __/ __/   <  __/ |
|_|  |_|\___|_| |_| |_|____/ \___|\___|_|\_\___|_|

              by CyberBoy50
        MEMORY SCANNER  |  AUTHORIZED USE ONLY
 ==================================================
"""


class MemSeekerError(Exception):
    """A clean, user-facing failure: no traceback, just the message."""


# --- Regions -------------------------------------------------------------
class Region:
    """One line of /proc/<pid>/maps: address range, perms, pathname."""

    __slots__ = ("start", "end", "perms", "offset", "dev", "inode", "pathname")

    def __init__(self, start, end, perms, offset, dev, inode, pathname):
        self.start = start
        self.end = end
        self.perms = perms
        self.offset = offset
        self.dev = dev
        self.inode = inode
        self.pathname = pathname

    @property
    def size(self):
        return self.end - self.start

    @property
    def readable(self):
        return self.perms.startswith("r")

    @property
    def name(self):
        """Display name: the mapped file, [heap]/[stack], or [anon]."""
        return self.pathname if self.pathname else "[anon]"

    def range_str(self):
        return f"{self.start:012x}-{self.end:012x}"

    def __repr__(self):
        return f"<Region {self.range_str()} {self.perms} {self.name}>"


MAPS_RE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]{4})\s+([0-9a-f]+)\s+"
    r"([0-9a-f]+:[0-9a-f]+)\s+(\d+)\s*(.*)$"
)


def parse_maps(pid):
    """Read /proc/<pid>/maps and return every Region (readable or not).

    Raises MemSeekerError (no such process / permission denied) — the
    caller prints the message, never a traceback.
    """
    path = f"/proc/{pid}/maps"
    try:
        with open(path, "r") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        raise MemSeekerError(f"No process with PID {pid} (no {path}).")
    except PermissionError:
        raise MemSeekerError(
            f"Permission denied reading {path} for PID {pid}. "
            "Run as root / with sudo, or start the process from this tool."
        )
    regions = []
    for line in lines:
        m = MAPS_RE.match(line.rstrip("\n"))
        if not m:
            continue
        start, end = int(m.group(1), 16), int(m.group(2), 16)
        regions.append(Region(start, end, m.group(3), int(m.group(4), 16),
                              m.group(5), int(m.group(6)), m.group(7)))
    if not regions:
        raise MemSeekerError(f"No memory regions found for PID {pid}.")
    return regions


def readable_regions(regions):
    """Only the regions the tool is allowed to read."""
    return [r for r in regions if r.readable]


def check_ownership(pid):
    """PDF must-have 1: refuse any process owned by another user.

    Compares the owner UID of /proc/<pid> with our own UID. Works for
    root too (root's UID is 0; another user's process has a different
    UID, so it is refused). Returns the owner's UID on success.
    """
    try:
        owner_uid = os.stat(f"/proc/{pid}").st_uid
    except FileNotFoundError:
        raise MemSeekerError(f"No process with PID {pid}.")
    if owner_uid != os.getuid():
        raise MemSeekerError(
            f"Refusing PID {pid}: it is owned by UID {owner_uid}, not by "
            f"you (UID {os.getuid()}). MemSeeker only scans processes you "
            "own. Reading another person's process memory without "
            "permission is unauthorized access."
        )
    return owner_uid


def process_name(pid):
    """Short name of the process (from /proc/<pid>/comm), or '?'."""
    try:
        with open(f"/proc/{pid}/comm", "r") as fh:
            return fh.read().strip()
    except OSError:
        return "?"


# --- Rules ---------------------------------------------------------------
class Rule:
    """One rule from the rule file: name, type, compiled matcher."""

    __slots__ = ("name", "rtype", "raw", "compiled", "description", "plen")

    def __init__(self, name, rtype, raw, compiled, description, plen):
        self.name = name
        self.rtype = rtype          # "string" | "hex" | "regex"
        self.raw = raw              # pattern text as written in the file
        self.compiled = compiled    # bytes (string/hex) or re.Pattern (regex)
        self.description = description
        self.plen = plen            # length used for the overlap window

    def find_all(self, buf):
        """Yield (start, end) of every match of this rule in buf."""
        if self.rtype == "regex":
            for m in self.compiled.finditer(buf):
                yield m.start(), m.end()
        else:
            start = 0
            while True:
                i = buf.find(self.compiled, start)
                if i < 0:
                    return
                yield i, i + len(self.compiled)
                start = i + 1


def load_rules(path):
    """Load and compile the INI rule file. Returns a list of Rule.

    Format (see rules_lab.txt):
        [RuleName]
        type = string | hex | regex
        pattern = <the pattern>
        description = <optional, shown in reports>
    A bad rule (unknown type, bad hex, bad regex) raises
    MemSeekerError NAMING the rule, before any scanning starts.
    """
    if not os.path.isfile(path):
        raise MemSeekerError(f"Rule file not found: {path}")
    cfg = configparser.ConfigParser(interpolation=None)
    try:
        cfg.read(path)
    except configparser.Error as exc:
        raise MemSeekerError(f"Cannot parse rule file {path}: {exc}")
    rules = []
    for section in cfg.sections():
        rtype = cfg.get(section, "type", fallback="").strip().lower()
        raw = cfg.get(section, "pattern", fallback="").strip()
        desc = cfg.get(section, "description", fallback="").strip()
        if not raw:
            raise MemSeekerError(
                f"Rule '{section}' in {path} has an empty pattern.")
        if rtype == "string":
            compiled = raw.encode("utf-8")
            plen = len(compiled)
        elif rtype == "hex":
            try:
                compiled = bytes.fromhex(raw.replace(" ", ""))
            except ValueError:
                raise MemSeekerError(
                    f"Rule '{section}' in {path} has bad hex: '{raw}' "
                    "(use pairs like 'de ad be ef').")
            plen = len(compiled)
        elif rtype == "regex":
            try:
                compiled = re.compile(raw.encode("utf-8"))
            except re.error as exc:
                raise MemSeekerError(
                    f"Rule '{section}' in {path} has a bad regex: {exc}")
            plen = REGEX_MAX_LEN
        else:
            raise MemSeekerError(
                f"Rule '{section}' in {path} has unknown type '{rtype}' "
                "(use string, hex or regex).")
        if plen == 0:
            raise MemSeekerError(
                f"Rule '{section}' in {path} has an empty pattern.")
        rules.append(Rule(section, rtype, raw, compiled, desc, plen))
    if not rules:
        raise MemSeekerError(f"No rules found in {path}.")
    return rules


def overlap_size(rules):
    """Bytes of overlap between chunks: longest pattern minus one, so a
    pattern split across a chunk boundary is never missed (PDF Step 5).
    Capped so one wild regex cannot blow up the window."""
    longest = max(r.plen for r in rules)
    return min(max(longest - 1, 0), MAX_OVERLAP)


# --- Helpers: entropy, strings, context ----------------------------------
def shannon_entropy(data):
    """Shannon entropy of bytes, in bits per byte (0.0–8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_strings(data, min_len=STRINGS_MIN_LEN):
    """Printable ASCII runs (like the `strings` command), >= min_len."""
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return out


def printable(data):
    """Bytes as printable ASCII, '.' for anything else (context display)."""
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def hexdump(data):
    """Bytes as a hex string with spaces: 'de ad be ef'."""
    return " ".join(f"{b:02x}" for b in data)


# --- Hits and scan results -----------------------------------------------
class Hit:
    """One rule match: rule, region, address, offset, context bytes."""

    __slots__ = ("rule", "region", "address", "offset", "match",
                 "ctx_before", "ctx_after", "strings")

    def __init__(self, rule, region, address, match, ctx_before, ctx_after,
                 strings=None):
        self.rule = rule
        self.region = region
        self.address = address
        self.offset = address - region.start
        self.match = match
        self.ctx_before = ctx_before
        self.ctx_after = ctx_after
        self.strings = strings or []

    def key(self):
        """Stable identity of a hit (for watch mode: same rule + address
        = the same hit, even across rescans)."""
        return (self.rule.name, self.address)

    def to_dict(self):
        return {
            "rule": self.rule.name,
            "rule_type": self.rule.rtype,
            "region": self.region.name,
            "region_range": self.region.range_str(),
            "address": f"0x{self.address:x}",
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:x}",
            "match_hex": hexdump(self.match),
            "match_ascii": printable(self.match),
            "context_before_hex": hexdump(self.ctx_before),
            "context_after_hex": hexdump(self.ctx_after),
            "context_ascii": printable(self.ctx_before + self.match
                                       + self.ctx_after),
            "strings": self.strings,
        }


class ScanResult:
    """Everything one scan found, for printing and for the report."""

    def __init__(self, pid, proc_name, rules_path, chunk_size):
        self.pid = pid
        self.proc_name = proc_name
        self.rules_path = rules_path
        self.chunk_size = chunk_size
        self.regions_total = 0
        self.regions_read = 0
        self.regions_skipped = []   # (region, reason)
        self.bytes_read = 0
        self.hits = []
        self.hits_capped = []       # rule names that hit the safety cap
        self.entropy_flags = []     # (region, chunk_address, entropy)
        self.started = datetime.now()
        self.seconds = 0.0

    def hits_per_rule(self):
        counts = Counter(h.rule.name for h in self.hits)
        return dict(counts)


# --- Scanning ------------------------------------------------------------
def read_region_chunks(mem, region, chunk_size):
    """Yield (chunk_start_address, data) for one region, chunk by chunk.

    A region is never loaded whole: at most chunk_size bytes are in
    memory at once. An OSError (guarded page, vanished region, vsyscall)
    raises here and the caller skips the region — never a crash.
    """
    pos = region.start
    while pos < region.end:
        want = min(chunk_size, region.end - pos)
        mem.seek(pos)
        data = mem.read(want)
        if not data:
            break
        yield pos, data
        pos += len(data)


def _read_at(mem, address, size):
    """Read size bytes at one address; b"" on any failure (gap between
    regions, guarded page, end of mapping). Never raises."""
    if size <= 0 or address < 0:
        return b""
    try:
        mem.seek(address)
        return mem.read(size)
    except OSError:
        return b""


def fetch_window(mem, address, match_len, window=STRINGS_WINDOW):
    """Read bytes around a hit: [address-window, address+len+window).

    Read in three segments (before / match / after) so a hit near a
    region edge still gets the context that exists — one read across
    a gap would fail as a whole. A second file handle is used so the
    chunk loop's position is never disturbed. Returns (start, bytes)
    where start is the address of bytes[0].
    """
    before = _read_at(mem, address - window, window)
    match = _read_at(mem, address, match_len)
    after = _read_at(mem, address + match_len, window)
    return address - len(before), before + match + after


def scan_region(mem, mem_ctx, region, rules, overlap, opts, result):
    """Scan one readable region, chunk by chunk, with the overlap
    window. Returns nothing — hits and entropy flags go into result."""
    # seen[(rule, address)] stops a match that sits in the overlap
    # prefix from being reported twice (it was already found in the
    # previous chunk), while a match that STRADDLES the boundary is
    # reported exactly once, in the chunk where it first completes.
    seen = set()
    carry = b""          # tail of the previous chunk (the overlap window)
    carry_start = 0      # absolute address of carry[0]
    hit_count = Counter()
    try:
        for chunk_start, data in read_region_chunks(mem, region,
                                                    opts["chunk_size"]):
            result.bytes_read += len(data)
            buf = carry + data
            buf_start = carry_start if carry else chunk_start
            if opts["entropy"]:
                ent = shannon_entropy(data)
                if ent >= ENTROPY_THRESHOLD:
                    result.entropy_flags.append((region, chunk_start, ent))
            for rule in rules:
                if hit_count[rule.name] >= MAX_HITS_PER_RULE:
                    continue
                for mstart, mend in rule.find_all(buf):
                    addr = buf_start + mstart
                    key = (rule.name, addr)
                    if key in seen:
                        continue
                    seen.add(key)
                    match = buf[mstart:mend]
                    wstart, window = fetch_window(mem_ctx, addr, len(match))
                    # context: 16 bytes on each side of the match.
                    lo = addr - wstart - CONTEXT_BYTES
                    hi = addr - wstart + len(match) + CONTEXT_BYTES
                    ctx = window[max(lo, 0):max(hi, 0)]
                    cut = max(lo, 0)
                    before = ctx[:addr - wstart - cut]
                    after = ctx[addr - wstart - cut + len(match):]
                    strings = (extract_strings(window) if opts["strings"]
                               else [])
                    result.hits.append(Hit(rule, region, addr, match,
                                           before, after, strings))
                    hit_count[rule.name] += 1
                    if hit_count[rule.name] == MAX_HITS_PER_RULE:
                        result.hits_capped.append(rule.name)
            # Keep the tail of this buffer as the next chunk's overlap.
            if overlap > 0 and len(buf) > overlap:
                carry = buf[-overlap:]
                carry_start = buf_start + len(buf) - overlap
            elif overlap > 0:
                carry = buf
                carry_start = buf_start
            else:
                carry = b""
                carry_start = 0
        result.regions_read += 1
    except OSError as exc:
        # Guarded page / vanished region / unreadable mapping: skip it
        # with a note. The scan carries on (PDF Step 2).
        result.regions_skipped.append((region, str(exc) or "unreadable"))


def scan_process(pid, rules, opts):
    """Full scan of one process. Returns a ScanResult.

    Raises MemSeekerError on ownership refusal, missing process, or a
    mem file that cannot be opened at all (Yama / permissions).
    """
    check_ownership(pid)
    regions = parse_maps(pid)
    readable = readable_regions(regions)
    overlap = overlap_size(rules)
    result = ScanResult(pid, process_name(pid), opts["rules_path"],
                        opts["chunk_size"])
    result.regions_total = len(regions)
    try:
        mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    except FileNotFoundError:
        raise MemSeekerError(f"No process with PID {pid}.")
    except PermissionError:
        raise MemSeekerError(
            f"Permission denied opening /proc/{pid}/mem for PID {pid}. "
            "The kernel blocked the read (Yama ptrace_scope). Run as root "
            "/ with sudo, or start the process from this tool "
            "(--lab, or menu option 2), or set ptrace_scope=0."
        )
    try:
        mem_ctx = open(f"/proc/{pid}/mem", "rb", buffering=0)
    except OSError:
        mem_ctx = mem
    started = time.time()
    try:
        for region in readable:
            scan_region(mem, mem_ctx, region, rules, overlap, opts, result)
    finally:
        mem.close()
        if mem_ctx is not mem:
            mem_ctx.close()
    result.seconds = time.time() - started
    return result


# --- Reports -------------------------------------------------------------
def build_text_report(result, rules):
    """The text report: every hit with rule, region and offset."""
    lines = []
    lines.append("=" * 58)
    lines.append("MemSeeker — Process Memory Scan Report")
    lines.append("=" * 58)
    lines.append(f"Tool:      MemSeeker v{VERSION} by {AUTHOR}")
    lines.append(f"Date:      {result.started:%Y-%m-%d %H:%M:%S}")
    lines.append(f"PID:       {result.pid} ({result.proc_name})")
    lines.append(f"Rules:     {result.rules_path} ({len(rules)} rules)")
    lines.append(f"Chunk:     {result.chunk_size} bytes, "
                 f"overlap {overlap_size(rules)} bytes")
    lines.append(f"Regions:   {result.regions_read} read, "
                 f"{len(result.regions_skipped)} skipped, "
                 f"{result.regions_total} total")
    lines.append(f"Bytes:     {result.bytes_read} read in "
                 f"{result.seconds:.2f} s")
    lines.append(f"Hits:      {len(result.hits)}")
    for name, count in sorted(result.hits_per_rule().items()):
        lines.append(f"  {name}: {count}")
    if result.entropy_flags:
        lines.append(f"Entropy:   {len(result.entropy_flags)} high-entropy "
                     f"chunk(s) flagged (>= {ENTROPY_THRESHOLD} bits/byte)")
    lines.append("")
    if not result.hits and not result.entropy_flags:
        lines.append("No hits. No rule matched anything in this process.")
    for i, hit in enumerate(result.hits, 1):
        lines.append("-" * 58)
        lines.append(f"Hit {i}: rule {hit.rule.name} ({hit.rule.rtype})")
        if hit.rule.description:
            lines.append(f"  Rule:    {hit.rule.description}")
        lines.append(f"  Region:  {hit.region.name} "
                     f"({hit.region.range_str()}, {hit.region.perms})")
        lines.append(f"  Address: 0x{hit.address:x} "
                     f"(offset 0x{hit.offset:x} in region)")
        lines.append(f"  Match:   {hexdump(hit.match)} "
                     f"({printable(hit.match)!r})")
        lines.append(f"  Context: {printable(hit.ctx_before)}"
                     f"<<{printable(hit.match)}>>"
                     f"{printable(hit.ctx_after)}")
        lines.append(f"  Context hex (before): {hexdump(hit.ctx_before)}")
        lines.append(f"  Context hex (after):  {hexdump(hit.ctx_after)}")
        if hit.strings:
            lines.append("  Strings around hit:")
            for s in hit.strings:
                lines.append(f"    {s}")
    for region, addr, ent in result.entropy_flags:
        lines.append("-" * 58)
        lines.append(f"Entropy flag: {region.name} ({region.range_str()})")
        lines.append(f"  Chunk at 0x{addr:x}: {ent:.2f} bits/byte — "
                     "possibly packed or encrypted data.")
    if result.hits_capped:
        lines.append("")
        lines.append("Note: hit cap reached for rule(s): "
                     + ", ".join(result.hits_capped)
                     + f" (first {MAX_HITS_PER_RULE} shown).")
    lines.append("")
    lines.append("Defensive lesson: secrets must never sit in process "
                 "memory in plaintext. A password or key left in a plain "
                 "variable can be read by anyone who can read the process "
                 "memory — this scan just proved it. Programs that handle "
                 "secrets lock the memory (mlock), zero the buffer as soon "
                 "as they are done with it, and keep keys in a system "
                 "keyring or a hardware-backed store instead of a variable.")
    lines.append("")
    return "\n".join(lines) + "\n"


def build_json_report(result, rules):
    """The same report as JSON (machine-readable)."""
    return json.dumps({
        "tool": f"MemSeeker v{VERSION}",
        "author": AUTHOR,
        "date": result.started.strftime("%Y-%m-%d %H:%M:%S"),
        "pid": result.pid,
        "process": result.proc_name,
        "rules_file": result.rules_path,
        "rules": [r.name for r in rules],
        "chunk_size": result.chunk_size,
        "regions_total": result.regions_total,
        "regions_read": result.regions_read,
        "regions_skipped": [
            {"region": r.name, "range": r.range_str(), "reason": why}
            for r, why in result.regions_skipped
        ],
        "bytes_read": result.bytes_read,
        "seconds": round(result.seconds, 3),
        "hits": [h.to_dict() for h in result.hits],
        "hits_per_rule": result.hits_per_rule(),
        "entropy_flags": [
            {"region": r.name, "range": r.range_str(),
             "chunk_address": f"0x{a:x}", "entropy_bits_per_byte": round(e, 2)}
            for r, a, e in result.entropy_flags
        ],
    }, indent=2) + "\n"


def write_report(result, rules, path, as_json):
    """Write the report file. Returns the path written."""
    text = build_json_report(result, rules) if as_json \
        else build_text_report(result, rules)
    with open(path, "w") as fh:
        fh.write(text)
    return path


def print_hits(result):
    """Print the hits of one scan (skipped in quiet mode)."""
    if QUIET:
        return
    if not result.hits and not result.entropy_flags:
        ok("No hits — no rule matched anything in this process.")
        return
    for i, hit in enumerate(result.hits, 1):
        header(f"Hit {i}: {hit.rule.name} ({hit.rule.rtype})")
        info("Region", f"{hit.region.name} ({hit.region.range_str()})")
        info("Address", f"0x{hit.address:x} "
             f"(offset 0x{hit.offset:x} in region)")
        info("Match", f"{hexdump(hit.match)} "
             f"({printable(hit.match)!r})")
        info("Context", f"{printable(hit.ctx_before)}"
             f"<<{printable(hit.match)}>>{printable(hit.ctx_after)}")
        if hit.strings:
            info("Strings", "; ".join(hit.strings[:5]))
    for region, addr, ent in result.entropy_flags:
        warn(f"High entropy: {region.name} chunk at 0x{addr:x} — "
             f"{ent:.2f} bits/byte (possibly packed/encrypted).")


def print_config(pid, rules_path, rules, opts):
    """Gobuster-style SCAN config block before each scan."""
    if QUIET:
        return
    sep()
    print(f" {C.WHT}[ {C.GRN}SCAN {C.WHT}] {C.GRN}MemSeeker v{VERSION}"
          f"{C.RST}")
    sep()
    info("Process ID", str(pid))
    info("Process", process_name(pid))
    info("Rules file", f"{rules_path} ({len(rules)} rules)")
    info("Chunk size", f"{opts['chunk_size']} bytes")
    info("Entropy scan", "on" if opts["entropy"] else "off")
    info("String extraction", "on" if opts["strings"] else "off")
    info("Output", opts["output"])
    sep()


# --- Watch mode ----------------------------------------------------------
def watch_process(pid, rules, opts, interval, rounds=0):
    """Stretch 3: rescan every N seconds, report only NEW hits.

    rounds = 0 means forever; a positive number stops after that many
    rounds (used by the test suite and by scripts). The rules file is
    reloaded every round, so rules edited between rounds take effect.
    Returns 0 on a clean stop, 2 if the process vanished.
    """
    seen = set()
    round_no = 0
    try:
        while True:
            round_no += 1
            try:
                rules = load_rules(opts["rules_path"])
            except MemSeekerError as exc:
                err(str(exc))
                return 2
            try:
                result = scan_process(pid, rules, opts)
            except MemSeekerError as exc:
                err(f"Watch stopped: {exc}")
                return 2 if round_no == 1 else 0
            new_hits = [h for h in result.hits if h.key() not in seen]
            for h in result.hits:
                seen.add(h.key())
            if not QUIET:
                header(f"Watch round {round_no} — PID {pid} "
                       f"({result.proc_name})")
                info("Regions read", str(result.regions_read))
                info("Bytes read", str(result.bytes_read))
            if new_hits:
                if not QUIET:
                    warn(f"{len(new_hits)} NEW hit(s) in this round:")
                mini = ScanResult(pid, result.proc_name,
                                  result.rules_path, result.chunk_size)
                mini.hits = new_hits
                print_hits(mini)
            else:
                if not QUIET:
                    ok("No new hits in this round.")
            if rounds and round_no >= rounds:
                if not QUIET:
                    ok(f"Watch finished after {round_no} round(s).")
                return 0
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Watch stopped"
              f"{C.RST}")
        return 0


# --- Doctor --------------------------------------------------------------
def ptrace_scope():
    """Yama ptrace_scope value, or None if the kernel has no Yama."""
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def doctor():
    """Check setup: Linux, Python, /proc access, ptrace_scope, files."""
    print_banner()
    header("Doctor — check setup")
    problems = 0
    if os.name == "posix" and os.path.isdir("/proc"):
        ok(f"Linux with /proc (needed — this tool reads process memory "
           f"from /proc/<pid>/maps and /proc/<pid>/mem).")
    else:
        err("Not Linux, or no /proc — MemSeeker is Linux-only.")
        problems += 1
    ok(f"Python {sys.version.split()[0]}")
    scope = ptrace_scope()
    if scope is None:
        info("ptrace_scope", "no Yama (any same-user process is readable)")
    elif scope == 0:
        info("ptrace_scope", "0 — any same-user process is readable")
    elif scope == 1:
        warn("ptrace_scope is 1 — only a PARENT process may be read. "
             "Scan as root / with sudo, or start the process from this "
             "tool's menu (option 2).")
    else:
        warn(f"ptrace_scope is {scope} — reading other processes is "
             "restricted. Run as root / with sudo.")
    try:
        regions = parse_maps(os.getpid())
        ok(f"Can read my own memory map ({len(regions)} regions).")
        with open("/proc/self/mem", "rb", 0) as mem:
            mem.seek(regions[0].start)
            mem.read(16)
        ok("Can read my own process memory.")
    except (OSError, MemSeekerError) as exc:
        err(f"Cannot read my own process memory: {exc}")
        problems += 1
    here = os.path.dirname(os.path.abspath(__file__))
    for label, rel in (("lab process", "lab_proc.py"),
                       ("lab rules", "rules_lab.txt"),
                       ("default rules", "rules_default.txt"),
                       ("step tests", "test_memseeker.py")):
        full = os.path.join(here, rel)
        if os.path.isfile(full):
            ok(f"{label}: {rel}")
        else:
            warn(f"{label} missing: {rel}")
            problems += 1
    sep()
    if problems:
        err(f"Doctor: {problems} problem(s) found (see [!] lines).")
        return 1
    ok("Doctor: all good. Try: python3 memseeker.py --menu")
    return 0


# --- Menu ----------------------------------------------------------------
def print_banner():
    if not QUIET:
        print(f"{C.GRN}{BANNER}{C.RST}")
        print(f"{C.WHT}  MemSeeker v{VERSION} — Linux process memory "
              f"scanner (read-only){C.RST}")
        print(f"{C.YEL}  AUTHORIZED USE ONLY — only scan processes you own "
              f"or have written permission to test.{C.RST}")
        print(f"{C.DIM}  Reading another person's process memory without "
              f"permission is unauthorized access (PECA 2016).{C.RST}")
        print()


def show_menu():
    clear()
    print_banner()
    print(f" {C.WHT}[ {C.GRN}1 {C.WHT}] {C.GRN}Scan a process "
          f"(enter PID, rules file){C.RST}")
    print(f" {C.WHT}[ {C.GRN}2 {C.WHT}] {C.GRN}Quick scan: lab process "
          f"(starts the lab, scans it){C.RST}")
    print(f" {C.WHT}[ {C.GRN}3 {C.WHT}] {C.GRN}Show the memory map of a "
          f"process{C.RST}")
    print(f" {C.WHT}[ {C.GRN}4 {C.WHT}] {C.GRN}List all rules in a rule "
          f"file{C.RST}")
    print(f" {C.WHT}[ {C.GRN}5 {C.WHT}] {C.GRN}Run the step tests{C.RST}")
    print(f" {C.WHT}[ {C.GRN}6 {C.WHT}] {C.GRN}Check setup (doctor)"
          f"{C.RST}")
    print(f" {C.WHT}[ {C.GRN}7 {C.WHT}] {C.GRN}Watch a process (rescan "
          f"every N seconds, new hits only){C.RST}")
    print(f" {C.WHT}[ {C.RED}0 {C.WHT}] {C.RED}Exit{C.RST}")


def ask_interactive(prompt, default=""):
    """[?] prompt with a default (Enter = default), TraceRecon style."""
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{C.WHT}\n [ ? ] {C.GRN}{prompt}{suffix}"
                      f"{C.WHT} : {C.GRN}").strip()
    except KeyboardInterrupt:
        print(C.RST, end="")
        raise
    print(C.RST, end="")
    return value or default


def ask_pid(default=""):
    """Ask for a PID until a valid integer is given."""
    while True:
        value = ask_interactive("ENTER PROCESS ID (PID)", default)
        try:
            pid = int(value)
            if pid <= 0:
                raise ValueError
            return pid
        except ValueError:
            err("Please enter a positive integer PID.")


def ask_rules(default=DEFAULT_RULES):
    """Ask for a rule file (Enter = default)."""
    return ask_interactive("ENTER RULE FILE", default)


def do_scan(args, pid=None, rules_path=None):
    """Run one scan from CLI args or menu answers. Returns an exit code:
    0 = clean, 1 = hits found, 2 = error / refusal."""
    pid = pid if pid is not None else args.pid
    rules_path = rules_path or args.rules or DEFAULT_RULES
    opts = {
        "rules_path": rules_path,
        "chunk_size": args.chunk_size,
        "entropy": args.entropy,
        "strings": args.strings,
        "output": args.output,
    }
    print_banner()
    try:
        rules = load_rules(rules_path)
        print_config(pid, rules_path, rules, opts)
        result = scan_process(pid, rules, opts)
    except MemSeekerError as exc:
        err(str(exc))
        return 2
    if not QUIET:
        print()
        info("Regions read",
             f"{result.regions_read} ({len(result.regions_skipped)} "
             "skipped)")
        info("Bytes read", f"{result.bytes_read} in {result.seconds:.2f} s")
        info("Hits", str(len(result.hits)))
        if result.entropy_flags:
            info("Entropy flags", str(len(result.entropy_flags)))
        print()
    print_hits(result)
    try:
        write_report(result, rules, opts["output"], args.json)
        ok(f"Report saved: {opts['output']}")
    except OSError as exc:
        err(f"Cannot write report {opts['output']}: {exc}")
        return 2
    if result.hits:
        warn(f"{len(result.hits)} hit(s) — see the report.")
        return 1
    return 0


def do_map(args, pid=None):
    """Option 3 / --map: print every region of a process."""
    pid = pid if pid is not None else args.pid
    print_banner()
    try:
        check_ownership(pid)
        regions = parse_maps(pid)
    except MemSeekerError as exc:
        err(str(exc))
        return 2
    header(f"Memory map — PID {pid} ({process_name(pid)})")
    readable = readable_regions(regions)
    info("Regions", f"{len(regions)} total, {len(readable)} readable")
    print()
    print(f" {'RANGE':26} {'PERM':5} {'SIZE':>10}  NAME")
    for r in regions:
        mark = "r" if r.readable else " "
        print(f" {mark}{r.range_str():25} {r.perms:5} "
              f"{r.size:>10}  {r.name}")
    return 0


def do_list_rules(args, rules_path=None):
    """Option 4 / --list-rules: print every rule in a rule file."""
    rules_path = rules_path or args.rules or DEFAULT_RULES
    print_banner()
    try:
        rules = load_rules(rules_path)
    except MemSeekerError as exc:
        err(str(exc))
        return 2
    header(f"Rules — {rules_path} ({len(rules)} rules)")
    for rule in rules:
        print(f" {C.WHT}[{C.GRN}+{C.WHT}]{C.RST} {C.BLD}{rule.name}{C.RST} "
              f"({rule.rtype})")
        if rule.description:
            print(f"      {rule.description}")
        print(f"      pattern: {rule.raw}")
    return 0


def start_lab_process():
    """Start lab_proc.py as OUR child (so Yama ptrace_scope=1 allows the
    read) and return the Popen object. The lab prints one JSON line with
    its PID and marker addresses, then sleeps."""
    import json as _json
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    lab = os.path.join(here, "lab_proc.py")
    proc = subprocess.Popen([sys.executable, lab],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    info_line = None
    for _ in range(50):  # wait up to ~5 s for the JSON line
        line = proc.stdout.readline()
        if not line:
            break
        if line.lstrip().startswith("{"):
            info_line = _json.loads(line)
            break
    if info_line is None:
        proc.kill()
        raise MemSeekerError("Lab process did not start (no PID line).")
    return proc, info_line


def do_lab_scan(args):
    """Option 2: start the lab as our child, scan it, stop it."""
    print_banner()
    here = os.path.dirname(os.path.abspath(__file__))
    rules_path = os.path.join(here, DEFAULT_RULES)
    try:
        proc, lab_info = start_lab_process()
    except MemSeekerError as exc:
        err(str(exc))
        return 2
    pid = lab_info["pid"]
    ok(f"Lab process started: PID {pid} ({process_name(pid)})")
    opts = {
        "rules_path": rules_path,
        "chunk_size": args.chunk_size,
        "entropy": True,
        "strings": True,
        "output": args.output,
    }
    try:
        rules = load_rules(rules_path)
        print_config(pid, rules_path, rules, opts)
        result = scan_process(pid, rules, opts)
    except MemSeekerError as exc:
        err(str(exc))
        proc.kill()
        return 2
    if not QUIET:
        print()
        info("Regions read",
             f"{result.regions_read} ({len(result.regions_skipped)} "
             "skipped)")
        info("Bytes read", f"{result.bytes_read} in {result.seconds:.2f} s")
        info("Hits", str(len(result.hits)))
        if result.entropy_flags:
            info("Entropy flags", str(len(result.entropy_flags)))
        print()
    print_hits(result)
    try:
        write_report(result, rules, opts["output"], args.json)
        ok(f"Report saved: {opts['output']}")
    except OSError as exc:
        err(f"Cannot write report {opts['output']}: {exc}")
        proc.kill()
        return 2
    proc.kill()
    proc.wait()
    if result.hits:
        warn(f"{len(result.hits)} hit(s) in the lab process — "
             "see the report.")
        return 1
    return 0


def menu_loop(args):
    """Numbered menu loop. Returns 0 on clean exit."""
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    while True:
        show_menu()
        try:
            choice = input(f"{C.WHT}\n [ ? ] {C.GRN}Select option"
                           f"{C.WHT} : {C.GRN}").strip()
            print(C.RST, end="")
            if choice == "0":
                print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
                return 0
            if choice == "1":
                pid = ask_pid()
                rules_path = ask_rules()
                args.entropy = True
                args.strings = True
                do_scan(args, pid=pid, rules_path=rules_path)
            elif choice == "2":
                do_lab_scan(args)
            elif choice == "3":
                pid = ask_pid()
                do_map(args, pid=pid)
            elif choice == "4":
                rules_path = ask_rules()
                do_list_rules(args, rules_path=rules_path)
            elif choice == "5":
                test = os.path.join(here, "test_memseeker.py")
                subprocess.run([sys.executable, test])
            elif choice == "6":
                doctor()
            elif choice == "7":
                pid = ask_pid()
                rules_path = ask_rules()
                raw = ask_interactive("ENTER WATCH INTERVAL IN SECONDS",
                                      "5")
                try:
                    interval = int(raw)
                    if interval <= 0:
                        raise ValueError
                except ValueError:
                    err("Interval must be a positive integer.")
                    interval = 5
                opts = {
                    "rules_path": rules_path,
                    "chunk_size": args.chunk_size,
                    "entropy": args.entropy,
                    "strings": args.strings,
                    "output": args.output,
                }
                watch_process(pid, load_rules(rules_path), opts, interval)
            else:
                err("Please input a number from the menu (0-7).")
                time.sleep(1)
                continue
        except ValueError:
            err("Please input a number from the menu (0-7).")
            time.sleep(1)
            continue
        except KeyboardInterrupt:
            print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
            return 0
        except MemSeekerError as exc:
            err(str(exc))
        input(f"\n{C.WHT}[ {C.GRN}+ {C.WHT}] {C.GRN}Press enter to "
              f"continue{C.RST}")
    return 0


# --- CLI -----------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="MemSeeker v%s — Linux process memory scanner "
                    "(read-only). Scans ONLY processes you own." % VERSION)
    p.add_argument("pid", type=int, nargs="?",
                   help="process ID to scan")
    p.add_argument("--rules", metavar="FILE",
                   help="rule file (default: rules_lab.txt)")
    p.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                   help="report file (default: memseeker_report.txt)")
    p.add_argument("--json", action="store_true",
                   help="write the report as JSON instead of text")
    p.add_argument("--entropy", action="store_true",
                   help="flag high-entropy chunks (possibly packed/encrypted)")
    p.add_argument("--strings", action="store_true",
                   help="extract printable strings around each hit")
    p.add_argument("--watch", type=int, metavar="N",
                   help="watch mode: rescan every N seconds, new hits only")
    p.add_argument("--rounds", type=int, default=0, metavar="N",
                   help="watch mode: stop after N rounds (0 = forever)")
    p.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE,
                   help="bytes read per chunk (default: 65536)")
    p.add_argument("--map", action="store_true",
                   help="only print the process memory map, do not scan")
    p.add_argument("--lab", action="store_true",
                   help="start the lab process as this tool's child and "
                        "scan it (dodges Yama ptrace_scope=1)")
    p.add_argument("--list-rules", action="store_true",
                   help="only list the rules in the rule file, do not scan")
    p.add_argument("--doctor", action="store_true",
                   help="check the setup and exit")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="quiet: only print errors and the summary")
    p.add_argument("--batch", action="store_true",
                   help="never ask, use defaults (for scripts)")
    p.add_argument("-i", "--interactive", "--menu", action="store_true",
                   dest="menu", help="open the numbered menu")
    p.add_argument("--version", action="store_true",
                   help="print the version and exit")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output")
    return p.parse_args(argv)


def main(argv=None):
    global QUIET
    args = parse_args(argv)
    if args.no_color:
        for name in ("RST", "BLD", "DIM", "RED", "GRN", "YEL", "BLU",
                     "MAG", "CYN", "WHT"):
            setattr(C, name, "")
    if args.version:
        print(f"MemSeeker v{VERSION} by {AUTHOR}")
        return 0
    if args.chunk_size <= 0:
        err("--chunk-size must be a positive integer.")
        return 2
    QUIET = args.quiet
    try:
        if args.doctor:
            return doctor()
        if args.list_rules:
            print_banner()
            return do_list_rules(args)
        if args.lab:
            return do_lab_scan(args)
        if args.batch or args.quiet:
            # Never ask: missing values become the defaults.
            if args.map:
                return do_map(args, pid=args.pid or os.getpid())
            if args.watch:
                opts = {"rules_path": args.rules or DEFAULT_RULES,
                        "chunk_size": args.chunk_size,
                        "entropy": args.entropy,
                        "strings": args.strings,
                        "output": args.output}
                rules = load_rules(opts["rules_path"])
                return watch_process(args.pid or os.getpid(), rules, opts,
                                     args.watch, rounds=args.rounds)
            return do_scan(args, pid=args.pid or os.getpid())
        if args.menu or args.pid is None:
            return menu_loop(args)
        # Args given: PID present, maybe rules missing — ask for it.
        if args.map:
            return do_map(args)
        if args.watch:
            opts = {"rules_path": args.rules or DEFAULT_RULES,
                    "chunk_size": args.chunk_size,
                    "entropy": args.entropy,
                    "strings": args.strings,
                    "output": args.output}
            rules = load_rules(opts["rules_path"])
            return watch_process(args.pid, rules, opts, args.watch,
                                 rounds=args.rounds)
        if not args.rules:
            print_banner()
            args.rules = ask_rules()
        return do_scan(args)
    except KeyboardInterrupt:
        print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
