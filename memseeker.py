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
  no YARA. It runs on Linux, Windows and macOS (v1.1) — the project
  itself specifies Linux (/proc), and the Windows/macOS backends were
  added in v1.1 so the same tool works on the other two platforms:
    python3 memseeker.py <pid> --rules rules_lab.txt

V1.1 ADDITIONS (on top of the 6 must-haves + 3 stretch items):
  * Multi-PID scan: --all (every process you own) or
    --pids 1234,5678 — one report, grouped per process
  * Memory image scan: --image dump.bin [--base 0x...] — scans a raw
    memory dump file as if it were memory; works on every OS, with no
    live-process access at all (the portable fallback)
  * Region dump: --dump dir — saves every region that contains a hit
    as <pid>_<range>_<region>.bin, named in the report
  * Rule groups: [Group:Name] with '2 of (A, B, C)' / 'all of (A, B)'
    / 'any of (A, B)' — fires as ONE finding per region when the
    condition is met by the rules that fired in that region
  * Cross-platform backends: Linux (/proc), Windows (kernel32 via
    ctypes), macOS (task_for_pid + vm_read via ctypes) — same CLI,
    same menu, same rule file, same report format

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
      [ 8] Scan all my processes (every process you own)
      [ 9] Scan a memory image file (works on every OS)
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
    python3 memseeker.py 1234 --rules rules_lab.txt --map
    python3 memseeker.py --list-rules --rules rules_lab.txt
    python3 memseeker.py --all --rules rules_lab.txt
    python3 memseeker.py --pids 1234,5678 --rules rules_lab.txt
    python3 memseeker.py --image dump.bin --rules rules_lab.txt
    python3 memseeker.py 1234 --rules rules_lab.txt --dump dumps/
    python3 memseeker.py --version
    python3 memseeker.py 1234 --rules rules_lab.txt --no-color
    python3 memseeker.py 1234 --rules rules_lab.txt --batch
    python3 memseeker.py 1234 --rules rules_lab.txt -q   # quiet
"""

import argparse
import configparser
import ctypes
import json
import math
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime

VERSION = "1.2"
AUTHOR = "CyberBoy50"
QUIET = False

# Explicit responsibility disclaimer — shown in the banner, in every
# generated report (text header + JSON "disclaimer" field) and in the
# README. Wording is fixed; do not paraphrase it.
DISCLAIMER = (
    "DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for ethical, "
    "authorized security testing only. You are using it on your own "
    "responsibility. The authors are not responsible for how you use it, "
    "or for anything that happens because of your use. Only test systems, "
    "code, and data you own or have explicit written permission to test — "
    "testing anything else may be illegal (for example, PECA 2016 in "
    "Pakistan).")

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
 --------------------------------------------------
  DISCLAIMER — AUTHORIZED USE ONLY. This tool was built
  for ethical, authorized security testing only. You
  are using it on your own responsibility. The authors
  are not responsible for how you use it, or for
  anything that happens because of your use. Only test
  systems, code, and data you own or have explicit
  written permission to test — testing anything else
  may be illegal (for example, PECA 2016 in Pakistan).
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


# --- Platform backends (v1.1) -------------------------------------------
# One reader interface, three backends. The scan pipeline only ever
# sees a file-like object (seek/read/close) plus a list of Regions,
# so the same matcher, overlap window, entropy scan, groups and
# reports run on every OS. The --image mode is a fourth reader: a
# plain file, which works on every OS with no live-process access.
#
#   Linux   — /proc/<pid>/maps + /proc/<pid>/mem (the v1.0 code)
#   Windows — ctypes + kernel32: OpenProcess, VirtualQueryEx,
#             ReadProcessMemory. A process owned by another user (or
#             a protected process) refuses PROCESS_VM_READ with
#             access denied — that IS the ownership refusal on
#             Windows, same spirit as the Linux check.
#   macOS   — ctypes + libSystem: task_for_pid + vm_region_64 +
#             vm_read. Needs root or the debugger entitlement;
#             without it the backend refuses cleanly and says so.
#
# The raw OS calls are small module-level functions (_win_*, _mac_*)
# so the test suite can stub them: on this Linux-only VM the
# Windows/macOS backends are tested with fakes, never with real OS
# calls. On the wrong platform the real functions raise
# MemSeekerError instead of crashing on a missing ctypes.windll.

# --- Windows (ctypes, kernel32) ----------------------------------------
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MEM_COMMIT = 0x1000
ERROR_ACCESS_DENIED = 5
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
TH32CS_SNAPPROCESS = 0x00000002


class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """kernel32 MEMORY_BASIC_INFORMATION (64-bit layout)."""
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32),
        ("PartitionId", ctypes.c_uint16),
        ("_pad", ctypes.c_uint16),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]


class _PROCESSENTRY32W(ctypes.Structure):
    """kernel32 PROCESSENTRY32W (Toolhelp process list)."""
    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", ctypes.c_uint32),
        ("cntThreads", ctypes.c_uint32),
        ("th32ParentProcessID", ctypes.c_uint32),
        ("pcPriClassBase", ctypes.c_int32),
        ("dwFlags", ctypes.c_uint32),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def _win_kernel32():
    """kernel32, loaded lazily (ctypes.windll only exists on Windows)."""
    if sys.platform != "win32":
        raise MemSeekerError("The Windows backend only works on Windows.")
    return ctypes.windll.kernel32


def _win_last_error():
    """The calling thread's last Win32 error code."""
    return ctypes.windll.kernel32.GetLastError()


def _win_open_process(pid, access):
    """OpenProcess handle, or None (caller reads _win_last_error())."""
    k32 = _win_kernel32()
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int,
                                ctypes.c_uint32]
    return k32.OpenProcess(access, False, pid)


def _win_close_handle(handle):
    if handle:
        _win_kernel32().CloseHandle(handle)


def _win_virtual_query_ex(handle, address):
    """One region as (base, size, state, protect), or None when the
    address is past the last region."""
    k32 = _win_kernel32()
    mbi = _MEMORY_BASIC_INFORMATION()
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.POINTER(_MEMORY_BASIC_INFORMATION),
                                   ctypes.c_size_t]
    n = k32.VirtualQueryEx(handle, ctypes.c_void_p(address),
                           ctypes.byref(mbi), ctypes.sizeof(mbi))
    if n == 0:
        return None
    return (mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect)


def _win_read_process_memory(handle, address, size):
    """Bytes read from a process (may be shorter than size). Raises
    OSError when nothing could be read at all — the scan then skips
    that region, like a guarded page on Linux."""
    k32 = _win_kernel32()
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    k32.ReadProcessMemory.restype = ctypes.c_int
    k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t)]
    k32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size,
                          ctypes.byref(got))
    if got.value == 0:
        raise OSError(f"ReadProcessMemory failed at 0x{address:x}")
    return buf.raw[:got.value]


def _win_get_process_name(handle):
    """Executable name of an open process, or '?'."""
    k32 = _win_kernel32()
    buf = ctypes.create_unicode_buffer(512)
    size = ctypes.c_uint32(512)
    k32.QueryFullProcessImageNameW.restype = ctypes.c_int
    k32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32)]
    if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
        path = buf.value
        return path.replace("\\", "/").rsplit("/", 1)[-1] or path
    return "?"


def _win_get_mapped_file_name(handle, address):
    """Device path of the file mapped at an address ('' when none —
    best effort, never fatal)."""
    try:
        psapi = ctypes.windll.psapi
    except Exception:  # noqa: BLE001 - mapped name is cosmetic
        return ""
    buf = ctypes.create_unicode_buffer(512)
    psapi.GetMappedFileNameW.restype = ctypes.c_uint32
    psapi.GetMappedFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_wchar_p, ctypes.c_uint32]
    n = psapi.GetMappedFileNameW(handle, ctypes.c_void_p(address), buf, 512)
    return buf.value[:n] if n else ""


def _win_list_processes():
    """[(pid, exe_name)] via Toolhelp32Snapshot."""
    k32 = _win_kernel32()
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32,
                                             ctypes.c_uint32]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == ctypes.c_void_p(-1).value:
        raise MemSeekerError(
            "Cannot list processes (Toolhelp snapshot failed).")
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        k32.Process32FirstW.restype = ctypes.c_int
        k32.Process32FirstW.argtypes = [ctypes.c_void_p,
                                        ctypes.POINTER(_PROCESSENTRY32W)]
        k32.Process32NextW.restype = ctypes.c_int
        k32.Process32NextW.argtypes = [ctypes.c_void_p,
                                       ctypes.POINTER(_PROCESSENTRY32W)]
        out = []
        if k32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                out.append((entry.th32ProcessID, entry.szExeFile))
                if not k32.Process32NextW(snap, ctypes.byref(entry)):
                    break
        return out
    finally:
        _win_close_handle(snap)


def _win_readable(protect):
    """Is this protection readable? (Guard pages never are.)"""
    if protect & PAGE_GUARD:
        return False
    base = protect & 0xFF
    return base in (PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
                    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                    PAGE_EXECUTE_WRITECOPY)


def _win_perms(protect):
    """Protection -> 'rwxp'-style string."""
    base = protect & 0xFF
    r = "r" if base in (PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
                        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                        PAGE_EXECUTE_WRITECOPY) else "-"
    w = "w" if base in (PAGE_READWRITE, PAGE_WRITECOPY,
                        PAGE_EXECUTE_READWRITE,
                        PAGE_EXECUTE_WRITECOPY) else "-"
    x = "x" if base in (PAGE_EXECUTE, PAGE_EXECUTE_READ,
                        PAGE_EXECUTE_READWRITE,
                        PAGE_EXECUTE_WRITECOPY) else "-"
    return r + w + x + "p"


class WindowsMemoryFile:
    """File-like reader over another process (ReadProcessMemory)."""

    def __init__(self, handle):
        self.handle = handle
        self.pos = 0

    def seek(self, pos, whence=0):
        if whence == 0:
            self.pos = pos
        elif whence == 1:
            self.pos += pos
        elif whence == 2:
            raise OSError("seek from end is not supported")
        else:
            raise ValueError("invalid whence")
        return self.pos

    def read(self, size=-1):
        if size is None or size < 0:
            raise OSError("unbounded read is not supported")
        if size == 0:
            return b""
        data = _win_read_process_memory(self.handle, self.pos, size)
        self.pos += len(data)
        return data

    def close(self):
        if self.handle:
            _win_close_handle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class WindowsBackend:
    """Windows: kernel32 via ctypes (no install, no extra library)."""
    name = "windows"

    def check_ownership(self, pid):
        # Windows has no /proc owner to compare: the access check IS
        # the enforcement — a process owned by another user (or a
        # protected process) refuses PROCESS_VM_READ with access
        # denied. That is the same refusal, in Windows terms.
        handle = _win_open_process(
            pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
        if handle is None:
            code = _win_last_error()
            if code == ERROR_ACCESS_DENIED:
                raise MemSeekerError(
                    f"Refusing PID {pid}: access denied opening the "
                    "process (owned by another user, or a protected "
                    "process). MemSeeker only scans processes you can "
                    "open for reading.")
            raise MemSeekerError(
                f"Cannot open process {pid} (Windows error {code}).")
        _win_close_handle(handle)
        return pid

    def list_regions(self, pid):
        handle = _win_open_process(
            pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
        if handle is None:
            code = _win_last_error()
            if code == ERROR_ACCESS_DENIED:
                raise MemSeekerError(
                    f"Refusing PID {pid}: access denied opening the "
                    "process (owned by another user, or a protected "
                    "process).")
            raise MemSeekerError(
                f"Cannot open process {pid} (Windows error {code}).")
        regions = []
        try:
            addr = 0
            for _ in range(100000):  # safety: never loop forever
                info = _win_virtual_query_ex(handle, addr)
                if info is None:
                    break
                base, size, state, protect = info
                if size == 0:
                    break
                if state == MEM_COMMIT and _win_readable(protect):
                    name = _win_get_mapped_file_name(handle, base)
                    regions.append(Region(base, base + size,
                                          _win_perms(protect), 0, "0:0", 0,
                                          name))
                addr = base + size
            if not regions:
                raise MemSeekerError(
                    f"No readable memory regions found for PID {pid}.")
            return regions
        finally:
            _win_close_handle(handle)

    def open_memory(self, pid):
        handle = _win_open_process(
            pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
        if handle is None:
            code = _win_last_error()
            if code == ERROR_ACCESS_DENIED:
                raise MemSeekerError(
                    f"Refusing PID {pid}: access denied opening the "
                    "process (owned by another user, or a protected "
                    "process). Run as Administrator, or as the user "
                    "that owns the process.")
            raise MemSeekerError(
                f"Cannot open process {pid} (Windows error {code}).")
        return WindowsMemoryFile(handle)

    def process_name(self, pid):
        handle = _win_open_process(pid, PROCESS_QUERY_INFORMATION)
        if handle is None:
            return "?"
        try:
            return _win_get_process_name(handle)
        finally:
            _win_close_handle(handle)

    def list_own_pids(self):
        # Windows has no per-process owner file to filter on: return
        # every PID; scan_process refuses the ones we cannot open,
        # and --all skips them with a one-line note.
        return sorted(pid for pid, _name in _win_list_processes())


# --- macOS (ctypes, libSystem / mach) ------------------------------------
VM_PROT_READ = 0x01
VM_PROT_WRITE = 0x02
VM_PROT_EXECUTE = 0x04
VM_REGION_BASIC_INFO_64 = 9
KERN_SUCCESS = 0


class _VMRegionBasicInfo64(ctypes.Structure):
    """mach vm_region_basic_info_64 (only protection and share_mode
    are used; the count passed to vm_region_64 is computed from the
    size of this struct, so the layout stays self-consistent)."""
    _fields_ = [
        ("protection", ctypes.c_int),
        ("max_protection", ctypes.c_int),
        ("inheritance", ctypes.c_int),
        ("offset", ctypes.c_uint64),
        ("user_tag", ctypes.c_uint32),
        ("pages_resident", ctypes.c_uint32),
        ("pages_shared_now_private", ctypes.c_uint32),
        ("pages_swapped_out", ctypes.c_uint32),
        ("pages_dirtied", ctypes.c_uint32),
        ("ref_count", ctypes.c_uint32),
        ("shadow_depth", ctypes.c_uint16),
        ("external_pager", ctypes.c_uint8),
        ("share_mode", ctypes.c_uint8),
        ("reserved", ctypes.c_int),
        ("pages_reusable", ctypes.c_uint32),
        ("pages_pageable", ctypes.c_uint32),
    ]


def _mac_libsystem():
    """libSystem, loaded lazily (only exists on macOS)."""
    if sys.platform != "darwin":
        raise MemSeekerError("The macOS backend only works on macOS.")
    import ctypes.util
    path = ctypes.util.find_library("System") or "/usr/lib/libSystem.dylib"
    return ctypes.CDLL(path)


def _mac_task_self():
    lib = _mac_libsystem()
    lib.mach_task_self.restype = ctypes.c_uint
    lib.mach_task_self.argtypes = []
    return lib.mach_task_self()


def _mac_task_for_pid(pid):
    """A task port for the process, or MemSeekerError (with the
    privilege hint) when the kernel refuses."""
    lib = _mac_libsystem()
    lib.task_for_pid.restype = ctypes.c_int
    lib.task_for_pid.argtypes = [ctypes.c_uint, ctypes.c_int,
                                 ctypes.POINTER(ctypes.c_uint)]
    task = ctypes.c_uint(0)
    kr = lib.task_for_pid(_mac_task_self(), pid, ctypes.byref(task))
    if kr != KERN_SUCCESS:
        raise MemSeekerError(
            f"Cannot get a task port for PID {pid} (task_for_pid "
            f"failed, kern_return {kr}). On macOS, reading another "
            "process needs root or the debugger entitlement "
            "(com.apple.security.get-task-allow); run as root with "
            "sudo, or start the process from this tool.")
    return task.value


def _mac_vm_region_64(task, address):
    """(address, size, protection, share_mode) for the region at or
    after `address`, or None when there are no more regions."""
    lib = _mac_libsystem()
    info = _VMRegionBasicInfo64()
    count = ctypes.c_uint32(ctypes.sizeof(info) // 4)
    obj = ctypes.c_uint(0)
    addr = ctypes.c_uint64(address)
    size = ctypes.c_uint64(0)
    lib.vm_region_64.restype = ctypes.c_int
    lib.vm_region_64.argtypes = [ctypes.c_uint,
                                 ctypes.POINTER(ctypes.c_uint64),
                                 ctypes.POINTER(ctypes.c_uint64),
                                 ctypes.c_int,
                                 ctypes.POINTER(_VMRegionBasicInfo64),
                                 ctypes.POINTER(ctypes.c_uint32),
                                 ctypes.POINTER(ctypes.c_uint)]
    kr = lib.vm_region_64(task, ctypes.byref(addr), ctypes.byref(size),
                          VM_REGION_BASIC_INFO_64, ctypes.byref(info),
                          ctypes.byref(count), ctypes.byref(obj))
    if kr != KERN_SUCCESS:
        return None
    return (addr.value, size.value, info.protection, info.share_mode)


def _mac_vm_read(task, address, size):
    """Bytes read from a task (may be shorter). Raises OSError when
    nothing could be read — the scan then skips that region."""
    lib = _mac_libsystem()
    data = ctypes.c_void_p(0)
    count = ctypes.c_uint32(0)
    lib.vm_read.restype = ctypes.c_int
    lib.vm_read.argtypes = [ctypes.c_uint, ctypes.c_uint64,
                            ctypes.c_uint64, ctypes.POINTER(ctypes.c_void_p),
                            ctypes.POINTER(ctypes.c_uint32)]
    kr = lib.vm_read(task, address, size, ctypes.byref(data),
                     ctypes.byref(count))
    if kr != KERN_SUCCESS or count.value == 0:
        raise OSError(f"vm_read failed at 0x{address:x} (kern {kr})")
    try:
        return ctypes.string_at(data.value, count.value)
    finally:
        lib.vm_deallocate.restype = ctypes.c_int
        lib.vm_deallocate.argtypes = [ctypes.c_uint, ctypes.c_uint64,
                                      ctypes.c_uint64]
        lib.vm_deallocate(task, data.value, count.value)


def _mac_ps(pid, *fields):
    """One data line of `ps -o <fields> -p <pid>` (no header), or
    None when the process does not exist."""
    import subprocess
    try:
        r = subprocess.run(["ps", "-o", ",".join(fields), "-p", str(pid)],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    if len(lines) < 2:
        return None
    return lines[1]


def _mac_process_uid(pid):
    """Owner UID of a process (via ps), or None."""
    line = _mac_ps(pid, "uid")
    if line is None:
        return None
    try:
        return int(line)
    except ValueError:
        return None


def _mac_process_name(pid):
    """Short name of a process (via ps), or '?'."""
    line = _mac_ps(pid, "comm")
    if line is None:
        return "?"
    return line.rsplit("/", 1)[-1] or line


def _mac_list_processes():
    """[(pid, uid)] for every process (via ps)."""
    import subprocess
    try:
        r = subprocess.run(["ps", "-ax", "-o", "pid=", "-o", "uid="],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return []
    out = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            out.append((int(parts[0]), int(parts[1])))
        except ValueError:
            continue
    return out


def _mac_perms(protection, share_mode):
    """vm_prot_t + share_mode -> 'rwxp'-style string."""
    r = "r" if protection & VM_PROT_READ else "-"
    w = "w" if protection & VM_PROT_WRITE else "-"
    x = "x" if protection & VM_PROT_EXECUTE else "-"
    return r + w + x + ("p" if share_mode == 0 else "s")


class MachMemoryFile:
    """File-like reader over a macOS task (vm_read)."""

    def __init__(self, task):
        self.task = task
        self.pos = 0

    def seek(self, pos, whence=0):
        if whence == 0:
            self.pos = pos
        elif whence == 1:
            self.pos += pos
        elif whence == 2:
            raise OSError("seek from end is not supported")
        else:
            raise ValueError("invalid whence")
        return self.pos

    def read(self, size=-1):
        if size is None or size < 0:
            raise OSError("unbounded read is not supported")
        if size == 0:
            return b""
        data = _mac_vm_read(self.task, self.pos, size)
        self.pos += len(data)
        return data

    def close(self):
        # The task port is released when this process exits; there is
        # no vm task to tear down for a read-only scan.
        self.task = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class MacOSBackend:
    """macOS: task_for_pid + vm_read via ctypes (no install)."""
    name = "macos"

    def check_ownership(self, pid):
        uid = _mac_process_uid(pid)
        if uid is None:
            raise MemSeekerError(f"No process with PID {pid}.")
        if uid != os.getuid():
            raise MemSeekerError(
                f"Refusing PID {pid}: it is owned by UID {uid}, not by "
                f"you (UID {os.getuid()}). MemSeeker only scans "
                "processes you own.")
        return uid

    def list_regions(self, pid):
        task = _mac_task_for_pid(pid)
        regions = []
        addr = 0
        for _ in range(100000):  # safety: never loop forever
            info = _mac_vm_region_64(task, addr)
            if info is None:
                break
            address, size, protection, share_mode = info
            if size == 0:
                break
            if protection & VM_PROT_READ:
                regions.append(Region(address, address + size,
                                      _mac_perms(protection, share_mode),
                                      0, "0:0", 0, ""))
            addr = address + size
        if not regions:
            raise MemSeekerError(
                f"No readable memory regions found for PID {pid}.")
        return regions

    def open_memory(self, pid):
        task = _mac_task_for_pid(pid)
        return MachMemoryFile(task)

    def process_name(self, pid):
        return _mac_process_name(pid)

    def list_own_pids(self):
        return sorted(pid for pid, uid in _mac_list_processes()
                      if uid == os.getuid())


# --- Linux backend (v1.0 code, wrapped) ----------------------------------
class LinuxBackend:
    """Linux: /proc/<pid>/maps + /proc/<pid>/mem."""
    name = "linux"

    def check_ownership(self, pid):
        return check_ownership(pid)

    def list_regions(self, pid):
        return parse_maps(pid)

    def open_memory(self, pid):
        try:
            return open(f"/proc/{pid}/mem", "rb", buffering=0)
        except FileNotFoundError:
            raise MemSeekerError(f"No process with PID {pid}.")
        except PermissionError:
            raise MemSeekerError(
                f"Permission denied opening /proc/{pid}/mem for PID {pid}. "
                "The kernel blocked the read (Yama ptrace_scope). Run as "
                "root / with sudo, or start the process from this tool "
                "(--lab, or menu option 2), or set ptrace_scope=0.")

    def process_name(self, pid):
        return process_name(pid)

    def list_own_pids(self):
        out = []
        try:
            entries = os.listdir("/proc")
        except OSError:
            return out
        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                if os.stat(f"/proc/{pid}").st_uid == os.getuid():
                    out.append(pid)
            except OSError:
                continue
        return sorted(out)


def get_backend(name=None):
    """The backend for this platform (or the named one, for tests)."""
    if name is None:
        if sys.platform.startswith("win"):
            name = "windows"
        elif sys.platform == "darwin":
            name = "macos"
        else:
            name = "linux"
    if name == "windows":
        return WindowsBackend()
    if name == "macos":
        return MacOSBackend()
    return LinuxBackend()


class ImageFile:
    """File-like reader over a raw memory dump file (v1.1 --image).

    Addresses are file offsets plus `base` (default 0), so the scan
    pipeline can treat a dump exactly like live memory. This is the
    portable fallback: it works on every OS, with no live-process
    access at all."""

    def __init__(self, fh, base=0):
        self.fh = fh
        self.base = base
        self.pos = base

    def seek(self, pos, whence=0):
        if whence == 0:
            self.pos = pos
        elif whence == 1:
            self.pos += pos
        elif whence == 2:
            raise OSError("seek from end is not supported")
        else:
            raise ValueError("invalid whence")
        return self.pos

    def read(self, size=-1):
        if size is None or size < 0:
            raise OSError("unbounded read is not supported")
        if size == 0:
            return b""
        off = self.pos - self.base
        if off < 0:
            raise OSError(f"address 0x{self.pos:x} is below the image "
                          f"base 0x{self.base:x}")
        self.fh.seek(off)
        data = self.fh.read(size)
        self.pos += len(data)
        return data

    def close(self):
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


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
        if section.startswith("Group:"):
            continue  # groups are loaded by load_groups()
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


# --- Rule groups (v1.1: YARA-style conditions) ---------------------------
class Group:
    """A [Group:Name] section: a condition over member rules.

    Condition forms (case-insensitive, parens required):
        2 of (RuleA, RuleB, RuleC)   — at least 2 members fired
        all of (RuleA, RuleB)        — every member fired
        any of (RuleA, RuleB)        — at least one member fired
    A group is evaluated PER REGION: it fires as ONE finding (rule
    name = the group name) when its condition is met by the rules
    that fired in that region.
    """

    __slots__ = ("name", "kind", "n", "members", "raw")

    def __init__(self, name, kind, n, members, raw):
        self.name = name
        self.kind = kind            # "n_of" | "all" | "any"
        self.n = n                  # threshold for "n_of"
        self.members = members      # rule names (list of str)
        self.raw = raw              # condition text as written

    def evaluate(self, fired):
        """True when the condition is met by the set of rule names
        that fired in one region."""
        have = len(set(self.members) & set(fired))
        if self.kind == "any":
            return have >= 1
        if self.kind == "all":
            return have == len(self.members)
        return have >= self.n


CONDITION_RE = re.compile(
    r"^\s*(\d+|all|any)\s+of\s*\(([^)]*)\)\s*$", re.IGNORECASE)


def load_groups(path, rules):
    """Load [Group:Name] sections from a rule file. Returns a list of
    Group (empty when the file has none). A group that names a missing
    rule, or a condition that can never fire, raises MemSeekerError
    NAMING the group — before any scanning starts."""
    if not os.path.isfile(path):
        raise MemSeekerError(f"Rule file not found: {path}")
    cfg = configparser.ConfigParser(interpolation=None)
    try:
        cfg.read(path)
    except configparser.Error as exc:
        raise MemSeekerError(f"Cannot parse rule file {path}: {exc}")
    known = {r.name for r in rules}
    groups = []
    for section in cfg.sections():
        if not section.startswith("Group:"):
            continue
        name = section[len("Group:"):].strip()
        if not name:
            raise MemSeekerError(
                f"Rule file {path} has a [Group:] section with no name.")
        if name in known:
            raise MemSeekerError(
                f"Group '{name}' in {path} has the same name as a rule — "
                "group names must be different from rule names.")
        raw = cfg.get(section, "condition", fallback="").strip()
        m = CONDITION_RE.match(raw)
        if not m:
            raise MemSeekerError(
                f"Group '{name}' in {path} has a bad condition: '{raw}' "
                "(use '2 of (A, B, C)', 'all of (A, B)' or "
                "'any of (A, B)').")
        head = m.group(1).lower()
        members = [x.strip() for x in m.group(2).split(",") if x.strip()]
        if not members:
            raise MemSeekerError(
                f"Group '{name}' in {path} names no member rules.")
        missing = [x for x in members if x not in known]
        if missing:
            raise MemSeekerError(
                f"Group '{name}' in {path} names unknown rule(s): "
                + ", ".join(missing) + ".")
        if head == "all":
            kind, n = "all", len(members)
        elif head == "any":
            kind, n = "any", 1
        else:
            kind, n = "n_of", int(head)
            if n < 1:
                raise MemSeekerError(
                    f"Group '{name}' in {path} has condition '{raw}' — "
                    "the number must be at least 1.")
            if n > len(members):
                raise MemSeekerError(
                    f"Group '{name}' in {path} has condition '{raw}' — "
                    f"it can never fire ({len(members)} member(s)).")
        groups.append(Group(name, kind, n, members, raw))
    return groups


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
                 "ctx_before", "ctx_after", "strings", "dump_file")

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
        self.dump_file = None       # set by --dump, when the region
                                    # holding this hit was dumped to disk

    def key(self):
        """Stable identity of a hit (for watch mode: same rule + address
        = the same hit, even across rescans)."""
        return (self.rule.name, self.address)

    def to_dict(self):
        d = {
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
        if self.dump_file:
            d["dump_file"] = self.dump_file
        return d


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
        self.image_path = None      # set for --image scans (no live PID)
        self.base_address = 0       # --base for image scans
        self.dump_files = {}        # (region start, end) -> dump path
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
    hits_before = len(result.hits)  # where this region's hits start
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
        # v1.1 groups: evaluated PER REGION, once the region is fully
        # read. A group fires as ONE finding (rule name = the group
        # name) at the earliest member hit's address, when its
        # condition is met by the rules that fired in this region.
        groups = opts.get("groups") or []
        if groups:
            region_hits = result.hits[hits_before:]
            fired = {h.rule.name for h in region_hits}
            for group in groups:
                if group.evaluate(fired):
                    member_hits = [h for h in region_hits
                                   if h.rule.name in group.members]
                    first = min(member_hits, key=lambda h: h.address)
                    group_rule = Rule(group.name, "group", group.raw,
                                      None,
                                      f"Group condition: {group.raw}", 0)
                    result.hits.append(Hit(group_rule, region,
                                           first.address, first.match,
                                           first.ctx_before,
                                           first.ctx_after, first.strings))
        result.regions_read += 1
    except OSError as exc:
        # Guarded page / vanished region / unreadable mapping: skip it
        # with a note. The scan carries on (PDF Step 2).
        result.regions_skipped.append((region, str(exc) or "unreadable"))


def _scan_regions(reader, regions, rules, opts, pid, proc_name,
                  image_path=None, base_address=0):
    """The shared scan loop: live processes and image files both come
    through here. `reader` is file-like (seek/read) — a /proc mem
    file, a Windows/macOS memory reader, or an ImageFile. Returns a
    ScanResult."""
    readable = readable_regions(regions)
    overlap = overlap_size(rules)
    result = ScanResult(pid, proc_name, opts["rules_path"],
                        opts["chunk_size"])
    result.regions_total = len(regions)
    result.image_path = image_path
    result.base_address = base_address
    started = time.time()
    for region in readable:
        scan_region(reader, reader, region, rules, overlap, opts, result)
    result.seconds = time.time() - started
    return result


def scan_process(pid, rules, opts, backend=None):
    """Full scan of one process. Returns a ScanResult.

    Raises MemSeekerError on ownership refusal, missing process, or a
    mem file that cannot be opened at all (Yama / permissions). The
    reader is opened once and shared by the chunk loop and the
    context reads — every read is seek-prefixed, so the two never
    disturb each other.
    """
    backend = backend or get_backend()
    backend.check_ownership(pid)
    regions = backend.list_regions(pid)
    reader = backend.open_memory(pid)
    try:
        result = _scan_regions(reader, regions, rules, opts, pid,
                               backend.process_name(pid))
        if opts.get("dump"):
            _dump_hit_regions(reader, result, opts["dump"])
        return result
    finally:
        reader.close()


def scan_image(path, rules, opts, base=0):
    """Scan a raw memory dump file as if it were memory (v1.1).

    The file is one flat region [base, base+size). Hits report file
    offsets as addresses (base + offset). Works on every OS — the
    portable fallback that needs no live-process access."""
    if not path:
        raise MemSeekerError("No memory image file given.")
    if not os.path.isfile(path):
        raise MemSeekerError(f"Memory image not found: {path}")
    size = os.path.getsize(path)
    if size == 0:
        raise MemSeekerError(f"Memory image is empty: {path}")
    region = Region(base, base + size, "r--p", 0, "0:0", 0,
                    os.path.basename(path))
    fh = open(path, "rb", buffering=0)
    reader = ImageFile(fh, base)
    try:
        result = _scan_regions(reader, [region], rules, opts, None,
                               os.path.basename(path),
                               image_path=path, base_address=base)
        if opts.get("dump"):
            _dump_hit_regions(reader, result, opts["dump"])
        return result
    finally:
        reader.close()


def scan_pids(pids, rules, opts, backend=None):
    """Scan several PIDs (v1.1). Returns (results, skipped): results
    is a list of ScanResult (one per process scanned), skipped is a
    list of (pid, reason) for processes that could not be scanned at
    all (refused, vanished, unreadable). One bad PID never stops the
    others."""
    backend = backend or get_backend()
    results = []
    skipped = []
    for pid in pids:
        try:
            results.append(scan_process(pid, rules, opts, backend))
        except MemSeekerError as exc:
            skipped.append((pid, str(exc)))
        except OSError as exc:
            skipped.append((pid, str(exc) or "unreadable"))
    return results, skipped


def scan_all(rules, opts, backend=None):
    """Scan every process owned by the current user (v1.1 --all)."""
    backend = backend or get_backend()
    return scan_pids(backend.list_own_pids(), rules, opts, backend)


def sanitize_region_name(name):
    """A region name safe for a filename: '/usr/lib/libc.so.6' ->
    'usr_lib_libc.so.6', '[anon]' -> 'anon'."""
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return clean or "region"


def dump_region(reader, region, path):
    """Write one region's full bytes to path, in chunks. Returns the
    bytes written. A read that fails mid-region stops the dump there
    (the file holds a partial dump) — never a crash."""
    written = 0
    with open(path, "wb") as fh:
        pos = region.start
        while pos < region.end:
            want = min(DEFAULT_CHUNK_SIZE, region.end - pos)
            try:
                reader.seek(pos)
                data = reader.read(want)
            except OSError:
                break
            if not data:
                break
            fh.write(data)
            written += len(data)
            pos += len(data)
    return written


def _dump_hit_regions(reader, result, dump_dir):
    """Dump every region that contains at least one hit (v1.1 --dump).

    Files are named <pid>_<start>-<end>_<region>.bin in dump_dir
    ('image' instead of a PID for image scans). The dump path is
    recorded on each hit of that region, so the report names the
    file. Regions without hits are never dumped. Raises
    MemSeekerError if the directory cannot be created."""
    try:
        os.makedirs(dump_dir, exist_ok=True)
    except OSError as exc:
        raise MemSeekerError(
            f"Cannot create dump directory {dump_dir}: {exc}")
    hit_regions = {}
    for hit in result.hits:
        hit_regions[(hit.region.start, hit.region.end)] = hit.region
    label = result.pid if result.pid is not None else "image"
    out = {}
    for (start, end), region in hit_regions.items():
        fname = (f"{label}_{region.range_str()}_"
                 f"{sanitize_region_name(region.name)}.bin")
        path = os.path.join(dump_dir, fname)
        try:
            dump_region(reader, region, path)
        except OSError as exc:
            raise MemSeekerError(f"Cannot write dump file {path}: {exc}")
        out[(start, end)] = path
    for hit in result.hits:
        hit.dump_file = out.get((hit.region.start, hit.region.end))
    result.dump_files = out
    return out


# --- Reports -------------------------------------------------------------
_DEFENSIVE_LESSON = (
    "Defensive lesson: secrets must never sit in process memory in "
    "plaintext. A password or key left in a plain variable can be read "
    "by anyone who can read the process memory — this scan just proved "
    "it. Programs that handle secrets lock the memory (mlock), zero the "
    "buffer as soon as they are done with it, and keep keys in a system "
    "keyring or a hardware-backed store instead of a variable.")


def _report_header(started):
    """The banner + tool/date lines shared by every report."""
    return ["=" * 58,
            "MemSeeker — Process Memory Scan Report",
            "=" * 58,
            f"Tool:      MemSeeker v{VERSION} by {AUTHOR}",
            f"Date:      {started:%Y-%m-%d %H:%M:%S}",
            f"Disclaimer: {DISCLAIMER}"]


def _summary_lines(result, rules, include_identity=True):
    """Summary block for ONE scan result (single + multi reports)."""
    lines = []
    if include_identity:
        if result.image_path is not None:
            lines.append(f"Image file: {result.image_path}")
            lines.append(f"Base addr: 0x{result.base_address:x}")
        else:
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
    return lines


def _hit_lines(result):
    """Hit + entropy lines for ONE scan result."""
    lines = []
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
        if hit.dump_file:
            lines.append(f"  Dump:    {hit.dump_file}")
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
    return lines


def build_text_report(result, rules):
    """The text report: every hit with rule, region and offset."""
    lines = _report_header(result.started)
    lines += _summary_lines(result, rules)
    lines.append("")
    lines += _hit_lines(result)
    lines.append("")
    lines.append(_DEFENSIVE_LESSON)
    lines.append("")
    return "\n".join(lines) + "\n"


def build_multi_text_report(results, skipped, rules):
    """The text report for a multi-process scan: one section per
    process, then the processes that could not be scanned."""
    started = results[0].started if results else datetime.now()
    lines = _report_header(started)
    lines.append(f"Processes: {len(results)} scanned, "
                 f"{len(skipped)} skipped")
    lines.append(f"Hits:      {sum(len(r.hits) for r in results)}")
    for result in results:
        lines.append("")
        lines.append("-" * 58)
        lines.append(f"Process: PID {result.pid} ({result.proc_name})")
        lines += _summary_lines(result, rules, include_identity=False)
        lines.append("")
        lines += _hit_lines(result)
    if skipped:
        lines.append("")
        lines.append("-" * 58)
        lines.append("Skipped processes (could not be scanned):")
        for pid, reason in skipped:
            lines.append(f"  PID {pid}: {reason}")
    lines.append("")
    lines.append(_DEFENSIVE_LESSON)
    lines.append("")
    return "\n".join(lines) + "\n"


def result_to_dict(result, rules):
    """One scan result as a dict (used by single + multi JSON)."""
    d = {
        "tool": f"MemSeeker v{VERSION}",
        "author": AUTHOR,
        "disclaimer": DISCLAIMER,
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
    }
    if result.image_path is not None:
        d["image_file"] = result.image_path
        d["base_address"] = f"0x{result.base_address:x}"
    return d


def build_json_report(result, rules):
    """The same report as JSON (machine-readable)."""
    return json.dumps(result_to_dict(result, rules), indent=2) + "\n"


def build_multi_json_report(results, skipped, rules):
    """The multi-process report as JSON."""
    return json.dumps({
        "tool": f"MemSeeker v{VERSION}",
        "author": AUTHOR,
        "disclaimer": DISCLAIMER,
        "date": (results[0].started if results else datetime.now()
                 ).strftime("%Y-%m-%d %H:%M:%S"),
        "mode": "multi-process",
        "rules_file": results[0].rules_path if results else "",
        "rules": [r.name for r in rules],
        "processes": [result_to_dict(r, rules) for r in results],
        "skipped": [{"pid": pid, "reason": reason}
                    for pid, reason in skipped],
    }, indent=2) + "\n"


def write_report(result, rules, path, as_json):
    """Write the report file for ONE scan. Returns the path written."""
    text = build_json_report(result, rules) if as_json \
        else build_text_report(result, rules)
    with open(path, "w") as fh:
        fh.write(text)
    return path


def write_multi_report(results, skipped, rules, path, as_json):
    """Write the report file for a multi-process scan."""
    text = build_multi_json_report(results, skipped, rules) if as_json \
        else build_multi_text_report(results, skipped, rules)
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


def print_config(pid, rules_path, rules, opts, mode=None):
    """Gobuster-style SCAN config block before each scan.
    mode: None for a single-PID scan; a string like 'All my
    processes' or 'Memory image: /tmp/dump.bin' for the v1.1 modes."""
    if QUIET:
        return
    sep()
    print(f" {C.WHT}[ {C.GRN}SCAN {C.WHT}] {C.GRN}MemSeeker v{VERSION}"
          f"{C.RST}")
    sep()
    if mode is not None:
        info("Mode", mode)
    else:
        info("Process ID", str(pid))
        info("Process", process_name(pid))
    info("Rules file", f"{rules_path} ({len(rules)} rules)")
    info("Chunk size", f"{opts['chunk_size']} bytes")
    info("Entropy scan", "on" if opts["entropy"] else "off")
    info("String extraction", "on" if opts["strings"] else "off")
    if opts.get("dump"):
        info("Region dump", opts["dump"])
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
    """Check setup for THIS platform's backend: Linux (/proc +
    ptrace_scope), Windows (kernel32 + process listing) or macOS
    (libSystem + task_for_pid) — plus the shared files. The --image
    mode works on every platform even when live scans cannot."""
    print_banner()
    header("Doctor — check setup")
    problems = 0
    backend = get_backend()
    info("Platform", f"{sys.platform} (backend: {backend.name})")
    ok(f"Python {sys.version.split()[0]}")
    if backend.name == "linux":
        if os.path.isdir("/proc"):
            ok("Linux with /proc (live scans read /proc/<pid>/maps and "
               "/proc/<pid>/mem).")
        else:
            err("No /proc — live scans cannot work on this machine.")
            problems += 1
        scope = ptrace_scope()
        if scope is None:
            info("ptrace_scope",
                 "no Yama (any same-user process is readable)")
        elif scope == 0:
            info("ptrace_scope", "0 — any same-user process is readable")
        elif scope == 1:
            warn("ptrace_scope is 1 — only a PARENT process may be read. "
                 "Scan as root / with sudo, or start the process from "
                 "this tool's menu (option 2).")
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
    elif backend.name == "windows":
        try:
            _win_kernel32()
            ok("kernel32 reachable via ctypes (live scans need no "
               "install).")
        except MemSeekerError as exc:
            err(str(exc))
            problems += 1
        try:
            pids = backend.list_own_pids()
            ok(f"Can list processes ({len(pids)} found).")
        except MemSeekerError as exc:
            warn(f"Cannot list processes: {exc}")
        try:
            handle = _win_open_process(
                os.getpid(), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
            if handle is None:
                warn("Cannot open my own process for reading — live "
                     "scans may be refused; try running as Administrator. "
                     "The --image mode still works.")
            else:
                _win_close_handle(handle)
                ok("Can open my own process for reading.")
        except MemSeekerError as exc:
            err(str(exc))
            problems += 1
    elif backend.name == "macos":
        try:
            _mac_libsystem()
            ok("libSystem reachable via ctypes (live scans need no "
               "install).")
        except MemSeekerError as exc:
            err(str(exc))
            problems += 1
        try:
            task = _mac_task_for_pid(os.getpid())
            ok("Can get a task port for my own process (live scans "
               "work).")
        except MemSeekerError as exc:
            warn("task_for_pid failed on my own process — live scans "
                 "need root (sudo) or the debugger entitlement. The "
                 "--image mode still works.")
    here = os.path.dirname(os.path.abspath(__file__))
    for label, rel in (("lab process", "lab_proc.py"),
                       ("lab rules", "rules_lab.txt"),
                       ("default rules", "rules_default.txt"),
                       ("group rules", "rules_groups.txt"),
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
    print(f" {C.WHT}[ {C.GRN}8 {C.WHT}] {C.GRN}Scan all my processes "
          f"(every process you own){C.RST}")
    print(f" {C.WHT}[ {C.GRN}9 {C.WHT}] {C.GRN}Scan a memory image file "
          f"(works on every OS){C.RST}")
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


def _scan_opts(args, rules_path):
    """The opts dict every scan entry point builds the same way."""
    return {
        "rules_path": rules_path,
        "chunk_size": args.chunk_size,
        "entropy": args.entropy,
        "strings": args.strings,
        "output": args.output,
        "dump": getattr(args, "dump", None),
        "groups": [],
    }


def _load_rules_and_groups(rules_path):
    """Load the rules and their groups (both errors are clean and
    happen before any scanning starts). Returns (rules, groups)."""
    rules = load_rules(rules_path)
    groups = load_groups(rules_path, rules)
    return rules, groups


def _finish_single(result, rules, opts, as_json):
    """Print the summary, print the hits, write the report. Returns
    the exit code: 0 clean, 1 hits, 2 write error."""
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
        write_report(result, rules, opts["output"], as_json)
        ok(f"Report saved: {opts['output']}")
    except OSError as exc:
        err(f"Cannot write report {opts['output']}: {exc}")
        return 2
    if result.hits:
        warn(f"{len(result.hits)} hit(s) — see the report.")
        return 1
    return 0


def do_scan(args, pid=None, rules_path=None):
    """Run one scan from CLI args or menu answers. Returns an exit code:
    0 = clean, 1 = hits found, 2 = error / refusal."""
    pid = pid if pid is not None else (
        args.pid[0] if getattr(args, "pid", None) else os.getpid())
    rules_path = rules_path or args.rules or DEFAULT_RULES
    opts = _scan_opts(args, rules_path)
    print_banner()
    try:
        rules, groups = _load_rules_and_groups(rules_path)
        opts["groups"] = groups
        print_config(pid, rules_path, rules, opts)
        result = scan_process(pid, rules, opts)
    except MemSeekerError as exc:
        err(str(exc))
        return 2
    return _finish_single(result, rules, opts, args.json)


def do_image_scan(args, image_path=None, rules_path=None):
    """v1.1: scan a memory image file (works on every OS). Returns an
    exit code: 0 = clean, 1 = hits found, 2 = error."""
    image_path = image_path or args.image
    rules_path = rules_path or args.rules or DEFAULT_RULES
    opts = _scan_opts(args, rules_path)
    print_banner()
    try:
        rules, groups = _load_rules_and_groups(rules_path)
        opts["groups"] = groups
        print_config(None, rules_path, rules, opts,
                     mode=f"Memory image: {image_path}")
        result = scan_image(image_path, rules, opts,
                            base=args.base or 0)
    except MemSeekerError as exc:
        err(str(exc))
        return 2
    return _finish_single(result, rules, opts, args.json)


def do_multi_scan(args, pids=None, all_flag=False, rules_path=None):
    """v1.1: scan several PIDs (or --all: every process you own).
    Returns an exit code: 0 = clean, 1 = hits found, 2 = error (bad
    rules, or no process could be scanned at all)."""
    rules_path = rules_path or args.rules or DEFAULT_RULES
    opts = _scan_opts(args, rules_path)
    print_banner()
    try:
        rules, groups = _load_rules_and_groups(rules_path)
        opts["groups"] = groups
        if all_flag:
            targets = get_backend().list_own_pids()
            if not targets:
                err("No processes found that you own.")
                return 2
            mode = f"All my processes ({len(targets)} PIDs)"
        else:
            targets = list(pids or [])
            if not targets:
                err("No process ID given.")
                return 2
            mode = f"{len(targets)} process(es): " + ", ".join(
                str(p) for p in targets)
        print_config(None, rules_path, rules, opts, mode=mode)
        results, skipped = scan_pids(targets, rules, opts)
    except MemSeekerError as exc:
        err(str(exc))
        return 2
    if not results:
        err("No process could be scanned.")
        for pid, reason in skipped:
            err(f"  PID {pid}: {reason}")
        return 2
    total_hits = sum(len(r.hits) for r in results)
    if not QUIET:
        print()
        for result in results:
            info(f"PID {result.pid} ({result.proc_name})",
                 f"{len(result.hits)} hit(s), "
                 f"{result.regions_read} regions, "
                 f"{result.bytes_read} bytes")
        if skipped:
            info("Skipped", f"{len(skipped)} process(es) — see the "
                 "report for the reasons")
        print()
    for result in results:
        if not QUIET:
            header(f"PID {result.pid} ({result.proc_name}) — "
                   f"{len(result.hits)} hit(s)")
        print_hits(result)
    try:
        write_multi_report(results, skipped, rules, opts["output"],
                           args.json)
        ok(f"Report saved: {opts['output']}")
    except OSError as exc:
        err(f"Cannot write report {opts['output']}: {exc}")
        return 2
    if total_hits:
        warn(f"{total_hits} hit(s) across {len(results)} process(es) — "
             "see the report.")
        return 1
    return 0


def do_map(args, pid=None):
    """Option 3 / --map: print every region of a process."""
    pid = pid if pid is not None else (
        args.pid[0] if getattr(args, "pid", None) else os.getpid())
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
    """Option 4 / --list-rules: print every rule (and group) in a
    rule file."""
    rules_path = rules_path or args.rules or DEFAULT_RULES
    print_banner()
    try:
        rules, groups = _load_rules_and_groups(rules_path)
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
    if groups:
        header(f"Rule groups — {rules_path} ({len(groups)} group(s))")
        for group in groups:
            print(f" {C.WHT}[{C.GRN}+{C.WHT}]{C.RST} "
                  f"{C.BLD}{group.name}{C.RST} (group)")
            print(f"      condition: {group.raw}")
            print(f"      members: {', '.join(group.members)}")
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
    rules_path = args.rules or os.path.join(here, DEFAULT_RULES)
    try:
        proc, lab_info = start_lab_process()
    except MemSeekerError as exc:
        err(str(exc))
        return 2
    pid = lab_info["pid"]
    ok(f"Lab process started: PID {pid} ({process_name(pid)})")
    opts = _scan_opts(args, rules_path)
    opts["entropy"] = True
    opts["strings"] = True
    try:
        rules, groups = _load_rules_and_groups(rules_path)
        opts["groups"] = groups
        print_config(pid, rules_path, rules, opts)
        result = scan_process(pid, rules, opts)
    except MemSeekerError as exc:
        err(str(exc))
        proc.kill()
        return 2
    rc = _finish_single(result, rules, opts, args.json)
    proc.kill()
    proc.wait()
    return rc


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
                opts = _scan_opts(args, rules_path)
                opts["dump"] = None  # watch mode never dumps regions
                watch_process(pid, load_rules(rules_path), opts, interval)
            elif choice == "8":
                rules_path = ask_rules()
                args.entropy = True
                args.strings = True
                do_multi_scan(args, all_flag=True,
                              rules_path=rules_path)
            elif choice == "9":
                image_path = ask_interactive("ENTER MEMORY IMAGE FILE", "")
                if not image_path:
                    err("Please enter an image file path.")
                    time.sleep(1)
                    continue
                rules_path = ask_rules()
                args.entropy = True
                args.strings = True
                do_image_scan(args, image_path=image_path,
                              rules_path=rules_path)
            else:
                err("Please input a number from the menu (0-9).")
                time.sleep(1)
                continue
        except ValueError:
            err("Please input a number from the menu (0-9).")
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
def parse_int(text):
    """An integer that also accepts 0x... (for --base)."""
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"not an integer: {text!r} (use 1234 or 0x1000)")


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="MemSeeker v%s — process memory scanner "
                    "(read-only). Scans ONLY processes you own. "
                    "Linux, Windows and macOS." % VERSION)
    p.add_argument("pid", type=int, nargs="*",
                   help="process ID(s) to scan (one or several)")
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
    p.add_argument("--all", action="store_true",
                   help="scan every process owned by the current user")
    p.add_argument("--pids", metavar="LIST",
                   help="comma-separated process IDs to scan "
                        "(e.g. --pids 1234,5678)")
    p.add_argument("--image", metavar="FILE",
                   help="scan a raw memory dump file instead of a live "
                        "process (works on every OS)")
    p.add_argument("--base", type=parse_int, default=0, metavar="ADDR",
                   help="base address of the image file (default: 0; "
                        "accepts 1234 or 0x1000)")
    p.add_argument("--dump", metavar="DIR",
                   help="dump every region that contains a hit to this "
                        "directory (<pid>_<range>_<region>.bin)")
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
        # Target PIDs: positional (one or several) and/or --pids.
        targets = list(args.pid or [])
        if args.pids:
            try:
                targets += [int(x) for x in args.pids.split(",")
                            if x.strip()]
            except ValueError:
                err("--pids must be a comma-separated list of integers "
                    "(e.g. --pids 1234,5678).")
                return 2
        if args.watch and len(targets) > 1:
            err("--watch scans one process at a time; give a single PID.")
            return 2
        if args.image:
            # Image mode works in batch, quiet and interactive alike.
            if not args.rules and not (args.batch or args.quiet):
                print_banner()
                args.rules = ask_rules()
            return do_image_scan(args)
        if args.map:
            if not targets:
                return do_map(args, pid=os.getpid())
            for pid in targets:
                rc = do_map(args, pid=pid)
                if rc != 0:
                    return rc
            return 0
        if args.all or len(targets) > 1:
            if not args.rules and not (args.batch or args.quiet):
                print_banner()
                args.rules = ask_rules()
            return do_multi_scan(args, pids=targets,
                                 all_flag=args.all)
        if args.batch or args.quiet:
            # Never ask: missing values become the defaults.
            if args.watch:
                opts = _scan_opts(args, args.rules or DEFAULT_RULES)
                opts["dump"] = None  # watch mode never dumps regions
                rules = load_rules(opts["rules_path"])
                return watch_process(targets[0] if targets
                                     else os.getpid(), rules, opts,
                                     args.watch, rounds=args.rounds)
            return do_scan(args, pid=targets[0] if targets
                           else os.getpid())
        if args.menu or not targets:
            return menu_loop(args)
        # Args given: one PID, maybe rules missing — ask for it.
        if args.watch:
            opts = _scan_opts(args, args.rules or DEFAULT_RULES)
            opts["dump"] = None  # watch mode never dumps regions
            rules = load_rules(opts["rules_path"])
            return watch_process(targets[0], rules, opts, args.watch,
                                 rounds=args.rounds)
        if not args.rules:
            print_banner()
            args.rules = ask_rules()
        return do_scan(args, pid=targets[0])
    except KeyboardInterrupt:
        print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
