#!/usr/bin/env python3
"""MemSeeker step tests — one function per PDF build-plan step.

Every step starts the lab process (lab_proc.py) as a CHILD of this
test process, so the in-process scans are allowed even under Yama
ptrace_scope=1 (a parent may read its descendants). The CLI scan of
the lab from a separate process is environment-dependent (it works
where the user has CAP_SYS_PTRACE, e.g. root on Kali; in this VM it
is refused cleanly) — the test accepts either outcome, but never a
traceback.

Run:  python3 test_memseeker.py
Exit: 0 when every check passes, 1 otherwise.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "memseeker.py")
LAB = os.path.join(HERE, "lab_proc.py")
RULES_LAB = os.path.join(HERE, "rules_lab.txt")

sys.path.insert(0, HERE)
import memseeker  # noqa: E402

PASSED = 0
FAILED = 0
FAILURES = []


def check(name, cond, detail=""):
    """One check: count it, print it, remember failures."""
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  [PASS] {name}")
    else:
        FAILED += 1
        FAILURES.append(name)
        print(f"  [FAIL] {name}  {detail}")


def start_lab():
    """Start lab_proc.py as our child; read its JSON info line."""
    proc = subprocess.Popen([sys.executable, LAB],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    for _ in range(100):
        line = proc.stdout.readline()
        if not line:
            break
        if line.lstrip().startswith("{"):
            return proc, json.loads(line)
    proc.kill()
    raise RuntimeError("lab process did not print its info line")


def stop_lab(proc):
    try:
        proc.kill()
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001 - cleanup, never fatal
        pass


def run_tool(args, **kw):
    """Run memseeker.py as a subprocess, capture output."""
    return subprocess.run([sys.executable, TOOL] + args,
                          capture_output=True, text=True,
                          cwd=HERE, timeout=120, **kw)


def opts(rules_path=RULES_LAB, chunk_size=65536, entropy=False,
         strings=False):
    return {"rules_path": rules_path, "chunk_size": chunk_size,
            "entropy": entropy, "strings": strings, "output": "test_out.txt"}


def region_of(regions, addr):
    for r in regions:
        if r.start <= addr < r.end:
            return r
    return None


def find_straddle_chunk_size(offset, marker_len):
    """A chunk size c (bigger than the marker) that makes a marker at
    `offset` inside its region straddle a chunk boundary."""
    for c in (16, 24, 32, 40, 48, 56, 64, 80, 96, 128, 192, 256, 512):
        if c > marker_len and (offset % c) + marker_len > c:
            return c
    return None


# --- Step 1 — Read the memory map ----------------------------------------
def step1():
    print("\nStep 1 — Read the memory map")
    proc, info = start_lab()
    try:
        pid = info["pid"]
        regions = memseeker.parse_maps(pid)
        manual = open(f"/proc/{pid}/maps").read().splitlines()
        check("maps: region count matches a manual read",
              len(regions) == len(manual),
              f"{len(regions)} vs {len(manual)}")
        first = manual[0].split()
        check("maps: first region range matches the manual read",
              regions[0].start == int(first[0].split("-")[0], 16)
              and regions[0].end == int(first[0].split("-")[1], 16))
        check("maps: every region has start < end and a permission string",
              all(r.start < r.end and len(r.perms) == 4 for r in regions))
        readable = memseeker.readable_regions(regions)
        check("maps: at least one readable region found", len(readable) > 0,
              f"readable={len(readable)}")
        names = {r.name for r in regions}
        check("maps: region names present ([heap]/[stack]/file/[anon])",
              any(n in names for n in ("[heap]", "[stack]"))
              or any(n.startswith("/") for n in names))
        check("maps: [heap] region exists",
              any(r.name == "[heap]" for r in regions))
    finally:
        stop_lab(proc)


# --- Step 2 — Read one region --------------------------------------------
def step2():
    print("\nStep 2 — Read one region")
    proc, info = start_lab()
    try:
        pid = info["pid"]
        regions = memseeker.parse_maps(pid)
        heap = region_of(regions, info["markers"]["alpha"])
        check("read: alpha marker lives in a region", heap is not None)
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
            total = 0
            for _addr, data in memseeker.read_region_chunks(
                    mem, heap, 4096):
                total += len(data)
        check("read: total bytes read == region size",
              total == heap.size, f"{total} vs {heap.size}")
        # Full scan must never crash on a guarded page ([vvar]/[vdso]
        # often refuse reads): it completes and reports what it skipped.
        rules = memseeker.load_rules(RULES_LAB)
        result = memseeker.scan_process(pid, rules, opts())
        check("read: full scan completes without crashing",
              result.regions_read > 0)
        check("read: skipped regions are recorded, not fatal",
              isinstance(result.regions_skipped, list))
    finally:
        stop_lab(proc)


# --- Step 3 — One pattern match ------------------------------------------
def step3():
    print("\nStep 3 — One pattern match")
    proc, info = start_lab()
    try:
        pid = info["pid"]
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as fh:
            fh.write("[MemMarkerAlpha]\ntype = string\n"
                     "pattern = MEMSEEKER_MARKER_ALPHA\n")
            rules_path = fh.name
        try:
            rules = memseeker.load_rules(rules_path)
            result = memseeker.scan_process(pid, rules, opts(rules_path))
        finally:
            os.unlink(rules_path)
        check("match: exactly one hit for the string marker",
              len(result.hits) == 1, f"hits={len(result.hits)}")
        if result.hits:
            hit = result.hits[0]
            check("match: hit address == the address the lab printed",
                  hit.address == info["markers"]["alpha"],
                  f"0x{hit.address:x} vs "
                  f"0x{info['markers']['alpha']:x}")
            regions = memseeker.parse_maps(pid)
            region = region_of(regions, hit.address)
            check("match: offset == address - region start",
                  hit.offset == hit.address - region.start)
            check("match: hit is in the anonymous heap region",
                  region.name == "[anon]", region.name)
            check("match: context bytes surround the hit",
                  len(hit.ctx_before) == 16 and len(hit.ctx_after) == 16,
                  f"{len(hit.ctx_before)}/{len(hit.ctx_after)}")
    finally:
        stop_lab(proc)


# --- Step 4 — The rule file (all three pattern types) --------------------
def step4():
    print("\nStep 4 — The rule file (string, hex, regex)")
    proc, info = start_lab()
    try:
        pid = info["pid"]
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as fh:
            fh.write("[MemMarkerAlpha]\ntype = string\n"
                     "pattern = MEMSEEKER_MARKER_ALPHA\n\n"
                     "[InjectedBytes]\ntype = hex\n"
                     "pattern = de ad be ef 00 11 22 33\n\n"
                     "[ApiKeyPattern]\ntype = regex\n"
                     "pattern = sk-[A-Za-z0-9]{20,}\n")
            rules_path = fh.name
        try:
            rules = memseeker.load_rules(rules_path)
            check("rules: three rules loaded from the file",
                  len(rules) == 3, f"rules={len(rules)}")
            check("rules: types are string, hex, regex",
                  [r.rtype for r in rules] == ["string", "hex", "regex"])
            result = memseeker.scan_process(pid, rules, opts(rules_path))
        finally:
            os.unlink(rules_path)
        by_rule = {h.rule.name: h for h in result.hits}
        check("rules: string rule fires once on its marker",
              len([h for h in result.hits
                   if h.rule.name == "MemMarkerAlpha"]) == 1)
        check("rules: hex rule fires once on its marker",
              len([h for h in result.hits
                   if h.rule.name == "InjectedBytes"]) == 1)
        check("rules: regex rule fires once on its marker",
              len([h for h in result.hits
                   if h.rule.name == "ApiKeyPattern"]) == 1)
        check("rules: string hit is at the lab's alpha address",
              by_rule.get("MemMarkerAlpha") is not None
              and by_rule["MemMarkerAlpha"].address
              == info["markers"]["alpha"])
        check("rules: hex hit is at the lab's hex address",
              by_rule.get("InjectedBytes") is not None
              and by_rule["InjectedBytes"].address
              == info["markers"]["hex"])
        check("rules: regex hit is at the lab's apikey address",
              by_rule.get("ApiKeyPattern") is not None
              and by_rule["ApiKeyPattern"].address
              == info["markers"]["apikey"])
        hit_addrs = {h.address for h in result.hits}
        check("rules: decoy markers stay silent (no hit on their "
              "addresses)",
              info["markers"]["decoy_beta"] not in hit_addrs
              and info["markers"]["decoy_short"] not in hit_addrs)
    finally:
        stop_lab(proc)


# --- Step 5 — Overlap window ---------------------------------------------
def step5():
    print("\nStep 5 — Overlap window (straddling pattern)")
    proc, info = start_lab()
    try:
        pid = info["pid"]
        regions = memseeker.parse_maps(pid)
        region = region_of(regions, info["markers"]["straddle"])
        offset = info["markers"]["straddle"] - region.start
        marker_len = len(b"MEMSEEKER_STRADDLE_MARKER")
        chunk = find_straddle_chunk_size(offset, marker_len)
        check("overlap: a straddling chunk size exists for this run",
              chunk is not None, f"offset={offset}")
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as fh:
            fh.write("[StraddleMarker]\ntype = string\n"
                     "pattern = MEMSEEKER_STRADDLE_MARKER\n")
            rules_path = fh.name
        try:
            rules = memseeker.load_rules(rules_path)
            result = memseeker.scan_process(
                pid, rules, opts(rules_path, chunk_size=chunk))
        finally:
            os.unlink(rules_path)
        check(f"overlap: straddling marker found with chunk size {chunk}",
              len(result.hits) == 1
              and result.hits[0].address == info["markers"]["straddle"],
              f"hits={len(result.hits)}")
        # And with the default chunk size it is found too.
        rules = memseeker.load_rules(RULES_LAB)
        result2 = memseeker.scan_process(pid, rules, opts())
        check("overlap: straddle marker also found with default chunks",
              any(h.address == info["markers"]["straddle"]
                  for h in result2.hits))
    finally:
        stop_lab(proc)


# --- Step 6 — CLI, ownership check and report ----------------------------
def step6():
    print("\nStep 6 — CLI, ownership check and report")
    # Another user's process: start `sleep` as nobody (we are root).
    # The su process itself is root-owned, so the shell echoes its own
    # PID first; exec then turns that same PID into sleep, owned by
    # nobody — that is the PID the tool must refuse.
    other = subprocess.Popen(
        ["su", "nobody", "-s", "/bin/sh", "-c", "echo $$; exec sleep 60"],
        stdout=subprocess.PIPE, text=True)
    try:
        nobody_pid = int(other.stdout.readline().strip())
        time.sleep(0.5)
        r = run_tool([str(nobody_pid), "--rules", RULES_LAB, "--no-color"])
        check("ownership: tool refuses another user's process",
              r.returncode == 2, f"exit={r.returncode}")
        check("ownership: refusal names the owner, no traceback",
              "Refusing" in r.stdout and "Traceback" not in r.stdout
              and "Traceback" not in r.stderr,
              (r.stdout + r.stderr)[:200])
    finally:
        other.kill()
        other.wait()
    # Nonexistent PID.
    r = run_tool(["999999", "--rules", RULES_LAB, "--no-color"])
    check("ownership: nonexistent PID is a clean error (exit 2)",
          r.returncode == 2 and "No process" in r.stdout
          and "Traceback" not in r.stdout)
    # Bad rule files: each must name the rule and exit 2.
    for label, body, needle in (
            ("bad hex", "[BadHex]\ntype = hex\npattern = zz zz\n", "BadHex"),
            ("bad regex", "[BadRe]\ntype = regex\npattern = ([a-\n",
             "BadRe"),
            ("unknown type", "[BadType]\ntype = binary\npattern = xx\n",
             "BadType"),
            ("empty pattern", "[Empty]\ntype = string\npattern =\n",
             "Empty")):
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as fh:
            fh.write(body)
            path = fh.name
        try:
            r = run_tool([str(os.getpid()), "--rules", path, "--no-color"])
        finally:
            os.unlink(path)
        check(f"rules: {label} errors cleanly and names the rule",
              r.returncode == 2 and needle in r.stdout
              and "Traceback" not in r.stdout,
              (r.stdout + r.stderr)[:160])
    # Missing rule file.
    r = run_tool([str(os.getpid()), "--rules", "/tmp/no-such-rules.txt",
                  "--no-color"])
    check("rules: missing rule file is a clean error (exit 2)",
          r.returncode == 2 and "not found" in r.stdout)
    # CLI scan of the lab from a separate process: works where the
    # user has CAP_SYS_PTRACE, refused cleanly where Yama blocks it.
    proc, info = start_lab()
    try:
        r = run_tool([str(info["pid"]), "--rules", RULES_LAB,
                      "--no-color", "-q"])
        if r.returncode == 1:
            check("cli: separate-process scan finds the lab markers "
                  "(CAP_SYS_PTRACE present)",
                  "5 hit(s)" in r.stdout, r.stdout.strip()[-120:])
        elif r.returncode == 2:
            check("cli: separate-process scan refused cleanly by Yama "
                  "(no CAP_SYS_PTRACE here)",
                  "Yama" in r.stdout and "Traceback" not in r.stdout,
                  r.stdout.strip()[-160:])
        else:
            check("cli: separate-process scan returns 1 or 2, never a "
                  "traceback", False, f"exit={r.returncode}")
    finally:
        stop_lab(proc)


# --- Step 7 — Full scan of the lab process -------------------------------
def step7():
    print("\nStep 7 — Full scan of the lab process")
    proc, info = start_lab()
    try:
        pid = info["pid"]
        rules = memseeker.load_rules(RULES_LAB)
        result = memseeker.scan_process(
            pid, rules, opts(entropy=True, strings=True))
        check("full: all five planted markers found",
              len(result.hits) == 5, f"hits={len(result.hits)}")
        by_rule = {h.rule.name: h for h in result.hits}
        for rule, key in (("MemMarkerAlpha", "alpha"),
                          ("LeakedPassword", "password"),
                          ("InjectedBytes", "hex"),
                          ("ApiKeyPattern", "apikey"),
                          ("StraddleMarker", "straddle")):
            hit = by_rule.get(rule)
            check(f"full: {rule} at the lab's {key} address",
                  hit is not None
                  and hit.address == info["markers"][key])
        regions = memseeker.parse_maps(pid)
        check("full: every hit is in the anonymous heap region",
              all(region_of(regions, h.address).name == "[anon]"
                  for h in result.hits))
        check("full: one hit per rule (no duplicates)",
              sorted(result.hits_per_rule().values()) == [1, 1, 1, 1, 1])
        check("full: bytes were actually read",
              result.bytes_read > 0, f"bytes={result.bytes_read}")
        # Report file: write it, read it back, check the contents.
        with tempfile.TemporaryDirectory() as td:
            txt = os.path.join(td, "report.txt")
            memseeker.write_report(result, rules, txt, as_json=False)
            body = open(txt).read()
            check("full: text report lists every rule name",
                  all(name in body for name in by_rule))
            check("full: text report lists every hit offset",
                  all(f"0x{h.offset:x}" in body for h in result.hits))
            check("full: text report carries the defensive lesson",
                  "Defensive lesson" in body)
            js = os.path.join(td, "report.json")
            memseeker.write_report(result, rules, js, as_json=True)
            data = json.load(open(js))
            check("full: JSON report parses and has 5 hits",
                  len(data["hits"]) == 5)
            check("full: JSON report has region + offset per hit",
                  all("region" in h and "offset" in h
                      for h in data["hits"]))
    finally:
        stop_lab(proc)


# --- Step 8 — Stretch: entropy, strings, watch ---------------------------
def step8():
    print("\nStep 8 — Stretch: entropy, strings, watch")
    proc, info = start_lab()
    try:
        pid = info["pid"]
        rules = memseeker.load_rules(RULES_LAB)
        result = memseeker.scan_process(
            pid, rules, opts(entropy=True, strings=True))
        blob_start = info["markers"]["entropy_blob"]
        blob_end = blob_start + 256 * 1024
        heap_flags = [(r, a, e) for r, a, e in result.entropy_flags
                      if blob_start <= a < blob_end]
        check("entropy: high-entropy chunks flagged inside the random "
              "blob", len(heap_flags) >= 1,
              f"flags={len(result.entropy_flags)}")
        check("entropy: flagged chunks are ~8.0 bits/byte",
              all(e > 7.9 for _r, _a, e in heap_flags))
        regions = memseeker.parse_maps(pid)
        check("entropy: flagged chunks are in the anonymous region",
              all(region_of(regions, a).name == "[anon]"
                  for _r, a, _e in heap_flags))
        pw = [h for h in result.hits if h.rule.name == "LeakedPassword"]
        check("strings: strings around the password hit include it",
              len(pw) == 1 and "hunter2" in pw[0].strings,
              str(pw[0].strings[:4]) if pw else "no hit")
        # Watch mode, in-process (the test is the lab's parent, so the
        # reads are allowed): round 1 with a rules file missing the
        # ApiKey rule, then swap the file in — round 2 must report the
        # ApiKey hit as NEW, round 3 must report nothing new.
        with tempfile.TemporaryDirectory() as td:
            rules_path = os.path.join(td, "watch_rules.txt")
            short_rules = ("[MemMarkerAlpha]\ntype = string\n"
                           "pattern = MEMSEEKER_MARKER_ALPHA\n")
            full_rules = short_rules + (
                "\n[ApiKeyPattern]\ntype = regex\n"
                "pattern = sk-[A-Za-z0-9]{20,}\n")
            open(rules_path, "w").write(short_rules)

            def swap():
                time.sleep(1.2)
                open(rules_path, "w").write(full_rules)

            threading.Thread(target=swap, daemon=True).start()
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            wopts = {"rules_path": rules_path, "chunk_size": 65536,
                     "entropy": False, "strings": False,
                     "output": "test_out.txt"}
            with redirect_stdout(buf):
                rc = memseeker.watch_process(
                    pid, memseeker.load_rules(rules_path), wopts,
                    interval=1, rounds=3)
            out = buf.getvalue()
            check("watch: watch mode ends cleanly after 3 rounds",
                  rc == 0, f"rc={rc}")
            check("watch: the ApiKey hit appears as NEW in round 2",
                  "NEW hit(s)" in out and "ApiKeyPattern" in out,
                  out[-400:])
            check("watch: round 3 reports no new hits",
                  "No new hits" in out)
    finally:
        stop_lab(proc)


# --- CLI bits: --map, --list-rules, --version, doctor --------------------
def step_cli_bits():
    print("\nCLI bits — --map, --list-rules, --version, doctor")
    r = run_tool(["--list-rules", "--rules", RULES_LAB, "--no-color"])
    check("cli: --list-rules shows all five lab rules",
          r.returncode == 0
          and all(n in r.stdout for n in
                  ("MemMarkerAlpha", "LeakedPassword", "InjectedBytes",
                   "ApiKeyPattern", "StraddleMarker")),
          r.stdout[:200])
    r = run_tool(["--version"])
    check("cli: --version prints 1.0", "1.0" in r.stdout)
    r = run_tool(["--doctor", "--no-color"])
    check("cli: doctor passes on this machine",
          r.returncode == 0 and "all good" in r.stdout,
          r.stdout.strip().splitlines()[-1] if r.stdout else "")
    proc, info = start_lab()
    try:
        r = run_tool([str(info["pid"]), "--map", "--no-color"])
        check("cli: --map lists the process regions",
              r.returncode == 0 and "[heap]" in r.stdout
              and "Regions" in r.stdout, r.stdout[:200])
    finally:
        stop_lab(proc)


def main():
    print("MemSeeker step tests")
    print("=" * 58)
    for step in (step1, step2, step3, step4, step5, step6, step7, step8,
                 step_cli_bits):
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - one step's crash
            # must not kill the whole suite; count it as failed.
            import traceback
            FAILED_G = globals()
            FAILED_G["FAILED"] += 1
            FAILURES.append(step.__name__)
            print(f"  [FAIL] {step.__name__} crashed: {exc}")
            traceback.print_exc(limit=3)
    print()
    print("=" * 58)
    print(f"PASSED: {PASSED}   FAILED: {FAILED}")
    if FAILED:
        print("Failed checks: " + ", ".join(FAILURES))
        print("ALL CHECKS FAILED" if PASSED == 0 else
              "SOME CHECKS FAILED")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
