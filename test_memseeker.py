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
            check("full: text report carries the disclaimer",
                  memseeker.DISCLAIMER in body)
            js = os.path.join(td, "report.json")
            memseeker.write_report(result, rules, js, as_json=True)
            data = json.load(open(js))
            check("full: JSON report carries the disclaimer field",
                  data.get("disclaimer") == memseeker.DISCLAIMER)
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


# --- Step 9 — v1.1: multi-PID, image, dump, groups -----------------------
def step9():
    print("\nStep 9 — v1.1: multi-PID, image, dump, groups")
    proc1, info1 = start_lab()
    proc2, info2 = start_lab()
    try:
        rules = memseeker.load_rules(RULES_LAB)
        # --all: scan every process we own; both labs must appear with
        # exactly their 5 lab hits, all in the anonymous heap region.
        results, skipped = memseeker.scan_all(rules, opts())
        by_pid = {r.pid: r for r in results}
        check("all: both lab processes appear in the --all results",
              info1["pid"] in by_pid and info2["pid"] in by_pid,
              f"pids={sorted(by_pid)[:8]}")
        for label, info in (("lab 1", info1), ("lab 2", info2)):
            res = by_pid.get(info["pid"])
            check(f"all: {label} has all five lab hits",
                  res is not None and len(res.hits) == 5,
                  f"hits={len(res.hits) if res else None}")
            if res is not None:
                regions = memseeker.parse_maps(info["pid"])
                check(f"all: {label} hits are in the anonymous heap",
                      all(region_of(regions, h.address).name == "[anon]"
                          for h in res.hits))
        check("all: unreadable processes are skipped, not fatal",
              len(skipped) >= 1,
              f"skipped={len(skipped)}")
        # --pids: exactly the two labs.
        results2, skipped2 = memseeker.scan_pids(
            [info1["pid"], info2["pid"]], rules, opts())
        check("pids: scan_pids returns one result per PID",
              len(results2) == 2 and len(skipped2) == 0,
              f"results={len(results2)} skipped={len(skipped2)}")
        check("pids: both results have five hits each",
              all(len(r.hits) == 5 for r in results2))
        # Multi report: one file, grouped per process.
        with tempfile.TemporaryDirectory() as td:
            txt = os.path.join(td, "multi.txt")
            memseeker.write_multi_report(results2, skipped2, rules, txt,
                                         as_json=False)
            body = open(txt).read()
            check("multi: text report lists both PIDs",
                  str(info1["pid"]) in body
                  and str(info2["pid"]) in body)
            check("multi: text report lists every hit offset",
                  all(f"0x{h.offset:x}" in body
                      for r in results2 for h in r.hits))
            js = os.path.join(td, "multi.json")
            memseeker.write_multi_report(results2, skipped2, rules, js,
                                         as_json=True)
            data = json.load(open(js))
            check("multi: JSON report has one entry per process",
                  len(data["processes"]) == 2
                  and sorted(p["pid"] for p in data["processes"])
                  == sorted([info1["pid"], info2["pid"]]))
        # CLI --pids: from a separate process the labs are refused by
        # Yama here (no CAP_SYS_PTRACE) — or scanned where the reader
        # holds the capability. Accept either, never a traceback.
        r = run_tool(["--pids", f"{info1['pid']},{info2['pid']}",
                      "--rules", RULES_LAB, "--no-color", "-q"])
        if r.returncode == 1:
            check("pids: CLI --pids finds hits in both labs "
                  "(CAP_SYS_PTRACE present)",
                  "2 process(es)" in r.stdout and "10 hit(s)" in r.stdout,
                  r.stdout.strip()[-200:])
        elif r.returncode == 2:
            check("pids: CLI --pids refused cleanly by Yama "
                  "(no CAP_SYS_PTRACE here)",
                  "No process could be scanned" in r.stdout
                  and "Traceback" not in r.stdout,
                  r.stdout.strip()[-200:])
        else:
            check("pids: CLI --pids returns 1 or 2, never a traceback",
                  False, f"exit={r.returncode}")
        # --image: dump lab 1's heap region to a file, then scan the
        # file and find the same markers at the same offsets.
        regions = memseeker.parse_maps(info1["pid"])
        heap = region_of(regions, info1["markers"]["alpha"])
        check("image: alpha marker lives in a region", heap is not None)
        with tempfile.TemporaryDirectory() as td:
            dump_path = os.path.join(td, "heap.bin")
            backend = memseeker.get_backend()
            reader = backend.open_memory(info1["pid"])
            try:
                written = memseeker.dump_region(reader, heap, dump_path)
            finally:
                reader.close()
            check("image: the heap region dumps to a file",
                  written == heap.size
                  and os.path.getsize(dump_path) == heap.size,
                  f"written={written} size={heap.size}")
            expected_keys = [k for k in ("alpha", "password", "hex",
                                         "apikey", "straddle")
                             if heap.start <= info1["markers"][k] < heap.end]
            img_rules = memseeker.load_rules(RULES_LAB)
            img = memseeker.scan_image(dump_path, img_rules, opts())
            check("image: the dump scan finds the region's markers",
                  len(img.hits) == len(expected_keys),
                  f"hits={len(img.hits)} expected={expected_keys}")
            for key, rule in (("alpha", "MemMarkerAlpha"),
                              ("password", "LeakedPassword"),
                              ("hex", "InjectedBytes"),
                              ("apikey", "ApiKeyPattern"),
                              ("straddle", "StraddleMarker")):
                if key not in expected_keys:
                    continue
                hit = next((h for h in img.hits
                            if h.rule.name == rule), None)
                check(f"image: {rule} at the same offset as the live scan",
                      hit is not None
                      and hit.offset == info1["markers"][key] - heap.start,
                      f"offset={hit.offset if hit else None}")
            img2 = memseeker.scan_image(dump_path, img_rules, opts(),
                                        base=0x100000)
            check("image: --base shifts every hit address by the base",
                  all(h.address == h.offset + 0x100000 for h in img2.hits)
                  and len(img2.hits) == len(img.hits))
            r = run_tool(["--image", dump_path, "--rules", RULES_LAB,
                          "--no-color", "-q"])
            check("image: CLI --image finds the markers (exit 1)",
                  r.returncode == 1 and "hit(s)" in r.stdout,
                  f"exit={r.returncode} out={r.stdout.strip()[-160:]}")
            # --dump: scan lab 1 with a dump dir; exactly the hit
            # regions are dumped, and the report names the files.
            dump_dir = os.path.join(td, "dumps")
            dopts = opts()
            dopts["dump"] = dump_dir
            dres = memseeker.scan_process(info1["pid"], rules, dopts)
            files = sorted(os.listdir(dump_dir))
            check("dump: exactly the hit regions are dumped (one file)",
                  len(files) == 1, f"files={files}")
            check("dump: the file name carries PID, range and region",
                  bool(files) and files[0].startswith(f"{info1['pid']}_")
                  and files[0].endswith(".bin"),
                  str(files))
            dumped = os.path.join(dump_dir, files[0]) if files else ""
            check("dump: the dumped file holds the region bytes",
                  bool(dumped)
                  and os.path.getsize(dumped) == heap.size
                  and b"MEMSEEKER_MARKER_ALPHA" in open(dumped, "rb").read(),
                  f"size={os.path.getsize(dumped) if dumped else 0}")
            check("dump: every hit names its dump file",
                  bool(dres.hits)
                  and all(h.dump_file == dumped for h in dres.hits))
            js = os.path.join(td, "r.json")
            memseeker.write_report(dres, rules, js, as_json=True)
            data = json.load(open(js))
            check("dump: the JSON report names the dump file",
                  all(h.get("dump_file") == dumped
                      for h in data["hits"]))
            # CLI --dump with --image: works from any process.
            dd = os.path.join(td, "dumps2")
            r = run_tool(["--image", dump_path, "--rules", RULES_LAB,
                          "--dump", dd, "--no-color", "-q"])
            check("dump: CLI --image --dump writes the region file",
                  r.returncode == 1 and os.path.isdir(dd)
                  and len(os.listdir(dd)) == 1,
                  f"exit={r.returncode} files="
                  f"{os.listdir(dd) if os.path.isdir(dd) else 'no dir'}")
        # Groups: rule files with member rules + a group.
        def write_rules(body):
            fh = tempfile.NamedTemporaryFile("w", suffix=".txt",
                                             delete=False)
            fh.write(body)
            fh.close()
            return fh.name

        alpha_rule = ("[MemMarkerAlpha]\ntype = string\n"
                      "pattern = MEMSEEKER_MARKER_ALPHA\n")
        pw_rule = ("[LeakedPassword]\ntype = string\n"
                   "pattern = hunter2\n")
        key_rule = ("[ApiKeyPattern]\ntype = regex\n"
                    "pattern = sk-[A-Za-z0-9]{20,}\n")
        miss_rule = ("[NoSuchOne]\ntype = string\n"
                     "pattern = NO_SUCH_MARKER_ONE_XYZ\n")
        miss2_rule = ("[NoSuchTwo]\ntype = string\n"
                      "pattern = NO_SUCH_MARKER_TWO_XYZ\n")
        # 2 of (A, B, C) — all three fire in the lab.
        path = write_rules(alpha_rule + pw_rule + key_rule +
                           "\n[Group:Pair]\ncondition = 2 of "
                           "(MemMarkerAlpha, LeakedPassword, "
                           "ApiKeyPattern)\n")
        try:
            grules = memseeker.load_rules(path)
            groups = memseeker.load_groups(path, grules)
            check("groups: one group loaded from the file",
                  len(groups) == 1 and groups[0].name == "Pair")
            gopts = opts(path)
            gopts["groups"] = groups
            gres = memseeker.scan_process(info1["pid"], grules, gopts)
            g_hits = [h for h in gres.hits if h.rule.rtype == "group"]
            check("groups: '2 of' fires once when all three members fire",
                  len(g_hits) == 1 and g_hits[0].rule.name == "Pair",
                  f"group hits={len(g_hits)}")
            check("groups: the group hit is in the anonymous heap",
                  bool(g_hits) and region_of(
                      memseeker.parse_maps(info1["pid"]),
                      g_hits[0].address).name == "[anon]")
        finally:
            os.unlink(path)
        # 2 of (A, B, C) — only A fires.
        path = write_rules(alpha_rule + miss_rule + miss2_rule +
                           "\n[Group:Pair]\ncondition = 2 of "
                           "(MemMarkerAlpha, NoSuchOne, NoSuchTwo)\n")
        try:
            grules = memseeker.load_rules(path)
            groups = memseeker.load_groups(path, grules)
            gopts = opts(path)
            gopts["groups"] = groups
            gres = memseeker.scan_process(info1["pid"], grules, gopts)
            check("groups: '2 of' stays silent when only one member fires",
                  not any(h.rule.rtype == "group" for h in gres.hits)
                  and len(gres.hits) == 1)
        finally:
            os.unlink(path)
        # all of + any of — all members fire.
        path = write_rules(alpha_rule + pw_rule + key_rule +
                           "\n[Group:AllThree]\ncondition = all of "
                           "(MemMarkerAlpha, LeakedPassword, "
                           "ApiKeyPattern)\n"
                           "\n[Group:AnyOne]\ncondition = any of "
                           "(MemMarkerAlpha, LeakedPassword, "
                           "ApiKeyPattern)\n")
        try:
            grules = memseeker.load_rules(path)
            groups = memseeker.load_groups(path, grules)
            check("groups: two groups loaded (all of + any of)",
                  len(groups) == 2)
            gopts = opts(path)
            gopts["groups"] = groups
            gres = memseeker.scan_process(info1["pid"], grules, gopts)
            names = sorted(h.rule.name for h in gres.hits
                           if h.rule.rtype == "group")
            check("groups: 'all of' and 'any of' both fire when all "
                  "members fire", names == ["AllThree", "AnyOne"],
                  f"groups={names}")
        finally:
            os.unlink(path)
        # all of stays silent, any of fires, when one member is missing.
        path = write_rules(alpha_rule + miss_rule +
                           "\n[Group:AllTwo]\ncondition = all of "
                           "(MemMarkerAlpha, NoSuchOne)\n"
                           "\n[Group:AnyTwo]\ncondition = any of "
                           "(MemMarkerAlpha, NoSuchOne)\n")
        try:
            grules = memseeker.load_rules(path)
            groups = memseeker.load_groups(path, grules)
            gopts = opts(path)
            gopts["groups"] = groups
            gres = memseeker.scan_process(info1["pid"], grules, gopts)
            names = sorted(h.rule.name for h in gres.hits
                           if h.rule.rtype == "group")
            check("groups: 'all of' stays silent, 'any of' fires, when "
                  "one member is missing", names == ["AnyTwo"],
                  f"groups={names}")
        finally:
            os.unlink(path)
        # Bad groups are clean errors that name the group.
        for label, body, needle in (
                ("unknown member",
                 alpha_rule + "\n[Group:Bad]\ncondition = 2 of "
                 "(MemMarkerAlpha, GhostRule)\n", "Bad"),
                ("impossible count",
                 alpha_rule + pw_rule + "\n[Group:Bad]\ncondition = 5 of "
                 "(MemMarkerAlpha, LeakedPassword)\n", "Bad"),
                ("bad syntax",
                 alpha_rule + "\n[Group:Bad]\ncondition = two of them\n",
                 "Bad")):
            path = write_rules(body)
            try:
                r = run_tool([str(os.getpid()), "--rules", path,
                              "--no-color"])
            finally:
                os.unlink(path)
            check(f"groups: {label} errors cleanly and names the group",
                  r.returncode == 2 and needle in r.stdout
                  and "Traceback" not in r.stdout,
                  (r.stdout + r.stderr)[:160])
        # --list-rules lists the groups too.
        r = run_tool(["--list-rules", "--rules",
                      os.path.join(HERE, "rules_groups.txt"), "--no-color"])
        check("groups: --list-rules shows the group names and conditions",
              r.returncode == 0 and "SecretPair" in r.stdout
              and "2 of" in r.stdout and "AllSecrets" in r.stdout,
              r.stdout[:200])
    finally:
        stop_lab(proc1)
        stop_lab(proc2)


# --- Step 10 — v1.1 cross-platform backends (mocked) ----------------------
def step10():
    print("\nStep 10 — Cross-platform backends (mocked Windows/macOS)")
    from unittest import mock

    # --- Windows: fake kernel32 -----------------------------------------
    alpha = b"".join([b"MEMSEEKER_", b"MARKER_", b"ALPHA"])
    straddle = b"".join([b"MEMSEEKER_", b"STRADDLE_", b"MARKER"])
    mem_base = 0x10000
    mem = bytearray(b"\x00" * 0x2000)
    mem[0x100:0x100 + len(alpha)] = alpha
    # Straddle marker: starts 2 bytes before the 64-byte boundary at
    # offset 0x140, so it crosses into the next chunk.
    mem[0x13e:0x13e + len(straddle)] = straddle
    mem2_base = 0x20000
    mem2 = b"kernel32.dll bytes here" + b"\x00" * (0x1000 - 24)
    fake_mem = {mem_base: bytes(mem), mem2_base: mem2}
    regions_win = [
        (mem_base, 0x2000, memseeker.MEM_COMMIT,
         memseeker.PAGE_READWRITE),
        (mem2_base, 0x1000, memseeker.MEM_COMMIT,
         memseeker.PAGE_READONLY),
        (0x30000, 0x1000, memseeker.MEM_COMMIT,
         memseeker.PAGE_NOACCESS),
        (0x40000, 0x1000, memseeker.MEM_COMMIT,
         memseeker.PAGE_EXECUTE_READWRITE | memseeker.PAGE_GUARD),
    ]

    def fake_vq(handle, address):
        for base, size, state, prot in regions_win:
            if base + size > address:
                return (base, size, state, prot)
        return None

    def fake_read(handle, address, size):
        for base, blob in fake_mem.items():
            if base <= address < base + len(blob):
                off = address - base
                return blob[off:off + size]
        raise OSError(f"ReadProcessMemory failed at 0x{address:x}")

    def fake_mapped(handle, address):
        return ("C:\\Windows\\System32\\kernel32.dll"
                if address == mem2_base else "")

    with mock.patch.object(memseeker, "_win_open_process",
                           return_value=1234), \
         mock.patch.object(memseeker, "_win_virtual_query_ex",
                           side_effect=fake_vq), \
         mock.patch.object(memseeker, "_win_read_process_memory",
                           side_effect=fake_read), \
         mock.patch.object(memseeker, "_win_get_mapped_file_name",
                           side_effect=fake_mapped), \
         mock.patch.object(memseeker, "_win_close_handle"), \
         mock.patch.object(memseeker, "_win_get_process_name",
                           return_value="notepad.exe"):
        backend = memseeker.WindowsBackend()
        regions = backend.list_regions(4242)
        check("win: mocked VirtualQueryEx lists the readable regions",
              len(regions) == 2
              and regions[0].start == mem_base
              and regions[1].start == mem2_base,
              f"regions={[(hex(r.start), r.perms) for r in regions]}")
        check("win: NOACCESS and GUARD regions are skipped",
              all(r.start not in (0x30000, 0x40000) for r in regions))
        check("win: mapped file name becomes the region name",
              "kernel32.dll" in regions[1].name,
              regions[1].name)
        check("win: process name comes from the image name",
              backend.process_name(4242) == "notepad.exe")
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as fh:
            fh.write("[MemMarkerAlpha]\ntype = string\n"
                     "pattern = MEMSEEKER_MARKER_ALPHA\n\n"
                     "[StraddleMarker]\ntype = string\n"
                     "pattern = MEMSEEKER_STRADDLE_MARKER\n")
            rules_path = fh.name
        try:
            rules = memseeker.load_rules(rules_path)
            result = memseeker.scan_process(
                4242, rules, opts(rules_path, chunk_size=64),
                backend=backend)
        finally:
            os.unlink(rules_path)
        check("win: mocked scan finds the alpha marker",
              len([h for h in result.hits
                   if h.rule.name == "MemMarkerAlpha"]) == 1)
        check("win: mocked scan finds the boundary-straddling marker",
              len([h for h in result.hits
                   if h.rule.name == "StraddleMarker"]) == 1)
        alpha_hits = [h for h in result.hits
                      if h.rule.name == "MemMarkerAlpha"]
        check("win: mocked hit address is the marker's address",
              bool(alpha_hits)
              and alpha_hits[0].address == mem_base + 0x100,
              f"0x{alpha_hits[0].address:x}" if alpha_hits else "no hit")
    # Access denied on Windows.
    with mock.patch.object(memseeker, "_win_open_process",
                           return_value=None), \
         mock.patch.object(memseeker, "_win_last_error",
                           return_value=5):
        backend = memseeker.WindowsBackend()
        try:
            backend.check_ownership(4242)
            denied = False
        except memseeker.MemSeekerError as exc:
            denied = "access denied" in str(exc).lower()
        check("win: access denied is a clean refusal, not a traceback",
              denied)

    # --- macOS: fake mach APIs -------------------------------------------
    mac_base = 0x100000000
    mac_mem = bytearray(b"\x00" * 0x6000)
    mac_mem[0x200:0x200 + len(alpha)] = alpha
    mac_regions = [
        (mac_base, 0x4000,
         memseeker.VM_PROT_READ | memseeker.VM_PROT_WRITE, 0),
        (mac_base + 0x4000, 0x2000, memseeker.VM_PROT_READ, 2),
        (mac_base + 0x6000, 0x1000, 0, 0),
    ]

    def fake_vm_region(task, address):
        for base, size, prot, share in mac_regions:
            if base + size > address:
                return (base, size, prot, share)
        return None

    def fake_vm_read(task, address, size):
        if mac_base <= address < mac_base + len(mac_mem):
            off = address - mac_base
            return bytes(mac_mem[off:off + size])
        raise OSError(f"vm_read failed at 0x{address:x}")

    with mock.patch.object(memseeker, "_mac_task_for_pid",
                           return_value=999), \
         mock.patch.object(memseeker, "_mac_vm_region_64",
                           side_effect=fake_vm_region), \
         mock.patch.object(memseeker, "_mac_vm_read",
                           side_effect=fake_vm_read), \
         mock.patch.object(memseeker, "_mac_process_uid",
                           return_value=os.getuid()), \
         mock.patch.object(memseeker, "_mac_process_name",
                           return_value="python3"):
        backend = memseeker.MacOSBackend()
        regions = backend.list_regions(4242)
        check("mac: mocked vm_region_64 lists the readable regions",
              len(regions) == 2 and regions[0].start == mac_base,
              f"regions={[(hex(r.start), r.perms) for r in regions]}")
        check("mac: a region without read permission is skipped",
              all(r.start != mac_base + 0x6000 for r in regions))
        check("mac: permissions map to the rwxp string",
              regions[0].perms == "rw-p" and regions[1].perms == "r--s",
              f"{regions[0].perms}/{regions[1].perms}")
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as fh:
            fh.write("[MemMarkerAlpha]\ntype = string\n"
                     "pattern = MEMSEEKER_MARKER_ALPHA\n")
            rules_path = fh.name
        try:
            rules = memseeker.load_rules(rules_path)
            result = memseeker.scan_process(
                4242, rules, opts(rules_path), backend=backend)
        finally:
            os.unlink(rules_path)
        alpha_hits = [h for h in result.hits
                      if h.rule.name == "MemMarkerAlpha"]
        check("mac: mocked scan finds the alpha marker",
              len(alpha_hits) == 1)
        check("mac: mocked hit address is the marker's address",
              bool(alpha_hits)
              and alpha_hits[0].address == mac_base + 0x200,
              f"0x{alpha_hits[0].address:x}" if alpha_hits else "no hit")
    # task_for_pid denied on macOS.
    with mock.patch.object(
            memseeker, "_mac_task_for_pid",
            side_effect=memseeker.MemSeekerError(
                "Cannot get a task port for PID 4242 (task_for_pid "
                "failed, kern_return 5). On macOS, reading another "
                "process needs root or the debugger entitlement.")):
        backend = memseeker.MacOSBackend()
        try:
            backend.list_regions(4242)
            denied = False
        except memseeker.MemSeekerError as exc:
            denied = "task_for_pid" in str(exc)
        check("mac: task_for_pid refusal is clean and names the privilege",
              denied)

    # --- ImageFile + backend selection ------------------------------------
    with tempfile.NamedTemporaryFile("wb", suffix=".bin",
                                     delete=False) as fh:
        fh.write(b"\x00" * 0x100 + alpha + b"\x00" * 0x100)
        img_path = fh.name
    try:
        with open(img_path, "rb", buffering=0) as raw:
            reader = memseeker.ImageFile(raw, base=0x1000)
            reader.seek(0x1100)
            check("image: ImageFile reads at base + offset",
                  reader.read(len(alpha)) == alpha)
            try:
                reader.seek(0x0fff)
                reader.read(4)
                below_base_ok = False
            except OSError:
                below_base_ok = True
            check("image: an address below the base is refused",
                  below_base_ok)
    finally:
        os.unlink(img_path)
    check("backends: get_backend() is the Linux backend on this VM",
          isinstance(memseeker.get_backend(), memseeker.LinuxBackend))
    check("backends: named backends construct on any platform",
          isinstance(memseeker.get_backend("windows"),
                     memseeker.WindowsBackend)
          and isinstance(memseeker.get_backend("macos"),
                         memseeker.MacOSBackend)
          and isinstance(memseeker.get_backend("linux"),
                         memseeker.LinuxBackend))


# --- Step 11 — v1.3: long regex overlap, modifiers, entropy threshold,
# map-change detection, watch groups, backend --map ----------------------
def step11():
    print("\nStep 11 — v1.3: regex overlap, modifiers, entropy, map change, watch groups")
    from unittest import mock
    import io
    from contextlib import redirect_stdout
    from types import SimpleNamespace

    def write_rules(body):
        fh = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        fh.write(body)
        fh.close()
        return fh.name

    # --- Long regex matches straddling a chunk boundary ------------------
    # A 2000-byte match straddling the 4096 boundary (far past the old
    # 512-byte bound) and a 1500-byte match inside one chunk.
    blob = bytearray(b"\x00" * 12288)
    blob[3500:5500] = b"B" * 2000
    blob[6500:8000] = b"B" * 1500
    with tempfile.TemporaryDirectory() as td:
        img_path = os.path.join(td, "long.bin")
        open(img_path, "wb").write(bytes(blob))
        path = write_rules("[LongRun]\ntype = regex\n"
                           "pattern = B{1500,}\n")
        try:
            rules = memseeker.load_rules(path)
            check("regex: a regex rule keeps 8191 bytes of overlap "
                  "(default chunk)",
                  memseeker.overlap_size(rules) == 8191,
                  f"overlap={memseeker.overlap_size(rules)}")
            check("regex: the overlap is capped by the chunk size",
                  memseeker.overlap_size(rules, chunk_size=64) == 63)
            res = memseeker.scan_image(img_path, rules,
                                       opts(path, chunk_size=4096))
            addrs = sorted(h.address for h in res.hits)
            check("regex: a 2000-byte match straddling a chunk boundary "
                  "is found (past the old 512 bound)",
                  3500 in addrs, f"addrs={addrs}")
            check("regex: a 1500-byte match inside one chunk is found",
                  6500 in addrs, f"addrs={addrs}")
            check("regex: each long match is found exactly once",
                  len(res.hits) == 2, f"hits={len(res.hits)}")
            lens = sorted(len(h.match) for h in res.hits)
            check("regex: the reported matches are 2000 and 1500 bytes",
                  lens == [1500, 2000], f"lens={lens}")
        finally:
            os.unlink(path)

    # --- String modifiers: nocase + wide --------------------------------
    data = bytearray(b"\x00" * 4096)
    data[100:107] = b"HuNtEr2"                       # mixed case
    data[500:514] = "hunter2".encode("utf-16-le")    # wide
    data[1000:1007] = b"hunter2"                     # plain
    with tempfile.TemporaryDirectory() as td:
        img_path = os.path.join(td, "mods.bin")
        open(img_path, "wb").write(bytes(data))
        path = write_rules(
            "[NocasePw]\ntype = string\npattern = hunter2\n"
            "nocase = true\n\n"
            "[WidePw]\ntype = string\npattern = hunter2\nwide = true\n\n"
            "[PlainPw]\ntype = string\npattern = hunter2\n")
        try:
            rules = memseeker.load_rules(path)
            res = memseeker.scan_image(img_path, rules, opts(path))
            by_rule = {}
            for h in res.hits:
                by_rule.setdefault(h.rule.name, []).append(h)
            check("mods: nocase matches the mixed-case and plain forms",
                  sorted(h.address for h in by_rule.get("NocasePw", []))
                  == [100, 1000],
                  f"{[h.address for h in by_rule.get('NocasePw', [])]}")
            check("mods: the nocase hit keeps its original case",
                  any(h.match == b"HuNtEr2"
                      for h in by_rule.get("NocasePw", [])))
            check("mods: wide matches the UTF-16LE encoding",
                  [h.address for h in by_rule.get("WidePw", [])] == [500])
            check("mods: wide match bytes are the UTF-16LE encoding",
                  bool(by_rule.get("WidePw"))
                  and by_rule["WidePw"][0].match
                  == "hunter2".encode("utf-16-le"))
            check("mods: a plain rule matches neither mixed-case nor wide",
                  [h.address for h in by_rule.get("PlainPw", [])] == [1000])
            # --list-rules shows the modifiers.
            r = run_tool(["--list-rules", "--rules", path, "--no-color"])
            check("mods: --list-rules shows nocase and wide",
                  r.returncode == 0 and "nocase" in r.stdout
                  and "wide" in r.stdout, r.stdout[:200])
        finally:
            os.unlink(path)
        # Bad modifiers are clean errors that name the rule.
        for label, body, needle in (
                ("nocase on a hex rule",
                 "[BadHex]\ntype = hex\npattern = de ad\nnocase = true\n",
                 "BadHex"),
                ("bad nocase value",
                 "[BadBool]\ntype = string\npattern = hunter2\n"
                 "nocase = maybe\n", "BadBool")):
            path = write_rules(body)
            try:
                try:
                    memseeker.load_rules(path)
                    raised = False
                except memseeker.MemSeekerError as exc:
                    raised = needle in str(exc)
                check(f"mods: {label} errors cleanly and names the rule",
                      raised)
            finally:
                os.unlink(path)

    # --- Tunable entropy threshold ---------------------------------------
    # One 64 KiB chunk of random bytes (~8.0 bits/byte) + one of plain
    # text (~4 bits/byte): deterministic, no live process needed.
    img = os.urandom(65536) + (b"hello world this is plain text "
                               * 2200)[:65536]
    with tempfile.TemporaryDirectory() as td:
        img_path = os.path.join(td, "ent.bin")
        open(img_path, "wb").write(img)
        rules = memseeker.load_rules(RULES_LAB)
        dopts = opts(chunk_size=65536, entropy=True)
        res = memseeker.scan_image(img_path, rules, dopts)
        check("entropy: default threshold 7.5 flags the random chunk",
              len(res.entropy_flags) == 1
              and res.entropy_flags[0][2] > 7.9,
              f"flags={res.entropy_flags}")
        check("entropy: the report names the 7.5 threshold",
              ">= 7.5" in memseeker.build_text_report(res, rules))
        dopts8 = opts(chunk_size=65536, entropy=True)
        dopts8["entropy_threshold"] = 8.0
        res8 = memseeker.scan_image(img_path, rules, dopts8)
        check("entropy: threshold 8.0 flags nothing (random data is "
              "below 8.0 bits/byte)",
              len(res8.entropy_flags) == 0)
        check("entropy: the result and report carry the 8.0 threshold",
              res8.entropy_threshold == 8.0
              and "Entropy threshold: 8.0" in
              memseeker.build_text_report(res8, rules))
        check("entropy: the JSON report carries the threshold",
              json.loads(memseeker.build_json_report(res8, rules))
              .get("entropy_threshold_bits_per_byte") == 8.0)
        # CLI: a threshold outside 0-8 is a clean error; a valid one
        # reaches the report.
        r = run_tool(["--image", img_path, "--rules", RULES_LAB,
                      "--entropy", "--entropy-threshold", "9",
                      "--no-color", "-q"])
        check("entropy: CLI threshold 9 is a clean error (exit 2)",
              r.returncode == 2 and "entropy-threshold" in r.stdout
              and "Traceback" not in r.stdout,
              r.stdout.strip()[-160:])
        rep = os.path.join(td, "ent.txt")
        r = run_tool(["--image", img_path, "--rules", RULES_LAB,
                      "--entropy", "--entropy-threshold", "8.0",
                      "-o", rep, "--no-color", "-q"])
        check("entropy: CLI --entropy-threshold 8.0 writes the "
              "threshold into the report",
              r.returncode == 0 and os.path.isfile(rep)
              and "Entropy threshold: 8.0" in open(rep).read(),
              f"exit={r.returncode}")

    # --- Map-change detection (mocked re-read) ---------------------------
    proc, info = start_lab()
    try:
        pid = info["pid"]
        rules = memseeker.load_rules(RULES_LAB)
        regions = memseeker.parse_maps(pid)
        # The re-read returns a map with the last region grown: the
        # scan must notice and say so in the report.
        grown = list(regions)
        last = grown[-1]
        grown[-1] = memseeker.Region(last.start, last.end + 0x1000,
                                     last.perms, last.offset, last.dev,
                                     last.inode, last.pathname)
        with mock.patch.object(memseeker.LinuxBackend, "list_regions",
                               side_effect=[regions, grown]):
            res = memseeker.scan_process(pid, rules, opts(),
                                         backend=memseeker.LinuxBackend())
        check("mapchange: a changed map is detected after the scan",
              res.map_changed is True)
        check("mapchange: the text report says the map changed",
              "Map changed during scan: yes" in
              memseeker.build_text_report(res, rules))
        check("mapchange: the JSON report carries map_changed=true",
              json.loads(memseeker.build_json_report(res, rules))
              .get("map_changed") is True)
        # The re-read fails (process exited): same flag, no crash.
        with mock.patch.object(memseeker.LinuxBackend, "list_regions",
                               side_effect=[regions,
                                            memseeker.MemSeekerError(
                                                "No process with PID "
                                                f"{pid}.")]):
            res2 = memseeker.scan_process(pid, rules, opts(),
                                          backend=memseeker.LinuxBackend())
        check("mapchange: a map that cannot be re-read is reported, "
              "not a crash",
              res2.map_changed is True
              and "could not be re-read" in res2.map_note)
        # Unchanged map: no flag.
        res3 = memseeker.scan_process(pid, rules, opts())
        check("mapchange: an unchanged map is not flagged",
              res3.map_changed is False
              and json.loads(memseeker.build_json_report(res3, rules))
              .get("map_changed") is False)
    finally:
        stop_lab(proc)

    # --- Watch mode honours rule groups ----------------------------------
    proc, info = start_lab()
    try:
        pid = info["pid"]
        path = write_rules(
            "[MemMarkerAlpha]\ntype = string\n"
            "pattern = MEMSEEKER_MARKER_ALPHA\n\n"
            "[LeakedPassword]\ntype = string\npattern = hunter2\n\n"
            "[ApiKeyPattern]\ntype = regex\n"
            "pattern = sk-[A-Za-z0-9]{20,}\n\n"
            "[Group:Pair]\ncondition = 2 of (MemMarkerAlpha, "
            "LeakedPassword, ApiKeyPattern)\n")
        try:
            wopts = {"rules_path": path, "chunk_size": 65536,
                     "entropy": False, "strings": False,
                     "output": "test_out.txt"}
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = memseeker.watch_process(
                    pid, memseeker.load_rules(path), wopts,
                    interval=1, rounds=1)
            out = buf.getvalue()
            check("watch: watch mode ends cleanly after 1 round",
                  rc == 0, f"rc={rc}")
            check("watch: the group fires inside watch mode (groups "
                  "are no longer ignored)",
                  "Pair" in out, out[-400:])
        finally:
            os.unlink(path)
    finally:
        stop_lab(proc)

    # --- --map through the platform backend (mocked Windows) -------------
    fake_backend = mock.Mock()
    fake_backend.check_ownership.return_value = 4242
    fake_backend.list_regions.return_value = [
        memseeker.Region(0x10000, 0x11000, "r--p", 0, "0:0", 0,
                         "C:\\test.exe"),
        memseeker.Region(0x20000, 0x21000, "rw-p", 0, "0:0", 0, ""),
    ]
    fake_backend.process_name.return_value = "notepad.exe"
    with mock.patch.object(memseeker, "get_backend",
                           return_value=fake_backend):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = memseeker.do_map(SimpleNamespace(pid=[]), pid=4242)
        out = buf.getvalue()
        check("map: --map works through the platform backend "
              "(Windows regions listed)",
              rc == 0 and "notepad.exe" in out
              and "000000010000" in out and "test.exe" in out,
              out[:200])
        check("map: the backend's ownership check was used",
              fake_backend.check_ownership.called
              and fake_backend.list_regions.called)
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
    check("cli: --version prints 1.3", "1.3" in r.stdout)
    r = run_tool(["--doctor", "--no-color"])
    check("cli: banner shows the authorized-use disclaimer",
          "DISCLAIMER" in r.stdout
          and "on your own responsibility" in r.stdout, r.stdout[:200])
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
                 step_cli_bits, step9, step10, step11):
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
