#!/usr/bin/env python3
"""MemSeeker launcher — setup, lab, scan, test, doctor, menu.

Usage:
    python run.py setup        # create venv (first time only)
    python run.py lab          # start the lab process (prints its PID)
    python run.py scan <pid> --rules rules_lab.txt   # scan a process
    python run.py scanall      # scan every process you own
    python run.py image <file> --rules rules_lab.txt # scan a dump file
    python run.py labscan      # start the lab AND scan it (one step)
    python run.py test         # run the 10 build-plan step tests
    python run.py doctor       # check the setup
    python run.py menu         # open the numbered menu

Cross-platform (v1.1): Linux (/proc), Windows (kernel32 via ctypes)
and macOS (task_for_pid + vm_read via ctypes). The lab process and
the --lab / labscan commands need Linux, where the lab runs; the
--image mode works on every OS. Plain `python3 memseeker.py` also
works (standard library only).
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def venv_python():
    """Path of the venv Python for this OS, or None if no venv yet."""
    if os.name == "nt":
        cand = os.path.join(HERE, "venv", "Scripts", "python.exe")
    else:
        cand = os.path.join(HERE, "venv", "bin", "python")
    return cand if os.path.isfile(cand) else None


def run(cmd, **kw):
    return subprocess.run(cmd, **kw)


def ensure_venv():
    """Create the venv if needed. Returns the Python to use.
    MemSeeker uses only the standard library, so there is nothing to
    install — the venv just keeps the setup identical to the other
    tools."""
    vp = venv_python()
    if vp is None:
        print("[*] Creating virtual environment (first time only)...")
        rc = run([sys.executable, "-m", "venv", os.path.join(HERE, "venv")]).returncode
        if rc != 0:
            print("[!] Could not create a venv. Using system Python.")
            return sys.executable
        vp = venv_python()
    print("[*] MemSeeker needs no packages (standard library only).")
    return vp


def cmd_setup(_args):
    vp = ensure_venv()
    print("[+] Setup done. Python: %s" % vp)
    print("    Test it: python run.py labscan")
    return 0


def cmd_lab(_args):
    vp = venv_python() or sys.executable
    print("[*] Lab process starting — note its PID, then scan it with:")
    print("    python run.py scan <pid> --rules rules_lab.txt")
    print("    (or press Ctrl+C to stop the lab)")
    return run([vp, os.path.join(HERE, "lab_proc.py")]).returncode


def cmd_scan(args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "memseeker.py")] + args).returncode


def cmd_scanall(args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "memseeker.py"), "--all"]
               + args).returncode


def cmd_image(args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "memseeker.py"), "--image"]
               + args).returncode


def cmd_labscan(args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "memseeker.py"), "--lab"]
               + args).returncode


def cmd_test(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "test_memseeker.py")]).returncode


def cmd_doctor(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "memseeker.py"), "--doctor"]).returncode


def cmd_menu(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "memseeker.py"), "--menu"]).returncode


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 0
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "setup":
        return cmd_setup(args)
    if cmd == "lab":
        return cmd_lab(args)
    if cmd == "scan":
        return cmd_scan(args)
    if cmd == "scanall":
        return cmd_scanall(args)
    if cmd == "image":
        return cmd_image(args)
    if cmd == "labscan":
        return cmd_labscan(args)
    if cmd == "test":
        return cmd_test(args)
    if cmd == "doctor":
        return cmd_doctor(args)
    if cmd == "menu":
        return cmd_menu(args)
    print("Unknown command: %s" % cmd)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
