#!/bin/sh
# MemSeeker launcher for macOS / Linux (v1.1 — the tool now works on
# Linux, Windows and macOS; the lab process itself needs Linux).
# Usage: ./run.sh setup | lab | scan <pid> --rules rules_lab.txt |
#        scanall | image <file> --rules rules_lab.txt |
#        labscan | test | doctor | menu
cd "$(dirname "$0")" || exit 1
if [ -x "venv/bin/python" ]; then
    PY="venv/bin/python"
else
    PY="python3"
fi
if [ "$1" = "setup" ]; then
    exec "$PY" run.py setup
elif [ "$1" = "lab" ]; then
    exec "$PY" run.py lab
elif [ "$1" = "scan" ]; then
    shift; exec "$PY" memseeker.py "$@"
elif [ "$1" = "scanall" ]; then
    shift; exec "$PY" memseeker.py --all "$@"
elif [ "$1" = "image" ]; then
    shift; exec "$PY" memseeker.py --image "$@"
elif [ "$1" = "labscan" ]; then
    shift; exec "$PY" memseeker.py --lab "$@"
elif [ "$1" = "test" ]; then
    exec "$PY" test_memseeker.py
elif [ "$1" = "doctor" ]; then
    exec "$PY" memseeker.py --doctor
elif [ "$1" = "menu" ]; then
    exec "$PY" memseeker.py --menu
else
    exec "$PY" run.py "$@"
fi
