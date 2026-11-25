#!/bin/sh
# MemSeeker launcher for Linux / macOS (the tool itself is Linux-only:
# it reads /proc — on macOS this script only prints that note).
# Usage: ./run.sh setup | lab | scan <pid> --rules rules_lab.txt |
#        labscan | test | doctor | menu
if [ "$(uname)" != "Linux" ]; then
    echo "[!] MemSeeker is Linux-only (it reads /proc/<pid>/maps and"
    echo "    /proc/<pid>/mem). Run it on Kali Linux or any Linux VM."
    echo "    The lab and the tests below will not work on this OS."
fi
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
