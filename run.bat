@echo off
REM MemSeeker launcher for Windows — NOTE: the tool itself is
REM Linux-only (it reads /proc/<pid>/maps and /proc/<pid>/mem, which
REM Windows does not have). Run it on Kali Linux or any Linux VM.
REM This file only prints that note; use run.sh / run.py on Linux.
echo [!] MemSeeker is Linux-only (it reads /proc, which Windows does not have).
echo     Run it on Kali Linux or any Linux VM:
echo       python run.py setup
echo       python run.py labscan
echo       python run.py test
pause
