@echo off
REM MemSeeker launcher for Windows (v1.1 — the tool now works on
REM Windows, macOS and Linux).
REM Usage: run.bat setup | scan <pid> --rules rules_lab.txt |
REM        scanall | image <file> --rules rules_lab.txt |
REM        test | doctor | menu
REM With no arguments it opens the menu.
setlocal
cd /d "%~dp0"
if exist "venv\Scripts\python.exe" (
    set "PY=venv\Scripts\python.exe"
) else (
    set "PY=python"
)
if "%~1"=="" (
    "%PY%" memseeker.py --menu
    goto :end
)
if /i "%~1"=="setup" (
    "%PY%" run.py setup
    goto :end
)
if /i "%~1"=="scan" (
    shift
    "%PY%" memseeker.py %*
    goto :end
)
if /i "%~1"=="scanall" (
    shift
    "%PY%" memseeker.py --all %*
    goto :end
)
if /i "%~1"=="image" (
    shift
    "%PY%" memseeker.py --image %*
    goto :end
)
if /i "%~1"=="test" (
    "%PY%" test_memseeker.py
    goto :end
)
if /i "%~1"=="doctor" (
    "%PY%" memseeker.py --doctor
    goto :end
)
if /i "%~1"=="menu" (
    "%PY%" memseeker.py --menu
    goto :end
)
REM Anything else is passed straight to run.py (e.g. labscan on Linux).
"%PY%" run.py %*
:end
endlocal
