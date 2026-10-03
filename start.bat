@echo off
rem ============================================
rem  net-optimizer launcher - double-click me
rem  Starts the GUI elevated (admin) by default.
rem  If UAC is declined, falls back to normal mode
rem  (repair buttons will re-elevate via new window).
rem  Set NOELEVATE=1 to always start normal mode.
rem
rem  Python lookup order (each candidate is probed):
rem    1. py launcher:  pyw.exe -3   (probe: py -3 must report 3.10+)
rem                     py.exe  -3   (only if pyw.exe is missing)
rem    2. pythonw.exe on PATH
rem    3. python.exe  on PATH (probe: must report 3.10+)
rem  If none works, a clear message is shown instead of the
rem  old silent exit (the window used to just flash and close).
rem
rem  Note: "py -3w" is NOT used - on this machine's py launcher
rem  (3.14) it exits with "No suitable Python runtime found" (103);
rem  pyw.exe -3 is the equivalent windowed launcher.
rem ============================================
setlocal
cd /d "%~dp0"

set "PYEXE="
set "PYARGS="
call :find_python
if not defined PYEXE goto :nopython

if "%NOELEVATE%"=="1" goto :normal

rem Already admin? Then just start normally.
net session >nul 2>nul
if not errorlevel 1 goto :normal

rem Not admin: relaunch elevated via UAC in a new window.
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "Start-Process -FilePath '%PYEXE%' -ArgumentList '%PYARGS% gui.py' -WorkingDirectory '%CD%' -Verb RunAs"
if errorlevel 1 (
    echo [net-optimizer] UAC elevation was cancelled or failed - starting in normal mode...
    goto :normal
)
exit /b

:normal
start "" %PYEXE% %PYARGS% gui.py
exit /b

rem ------------------------------------------------------------
:find_python
py -3 -c "import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>nul
if errorlevel 1 goto :fp_pythonw
where pyw.exe >nul 2>nul
if errorlevel 1 (
    set "PYEXE=py.exe"
    set "PYARGS=-3"
    exit /b 0
)
set "PYEXE=pyw.exe"
set "PYARGS=-3"
exit /b 0

:fp_pythonw
where pythonw.exe >nul 2>nul
if not errorlevel 1 (
    set "PYEXE=pythonw.exe"
    exit /b 0
)
python -c "import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>nul
if not errorlevel 1 (
    set "PYEXE=python.exe"
    exit /b 0
)
exit /b 1

rem ------------------------------------------------------------
:nopython
echo ============================================================
echo   [net-optimizer] Python 3.10 or newer was not found.
echo.
echo   Please install it from:
echo     https://www.python.org/downloads/windows/
echo   During setup, tick "Add python.exe to PATH",
echo   then double-click start.bat again.
echo ============================================================
echo.
pause
exit /b 1
