@echo off
rem ============================================
rem  net-optimizer launcher - double-click me
rem  Starts the GUI elevated (admin) by default.
rem  If UAC is declined, falls back to normal mode
rem  (repair buttons will re-elevate via new window).
rem  Set NOELEVATE=1 to always start normal mode.
rem ============================================
cd /d "%~dp0"
if not "%NOELEVATE%"=="1" (
    net session >nul 2>nul
    if errorlevel 1 (
        %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "Start-Process -FilePath 'pythonw.exe' -ArgumentList 'gui.py' -WorkingDirectory '%~dp0' -Verb RunAs"
        if errorlevel 1 (
            start "" pythonw.exe gui.py
        )
        exit /b
    )
)
start "" pythonw.exe gui.py
