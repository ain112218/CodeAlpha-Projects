@echo off
title NIDS - Network Intrusion Detection System
echo ============================================
echo   Starting Network Intrusion Detection System
echo   Press Ctrl+C to stop
echo ============================================
echo.

if not exist "venv" (
    echo Virtual environment not found. Please run setup.bat first.
    pause
    exit /b 1
)

call venv\Scripts\activate.bat
python nids.py %*

echo.
echo NIDS stopped. Check logs folder for alerts and stats.
pause
