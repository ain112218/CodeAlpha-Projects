@echo off
cd /d "%~dp0"
title Basic Network Sniffer

REM === AUTO-ELEVATE TO ADMINISTRATOR ===
>nul 2>&1 net session || (
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

REM === CHECK VIRTUAL ENVIRONMENT ===
if not exist venv\Scripts\activate.bat (
    echo [ERROR] Virtual environment not found.
    echo Please run setup.bat first to install dependencies.
    pause
    exit /b 1
)

echo Starting Basic Network Sniffer...
echo.

call venv\Scripts\activate.bat
python sniffer.py %*

if %errorlevel% neq 0 (
    echo.
)

echo.
echo Press any key to close this window...
pause >nul
