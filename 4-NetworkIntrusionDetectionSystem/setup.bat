@echo off
title NIDS Setup
echo ============================================
echo   Network Intrusion Detection System
echo   Setup Script
echo ============================================
echo.

echo [1/3] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)
python --version
echo.

echo [2/3] Creating virtual environment...
if not exist "venv" (
    python -m venv venv
    echo Virtual environment created.
) else (
    echo Virtual environment already exists.
)
echo.

echo [3/3] Installing dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt
echo.

echo ============================================
echo   Setup complete!
echo.
echo   To run the NIDS, double-click run.bat
echo   or run: run.bat
echo ============================================
pause
