@echo off
cd /d "%~dp0"
title Secure Coding Review - Setup

echo ============================================
echo  Secure Coding Review - Setup
echo ============================================
echo.

REM === CHECK PYTHON ===
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Python detected:
    python --version
) else (
    echo [ERROR] Python not found.
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

REM === CREATE VIRTUAL ENVIRONMENT ===
echo.
echo [*] Setting up virtual environment...
if exist venv\Scripts\python.exe (
    echo [OK] Virtual environment already exists.
) else (
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
)

REM === INSTALL DEPENDENCIES ===
echo [*] Installing dependencies (Bandit)...
call venv\Scripts\activate.bat
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)
echo [OK] Dependencies installed successfully.

echo.
echo ============================================
echo  Setup complete! You can now use run.bat
echo  to perform the secure coding review.
echo ============================================
pause
exit /b 0
