@echo off
cd /d "%~dp0"
title Basic Network Sniffer - Setup

REM === AUTO-ELEVATE TO ADMINISTRATOR ===
>nul 2>&1 net session || (
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

echo ============================================
echo  Basic Network Sniffer - Setup
echo ============================================
echo.

REM === CHECK / INSTALL PYTHON ===
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Python detected:
    python --version
) else (
    echo [*] Python not found. Downloading...
    call :install_python
    if %errorlevel% neq 0 (
        echo [ERROR] Could not install Python automatically.
        echo Please install Python 3.8+ from https://www.python.org/downloads/
        echo Make sure to check "Add Python to PATH" during installation.
        pause
        exit /b 1
    )
)

REM === CHECK / INSTALL NPCAP ===
sc query npcap >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Npcap is installed
) else (
    echo [*] Npcap not found.
    call :install_npcap
    if %errorlevel% neq 0 (
        echo [ERROR] Npcap installation was not completed.
        pause
        exit /b 1
    )
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
echo [*] Installing dependencies...
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
echo  to start the network sniffer.
echo ============================================
pause
exit /b 0


REM ===== SUBROUTINES =====

:install_python
    if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
        set "PY_ARCH=-amd64"
    ) else (
        set "PY_ARCH="
    )

    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.2/python-3.12.2%PY_ARCH%.exe' -OutFile '%TEMP%\python-installer.exe'"
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to download Python installer.
        exit /b 1
    )

    echo [*] Installing Python (this may take a minute)...
    start /wait "" "%TEMP%\python-installer.exe" /quiet InstallAllUsers=1 PrependPath=1
    set "PY_EXIT=%errorlevel%"

    if "%PY_EXIT%" neq "0" (
        if "%PY_EXIT%" neq "3010" (
            echo [ERROR] Python installer exited with code %PY_EXIT%.
            exit /b 1
        )
    )

    set "PATH=C:\Program Files\Python312\;C:\Program Files\Python312\Scripts\;%PATH%"
    echo [OK] Python 3.12.2 installed.
    exit /b 0


:install_npcap
    echo [*] Opening Npcap download page in your browser...
    start https://npcap.com/

    echo.
    echo [*] Npcap cannot be installed automatically (free version).
    echo.
    echo   1. Click "Download Npcap" on the page that just opened
    echo   2. Run the downloaded installer
    echo   3. Check "Install in WinPcap API-compatible Mode"
    echo   4. Complete the installation
    echo.
    echo [*] Press any key after Npcap is installed...
    pause >nul

    sc query npcap >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Npcap still not detected.
        echo Please install it manually, then run setup.bat again.
        exit /b 1
    )

    echo [OK] Npcap is installed
    exit /b 0
